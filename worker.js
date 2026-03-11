/**
 * Cloudflare Worker - DNS Log Scanner with Web UI, D1 Storage, and TLD Parsing
 * Scans Gateway DNS logs from R2 bucket and provides a web interface
 */

const WORKER_VERSION = "v3.0.1";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        // Serve web UI on root path
        if (url.pathname === '/' && request.method === 'GET') {
            const html = getHTML();
            return new Response(html, {
                headers: {
                    'Content-Type': 'text/html; charset=utf-8',
                    'X-Worker-Version': WORKER_VERSION,
                    'X-HTML-Length': html.length.toString(),
                    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }
            });
        }

        // Version check endpoint
        if (url.pathname === '/api/version') {
            return jsonResponse({
                version: WORKER_VERSION,
                timestamp: new Date().toISOString()
            });
        }

        // NEW endpoint - guaranteed to use new code
        if (url.pathname === '/api/list-dates-v2' && request.method === 'GET') {
            return handleListDatesV2(request, env);
        }

        // API routes
        if (url.pathname === '/api/scan' && request.method === 'POST') {
            return handleScan(request, env);
        } else if (url.pathname === '/api/scan-date' && request.method === 'POST') {
            return handleScanDate(request, env);
        } else if (url.pathname === '/api/debug-bucket' && request.method === 'GET') {
            return handleDebugBucket(request, env);
        } else if (url.pathname === '/api/list-files' && request.method === 'POST') {
            return handleListFiles(request, env);
        } else if (url.pathname === '/api/saved-scans' && request.method === 'GET') {
            return handleListSavedScans(request, env);
        } else if (url.pathname === '/api/load-scan' && request.method === 'POST') {
            return handleLoadScan(request, env);
        } else if (url.pathname === '/api/delete-scan' && request.method === 'POST') {
            return handleDeleteScan(request, env);
        }

        return new Response('Not Found', { status: 404 });
    }
};

/**
 * Initialize D1 database schema
 */
async function initDatabase(db) {
    try {
        await db.prepare(`
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        scan_time TEXT NOT NULL,
        file_count INTEGER NOT NULL,
        record_count INTEGER NOT NULL,
        UNIQUE(date)
      )
    `).run();

        await db.prepare(`
      CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        location TEXT,
        query_name TEXT,
        query_tld TEXT,
        query_categories TEXT,
        resolved_ips TEXT,
        resolver_decision TEXT,
        src_ip TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
      )
    `).run();

        await db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_scan_date ON scans(date)
    `).run();

        await db.prepare(`
      CREATE INDEX IF NOT EXISTS idx_record_scan ON records(scan_id)
    `).run();
    } catch (error) {
        console.error('Database init error:', error);
    }
}

/**
 * Extract TLD from domain name
 */
function extractTLD(domain) {
    if (!domain) return '';

    // Remove trailing dot if present
    domain = domain.replace(/\.$/, '');

    const parts = domain.split('.');
    if (parts.length === 0) return '';

    // Get the last part (TLD)
    const tld = parts[parts.length - 1];

    return tld ? `.${tld}` : '';
}

/**
 * List saved scans from D1
 */
async function handleListSavedScans(request, env) {
    try {
        if (!env.DB) {
            return jsonResponse({ scans: [], message: 'D1 database not configured' });
        }

        await initDatabase(env.DB);

        const result = await env.DB.prepare(`
      SELECT id, date, scan_time, file_count, record_count
      FROM scans
      ORDER BY date DESC
    `).all();

        return jsonResponse({ scans: result.results || [] });
    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

/**
 * Load a saved scan from D1
 */
async function handleLoadScan(request, env) {
    try {
        if (!env.DB) {
            return jsonResponse({ error: 'D1 database not configured' }, 400);
        }

        const { date } = await request.json();

        if (!date) {
            return jsonResponse({ error: 'Missing date parameter' }, 400);
        }

        const scanResult = await env.DB.prepare(`
      SELECT * FROM scans WHERE date = ?
    `).bind(date).first();

        if (!scanResult) {
            return jsonResponse({ error: 'Scan not found' }, 404);
        }

        const recordsResult = await env.DB.prepare(`
      SELECT location, query_name, query_tld, query_categories, 
             resolved_ips, resolver_decision, src_ip
      FROM records
      WHERE scan_id = ?
    `).bind(scanResult.id).all();

        const records = recordsResult.results.map(r => ({
            Location: r.location,
            QueryName: r.query_name,
            QueryTLD: r.query_tld,
            QueryCategoryNames: r.query_categories ? JSON.parse(r.query_categories) : [],
            ResolvedIPs: r.resolved_ips ? JSON.parse(r.resolved_ips) : [],
            ResolverDecision: r.resolver_decision,
            SrcIP: r.src_ip
        }));

        return jsonResponse({
            date: scanResult.date,
            filesProcessed: scanResult.file_count,
            recordCount: scanResult.record_count,
            records,
            fromCache: true
        });
    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

/**
 * Delete a saved scan from D1
 */
async function handleDeleteScan(request, env) {
    try {
        if (!env.DB) {
            return jsonResponse({ error: 'D1 database not configured' }, 400);
        }

        const { date } = await request.json();

        if (!date) {
            return jsonResponse({ error: 'Missing date parameter' }, 400);
        }

        const result = await env.DB.prepare(`
      DELETE FROM scans WHERE date = ?
    `).bind(date).run();

        return jsonResponse({ success: true, deleted: result.changes > 0 });
    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

/**
 * Save scan to D1
 */
async function saveScanToD1(db, date, fileCount, records) {
    try {
        await initDatabase(db);

        // Delete existing scan for this date
        await db.prepare(`DELETE FROM scans WHERE date = ?`).bind(date).run();

        // Insert scan metadata
        const scanResult = await db.prepare(`
      INSERT INTO scans (date, scan_time, file_count, record_count)
      VALUES (?, datetime('now'), ?, ?)
    `).bind(date, fileCount, records.length).run();

        const scanId = scanResult.meta.last_row_id;

        // Batch insert records (D1 has a limit, so we'll do chunks of 100)
        const chunkSize = 100;
        for (let i = 0; i < records.length; i += chunkSize) {
            const chunk = records.slice(i, i + chunkSize);

            const stmt = db.prepare(`
        INSERT INTO records (scan_id, location, query_name, query_tld, query_categories, 
                            resolved_ips, resolver_decision, src_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

            const batch = chunk.map(r =>
                stmt.bind(
                    scanId,
                    r.Location,
                    r.QueryName,
                    r.QueryTLD,
                    JSON.stringify(r.QueryCategoryNames),
                    JSON.stringify(r.ResolvedIPs),
                    r.ResolverDecision,
                    r.SrcIP
                )
            );

            await db.batch(batch);
        }

        return true;
    } catch (error) {
        console.error('Error saving to D1:', error);
        return false;
    }
}

/**
 * List files for a specific date
 */
async function handleListFiles(request, env) {
    try {
        const { date } = await request.json();

        if (!date) {
            return jsonResponse({ error: 'Missing date parameter' }, 400);
        }

        const prefix = `${date}/`;
        const listed = await env.R2_BUCKET.list({ prefix, limit: 1000 });

        const files = listed.objects.map(obj => ({
            name: obj.key.split('/').pop(),
            size: obj.size,
            uploaded: obj.uploaded
        }));

        return jsonResponse({ files });
    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

/**
 * Scan a specific log file
 */
async function handleScan(request, env) {
    try {
        const { date, filename } = await request.json();

        if (!date || !filename) {
            return jsonResponse({ error: 'Missing date or filename' }, 400);
        }

        const key = `${date}/${filename}`;
        const records = await processLogFile(env.R2_BUCKET, key);

        return jsonResponse({
            file: key,
            recordCount: records.length,
            records
        });
    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

/**
 * Scan all files for a specific date with progress streaming
 */
async function handleScanDate(request, env) {
    // Parse request body first
    let date, limit;
    try {
        const body = await request.json();
        date = body.date;
        limit = body.limit || 100;
    } catch (error) {
        return jsonResponse({ error: 'Invalid request body' }, 400);
    }

    if (!date) {
        return jsonResponse({ error: 'Missing date parameter' }, 400);
    }

    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();
    const encoder = new TextEncoder();

    // Start processing in background
    (async () => {
        try {
            const prefix = `${date}/`;
            const listed = await env.R2_BUCKET.list({ prefix, limit });

            const totalFiles = listed.objects.length;
            const allRecords = [];
            let filesProcessed = 0;

            for (const obj of listed.objects) {
                const records = await processLogFile(env.R2_BUCKET, obj.key);
                allRecords.push(...records);
                filesProcessed++;

                // Send progress update
                await writer.write(encoder.encode(`data: ${JSON.stringify({
                    progress: true,
                    filesProcessed,
                    totalFiles,
                    recordsFound: allRecords.length
                })}\n\n`));
            }

            // Save to D1 if available
            if (env.DB) {
                await writer.write(encoder.encode(`data: ${JSON.stringify({
                    progress: true,
                    status: 'Saving to database...'
                })}\n\n`));

                await saveScanToD1(env.DB, date, filesProcessed, allRecords);
            }

            // Send final result
            await writer.write(encoder.encode(`data: ${JSON.stringify({
                complete: true,
                date,
                filesProcessed,
                totalRecords: allRecords.length,
                records: allRecords
            })}\n\n`));

            await writer.close();
        } catch (error) {
            await writer.write(encoder.encode(`data: ${JSON.stringify({ error: error.message })}\n\n`));
            await writer.close();
        }
    })();

    return new Response(readable, {
        headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    });
}

/**
 * Debug endpoint to see raw bucket contents
 */
async function handleDebugBucket(request, env) {
    try {
        // Check if R2 binding exists
        if (!env.R2_BUCKET) {
            return jsonResponse({
                error: 'R2_BUCKET binding not found',
                availableBindings: Object.keys(env)
            }, 500);
        }

        const listed = await env.R2_BUCKET.list({
            delimiter: '/',
            limit: 100
        });

        return jsonResponse({
            delimitedPrefixes: listed.delimitedPrefixes,
            prefixCount: listed.delimitedPrefixes?.length || 0,
            objects: listed.objects?.slice(0, 10).map(o => o.key) || [],
            objectCount: listed.objects?.length || 0,
            truncated: listed.truncated,
            cursor: listed.cursor
        });
    } catch (error) {
        return jsonResponse({
            error: error.message,
            stack: error.stack,
            name: error.name
        }, 500);
    }
}

/**
 * List all available date folders - V2 (NEW)
 */
async function handleListDatesV2(request, env) {
    console.log('[handleListDatesV2] Starting');

    try {
        const listed = await env.R2_BUCKET.list({
            delimiter: '/',
            limit: 100  // Changed from 1000 to match debug endpoint
        });

        const dates = listed.delimitedPrefixes
            .map(p => p.replace('/', ''))
            .filter(d => /^\d{8}$/.test(d))
            .sort()
            .reverse();

        return jsonResponse({
            version: WORKER_VERSION,
            endpoint: 'v2',
            dates: dates,
            total: dates.length,
            allPrefixes: listed.delimitedPrefixes,
            truncated: listed.truncated,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        return jsonResponse({
            version: WORKER_VERSION,
            error: error.message
        }, 500);
    }
}



/**
 * Process a single log file from R2
 */
async function processLogFile(bucket, key) {
    const obj = await bucket.get(key);

    if (!obj) {
        throw new Error(`File not found: ${key}`);
    }

    const gzipData = await obj.arrayBuffer();
    const decompressed = await decompressGzip(gzipData);

    const lines = decompressed.split('\n').filter(line => line.trim());
    const records = [];

    for (const line of lines) {
        try {
            const log = JSON.parse(line);

            records.push({
                Location: log.Location || '',
                QueryName: log.QueryName || '',
                QueryTLD: extractTLD(log.QueryName),
                QueryCategoryNames: log.QueryCategoryNames || [],
                ResolvedIPs: log.ResolvedIPs || [],
                ResolverDecision: log.ResolverDecision || '',
                SrcIP: log.SrcIP || ''
            });
        } catch (e) {
            console.error('Failed to parse line:', e.message);
        }
    }

    return records;
}

/**
 * Decompress gzip data
 */
async function decompressGzip(data) {
    const stream = new Response(data).body
        .pipeThrough(new DecompressionStream('gzip'));

    const decompressed = await new Response(stream).arrayBuffer();
    return new TextDecoder().decode(decompressed);
}

/**
 * Helper to create JSON responses
 */
function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    });
}

/**
 * HTML interface
 */
function getHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title>DNS Log Scanner v3.0.1</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 20px;
    }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 {
      font-size: 2rem;
      margin-bottom: 30px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .controls {
      background: #1e293b;
      padding: 25px;
      border-radius: 12px;
      margin-bottom: 25px;
      border: 1px solid #334155;
    }
    .control-group {
      margin-bottom: 20px;
    }
    .control-group:last-child { margin-bottom: 0; }
    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
      color: #94a3b8;
      font-size: 0.875rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    select, input {
      width: 100%;
      padding: 12px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 0.95rem;
      transition: all 0.2s;
    }
    select:focus, input:focus {
      outline: none;
      border-color: #667eea;
      box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    select:disabled, input:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .button-group {
      display: flex;
      gap: 12px;
      margin-top: 20px;
    }
    button {
      flex: 1;
      padding: 12px 24px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.95rem;
      transition: all 0.2s;
    }
    button:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
    }
    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    button.secondary {
      background: #334155;
    }
    button.secondary:hover:not(:disabled) {
      background: #475569;
      box-shadow: 0 10px 25px rgba(51, 65, 85, 0.3);
    }
    button.danger {
      background: #ef4444;
    }
    button.danger:hover:not(:disabled) {
      background: #dc2626;
      box-shadow: 0 10px 25px rgba(239, 68, 68, 0.3);
    }
    .status {
      background: #1e293b;
      padding: 15px 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      border-left: 4px solid #667eea;
      display: none;
    }
    .status.show { display: block; }
    .status.error { border-left-color: #ef4444; }
    .status.success { border-left-color: #10b981; }
    .progress-bar {
      background: #1e293b;
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 20px;
      display: none;
      border: 1px solid #334155;
    }
    .progress-bar.show { display: block; }
    .progress-text {
      margin-bottom: 12px;
      color: #94a3b8;
      font-size: 0.9rem;
    }
    .progress-track {
      height: 8px;
      background: #0f172a;
      border-radius: 4px;
      overflow: hidden;
    }
    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
      width: 0%;
      transition: width 0.3s;
    }
    .saved-scans {
      background: #1e293b;
      padding: 20px;
      border-radius: 12px;
      margin-bottom: 25px;
      border: 1px solid #334155;
    }
    .saved-scans h2 {
      font-size: 1.2rem;
      margin-bottom: 15px;
      color: #e2e8f0;
    }
    .saved-scan-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px;
      background: #0f172a;
      border-radius: 6px;
      margin-bottom: 8px;
      border: 1px solid #334155;
    }
    .saved-scan-info {
      flex: 1;
    }
    .saved-scan-date {
      font-weight: 600;
      color: #e2e8f0;
    }
    .saved-scan-meta {
      font-size: 0.85rem;
      color: #94a3b8;
      margin-top: 4px;
    }
    .saved-scan-actions {
      display: flex;
      gap: 8px;
    }
    .saved-scan-actions button {
      padding: 8px 16px;
      font-size: 0.85rem;
    }
    .results {
      background: #1e293b;
      border-radius: 12px;
      overflow: hidden;
      border: 1px solid #334155;
    }
    .results-header {
      padding: 20px;
      background: #0f172a;
      border-bottom: 1px solid #334155;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .results-title {
      font-size: 1.1rem;
      font-weight: 600;
    }
    .record-count {
      color: #94a3b8;
      font-size: 0.9rem;
    }
    .table-container {
      overflow-x: auto;
      max-height: 600px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th {
      background: #0f172a;
      padding: 14px 16px;
      text-align: left;
      font-weight: 600;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #94a3b8;
      position: sticky;
      top: 0;
      z-index: 10;
      cursor: pointer;
      user-select: none;
      transition: background 0.2s;
    }
    th:hover {
      background: #1e293b;
    }
    th.sortable::after {
      content: '⇅';
      margin-left: 8px;
      opacity: 0.3;
    }
    th.sort-asc::after {
      content: '↑';
      opacity: 1;
    }
    th.sort-desc::after {
      content: '↓';
      opacity: 1;
    }
    td {
      padding: 12px 16px;
      border-top: 1px solid #334155;
      font-size: 0.9rem;
    }
    tr:hover {
      background: #0f172a;
    }
    .array-cell {
      max-width: 300px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      background: #334155;
      border-radius: 4px;
      font-size: 0.8rem;
      margin-right: 6px;
      margin-bottom: 4px;
    }
    .tld-badge {
      background: #764ba2;
      color: white;
      font-weight: 600;
    }
    .view-toggle {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }
    .view-toggle button {
      flex: 1;
    }
    .view-toggle button.active {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    .warning-badge {
      background: #f59e0b;
      color: white;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      margin-left: 8px;
    }
    .danger-badge {
      background: #ef4444;
      color: white;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔍 DNS Log Scanner</h1>
    <div style="color: #94a3b8; font-size: 0.85rem; margin-bottom: 20px;">
      Worker Version: ${WORKER_VERSION} | HTML Generated: ${new Date().toISOString()}
    </div>
    
    <div class="saved-scans" id="savedScans" style="display: none;">
      <h2>💾 Saved Scans</h2>
      <div id="savedScansList"></div>
    </div>
    
    <div class="controls">
      <div class="control-group">
        <label for="scanType">Scan Type</label>
        <select id="scanType">
          <option value="date">Scan All Files for Date</option>
          <option value="file">Scan Single File</option>
        </select>
      </div>
      
      <div class="control-group">
        <label for="dateSelect">Select Date</label>
        <select id="dateSelect">
          <option value="">Loading dates...</option>
        </select>
      </div>
      
      <div class="control-group" id="fileGroup" style="display: none;">
        <label for="fileSelect">Select File</label>
        <select id="fileSelect">
          <option value="">Select a date first...</option>
        </select>
      </div>
      
      <div class="control-group" id="limitGroup">
        <label for="limitInput">File Limit (for date scan)</label>
        <input type="number" id="limitInput" value="100" min="1" max="1000">
      </div>
      
      <div class="button-group">
        <button id="scanBtn">Scan Logs</button>
      </div>
    </div>
    
    <div class="status" id="status"></div>
    
    <div class="progress-bar" id="progressBar">
      <div class="progress-text" id="progressText">Processing files...</div>
      <div class="progress-track">
        <div class="progress-fill" id="progressFill"></div>
      </div>
    </div>
    
    <div class="view-toggle" id="viewToggle" style="display: none;">
      <button id="tldViewBtn" class="secondary active">TLD Analysis</button>
      <button id="allRecordsViewBtn" class="secondary">All Records</button>
    </div>
    
    <div class="results" id="tldResults" style="display: none;">
      <div class="results-header">
        <div class="results-title">🔍 TLD Analysis - APT Detection</div>
        <div class="record-count" id="tldRecordCount"></div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th class="sortable" data-column="tld">TLD</th>
              <th class="sortable" data-column="count">Query Count</th>
              <th class="sortable" data-column="uniqueDomains">Unique Domains</th>
              <th class="sortable" data-column="avgLength">Avg Domain Length</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="tldTableBody"></tbody>
        </table>
      </div>
    </div>
    
    <div class="results" id="domainResults" style="display: none;">
      <div class="results-header">
        <div>
          <div class="results-title">Domains for <span id="selectedTLD"></span></div>
          <button class="secondary" onclick="backToTLDView()" style="margin-top: 8px; padding: 6px 12px; font-size: 0.85rem;">← Back to TLD Analysis</button>
        </div>
        <div class="record-count" id="domainRecordCount"></div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th class="sortable" data-column="domain">Domain</th>
              <th class="sortable" data-column="count">Query Count</th>
              <th class="sortable" data-column="length">Length</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="domainTableBody"></tbody>
        </table>
      </div>
    </div>
    
    <div class="results" id="allResults" style="display: none;">
      <div class="results-header">
        <div class="results-title">DNS Query Results</div>
        <div class="record-count" id="recordCount"></div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th class="sortable" data-column="Location">Location</th>
              <th class="sortable" data-column="QueryName">Query Name</th>
              <th class="sortable" data-column="QueryTLD">TLD</th>
              <th class="sortable" data-column="QueryCategoryNames">Categories</th>
              <th class="sortable" data-column="ResolvedIPs">Resolved IPs</th>
              <th class="sortable" data-column="ResolverDecision">Decision</th>
              <th class="sortable" data-column="SrcIP">Source IP</th>
            </tr>
          </thead>
          <tbody id="tableBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    // Show version immediately
    document.addEventListener('DOMContentLoaded', function() {
      const versionDiv = document.createElement('div');
      versionDiv.style.cssText = 'position: fixed; top: 10px; right: 10px; background: #1e293b; padding: 8px 12px; border-radius: 6px; font-size: 0.75rem; color: #94a3b8; z-index: 9999;';
      versionDiv.textContent = 'Worker v3.0.1 | Page loaded: ' + new Date().toLocaleTimeString();
      document.body.appendChild(versionDiv);
    });
    
    let currentData = [];
    let tldAnalysisData = [];
    let currentView = 'tld';
    let sortColumn = null;
    let sortDirection = 'asc';

    // Analyze TLDs from records
    function analyzeTLDs(records) {
      const tldMap = new Map();
      
      records.forEach(record => {
        const tld = record.QueryTLD || 'unknown';
        const domain = record.QueryName || '';
        
        if (!tldMap.has(tld)) {
          tldMap.set(tld, {
            tld,
            count: 0,
            domains: new Map()
          });
        }
        
        const tldData = tldMap.get(tld);
        tldData.count++;
        
        if (domain) {
          tldData.domains.set(domain, (tldData.domains.get(domain) || 0) + 1);
        }
      });
      
      // Convert to array and calculate stats
      const analysis = Array.from(tldMap.values()).map(item => {
        const domains = Array.from(item.domains.entries()).map(([domain, count]) => ({
          domain,
          count,
          length: domain.length
        }));
        
        const avgLength = domains.length > 0 
          ? domains.reduce((sum, d) => sum + d.length, 0) / domains.length 
          : 0;
        
        return {
          tld: item.tld,
          count: item.count,
          uniqueDomains: item.domains.size,
          avgLength: Math.round(avgLength),
          domains: domains.sort((a, b) => b.count - a.count)
        };
      });
      
      // Sort by count descending
      return analysis.sort((a, b) => b.count - a.count);
    }

    // Display TLD analysis
    function displayTLDAnalysis(analysis) {
      const tbody = document.getElementById('tldTableBody');
      tbody.innerHTML = '';
      
      analysis.forEach(item => {
        const row = tbody.insertRow();
        
        const tldCell = row.insertCell();
        tldCell.innerHTML = \`<span class="badge tld-badge">\${item.tld}</span>\`;
        
        row.insertCell().textContent = item.count.toLocaleString();
        
        const uniqueCell = row.insertCell();
        uniqueCell.textContent = item.uniqueDomains.toLocaleString();
        
        // Flag potential DGA activity
        if (item.uniqueDomains > 20 && item.avgLength > 15) {
          uniqueCell.innerHTML += '<span class="warning-badge">Potential DGA</span>';
        }
        if (item.uniqueDomains > 50 && item.avgLength > 20) {
          uniqueCell.innerHTML = uniqueCell.innerHTML.replace('warning-badge', 'danger-badge');
          uniqueCell.innerHTML = uniqueCell.innerHTML.replace('Potential DGA', 'High DGA Risk');
        }
        
        row.insertCell().textContent = item.avgLength;
        
        const actionsCell = row.insertCell();
        const btn = document.createElement('button');
        btn.textContent = 'View Domains';
        btn.className = 'secondary';
        btn.style.padding = '6px 12px';
        btn.style.fontSize = '0.85rem';
        btn.onclick = () => showDomainsForTLD(item);
        actionsCell.appendChild(btn);
      });
      
      document.getElementById('tldRecordCount').textContent = 
        \`\${analysis.length} TLD\${analysis.length !== 1 ? 's' : ''} • \${currentData.length.toLocaleString()} total queries\`;
      document.getElementById('tldResults').style.display = 'block';
      document.getElementById('domainResults').style.display = 'none';
      document.getElementById('allResults').style.display = 'none';
      document.getElementById('viewToggle').style.display = 'flex';
    }

    // Show domains for a specific TLD
    function showDomainsForTLD(tldData) {
      document.getElementById('selectedTLD').textContent = tldData.tld;
      
      const tbody = document.getElementById('domainTableBody');
      tbody.innerHTML = '';
      
      tldData.domains.forEach(domain => {
        const row = tbody.insertRow();
        
        const domainCell = row.insertCell();
        domainCell.textContent = domain.domain;
        
        // Flag suspicious patterns
        if (domain.length > 30) {
          domainCell.innerHTML += '<span class="warning-badge">Long</span>';
        }
        if (/[0-9]{5,}/.test(domain.domain)) {
          domainCell.innerHTML += '<span class="warning-badge">Many Numbers</span>';
        }
        if (!/[aeiou]/i.test(domain.domain)) {
          domainCell.innerHTML += '<span class="warning-badge">No Vowels</span>';
        }
        
        row.insertCell().textContent = domain.count.toLocaleString();
        row.insertCell().textContent = domain.length;
        
        const actionsCell = row.insertCell();
        const btn = document.createElement('button');
        btn.textContent = 'Filter Records';
        btn.className = 'secondary';
        btn.style.padding = '6px 12px';
        btn.style.fontSize = '0.85rem';
        btn.onclick = () => filterByDomain(domain.domain);
        actionsCell.appendChild(btn);
      });
      
      document.getElementById('domainRecordCount').textContent = 
        \`\${tldData.domains.length} unique domain\${tldData.domains.length !== 1 ? 's' : ''} • \${tldData.count.toLocaleString()} queries\`;
      
      document.getElementById('tldResults').style.display = 'none';
      document.getElementById('domainResults').style.display = 'block';
    }

    // Back to TLD view
    function backToTLDView() {
      displayTLDAnalysis(tldAnalysisData);
    }

    // Filter records by domain
    function filterByDomain(domain) {
      const filtered = currentData.filter(r => r.QueryName === domain);
      document.getElementById('allRecordsViewBtn').classList.add('active');
      document.getElementById('tldViewBtn').classList.remove('active');
      displayAllRecords(filtered);
      showStatus('Filtered to ' + filtered.length + ' records for ' + domain, 'success');
    }

    // Load dates on page load
    async function loadDates() {
      try {
        const response = await fetch('/api/list-dates-v2');
        const data = await response.json();
        
        if (data.error) {
          showStatus('Error loading dates: ' + data.error, 'error');
          return;
        }
        
        const select = document.getElementById('dateSelect');
        
        if (!data.dates || data.dates.length === 0) {
          select.innerHTML = '<option value="">No dates found</option>';
          showStatus('No date folders found in bucket.', 'error');
          return;
        }
        
        select.innerHTML = '<option value="">Select a date...</option>';
        data.dates.forEach(date => {
          const option = document.createElement('option');
          option.value = date;
          option.textContent = formatDate(date);
          select.appendChild(option);
        });
        
        showStatus(\`Loaded \${data.dates.length} dates\`, 'success');
      } catch (error) {
        showStatus('Failed to load dates: ' + error.message, 'error');
      }
    }

    // Load saved scans
    async function loadSavedScans() {
      try {
        const response = await fetch('/api/saved-scans');
        const data = await response.json();
        
        if (data.scans && data.scans.length > 0) {
          document.getElementById('savedScans').style.display = 'block';
          const list = document.getElementById('savedScansList');
          list.innerHTML = '';
          
          data.scans.forEach(scan => {
            const item = document.createElement('div');
            item.className = 'saved-scan-item';
            item.innerHTML = \`
              <div class="saved-scan-info">
                <div class="saved-scan-date">\${formatDate(scan.date)}</div>
                <div class="saved-scan-meta">
                  \${scan.file_count} files • \${scan.record_count.toLocaleString()} records • 
                  Saved: \${new Date(scan.scan_time + 'Z').toLocaleString()}
                </div>
              </div>
              <div class="saved-scan-actions">
                <button class="secondary" onclick="loadSavedScan('\${scan.date}')">Load</button>
                <button class="danger" onclick="deleteSavedScan('\${scan.date}')">Delete</button>
              </div>
            \`;
            list.appendChild(item);
          });
        }
      } catch (error) {
        console.error('Failed to load saved scans:', error);
      }
    }

    // Load a saved scan
    async function loadSavedScan(date) {
      try {
        document.getElementById('scanBtn').disabled = true;
        showStatus('Loading saved scan...', 'success');
        
        const response = await fetch('/api/load-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ date })
        });
        
        const data = await response.json();
        
        if (data.error) {
          showStatus(data.error, 'error');
        } else {
          currentData = data.records;
          tldAnalysisData = analyzeTLDs(data.records);
          displayTLDAnalysis(tldAnalysisData);
          showStatus(\`Loaded \${data.recordCount.toLocaleString()} records from saved scan\`, 'success');
        }
      } catch (error) {
        showStatus('Failed to load scan: ' + error.message, 'error');
      } finally {
        document.getElementById('scanBtn').disabled = false;
      }
    }

    // Delete a saved scan
    async function deleteSavedScan(date) {
      if (!confirm(\`Delete saved scan for \${formatDate(date)}?\`)) return;
      
      try {
        const response = await fetch('/api/delete-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ date })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showStatus('Scan deleted successfully', 'success');
          loadSavedScans();
        } else {
          showStatus('Failed to delete scan', 'error');
        }
      } catch (error) {
        showStatus('Failed to delete scan: ' + error.message, 'error');
      }
    }

    // Load files for selected date
    async function loadFiles(date) {
      try {
        const response = await fetch('/api/list-files', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ date })
        });
        const data = await response.json();
        
        const select = document.getElementById('fileSelect');
        select.innerHTML = '<option value="">Select a file...</option>';
        data.files.forEach(file => {
          const option = document.createElement('option');
          option.value = file.name;
          option.textContent = file.name;
          select.appendChild(option);
        });
      } catch (error) {
        showStatus('Failed to load files: ' + error.message, 'error');
      }
    }

    // Format date string
    function formatDate(dateStr) {
      if (!dateStr) return '';
      
      // Handle YYYYMMDD format (20251112)
      if (dateStr.length === 8 && /^\d{8}$/.test(dateStr)) {
        const year = dateStr.substring(0, 4);
        const month = dateStr.substring(4, 6);
        const day = dateStr.substring(6, 8);
        return year + '-' + month + '-' + day;
      }
      
      // Handle YY-MM-DD format (26-01-01)
      if (dateStr.includes('-')) {
        const parts = dateStr.split('-');
        if (parts.length === 3) {
          const year = '20' + parts[0];
          const month = parts[1];
          const day = parts[2];
          return year + '-' + month + '-' + day;
        }
      }
      
      return dateStr;
    }

    // Show status message
    function showStatus(message, type = 'success') {
      const status = document.getElementById('status');
      status.textContent = message;
      status.className = 'status show ' + type;
      setTimeout(() => status.classList.remove('show'), 5000);
    }

    // Scan logs
    async function scanLogs() {
      const scanType = document.getElementById('scanType').value;
      const date = document.getElementById('dateSelect').value;
      
      if (!date) {
        showStatus('Please select a date', 'error');
        return;
      }
      
      const scanBtn = document.getElementById('scanBtn');
      scanBtn.disabled = true;
      
      document.getElementById('tldResults').style.display = 'none';
      document.getElementById('domainResults').style.display = 'none';
      document.getElementById('allResults').style.display = 'none';
      document.getElementById('viewToggle').style.display = 'none';
      
      try {
        if (scanType === 'file') {
          const filename = document.getElementById('fileSelect').value;
          if (!filename) {
            showStatus('Please select a file', 'error');
            return;
          }
          
          scanBtn.textContent = 'Scanning...';
          
          const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ date, filename })
          });
          
          const data = await response.json();
          
          if (data.error) {
            showStatus(data.error, 'error');
          } else {
            currentData = data.records;
            tldAnalysisData = analyzeTLDs(data.records);
            displayTLDAnalysis(tldAnalysisData);
            showStatus(\`Loaded \${data.recordCount.toLocaleString()} records\`, 'success');
          }
          
          scanBtn.textContent = 'Scan Logs';
        } else {
          // Date scan with progress
          const limit = parseInt(document.getElementById('limitInput').value);
          
          scanBtn.textContent = 'Scanning...';
          const progressBar = document.getElementById('progressBar');
          const progressFill = document.getElementById('progressFill');
          const progressText = document.getElementById('progressText');
          progressBar.classList.add('show');
          progressFill.style.width = '0%';
          progressText.textContent = 'Starting scan...';
          
          const response = await fetch('/api/scan-date', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ date, limit })
          });
          
          if (!response.ok) {
            throw new Error('Scan request failed');
          }
          
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          
          while (true) {
            const { done, value } = await reader.read();
            
            if (done) {
              console.log('Stream complete');
              break;
            }
            
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\\n\\n');
            buffer = lines.pop();
            
            for (const line of lines) {
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.substring(6));
                  console.log('Progress data:', data);
                  
                  if (data.progress) {
                    if (data.totalFiles) {
                      const percent = (data.filesProcessed / data.totalFiles) * 100;
                      progressFill.style.width = percent + '%';
                      progressText.textContent = 
                        \`Processing \${data.filesProcessed}/\${data.totalFiles} files... (\${data.recordsFound.toLocaleString()} records found)\`;
                    } else if (data.status) {
                      progressText.textContent = data.status;
                    }
                  } else if (data.complete) {
                    currentData = data.records;
                    tldAnalysisData = analyzeTLDs(data.records);
                    displayTLDAnalysis(tldAnalysisData);
                    showStatus(\`Loaded \${data.totalRecords.toLocaleString()} records from \${data.filesProcessed} files (saved to database)\`, 'success');
                    loadSavedScans();
                  } else if (data.error) {
                    showStatus(data.error, 'error');
                  }
                } catch (e) {
                  console.error('Error parsing SSE data:', e, line);
                }
              }
            }
          }
          
          progressBar.classList.remove('show');
          scanBtn.textContent = 'Scan Logs';
        }
      } catch (error) {
        console.error('Scan error:', error);
        showStatus('Scan failed: ' + error.message, 'error');
        document.getElementById('progressBar').classList.remove('show');
        scanBtn.textContent = 'Scan Logs';
      } finally {
        scanBtn.disabled = false;
      }
    }

    // Display results in table
    function displayAllRecords(records) {
      const tbody = document.getElementById('tableBody');
      tbody.innerHTML = '';
      
      records.forEach(record => {
        const row = tbody.insertRow();
        
        row.insertCell().textContent = record.Location;
        row.insertCell().textContent = record.QueryName;
        
        const tldCell = row.insertCell();
        if (record.QueryTLD) {
          tldCell.innerHTML = \`<span class="badge tld-badge">\${record.QueryTLD}</span>\`;
        }
        
        const catCell = row.insertCell();
        catCell.className = 'array-cell';
        catCell.innerHTML = record.QueryCategoryNames.map(cat => 
          \`<span class="badge">\${cat}</span>\`
        ).join('');
        
        const ipCell = row.insertCell();
        ipCell.className = 'array-cell';
        ipCell.innerHTML = record.ResolvedIPs.map(ip => 
          \`<span class="badge">\${ip}</span>\`
        ).join('');
        
        row.insertCell().textContent = record.ResolverDecision;
        row.insertCell().textContent = record.SrcIP;
      });
      
      document.getElementById('recordCount').textContent = 
        \`\${records.length.toLocaleString()} record\${records.length !== 1 ? 's' : ''}\`;
      document.getElementById('tldResults').style.display = 'none';
      document.getElementById('domainResults').style.display = 'none';
      document.getElementById('allResults').style.display = 'block';
    }

    // Sort table
    function sortTable(column) {
      if (sortColumn === column) {
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
      } else {
        sortColumn = column;
        sortDirection = 'asc';
      }
      
      const sorted = [...currentData].sort((a, b) => {
        let valA = a[column];
        let valB = b[column];
        
        if (Array.isArray(valA)) valA = valA.join(', ');
        if (Array.isArray(valB)) valB = valB.join(', ');
        
        valA = String(valA).toLowerCase();
        valB = String(valB).toLowerCase();
        
        if (sortDirection === 'asc') {
          return valA < valB ? -1 : valA > valB ? 1 : 0;
        } else {
          return valA > valB ? -1 : valA < valB ? 1 : 0;
        }
      });
      
      document.querySelectorAll('th').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.column === column) {
          th.classList.add('sort-' + sortDirection);
        }
      });
      
      displayAllRecords(sorted);
    }

    // Event listeners
    document.getElementById('scanType').addEventListener('change', (e) => {
      const isFile = e.target.value === 'file';
      document.getElementById('fileGroup').style.display = isFile ? 'block' : 'none';
      document.getElementById('limitGroup').style.display = isFile ? 'none' : 'block';
    });

    document.getElementById('dateSelect').addEventListener('change', (e) => {
      if (e.target.value && document.getElementById('scanType').value === 'file') {
        loadFiles(e.target.value);
      }
    });

    document.getElementById('scanBtn').addEventListener('click', scanLogs);

    document.querySelectorAll('th.sortable').forEach(th => {
      th.addEventListener('click', () => sortTable(th.dataset.column));
    });

    // View toggle buttons
    document.getElementById('tldViewBtn').addEventListener('click', () => {
      document.getElementById('tldViewBtn').classList.add('active');
      document.getElementById('allRecordsViewBtn').classList.remove('active');
      displayTLDAnalysis(tldAnalysisData);
    });

    document.getElementById('allRecordsViewBtn').addEventListener('click', () => {
      document.getElementById('allRecordsViewBtn').classList.add('active');
      document.getElementById('tldViewBtn').classList.remove('active');
      displayAllRecords(currentData);
    });

    // Initialize
    loadDates();
    loadSavedScans();
  </script>
</body>
</html>`;
}
