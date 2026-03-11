# Cloudflare Gateway DNS Log Scanner

A full-stack serverless application deployed as a Cloudflare Worker that scans, parses, and provides an interactive web interface for your Cloudflare Gateway DNS logs. This tool allows security administrators and network operators to quickly identify top-level domain distributions, identify suspicious Domain Generation Algorithm (DGA) behavior, and interactively filter query records directly from logs stored in an R2 bucket.

## Features

- **Serverless Architecture:** Entirely contained within a single Cloudflare Worker script. No dedicated backend servers to maintain.
- **Interactive Web Interface:** Built-in web dashboard served directly from the Worker root, featuring filtering, sorting, and pagination.
- **R2 Storage Integration:** Streams and parses gzipped `.gz` JSON log files directly from an R2 bucket.
- **D1 Database Caching:** Uses Cloudflare D1 (SQLite) to save and cache parsed scan results, enabling massive performance improvements on subsequent loads without re-processing R2 objects.
- **Threat Hunting:**
  - Automated extraction capability for Top-Level Domains (TLDs).
  - TLD Analysis tab offering insight into request volumes, unique domains, and average lengths.
  - Basic DGA detection flags alerting on domains that contain many numbers, lack vowels (AEIOU), or possess unusual lengths.
- **Progress Streaming:** Implements Server-Sent Events (SSE) to display real-time progress to the UI when processing hundreds of log files.

## Prerequisites

- A Cloudflare Account.
- Cloudflare Gateway configured to export DNS logs to a Cloudflare R2 Bucket.
- Node.js and Wrangler CLI installed for deployment.

## Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/dns-scan-worker.git
   cd dns-scan-worker
   ```

2. **Configure your `wrangler.toml`:**
   You will need to create a `wrangler.toml` file that binds your R2 Bucket and D1 database.
   ```toml
   name = "dns-scanner"
   main = "index.js"
   compatibility_date = "2024-01-01"

   [[r2_buckets]]
   binding = "R2_BUCKET"
   bucket_name = "your-gateway-logs-bucket"

   [[d1_databases]]
   binding = "DB"
   database_name = "dns-scan-cache"
   database_id = "your-d1-database-id"
   ```

3. **Deploy to Cloudflare:**
   ```bash
   npx wrangler deploy
   ```

## Security & Privacy Notes

**Important:** The web interface provided by this Worker is served over the root path (`/`) without any built-in authentication layer. Because this interface accesses raw DNS query logs—which can contain sensitive internal network topologies, identifying source IPs, and user browsing history—**you MUST restrict access to this application.**

It is highly recommended to place this Worker behind [Cloudflare Access (Zero Trust)](https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/) to ensure only authorized administrators can view the dashboard and trigger API endpoints.

This source code does not contain any hardcoded API keys, secrets, or account IDs. All integration with R2 and D1 is managed securely via Cloudflare Worker bindings.

## License

MIT License
