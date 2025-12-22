DNS-SCAN
DNS-SCAN is a Cloudflare Worker that reads DNS gateway logs stored in an R2 bucket, aggregates them by TLD and domain, and serves a simple HTML UI to explore “top talkers”.

It is designed to help you quickly answer questions like:

Which TLDs are most frequently queried?
Which domains are most popular?
Which client IP is the top requester for a given domain?
Features
R2 log reader
Reads .gz, .log, and .txt objects from a configured R2 bucket.
Flexible field mapping
Supports JSON logs (preferred) and a simple CSV fallback (domain,ip,...).
You can map the domain and client IP field names via query parameters.
Aggregation & sorting
Aggregates by:
TLD → total hits
Domain → total hits + top requester IP
Sortable via query parameters.
Built-in HTML UI
The Worker renders a single-page HTML form with:
Prefix / date filters
Safety limits for max files and bytes
Sorting options
Configurable log field names
Prerequisites
To develop, test, and deploy this project, you need:

Node.js & npm
Node.js 18+ (LTS recommended)
npm (bundled with Node.js)
Cloudflare account
A Cloudflare account with access to Workers and R2.
Wrangler CLI
Version compatible with this project:
The repo uses wrangler ^4.47.0.
Install globally (recommended):
bash
npm install -g wrangler
or use the local devDependency via npx wrangler.
R2 bucket with DNS logs
An R2 bucket containing your DNS logs.
Objects should be:
.gz (gzip) or
.log / .txt plain text
Each line should be either:
JSON with domain and IP fields, e.g.:
json
{"domain":"example.com","client_ip":"203.0.113.10", ...}
CSV: domain,ip,...
e.g.:
text
example.com,203.0.113.10,...
Runtime compatibility
The Worker is configured with:
toml
compatibility_date = "2024-11-01"
compatibility_flags = ["nodejs_compat"]
It uses DecompressionStream('gzip') for .gz objects where available in the Workers runtime.
Project Structure
Key files:

src/index.js
Main Worker script. Handles:
HTTP request routing
R2 listing & reading
Gzip decompression
DNS aggregation and HTML rendering
wrangler.toml
Wrangler configuration (name, entrypoint, compatibility, R2 binding).
wrangler.jsonc
Additional Wrangler/Workers configuration (if needed by your environment).
package.json
Scripts and dev dependencies:
wrangler (Cloudflare Workers CLI)
vitest + cloudflare/vitest-pool-workers for tests
Installation
Clone the repository
bash
git clone https://github.com/<your-org-or-user>/dns-scan.git
cd dns-scan
Install dependencies
bash
npm install
This installs the devDependencies:
wrangler
vitest
cloudflare/vitest-pool-workers
Configuration
1. Configure R2 bucket binding
wrangler.toml includes an R2 bucket binding:

toml
name = "dns-scan"
main = "src/index.js"
compatibility_date = "2024-11-01"
compatibility_flags = ["nodejs_compat"]
 
[[r2_buckets]]
binding = "LOGS"
bucket_name = "BUCKET_NAME"
Replace BUCKET_NAME with the actual name of your R2 bucket:
toml
bucket_name = "my-dns-logs-bucket"
The Worker will access your bucket via the env.LOGS binding.
2. (Optional) Additional Wrangler configuration
If you need to set account ID, routes, or environments, configure them in:

wrangler.toml
wrangler.jsonc (if you’ve added advanced settings)
Follow Cloudflare’s Wrangler docs for route / environment specifics: <https://developers.cloudflare.com/workers/wrangler/>

Local Development
Start the development server
bash
npm run dev
This runs:
jsonc
"dev": "wrangler dev"
Open the UI Visit:
text
http://localhost:8787/
You should see the DNS Scanner HTML page with a filter form and empty results until you run a scan.
Usage
UI Parameters
The Worker consumes query parameters (through the form) to control the scan:

Prefix (folder) – prefix
Example: 2025-11-10/
Used as the base prefix when listing R2 objects.
Start date / End date – start, end
Format: YYYY-MM-DD
If logs are date-partitioned in the key, the Worker will:
Generate prefixes from start to end (inclusive)
E.g. 2025-11-10/, 2025-11-11/, etc.
Max files – maxFiles
Safety guard for the number of objects read.
Default: 50 (bounded by DEFAULT_MAX_FILES = 200 in code).
Max bytes – maxBytes
Safety guard for total bytes read across all objects.
Default: DEFAULT_MAX_BYTES = 200 * 1024 * 1024 (200 MB).
Sort – sort
Options:
tld_desc – TLD: Most popular
tld_asc – TLD: Least popular
domain_desc – Domain: Most popular
domain_asc – Domain: Least popular
Domain field name – fieldDomain
Default: domain
Used when parsing JSON logs:
obj[fieldDomain] || obj.domain || obj.query || obj.hostname
Client IP field name – fieldIP
Default: client_ip
Used when parsing JSON logs:
obj[fieldIP] || obj.client_ip || obj.src_ip || obj.ip
Running a Scan
Go to http://localhost:8787/ (or your deployed URL).
Fill in:
Prefix (optional)
Start date / End date (optional but recommended if keys are date-based)
Max files and Max bytes (or use defaults)
Sort option
Domain field name and Client IP field name according to your log schema
Click Scan.
The page will display:

Top TLDs – Table of TLD and hit counts.
Top Domains – Table of domain, hit count, and top requester IP.
If nothing matches, you’ll see:

No matching log files found in R2 for the given filters.

Testing
The project uses vitest with the Cloudflare Workers pool.

Run tests
bash
npm test
This runs:
jsonc
"test": "vitest"
Add or modify tests under the test/ directory.

Deployment
Before deploying, ensure:

wrangler.toml has your correct bucket_name.
Your Cloudflare account credentials are configured:
bash
wrangler login
Deploy with npm script
bash
npm run deploy
This runs:

jsonc
"deploy": "wrangler deploy"
Wrangler will:

Build and upload the Worker defined by main = "src/index.js".
Bind the LOGS R2 bucket.
Once deployed, your DNS Scanner will be live at the route or worker URL configured in Wrangler (e.g. https://dns-scan.<your-subdomain>.workers.dev if you’re using the default).

Log Format Details
The Worker’s processLogLine logic:

JSON path (preferred):
js
const obj = JSON.parse(line);
const domain = obj[fieldDomain] || obj.domain || obj.query || obj.hostname;
const ip = obj[fieldIP] || obj.client_ip || obj.src_ip || obj.ip;
Domain is normalized:
Lowercased
Surrounding quotes removed
Trailing . removed
CSV fallback:
text
domain,ip,...
First column = domain
Second column = IP
Consider aligning your log export format with these expectations for best results.

License
Add your preferred license here, for example:

MIT
Apache-2.0
Proprietary / Internal use only
Contributing
Fork the repo.
Create a feature branch.
Make changes and add tests.
Run npm test.
Open a PR with a clear description of the changes.
