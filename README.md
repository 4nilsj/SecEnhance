# web-recon

A comprehensive static JavaScript security reconnaissance tool that analyzes **web pages** and **local JavaScript files/folders**. Extracts endpoints, detects sensitive API keys, identifies security vulnerabilities, and discovers HTTP request patterns (fetch, axios, XHR, jQuery, forms).

## Features

- **Web & Local Analysis**: Scan live websites or analyze local JavaScript files and directories
- **Endpoint Extraction**: Finds URL-like endpoints in HTML and JavaScript with heuristic categorization (API, Admin, Auth, Static, API Docs).
- **Parameter Analysis**: Collects query parameter names and flags potentially risky ones (id, token, redirect, url, etc.).
- **JavaScript Asset Discovery**: Lists target-origin JavaScript files referenced by the page.
- **Inline & HTML Analysis**: Scans inline scripts and raw HTML for security patterns and secrets.
- **Sensitive Key Detection**:
  - Google/Firebase API keys (AIza prefix)
  - AWS Access Keys (AKIA/ASIA/AROA prefix)
  - Stripe secret keys (sk_live_, sk_test_)
  - SendGrid API keys (SG.)
  - Slack tokens (xoxb, xoxp, etc.)
  - GitHub tokens (ghp_, gho_, etc.)
  - Twilio Account/Key SIDs
  - PEM private keys
  - Admin/Internal API keys and generic hardcoded secrets
- **Security Pattern Detection**:
  - DOM sinks (innerHTML, outerHTML, document.write, etc.)
  - Dynamic code evaluation (eval, Function constructor)
  - Weak cryptography (MD5, SHA1)
  - Prototype pollution indicators
  - Open redirects
  - CORS misconfigurations
  - Anti-debug/devtools detection
  - And more...
- **AST-Based Request Extraction**: Parses JavaScript AST (using acorn) to detect:
  - `fetch()` calls with method and body parameters
  - `axios.post/get/put/delete()` calls
  - `$.post/get()` jQuery AJAX calls
  - `XMLHttpRequest.open()` calls
  - Dynamic URL concatenation (e.g., baseURL + "/api/users")
- **HTML Form Detection**: Extracts form methods, actions, and input parameter names.
- **Technology Detection**: Identifies frameworks, libraries, and hosting platforms (Express, Next.js, React, Angular, Vue, WordPress, etc.).
- **Flexible Export**: JSON or XLSX format with separate sheets for endpoints, parameters, JS files, technologies, findings, identified keys, and discovered requests.

## Installation

```bash
npm install
```

### Dependencies

- `chalk` — Terminal styling
- `commander` — CLI argument parsing
- `jsdom` — DOM parsing and HTML analysis
- `node-fetch` — HTTP client (already ESM)
- `xlsx` — Excel export
- `acorn` — JavaScript AST parser for request extraction

## Usage

### Web Scanning (URLs)

Scan a single website and print results to console:

```bash
node index.js https://example.com
```

### Local File Analysis

Analyze a single JavaScript file:

```bash
node index.js ./app.js
node index.js /path/to/script.js
```

Analyze all JavaScript files in a directory (recursively scans folders, automatically excludes `node_modules` and hidden directories):

```bash
node index.js ./src
node index.js /path/to/project
node index.js .  # Current directory
```

The tool automatically detects whether the target is a URL or local path and routes it to the appropriate analyzer.

### Export Results

Export scans to JSON or XLSX format (works for both URLs and local files):

```bash
# Web scan to JSON
node index.js https://example.com -o results.json -f json

# Web scan to XLSX
node index.js https://example.com -o results.xlsx -f xlsx

# Local file analysis to JSON
node index.js ./src -o local-findings.json -f json

# Single JS file to XLSX
node index.js app.js -o app-analysis.xlsx -f xlsx
```

The exported files contain separate sheets/objects for:
- **Endpoints**: Extracted URLs and endpoints
- **Parameters**: Query parameter names with risk flags
- **JS Files**: JavaScript files analyzed (for web scans)
- **Technologies**: Detected frameworks and libraries
- **Findings**: Security vulnerabilities and patterns
- **Keys**: Identified sensitive API keys and tokens
- **Requests**: AST-detected HTTP requests (fetch, axios, XHR, forms)

### Batch Scanning

Read multiple targets from a file (URLs and local paths can be mixed):

```bash
node index.js -l targets.txt -f json -o batch_results.json
```

Example `targets.txt`:

```
https://example.com
https://app.example.org
./src
/path/to/app.js
./components
```

Read from stdin:

```bash
cat targets.txt | node index.js --stdin -f xlsx -o results.xlsx
```

The scanner automatically routes each target to the appropriate analyzer:
- **HTTP/HTTPS URLs** → Web crawling mode
- **Local .js files** → Direct file analysis
- **Local directories** → Recursive JS file discovery and analysis

### CLI Options

```
Usage: web-recon [options] [target]

Options:
  -l, --list <file>      File containing list of URLs or local paths (one per line)
  --stdin                Read URLs/paths from stdin (one per line)
  -o, --output <file>    Export results to file (JSON or XLSX)
  -f, --format <type>    Export format: json or xlsx (default: json)
  -c, --concurrency <n>  Concurrent JS fetches per target (default: 8)
  --insecure             Disable TLS verification (rejectUnauthorized=false)
  --ca <file>            Custom Root CA bundle file (PEM)
  --all-confidence       Display all detected keys (including low-confidence matches)
  --silent               Suppress console output (export only)
  --verbose              Verbose logging (shows JS file fetching progress)
  -h, --help             Display help information
```

## Console Output

The scanner prints:

1. **Endpoints Found** — URLs extracted from page and JS
2. **Parameters Found** — Query param names with risk flags
3. **JS Files (target origin)** — JavaScript files fetched and analyzed
4. **Technologies Detected** — Frameworks, libraries, server info
5. **Identified Keys** — Sensitive API keys and tokens (masked in console)
6. **Security Findings** — Detailed security pattern matches with severity
7. **Summary** — Aggregate counts per category

Example:

```
=== Scanning: https://example.com ===

Endpoints Found (12):
  /api/v1/users [API, auth]
  /admin/dashboard [Admin, API]
  ...

Parameters Found (8):
  id [risky] → Page content (3)
  token [risky] → inline.js (1)
  ...

JS Files (target origin) Found (3):
  https://example.com/static/bundle.js
  ...

Technologies Detected (5):
  React
  Express
  ...

Identified Keys (2):
  CRITICAL googleApiKey @ Inline script 1 → AIza...YZ2Z
  ...

Security Findings (15):
  Source: bundle.js (8 findings)
    CRITICAL domXss → element.innerHTML = ...
    HIGH eval → eval("var x = ...")
  ...

Summary:
  Endpoints: 12
  Parameters: 8 (risky: 3)
  JS Files: 3
  Technologies: 5
  Findings: 15
  Identified Keys: 2/2 -> googleApiKey (1), hardcodedSecrets (1)
```

## Confidence Scoring

To reduce false positives, the scanner assigns a **confidence score** (0.0–1.0) to each detected key. Keys with confidence ≥ 0.5 are displayed by default.

### Scoring Factors

1. **Detector Type** (base score):
   - High-confidence detectors (0.85–0.98): PEM keys, provider-specific patterns (Google, AWS, Stripe, etc.)
   - Medium-confidence detectors (0.60–0.80): JWT literals, Twilio, GitHub tokens
   - Lower-confidence detectors (0.50–0.65): Generic patterns (hardcoded secrets, admin keys)

2. **Entropy Analysis**:
   - High entropy (≥4 bits/char): Boost confidence by 1.1× (typical of random API keys)
   - Medium entropy (2–3 bits/char): Apply 0.6× modifier
   - Low entropy (<2 bits/char): Apply 0.3× modifier (suggests false positive like "password" string)

3. **Length Heuristics**:
   - Typical range (20–60 chars): Boost by 1.05×
   - Very short (<12 chars) or very long (>500 chars): Penalize with 0.4–0.6× modifier

4. **Contextual Clues**:
   - If code snippet contains key-like variable names (`api_key`, `secret`, `token`, `auth`, etc.): Boost by 1.2×

### Example

```
Identified Keys (2/4):
  CRITICAL googleApiKey [95%] @ bundle.js → AIza...abc123
  CRITICAL pemPrivateKey [92%] @ config.js → -----BEGIN...
  (2 low-confidence matches filtered; use --all-confidence to show all)
```

The "2/4" notation means 2 of 4 detected keys passed the confidence threshold. To display all matches:

```bash
node index.js https://example.com --all-confidence
```

## Export Formats

### JSON Export

```json
{
  "endpoints": ["/api/v1/users", "/admin/panel", ...],
  "endpointTags": {
    "/api/v1/users": ["API", "auth"],
    ...
  },
  "parameters": {
    "id": ["Page content", "inline.js"],
    ...
  },
  "riskyParameters": ["id", "token", "redirect"],
  "keys": [
    {
      "source": "Inline script 1",
      "type": "googleApiKey",
      "key": "AIzaSyDp4Hn8Z1F...",
      "snippet": "...",
      "severity": "critical"
    },
    ...
  ],
  "jsFiles": [...],
  "technologies": [...],
  "findings": {
    "bundle.js": [
      {
        "type": "domXss",
        "snippet": "element.innerHTML = ...",
        "severity": "critical"
      },
      ...
    ]
  },
  "requests": [
    {
      "source": "bundle.js",
      "method": "POST",
      "url": "/api/submit",
      "params": ["email", "data"],
      "snippet": "..."
    },
    ...
  ]
}
```

### XLSX Export

Sheets included:

- **Summary** — Count of endpoints, parameters, keys, findings, technologies, etc.
- **Endpoints** — Endpoint URLs with category tags
- **Parameters** — Parameter names, occurrence counts, risky flags
- **JS Files** — List of external JS assets analyzed
- **Technologies** — Detected frameworks and server info
- **Identified Keys** — Sensitive keys with source, type, severity, snippet
- **Security Findings** — Detailed security matches
- **Discovered Requests** — Extracted HTTP request patterns (method, URL, params)

All sheets have auto-filters and frozen header rows for easy filtering and sorting.

## Security & Privacy Warnings

### Sensitive Information

Exported files (JSON/XLSX) may contain:

- **Identified API keys and tokens** — Some detectors may capture partial or full keys
- **URLs and parameter names** — May reveal internal endpoints or data structure
- **Code snippets** — Context around findings may include business logic or comments

**Recommendations:**

1. **Treat export files as secrets.** Do not commit to version control or share publicly.
2. **Consider encrypting exports** before storing or transmitting.
3. **Use in authorized testing only.** Scanning production systems without permission is illegal.
4. **Review findings manually** — Regex/AST detection has false positives. Verify before taking action.
5. **Redact sensitive data** before sharing reports with non-technical stakeholders.

### False Positives

The scanner relies on heuristics and pattern matching:

- **Generic patterns** (long alphanumeric strings, admin_key, api_key) may flag benign tokens or IDs.
- **Minified code** — Some patterns won't be detected in heavily minified or obfuscated code.
- **Dynamic URLs** — Endpoints constructed via string concatenation (simple cases) are detected; complex expressions are not.

For best results:

- Review findings in context of the application.
- Whitelist known safe values (future enhancement: `--whitelist` flag).
- Use entropy scoring to filter low-confidence matches (future enhancement).

## Testing

The project includes **120 comprehensive tests** across 3 suites:

```bash
npm test                    # Run all tests (fixture + unit + integration)
npm run test:fixtures       # Run fixture/regex tests (36 tests)
npm run test:unit           # Run unit tests for core functions (52 tests)
npm run test:integration    # Run end-to-end workflow tests (32 tests)
```

**Test Coverage:**

- ✅ **36 Fixture Tests** — Regex patterns, fixture content, AST parsing
- ✅ **52 Unit Tests** — Entropy calculation, confidence scoring, store operations, URL resolution, utility functions
- ✅ **32 Integration Tests** — Request extraction, key detection, security pattern detection, multi-key filtering, parameter extraction

See [TESTING.md](./TESTING.md) for comprehensive testing documentation, test cases, and coverage details.

**Sample Test Output:**
```
=== Test Summary ===
Passed: 36
Failed: 0
Total: 36 (Fixture Tests)

=== Unit Test Summary ===
Passed: 52
Failed: 0
Total: 52 (Unit Tests)

=== Integration Test Summary ===
Passed: 32
Failed: 0
Total: 32 (Integration Tests)

✓ All 120 tests passed!
```

## Development & Future Improvements

**✅ Completed Enhancements:**

1. **Entropy-based confidence scoring** — Shannon entropy analysis + multi-factor weighting (base scores, length heuristics, context modifiers) to reduce false positives
2. **Comprehensive Unit Tests** — 52 tests covering entropy, confidence, storage, URL resolution
3. **Integration Tests** — 32 tests for end-to-end workflows and complex scenarios
4. **Fixture Tests** — 36 tests for regex patterns and AST parsing

Planned enhancements:

1. **--include-third-party-js flag** — Optionally fetch and scan cross-origin scripts
2. **--redact-keys flag** — Mask full keys in exports (show only first/last 4 chars)
3. **--whitelist <file>** — Whitelist known tokens or patterns to reduce noise
4. **--disable-detector <name>** — Disable specific detectors (e.g., no generic secret detection)
5. **--headless-browser mode** — Optional Puppeteer integration to capture runtime network requests
6. **GitHub Actions CI** — Automated testing and validation
7. **TypeScript migration** — Optional type definitions for better IDE support
8. **ESLint & Prettier** — Code quality and formatting standards
9. **Dataflow analysis** — Track variable assignments to resolve dynamically constructed URLs

## Contributing

Contributions welcome! Areas for improvement:

- Additional key patterns (Azure, GCP, database connection strings)
- Better parameter extraction (e.g., from FormData, multipart bodies)
- Symbolic execution for complex URL concatenation
- Integration with third-party vulnerability databases
- Performance optimizations for large sites

## License

ISC

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Always obtain written permission before scanning any target system.

---

**Questions or issues?** Open an issue on the repository.
