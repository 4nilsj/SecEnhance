# Available API Security Scanner Reports

## 📊 Latest Vulnerable API Scan Report

**Scan ID:** `scan_1750604977`  
**Date:** June 22, 2025 at 20:39:37  
**Duration:** 313.36 seconds  
**Status:** Completed

### 📄 Report Files:
- **JSON Report:** `vulnerable_api_scan_1750605290.json` (14KB, 396 lines)
- **HTML Report:** `reports/html/owasp_api_report_20250622_204450.html` (1.3KB, 147 lines)

### 🔍 Scan Results:
- **Endpoints Scanned:** 8
- **Vulnerabilities Found:** 13
- **Test Coverage:** 56 tests run across all endpoints

### 🚨 Vulnerabilities Detected:

#### High Severity (8 vulnerabilities):
1. **Missing Authentication** - All endpoints accessible without authentication
   - `/api/users` (GET, POST)
   - `/api/users/1` (GET)
   - `/api/posts` (GET, POST)
   - `/api/search` (GET)
   - `/api/file` (GET)
   - `/api/admin` (GET)

#### Medium Severity (5 vulnerabilities):
2. **Missing Rate Limiting** - No rate limiting detected on endpoints
   - `/api/users` (GET)
   - `/api/users/1` (GET)
   - `/api/posts` (GET)
   - `/api/search` (GET)
   - `/api/admin` (GET)

## 🌐 How to Access Reports

### 1. Web UI Access
**URL:** http://localhost:5000

**Steps:**
1. Open browser and navigate to `http://localhost:5000`
2. Click on **"Reports"** tab
3. View all available scan reports
4. Click **"Download"** buttons to download reports
5. Click **"View"** to open HTML reports in new tab
6. Click **"Delete"** to remove reports (with confirmation)

### 2. Direct File Access
**JSON Reports:**
- Latest: `vulnerable_api_scan_1750605290.json`
- Web UI Format: `reports/api_security_scan_*.json`

**HTML Reports:**
- Latest: `reports/html/owasp_api_report_20250622_204450.html`
- Web UI Format: `reports/owasp_api_scan_*.html`

### 3. Historical Reports Available
**Location:** `reports/` directory

**Available Scan Reports:**
- `api_security_scan_1750585080.json` (12KB, 384 lines)
- `api_security_scan_1750584648.json` (12KB, 384 lines)
- `api_security_scan_1750584567.json` (12KB, 384 lines)
- `api_security_scan_1750584461.json` (412B, 14 lines)
- `api_security_scan_1750584460.json` (412B, 14 lines)

**Available OWASP Reports:**
- `owasp_api_scan_1750586423.html` (1.3KB, 30 lines)
- `owasp_api_scan_1750586303.html` (1.3KB, 30 lines)
- `owasp_api_scan_1750585080.html` (1.3KB, 30 lines)
- `owasp_api_scan_1750584648.html` (1.3KB, 30 lines)
- `owasp_api_scan_1750584567.html` (1.3KB, 30 lines)
- `owasp_api_scan_1750584461.html` (1.3KB, 30 lines)
- `owasp_api_scan_1750584460.html` (1.3KB, 30 lines)

## 📈 Report Statistics

**Overall Summary:**
- Total Scans: 6+ completed scans
- Total Vulnerabilities Found: 13+ across all scans
- Most Common Issues: Missing Authentication, Missing Rate Limiting
- Scan Duration Range: 5-313 seconds
- Success Rate: 100% (all scans completed successfully)

**Vulnerability Distribution:**
- High Severity: 8 vulnerabilities (61.5%)
- Medium Severity: 5 vulnerabilities (38.5%)
- Low Severity: 0 vulnerabilities (0%)
- Critical Severity: 0 vulnerabilities (0%)

## 🚀 Next Steps

1. **View Reports in Web UI:** Open http://localhost:5000 and go to Reports tab
2. **Download Specific Reports:** Use the download buttons in the web UI
3. **Generate New Scans:** Use the scan script or web UI to scan new APIs
4. **Analyze Vulnerabilities:** Review the detailed vulnerability information
5. **Implement Fixes:** Address the identified security issues 