# Enhanced JWT Security Testing API - Scan ID Management

## Overview

The enhanced API now supports scan ID management, allowing you to:
- Track multiple concurrent scans
- Retrieve scan results later
- Generate reports for specific scans
- Manage scan sessions

## Report Organization

### Directory Structure

Reports are organized in separate directories to distinguish between CLI and API scans:

```
reports/
├── cli/          # CLI-generated reports
│   ├── cli_scan_YYYYMMDD_HHMMSS.html
│   └── cli_scan_YYYYMMDD_HHMMSS.json
└── api/          # API-generated reports
    └── api_scan_scan_id_YYYYMMDD_HHMMSS.html
```

### Naming Conventions

**CLI Reports:**
- **HTML**: `cli_scan_YYYYMMDD_HHMMSS.html`
- **JSON**: `cli_scan_YYYYMMDD_HHMMSS.json`
- **Location**: `reports/cli/`

**API Reports:**
- **HTML**: `api_scan_{scan_id}_{YYYYMMDD_HHMMSS}.html`
- **Location**: `reports/api/`

**Benefits:**
- Easy to distinguish CLI vs API reports
- Organized file structure
- No naming conflicts
- Clear audit trail with scan IDs for API reports

## API Endpoints

### 1. Start a Scan Session

**POST** `/scan/start`

Start a new scan session and get a scan ID.

```json
{
  "scan_type": "single",
  "description": "Testing production JWT tokens"
}
```

Response:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "started",
  "message": "Scan session 550e8400-e29b-41d4-a716-446655440000 created"
}
```

### 2. Analyze with Scan ID

**POST** `/scan/{scan_id}/analyze`

Analyze a JWT token with scan tracking.

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "secret": "your-secret-key",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

Response:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "results": {
    "vulnerabilities": [...],
    "recommendations": [...]
  }
}
```

### 3. Batch Analysis with Scan ID

**POST** `/scan/{scan_id}/batch`

Analyze multiple JWT tokens with scan tracking.

```json
{
  "tokens": [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  ],
  "secret": "your-secret-key"
}
```

### 4. Get Scan Status

**GET** `/scan/{scan_id}/status`

Check the status of a scan.

Response:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "timestamp": "2024-01-15T10:30:00",
  "scan_type": "single",
  "description": "Testing production JWT tokens",
  "has_results": true
}
```

### 5. Get Scan Results

**GET** `/scan/{scan_id}/results`

Retrieve scan results.

Response:
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "results": {
    "vulnerabilities": [...],
    "recommendations": [...]
  }
}
```

### 6. Generate Scan Report

**GET** `/scan/{scan_id}/report?format=html`

Generate and save a report locally, then download it.

- `format=html` (default): Generate HTML report and save locally
- `format=json`: Return JSON results

**Note:** Reports are automatically saved in the `reports/` directory on the server.

### 7. List All Reports

**GET** `/reports`

List all available reports stored locally.

Response:
```json
{
  "total_reports": 5,
  "reports_directory": "/path/to/reports",
  "reports": [
    {
      "filename": "jwt_scan_550e8400-e29b-41d4-a716-446655440000_20240115_103000.html",
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "file_size": 10702,
      "created": "2024-01-15T10:30:00",
      "modified": "2024-01-15T10:30:00"
    }
  ]
}
```

### 8. Download Specific Report

**GET** `/reports/{filename}`

Download a specific report file by filename.

Example:
```
GET /reports/jwt_scan_550e8400-e29b-41d4-a716-446655440000_20240115_103000.html
```

### 9. List All Scans

**GET** `/scans`

List all scan sessions with report information.

Response:
```json
{
  "total_scans": 3,
  "scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2024-01-15T10:30:00",
      "scan_type": "single",
      "status": "completed",
      "description": "Testing production JWT tokens",
      "has_report": true,
      "report_file": "jwt_scan_550e8400-e29b-41d4-a716-446655440000_20240115_103000.html",
      "report_generated": "20240115_103000"
    }
  ]
}
```

### 10. Delete Scan

**DELETE** `/scan/{scan_id}`

Delete a scan session.

## Usage Examples

### Python Example

```python
import requests
import json

# API base URL
base_url = "http://localhost:5000"

# 1. Start a scan session
response = requests.post(f"{base_url}/scan/start", json={
    "scan_type": "single",
    "description": "Testing authentication tokens"
})
scan_data = response.json()
scan_id = scan_data["scan_id"]

print(f"Started scan: {scan_id}")

# 2. Analyze a token
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
response = requests.post(f"{base_url}/scan/{scan_id}/analyze", json={
    "token": token,
    "secret": "your-secret"
})
results = response.json()

print(f"Analysis completed: {results['status']}")

# 3. Generate HTML report
response = requests.get(f"{base_url}/scan/{scan_id}/report?format=html")
with open(f"jwt_report_{scan_id}.html", "wb") as f:
    f.write(response.content)

print(f"Report saved: jwt_report_{scan_id}.html")
```

### cURL Examples

```bash
# Start scan
curl -X POST http://localhost:5000/scan/start \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "single", "description": "Test scan"}'

# Analyze token
curl -X POST http://localhost:5000/scan/550e8400-e29b-41d4-a716-446655440000/analyze \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}'

# Get results
curl http://localhost:5000/scan/550e8400-e29b-41d4-a716-446655440000/results

# Download report
curl -o report.html http://localhost:5000/scan/550e8400-e29b-41d4-a716-446655440000/report
```

## Scan Status Values

- `started`: Scan session created
- `running`: Analysis in progress
- `completed`: Analysis finished successfully
- `failed`: Analysis failed with error

## Benefits of Scan ID Management

1. **Concurrent Scans**: Run multiple scans simultaneously
2. **Result Persistence**: Retrieve results later without re-running analysis
3. **Report Generation**: Generate reports for specific scans
4. **Session Management**: Track and manage scan sessions
5. **Audit Trail**: Keep history of all scans performed

## Storage Notes

- Scan sessions are stored in memory (not persistent)
- For production use, consider implementing database storage
- Sessions are lost when the API server restarts
- Use the `/scans` endpoint to monitor active sessions

## Migration from Legacy API

The legacy endpoints (`/analyze`, `/batch`) still work and automatically create scan IDs for backward compatibility. 