# Mobile Security Testing API Reference

## Overview

The Mobile Security Testing API provides RESTful endpoints for performing mobile application security analysis. The API supports both Android (APK) and iOS (IPA) applications, with comprehensive security testing capabilities.

## Base URL

```
http://localhost:5001/api/v1
```

## Authentication

Currently, the API does not require authentication. For production deployments, implement proper authentication mechanisms.

## Endpoints

### Health Check

#### GET /health

Check the health status of the API server.

**Response:**
```json
{
  "status": "healthy",
  "service": "Mobile Security Testing API",
  "version": "2.0.0",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Scan Management

#### POST /scan

Start a new mobile security scan.

**Request Body:**
```json
{
  "file_path": "/app/uploads/app.apk",
  "tests": ["static", "network", "storage", "code"],
  "device_type": "android",
  "package_name": "com.example.app"
}
```

**Parameters:**
- `file_path` (string, optional): Path to APK/IPA file
- `device_type` (string, optional): "android" or "ios" for device analysis
- `package_name` (string, optional): Package name for device analysis
- `tests` (array, optional): List of tests to run

**Available Tests:**
- `static`: Static analysis of application files
- `dynamic`: Runtime behavior analysis (requires device)
- `network`: Network security analysis
- `storage`: Local storage analysis
- `code`: Source code analysis

**Response:**
```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "queued",
  "message": "Scan started successfully"
}
```

#### GET /scan/{scan_id}/status

Get the status and results of a scan.

**Response:**
```json
{
  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "completed",
  "created_at": "2024-01-01T12:00:00Z",
  "request_data": {
    "file_path": "/app/uploads/app.apk",
    "tests": ["static", "network", "storage", "code"]
  },
  "results": {
    "scan_info": {
      "file_path": "/app/uploads/app.apk",
      "file_type": "APK",
      "scan_date": "2024-01-01T12:00:00Z",
      "tests_performed": ["static", "network", "storage", "code"]
    },
    "summary": {
      "total_vulnerabilities": 5,
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 1,
      "overall_risk": "High"
    },
    "vulnerabilities": [
      {
        "title": "Weak SSL Implementation",
        "severity": "critical",
        "description": "App uses weak SSL configuration",
        "location": "NetworkSecurityConfig",
        "proof": "SSLv3 enabled in configuration",
        "reproduction": "Use SSL scanner to detect weak protocols"
      }
    ]
  },
  "report_path": "/app/reports/api/api_scan_123e4567-e89b-12d3-a456-426614174000_20240101_120000.html"
}
```

**Status Values:**
- `queued`: Scan is waiting to start
- `running`: Scan is currently executing
- `completed`: Scan finished successfully
- `failed`: Scan encountered an error

#### GET /scan/{scan_id}/report

Download the HTML report for a completed scan.

**Response:**
- Content-Type: `text/html`
- File download with name: `mobile_scan_report_{scan_id}.html`

#### DELETE /scan/{scan_id}

Delete a scan session and its associated data.

**Response:**
```json
{
  "message": "Scan deleted successfully"
}
```

### Scan Management

#### GET /scans

List all scan sessions.

**Response:**
```json
{
  "scans": [
    {
      "scan_id": "123e4567-e89b-12d3-a456-426614174000",
      "status": "completed",
      "created_at": "2024-01-01T12:00:00Z",
      "file_path": "/app/uploads/app.apk",
      "device_type": null
    }
  ],
  "total": 1
}
```

#### POST /clear

Clear all scan sessions.

**Response:**
```json
{
  "message": "Cleared 5 scan sessions"
}
```

## Error Responses

### 400 Bad Request
```json
{
  "error": "Missing required field: file_path or device_type"
}
```

### 404 Not Found
```json
{
  "error": "Scan not found"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error occurred"
}
```

## Usage Examples

### Start APK Analysis
```bash
curl -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/app/uploads/app.apk",
    "tests": ["static", "network", "storage", "code"]
  }'
```

### Start IPA Analysis
```bash
curl -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/app/uploads/app.ipa",
    "tests": ["static", "code", "storage"]
  }'
```

### Start Device Analysis
```bash
curl -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "device_type": "android",
    "package_name": "com.example.app",
    "tests": ["dynamic", "network", "storage"]
  }'
```

### Monitor Scan Progress
```bash
# Start scan
response=$(curl -s -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/app/uploads/app.apk"}')

scan_id=$(echo $response | jq -r '.scan_id')

# Check status
while true; do
  status=$(curl -s http://localhost:5001/api/v1/scan/$scan_id/status | jq -r '.status')
  echo "Scan status: $status"
  
  if [ "$status" = "completed" ] || [ "$status" = "failed" ]; then
    break
  fi
  
  sleep 5
done
```

### Download Report
```bash
curl http://localhost:5001/api/v1/scan/$scan_id/report \
  -o mobile_scan_report.html
```

## Rate Limiting

The API implements rate limiting to prevent abuse:
- Maximum 60 requests per minute per IP
- Rate limit headers included in responses

## Configuration

### Environment Variables
- `MOBILE_API_PORT`: API server port (default: 5001)
- `MOBILE_API_DEBUG`: Enable debug mode (default: false)
- `MOBILE_MAX_FILE_SIZE`: Maximum file size (default: 100MB)
- `MOBILE_DEFAULT_TESTS`: Default tests to run
- `MOBILE_TIMEOUT`: Analysis timeout (default: 300s)

### Configuration File
```json
{
  "api": {
    "host": "0.0.0.0",
    "port": 5001,
    "debug": false,
    "max_file_size": 104857600
  },
  "analysis": {
    "default_tests": ["static", "network", "storage", "code"],
    "timeout": 300,
    "max_concurrent_scans": 5
  },
  "security": {
    "enable_rate_limiting": true,
    "max_requests_per_minute": 60
  }
}
```

## Report Formats

### HTML Report
- Comprehensive security analysis report
- Includes vulnerability details, proof, and reproduction steps
- Color-coded severity levels
- Interactive elements for better navigation

### JSON Response
- Raw scan results in JSON format
- Includes all analysis data and metadata
- Suitable for programmatic processing

## Security Considerations

### Input Validation
- File path validation to prevent directory traversal
- File type validation for APK/IPA files
- Size limits to prevent resource exhaustion

### Output Sanitization
- HTML report content is properly escaped
- No sensitive data in error messages
- Secure file handling

### Network Security
- CORS configuration for cross-origin requests
- Rate limiting to prevent abuse
- Input validation for all endpoints

## Troubleshooting

### Common Issues

**Scan Fails to Start:**
- Check file path and permissions
- Verify file is valid APK/IPA
- Check available disk space

**Scan Stuck in Running State:**
- Check system resources
- Verify analysis tools are available
- Check logs for errors

**Report Download Fails:**
- Ensure scan is completed
- Check file permissions
- Verify report file exists

### Debug Mode
Enable debug mode for detailed logging:
```bash
export MOBILE_API_DEBUG=true
python start_api.py
```

### Logs
Check logs for detailed error information:
```bash
tail -f logs/mobile_security.log
``` 