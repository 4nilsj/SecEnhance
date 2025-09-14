# HAR File Support

The API Security Scanner now supports HAR (HTTP Archive) files, allowing you to scan APIs from various tools and browsers.

## What is HAR?

HAR (HTTP Archive) is a JSON-formatted archive file format for storing HTTP transaction data. It's widely supported by web browsers, API testing tools, and security scanners.

## Supported Tools

### ✅ Insomnia REST Client
- **Export Method**: Right-click workspace → "Export Data" → "HAR"
- **Best For**: API development and testing workflows
- **Features**: Preserves authentication, headers, and request bodies

### ✅ Postman
- **Export Method**: Collection → Export → "Collection v2.1" (convert to HAR)
- **Best For**: Team collaboration and API documentation
- **Features**: Maintains folder structure and environment variables

### ✅ Browser DevTools
- **Export Method**: DevTools → Network tab → Right-click → "Save all as HAR with content"
- **Best For**: Capturing real browser traffic
- **Features**: Includes all network requests with timing data

### ✅ Burp Suite
- **Export Method**: Proxy → HTTP history → Right-click → "Save items" → "HAR"
- **Best For**: Security testing and penetration testing
- **Features**: Includes intercepted and modified requests

### ✅ OWASP ZAP
- **Export Method**: Tools → Export → "HAR"
- **Best For**: Security scanning and vulnerability assessment
- **Features**: Includes security scan results and findings

## HAR File Features

### 🔍 Automatic Detection
The scanner automatically detects HAR files by:
- File extension (`.har`)
- JSON content structure (`log.entries` format)
- Content validation

### 📊 Complete Request Extraction
Extracts all request components:
- **HTTP Method** (GET, POST, PUT, DELETE, etc.)
- **URL** with query parameters
- **Headers** (including authentication)
- **Request Body** (JSON, form data, etc.)
- **Cookies** and session data
- **Timing Information** (optional)

### 🔐 JWT Token Detection
Automatically detects JWT tokens in:
- `Authorization: Bearer <token>` headers
- Custom authentication headers
- Cookie values

### ⚡ Conditional Scanning
When JWT tokens are detected:
- Enables JWT Security Plugin automatically
- Performs comprehensive JWT vulnerability analysis
- Checks for algorithm confusion, weak signatures, etc.

### 📁 Folder Organization
Preserves request grouping:
- Page titles from HAR files
- Request categorization
- Logical grouping for reports

## Usage Examples

### Basic HAR Scan
```bash
# Scan HAR file from Insomnia
python main.py scan -f insomnia-export.har

# Scan with Docker
docker run --rm -v $(pwd):/workspace api-security-scanner scan -f /workspace/insomnia-export.har
```

### HAR Scan with Authentication
```bash
# Add additional authentication
python main.py scan -f postman-export.har -a header -n "X-API-Key" -v "your-key"

# Cookie-based authentication
python main.py scan -f browser-export.har -a cookie -n "session" -v "session-value"
```

### Selective Scanning
```bash
# ZAP scanning only (skip custom plugins)
python main.py scan -f burp-export.har --no-plugins

# Custom plugins only (skip ZAP)
python main.py scan -f zap-export.har --no-zap

# JWT security plugin only (when JWT detected)
python main.py scan -f jwt-api-export.har --plugins JWTSecurityChecker
```

### Advanced Options
```bash
# Verbose output with performance stats
python main.py scan -f large-export.har -v --performance-stats

# Custom output directory
python main.py scan -f api-export.har --output-dir custom-reports

# Specific target URL (for ZAP scanning)
python main.py scan -f mixed-export.har --target https://api.example.com
```

## Creating HAR Files

### From Insomnia REST Client

1. **Open Insomnia** and load your workspace
2. **Right-click** on your workspace name
3. **Select** "Export Data" → "HAR"
4. **Save** the file with `.har` extension
5. **Use** with the scanner: `python main.py scan -f your-export.har`

### From Postman

1. **Open Postman** and select your collection
2. **Click** the three dots (...) next to collection name
3. **Select** "Export" → "Collection v2.1"
4. **Convert** to HAR format using:
   - Online converters (postman-to-har)
   - Postman's built-in HAR export (if available)
   - Custom scripts
5. **Use** with the scanner: `python main.py scan -f converted-export.har`

### From Browser DevTools

1. **Open** your web application in browser
2. **Press F12** to open DevTools
3. **Go to** Network tab
4. **Perform** your API interactions
5. **Right-click** in the network list
6. **Select** "Save all as HAR with content"
7. **Use** with the scanner: `python main.py scan -f network-export.har`

### From Burp Suite

1. **Open Burp Suite** and configure proxy
2. **Navigate** to Proxy → HTTP history
3. **Select** the requests you want to export
4. **Right-click** → "Save items"
5. **Choose** "HAR" format
6. **Use** with the scanner: `python main.py scan -f burp-export.har`

### From OWASP ZAP

1. **Open OWASP ZAP** and perform your scans
2. **Go to** Tools → Export
3. **Select** "HAR" format
4. **Choose** export options (requests, responses, etc.)
5. **Save** the HAR file
6. **Use** with the scanner: `python main.py scan -f zap-export.har`

## HAR File Structure

A typical HAR file contains:

```json
{
  "log": {
    "version": "1.2",
    "creator": {
      "name": "Insomnia REST Client",
      "version": "2023.5.8"
    },
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://api.example.com/users",
          "headers": [
            {
              "name": "Authorization",
              "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
          ],
          "queryString": [
            {
              "name": "limit",
              "value": "10"
            }
          ],
          "postData": {
            "mimeType": "application/json",
            "text": "{\"name\":\"test\"}"
          }
        },
        "response": {
          "status": 200,
          "headers": [
            {
              "name": "Content-Type",
              "value": "application/json"
            }
          ],
          "content": {
            "text": "{\"users\":[]}"
          }
        }
      }
    ]
  }
}
```

## Best Practices

### 🎯 Optimal HAR Files
- **Include Request Bodies**: Ensure POST/PUT requests have body content
- **Preserve Headers**: Keep all authentication and custom headers
- **Clean URLs**: Remove sensitive data from URLs before export
- **Reasonable Size**: Large HAR files (>100MB) may impact performance

### 🔒 Security Considerations
- **Remove Sensitive Data**: Clean tokens, passwords, and API keys
- **Use Test Environments**: Export from staging/dev environments
- **Validate Content**: Review HAR files before sharing
- **Secure Storage**: Store HAR files securely if they contain sensitive data

### ⚡ Performance Tips
- **Filter Requests**: Export only relevant API requests
- **Batch Processing**: Process large HAR files in smaller batches
- **Use Docker**: Containerized scanning for better isolation
- **Monitor Resources**: Watch memory usage with large files

## Troubleshooting

### Common Issues

**"Invalid HAR file structure"**
- Ensure the file has `log.entries` structure
- Check JSON validity
- Verify HAR version compatibility

**"No requests found"**
- Check if `entries` array is not empty
- Verify request objects have required fields
- Ensure URLs are valid

**"JWT tokens not detected"**
- Check Authorization header format
- Verify Bearer token prefix
- Ensure token is valid JWT format

**"Performance issues"**
- Reduce HAR file size
- Use `--no-zap` for plugin-only scanning
- Process in smaller batches

### Debug Mode
```bash
# Enable verbose logging
python main.py scan -f export.har -vv

# Test HAR parsing only
python test_har_parser.py

# Validate HAR structure
python -c "import json; print('Valid JSON' if json.load(open('export.har')) else 'Invalid')"
```

## Integration with Existing Workflows

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: Export API Tests to HAR
  run: |
    # Your API testing tool export command
    insomnia export --har output.har

- name: Security Scan HAR
  run: |
    docker run --rm -v $(pwd):/workspace \
      api-security-scanner scan -f /workspace/output.har
```

### Development Workflow
```bash
# 1. Develop APIs in Insomnia
# 2. Export to HAR
insomnia export --har api-tests.har

# 3. Security scan
python main.py scan -f api-tests.har

# 4. Review results
open reports/scan_report_*.html
```

### Security Testing
```bash
# 1. Capture traffic in Burp Suite
# 2. Export to HAR
# 3. Scan with custom plugins
python main.py scan -f burp-traffic.har --no-zap

# 4. Generate security report
python main.py scan -f burp-traffic.har --export security-report.html
```

## Future Enhancements

- **HAR Validation**: Enhanced HAR file validation and error reporting
- **Selective Export**: Export specific requests or time ranges
- **HAR Comparison**: Compare multiple HAR files for changes
- **Real-time Monitoring**: Live HAR file monitoring and scanning
- **Advanced Filtering**: Filter requests by method, status, or content type

---

For more information, see the main [README.md](../README.md) or contact the development team.
