# API Collection Upload Guide

## Overview
The API Security Scanner now supports uploading and scanning API collections from various popular tools and formats. This allows you to import your existing API collections for comprehensive security testing against OWASP API Top 10 vulnerabilities.

## 📁 Supported Collection Formats

### 1. Postman Collections (.json)
**Most Popular API Testing Tool**

**Features Extracted:**
- ✅ Full request/response data
- ✅ Authentication information (Bearer, API Key, Basic Auth)
- ✅ Environment variables and dynamic values
- ✅ Headers and body data
- ✅ Query parameters and path variables
- ✅ Request descriptions and metadata
- ✅ Folder organization and tags

**Export Instructions:**
1. Open Postman
2. Select your collection
3. Click "Export" (three dots menu)
4. Choose "Collection v2.1" format
5. Save as `.json` file

**Example Usage:**
```python
scanner = APISecurityScanner()
results = scanner.upload_and_scan_collection(
    "postman_collection.json", 
    "https://api.example.com"
)
```

---

### 2. Insomnia Collections (.json)
**Modern API Client**

**Features Extracted:**
- ✅ Request configurations
- ✅ Headers and authentication
- ✅ Body data and parameters
- ✅ Request metadata
- ✅ Environment variables

**Export Instructions:**
1. Open Insomnia
2. Go to Settings → Data → Export Data
3. Select "Insomnia v4" format
4. Save as `.json` file

**Example Usage:**
```python
results = scanner.upload_and_scan_collection(
    "insomnia_collection.json", 
    "https://api.example.com"
)
```

---

### 3. HAR Files (.har)
**HTTP Archive Format - Browser Network Traffic**

**Features Extracted:**
- ✅ Complete HTTP request/response data
- ✅ Headers and cookies
- ✅ Query parameters
- ✅ POST data and form submissions
- ✅ Response status codes and timing
- ✅ Browser-generated traffic

**Export Instructions:**
1. Open browser Developer Tools (F12)
2. Go to Network tab
3. Perform your API interactions
4. Right-click → "Save all as HAR"
5. Save as `.har` file

**Example Usage:**
```python
# HAR files contain full URLs, so base_url is optional
results = scanner.upload_and_scan_collection("network_traffic.har")
```

---

### 4. curl Commands (.txt)
**Command-line HTTP Requests**

**Features Extracted:**
- ✅ URL and HTTP method
- ✅ Headers and authentication
- ✅ Request body data
- ✅ Query parameters

**Format Example:**
```txt
curl -X POST "https://api.example.com/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token123" \
  -d '{"name": "John", "email": "john@example.com"}'

curl -X GET "https://api.example.com/users/1" \
  -H "Accept: application/json"
```

**Example Usage:**
```python
results = scanner.upload_and_scan_collection(
    "curl_commands.txt", 
    "https://api.example.com"
)
```

---

### 5. Generic JSON (.json)
**Custom API Specifications**

**Features Extracted:**
- ✅ Simple endpoint definitions
- ✅ URL and method information
- ✅ Headers and parameters
- ✅ Flexible format support

**Format Example:**
```json
{
  "endpoints": [
    {
      "name": "Get User",
      "method": "GET",
      "url": "/users/{id}",
      "headers": {
        "Authorization": "Bearer token"
      }
    },
    {
      "name": "Create User",
      "method": "POST",
      "url": "/users",
      "headers": {
        "Content-Type": "application/json"
      },
      "body": {
        "name": "string",
        "email": "string"
      }
    }
  ]
}
```

---

## 🔧 Usage Examples

### Basic Collection Upload
```python
from api_security_scanner import APISecurityScanner

# Initialize scanner
scanner = APISecurityScanner()

# Upload and scan collection
results = scanner.upload_and_scan_collection(
    "my_api_collection.json",
    "https://api.example.com"
)

# Check results
if 'error' not in results:
    print(f"✅ Collection format: {results['collection_format']}")
    print(f"✅ Endpoints found: {results['endpoints_found']}")
    print(f"✅ Reports: {results['reports']['standard_report']}")
    print(f"✅ OWASP Report: {results['reports']['owasp_report']}")
else:
    print(f"❌ Error: {results['error']}")
```

### Multiple Collection Processing
```python
# Process multiple collections
collections = [
    ("postman_collection.json", "https://api.example.com"),
    ("insomnia_collection.json", "https://api.example.com"),
    ("har_export.har", None),
    ("curl_commands.txt", "https://api.example.com")
]

for collection_file, base_url in collections:
    print(f"\n📂 Processing: {collection_file}")
    results = scanner.upload_and_scan_collection(collection_file, base_url)
    
    if 'error' not in results:
        print(f"✅ Format: {results['collection_format']}")
        print(f"✅ Endpoints: {results['endpoints_found']}")
    else:
        print(f"❌ Failed: {results['error']}")
```

### Direct Collection Scanning
```python
# Scan without automatic report generation
results = scanner.scan_from_api_collection(
    "my_collection.json", 
    "https://api.example.com"
)

if 'error' not in results:
    # Generate reports manually
    report_file = scanner.generate_api_security_report(results)
    owasp_report = scanner.generate_owasp_report(results, 'html')
    
    print(f"📊 Collection scanned successfully!")
    print(f"📄 Reports: {report_file}, {owasp_report}")
```

---

## 🔍 Collection Format Detection

The scanner automatically detects collection formats:

### Detection Logic
1. **Postman**: Checks for `info.schema` containing "postman"
2. **Insomnia**: Checks for `_type` field with value "export"
3. **OpenAPI/Swagger**: Checks for `openapi` or `swagger` fields
4. **HAR**: Checks for `log.entries` structure
5. **curl**: Checks for "curl" commands in list format
6. **Generic**: Falls back to generic JSON parsing

### Manual Format Specification
```python
# Force specific format parsing
collection_data = json.load(open("collection.json"))
format_type = scanner.detect_collection_format(collection_data)
endpoints = scanner.parse_api_collection(collection_data, format_type, base_url)
```

---

## 📊 Data Extraction Capabilities

### Authentication Information
- **Bearer Tokens**: Extracted from Authorization headers
- **API Keys**: Extracted from headers or query parameters
- **Basic Auth**: Username/password extraction
- **Custom Auth**: Header-based authentication

### Request Data
- **Headers**: All request headers
- **Body**: JSON, form data, raw data
- **Parameters**: Query and path parameters
- **URLs**: Full URL resolution with variables

### Metadata
- **Request Names**: Used for endpoint identification
- **Descriptions**: Request documentation
- **Tags**: Categorization information
- **Timing**: Response timing data (HAR)

---

## 🛡️ Security Testing Features

### OWASP API Top 10 Testing
Each endpoint from the collection is tested against:

1. **API1:2023** - Broken Object Property Level Authorization
2. **API2:2023** - Broken Authentication
3. **API3:2023** - Broken Object Property Level Authorization
4. **API4:2023** - Unrestricted Resource Consumption
5. **API5:2023** - Broken Function Level Authorization
6. **API6:2023** - Unrestricted Access to Sensitive Business Flows
7. **API7:2023** - Server-Side Request Forgery
8. **API8:2023** - Security Misconfiguration
9. **API9:2023** - Improper Inventory Management
10. **API10:2023** - Unsafe Consumption of APIs

### Vulnerability Detection
- **Authentication Bypass**: Test endpoints without auth
- **Authorization Flaws**: Test privilege escalation
- **Input Validation**: Test injection attacks
- **Rate Limiting**: Test DoS vulnerabilities
- **Business Logic**: Test workflow bypasses

---

## 📄 Report Generation

### Standard Security Report
- Comprehensive vulnerability assessment
- Detailed test results
- Evidence collection
- Security recommendations

### OWASP API Top 10 Report
- OWASP compliance checklist
- Security scoring (0-100)
- Category-wise vulnerability summary
- Remediation guidance

### Report Formats
- **HTML**: Interactive web reports
- **JSON**: Machine-readable format
- **Console Output**: Real-time progress

---

## 🔧 Integration with Burp Suite

### BCheck Script Generation
```python
# Generate BCheck scripts from collection
def generate_bcheck_from_collection(collection_file):
    results = scanner.scan_from_api_collection(collection_file)
    # Convert to BCheck format
    bcheck_script = convert_to_bcheck(results)
    return bcheck_script
```

### Workflow Automation
```python
# Automated collection processing
def process_collections_automatically():
    collections = glob.glob("collections/*.json")
    for collection in collections:
        results = scanner.upload_and_scan_collection(collection)
        # Send to Burp Suite for further testing
        send_to_burp(results)
```

---

## 🚀 Best Practices

### Collection Preparation
1. **Clean Data**: Remove sensitive information before upload
2. **Valid URLs**: Ensure all URLs are accessible
3. **Authentication**: Include test credentials if needed
4. **Documentation**: Add descriptions to requests

### Security Testing
1. **Environment**: Use test environments, not production
2. **Scope**: Define testing scope and boundaries
3. **Monitoring**: Monitor for false positives
4. **Validation**: Verify findings manually

### Integration
1. **Automation**: Integrate with CI/CD pipelines
2. **Reporting**: Schedule regular security reports
3. **Remediation**: Track vulnerability fixes
4. **Compliance**: Maintain OWASP compliance

---

## 🛠️ Troubleshooting

### Common Issues

#### File Not Found
```
Error: File not found: collection.json
```
**Solution**: Check file path and permissions

#### Unsupported Format
```
Error: Unsupported file format: .xml
```
**Solution**: Convert to supported format (.json, .har, .txt)

#### Parsing Errors
```
Error: Failed to parse collection
```
**Solution**: Validate JSON format and structure

#### Empty Collection
```
Warning: No endpoints found in collection
```
**Solution**: Check collection structure and content

### Debug Mode
```python
# Enable debug output
import logging
logging.basicConfig(level=logging.DEBUG)

# Detailed error information
try:
    results = scanner.upload_and_scan_collection("collection.json")
except Exception as e:
    print(f"Detailed error: {e}")
    import traceback
    traceback.print_exc()
```

---

## 📚 Resources

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [Postman Collection Format](https://learning.postman.com/docs/collections/collections-overview/)
- [Insomnia Export Format](https://docs.insomnia.rest/insomnia/import-export-data)
- [HAR Specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)

---

*This guide covers all aspects of API collection upload functionality for comprehensive security testing.* 