# API Security Scanner - Setup and Usage Guide

## 📋 Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Basic Usage](#basic-usage)
4. [Advanced Usage](#advanced-usage)
5. [Authentication](#authentication)
6. [Collection Upload](#collection-upload)
7. [Report Generation](#report-generation)
8. [Troubleshooting](#troubleshooting)
9. [Examples](#examples)

## 🔧 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Step 1: Install Dependencies
```bash
# Install required packages
pip install requests pyyaml

# Or install from requirements.txt
pip install -r requirements.txt
```

### Step 2: Download the Tool
```bash
# Clone or download the API Security Scanner files
# Make sure you have these files:
# - api_security_scanner.py
# - requirements.txt
# - README.md
```

### Step 3: Verify Installation
```bash
# Run the scanner to verify installation
python api_security_scanner.py
```

You should see output like:
```
🔍 OWASP API Top 10 Security Scanner with Collection Support
============================================================
📋 Example 1: Scanning from Swagger URL with OWASP Top 10
✅ Standard scan completed. Report saved to: api_security_report_1234567890.json
✅ OWASP API Top 10 report saved to: owasp_api_top10_report_1234567890.html
```

## 🚀 Quick Start

### Basic Swagger URL Scan
```python
from api_security_scanner import APISecurityScanner

# Initialize scanner
scanner = APISecurityScanner()

# Scan public API
results = scanner.scan_from_swagger_url(
    "https://petstore.swagger.io/v2/swagger.json",
    "https://petstore.swagger.io/v2"
)

# Generate reports
report_file = scanner.generate_api_security_report(results)
owasp_report = scanner.generate_owasp_report(results, 'html')

print(f"✅ Scan completed! Reports: {report_file}, {owasp_report}")
```

### Authenticated Scan
```python
# Initialize with authentication
auth_config = {
    'type': 'bearer',
    'token': 'your_jwt_token_here'
}
scanner = APISecurityScanner(auth_config=auth_config)

# Scan protected API
results = scanner.scan_from_swagger_url(
    "https://api.example.com/swagger.json",
    "https://api.example.com"
)
```

## 📖 Basic Usage

### 1. Swagger/OpenAPI URL Scanning
```python
from api_security_scanner import APISecurityScanner

scanner = APISecurityScanner()

# Method 1: Simple scan
results = scanner.scan_from_swagger_url(
    "https://api.example.com/swagger.json",
    "https://api.example.com"
)

# Method 2: With authentication
auth_config = {'type': 'bearer', 'token': 'your_token'}
results = scanner.scan_from_swagger_url(
    "https://api.example.com/swagger.json",
    "https://api.example.com",
    auth_config
)
```

### 2. JSON Specification File Scanning
```python
# Scan from local JSON file
results = scanner.scan_from_json_file(
    "api_spec.json",
    "https://api.example.com"
)

# With authentication
results = scanner.scan_from_json_file(
    "api_spec.json",
    "https://api.example.com",
    auth_config
)
```

### 3. Collection Upload and Scanning
```python
# Upload Postman collection
results = scanner.upload_and_scan_collection(
    "postman_collection.json",
    "https://api.example.com"
)

# Upload HAR file
results = scanner.upload_and_scan_collection("network_traffic.har")

# Upload curl commands
results = scanner.upload_and_scan_collection(
    "curl_commands.txt",
    "https://api.example.com"
)
```

## 🔐 Authentication

### Bearer Token
```python
scanner = APISecurityScanner()

# Method 1: Set during initialization
auth_config = {'type': 'bearer', 'token': 'your_token'}
scanner = APISecurityScanner(auth_config=auth_config)

# Method 2: Set after initialization
scanner.set_bearer_token("your_token")

# Method 3: Set with full config
scanner.set_auth_config({
    'type': 'bearer',
    'token': 'your_token',
    'headers': {'X-Custom-Header': 'value'}
})
```

### API Key
```python
# API Key in header
scanner.set_api_key("X-API-Key", "your_api_key", "header")

# API Key in query parameters
scanner.set_api_key("api_key", "your_api_key", "query")
```

### Basic Authentication
```python
scanner.set_basic_auth("username", "password")
```

### OAuth2 Token
```python
scanner.set_oauth2_token("your_oauth2_access_token")
```

### Custom Headers
```python
scanner.add_auth_header("X-Custom-Auth", "custom_value")
scanner.add_auth_header("X-User-Token", "user_token")
```

### Clear Authentication
```python
scanner.clear_auth()
```

## 📁 Collection Upload

### Supported Formats

#### 1. Postman Collections (.json)
```bash
# Export from Postman:
# 1. Open Postman
# 2. Select collection
# 3. Click "Export" (three dots)
# 4. Choose "Collection v2.1"
# 5. Save as .json file
```

```python
# Upload Postman collection
results = scanner.upload_and_scan_collection(
    "postman_collection.json",
    "https://api.example.com"
)
```

#### 2. Insomnia Collections (.json)
```bash
# Export from Insomnia:
# 1. Open Insomnia
# 2. Settings → Data → Export Data
# 3. Select "Insomnia v4"
# 4. Save as .json file
```

```python
# Upload Insomnia collection
results = scanner.upload_and_scan_collection(
    "insomnia_collection.json",
    "https://api.example.com"
)
```

#### 3. HAR Files (.har)
```bash
# Export from browser:
# 1. Open Developer Tools (F12)
# 2. Go to Network tab
# 3. Perform API interactions
# 4. Right-click → "Save all as HAR"
```

```python
# Upload HAR file
results = scanner.upload_and_scan_collection("network_traffic.har")
```

#### 4. curl Commands (.txt)
```txt
# Create file with curl commands:
curl -X GET "https://api.example.com/users" \
  -H "Authorization: Bearer token123"

curl -X POST "https://api.example.com/users" \
  -H "Content-Type: application/json" \
  -d '{"name": "John", "email": "john@example.com"}'
```

```python
# Upload curl commands
results = scanner.upload_and_scan_collection(
    "curl_commands.txt",
    "https://api.example.com"
)
```

## 📊 Report Generation

### Standard Security Report
```python
# Generate JSON report
report_file = scanner.generate_api_security_report(results)

# Generate HTML report
report_file = scanner.generate_api_security_report(results, 'html')
```

### OWASP API Top 10 Report
```python
# Generate OWASP report
owasp_report = scanner.generate_owasp_report(results, 'html')

# Generate JSON OWASP report
owasp_report = scanner.generate_owasp_report(results, 'json')
```

### Report Contents
- **Vulnerability Summary**: Count and severity of findings
- **OWASP Compliance**: Checklist for all Top 10 categories
- **Security Score**: 0-100 score based on findings
- **Detailed Results**: Evidence and recommendations
- **Remediation Guidance**: Specific fix suggestions

## 🔧 Advanced Usage

### Batch Processing
```python
# Process multiple APIs
apis = [
    ("https://api1.com/swagger.json", "https://api1.com"),
    ("https://api2.com/swagger.json", "https://api2.com"),
    ("https://api3.com/swagger.json", "https://api3.com")
]

for swagger_url, base_url in apis:
    print(f"Scanning: {base_url}")
    results = scanner.scan_from_swagger_url(swagger_url, base_url)
    report = scanner.generate_api_security_report(results)
    print(f"Report: {report}")
```

### Multiple Authentication Levels
```python
scanner = APISecurityScanner()

# Test 1: Unauthenticated
print("Testing public endpoints...")
unauth_results = scanner.scan_from_swagger_url("https://api.example.com/swagger.json")

# Test 2: User authentication
print("Testing user endpoints...")
scanner.set_bearer_token("user_token")
user_results = scanner.scan_from_swagger_url("https://api.example.com/swagger.json")

# Test 3: Admin authentication
print("Testing admin endpoints...")
scanner.set_auth_config({
    'type': 'bearer',
    'token': 'admin_token',
    'headers': {'X-User-Role': 'admin'}
})
admin_results = scanner.scan_from_swagger_url("https://api.example.com/swagger.json")
```

### Environment-Based Configuration
```python
import os

# Use environment variables for sensitive data
auth_config = {
    'type': 'bearer',
    'token': os.getenv('API_TOKEN'),
    'headers': {
        'X-API-Key': os.getenv('API_KEY')
    }
}

scanner = APISecurityScanner(auth_config=auth_config)
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Import Error
```bash
ModuleNotFoundError: No module named 'requests'
```
**Solution**: Install dependencies
```bash
pip install requests pyyaml
```

#### 2. File Not Found
```bash
Error: File not found: collection.json
```
**Solution**: Check file path and permissions
```bash
ls -la collection.json
```

#### 3. Authentication Failed
```bash
Error: 401 Unauthorized
```
**Solution**: Verify authentication configuration
```python
# Check current auth
auth_info = scanner.get_auth_info()
print(auth_info)
```

#### 4. Network Error
```bash
Error: Connection timeout
```
**Solution**: Check network connectivity and URL accessibility
```python
# Test URL manually
import requests
response = requests.get("https://api.example.com/swagger.json")
print(response.status_code)
```

### Debug Mode
```python
import logging

# Enable debug output
logging.basicConfig(level=logging.DEBUG)

# Run scanner with debug info
scanner = APISecurityScanner()
results = scanner.scan_from_swagger_url("https://api.example.com/swagger.json")
```

## 📝 Examples

### Complete Example Script
```python
#!/usr/bin/env python3
"""
Complete API Security Scanner Example
"""

from api_security_scanner import APISecurityScanner
import os

def main():
    # Initialize scanner
    scanner = APISecurityScanner()
    
    print("🔍 API Security Scanner - Complete Example")
    print("=" * 50)
    
    # Example 1: Public API scan
    print("\n1. Scanning public API...")
    public_results = scanner.scan_from_swagger_url(
        "https://petstore.swagger.io/v2/swagger.json",
        "https://petstore.swagger.io/v2"
    )
    
    if 'error' not in public_results:
        public_report = scanner.generate_api_security_report(public_results)
        public_owasp = scanner.generate_owasp_report(public_results, 'html')
        print(f"✅ Public scan completed: {public_report}, {public_owasp}")
    
    # Example 2: Authenticated API scan
    print("\n2. Scanning authenticated API...")
    
    # Set authentication (replace with your credentials)
    auth_config = {
        'type': 'bearer',
        'token': os.getenv('API_TOKEN', 'your_token_here'),
        'headers': {
            'X-API-Key': os.getenv('API_KEY', 'your_key_here')
        }
    }
    
    scanner.set_auth_config(auth_config)
    
    # Replace with your API URL
    auth_results = scanner.scan_from_swagger_url(
        "https://api.example.com/swagger.json",
        "https://api.example.com"
    )
    
    if 'error' not in auth_results:
        auth_report = scanner.generate_api_security_report(auth_results)
        auth_owasp = scanner.generate_owasp_report(auth_results, 'html')
        print(f"✅ Authenticated scan completed: {auth_report}, {auth_owasp}")
    
    # Example 3: Collection upload
    print("\n3. Uploading API collection...")
    
    # Check if collection file exists
    collection_file = "postman_collection.json"
    if os.path.exists(collection_file):
        collection_results = scanner.upload_and_scan_collection(
            collection_file,
            "https://api.example.com"
        )
        
        if 'error' not in collection_results:
            print(f"✅ Collection scan completed: {collection_results['reports']}")
    else:
        print(f"⚠️ Collection file not found: {collection_file}")
    
    print("\n🎉 All scans completed!")

if __name__ == "__main__":
    main()
```

### Command Line Usage
```bash
# Run the scanner
python api_security_scanner.py

# Run with custom script
python your_scan_script.py

# Run with environment variables
API_TOKEN=your_token API_KEY=your_key python your_scan_script.py
```

## 📚 Best Practices

### 1. Environment Setup
- Use test environments, not production
- Set up proper authentication credentials
- Use environment variables for sensitive data

### 2. Scanning Strategy
- Start with unauthenticated scans
- Add authentication for protected endpoints
- Test different user roles
- Scan all API versions

### 3. Report Management
- Generate both standard and OWASP reports
- Save reports with timestamps
- Review findings manually
- Track remediation progress

### 4. Security Considerations
- Don't scan production without permission
- Use test credentials only
- Monitor for false positives
- Validate findings manually

## 🆘 Getting Help

### Check Documentation
- Read this guide thoroughly
- Review example scripts
- Check OWASP API Top 10 documentation

### Debug Issues
```python
# Enable debug mode
import logging
logging.basicConfig(level=logging.DEBUG)

# Check authentication
auth_info = scanner.get_auth_info()
print(auth_info)

# Test URL manually
import requests
response = requests.get("your_api_url")
print(response.status_code)
```

### Common Commands
```bash
# Install dependencies
pip install requests pyyaml

# Run scanner
python api_security_scanner.py

# Check Python version
python --version

# List installed packages
pip list
```

---

*This guide covers all aspects of setting up and using the API Security Scanner tool.* 

# 🚀 **How to Run and Use the API Security Scanner**

## 📋 **Quick Start Guide**

### **Step 1: Installation**
```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Verify installation
python api_security_scanner.py
```

### **Step 2: Basic Usage**
```bash
# Run the demonstration script
python run_scanner.py
```

## 🎯 **Usage Examples**

### **1. Quick Demo (No Setup Required)**
```bash
# Run the demonstration script
python run_scanner.py
```

This will:
- ✅ Scan a public API (Petstore)
- ✅ Show authentication options
- ✅ Check for collection files
- ✅ Generate security reports

### **2. Public API Scanning**
```python
from api_security_scanner import APISecurityScanner

# Initialize scanner
scanner = APISecurityScanner()

# Scan public API
results = scanner.scan_from_swagger_url(
    "https://petstore.swagger.io/v2/swagger.json",
    "https://petstore.swagger.io/v2"
)

# Generate reports
report_file = scanner.generate_api_security_report(results)
owasp_report = scanner.generate_owasp_report(results, 'html')

print(f"✅ Scan completed! Reports: {report_file}, {owasp_report}")
```

### **3. Authenticated API Scanning**
```python
# Set up authentication
auth_config = {
    'type': 'bearer',
    'token': 'your_jwt_token_here'
}
scanner = APISecurityScanner(auth_config=auth_config)

# Scan protected API
results = scanner.scan_from_swagger_url(
    "https://api.example.com/swagger.json",
    "https://api.example.com"
)
```

### **4. Using Environment Variables**
```bash
# Set authentication credentials
export API_TOKEN="your_jwt_token_here"
export API_KEY="your_api_key_here"
export API_URL="https://api.example.com"

# Run with authentication
python run_scanner.py
```

### **5. Collection Upload**
```bash
# Place your collection files in the same directory
# Supported formats: .json, .har, .txt

# Run the scanner
python run_scanner.py
```

## 📁 **Supported Input Formats**

### **1. Swagger/OpenAPI URLs**
```python
# Public API
results = scanner.scan_from_swagger_url(
    "https://petstore.swagger.io/v2/swagger.json",
    "https://petstore.swagger.io/v2"
)

# Protected API with auth
auth_config = {'type': 'bearer', 'token': 'your_token'}
results = scanner.scan_from_swagger_url(
    "https://api.example.com/swagger.json",
    "https://api.example.com",
    auth_config
)
```

### **2. JSON Specification Files**
```python
# Local JSON file
results = scanner.scan_from_json_file(
    "api_spec.json",
    "https://api.example.com"
)
```

### **3. API Collections**
```python
# Postman collection
results = scanner.upload_and_scan_collection(
    "postman_collection.json",
    "https://api.example.com"
)

# HAR file (browser network traffic)
results = scanner.upload_and_scan_collection("network_traffic.har")

# curl commands
results = scanner.upload_and_scan_collection(
    "curl_commands.txt",
    "https://api.example.com"
)
```

## 🔐 **Authentication Options**

### **Bearer Token**
```python
scanner.set_bearer_token("your_jwt_token_here")
```

### **API Key**
```python
# In header
scanner.set_api_key("X-API-Key", "your_api_key", "header")

# In query parameters
scanner.set_api_key("api_key", "your_api_key", "query")
```

### **Basic Authentication**
```python
scanner.set_basic_auth("username", "password")
```

### **OAuth2 Token**
```python
scanner.set_oauth2_token("your_oauth2_access_token")
```

### **Custom Headers**
```python
scanner.add_auth_header("X-Custom-Auth", "custom_value")
```

### **Clear Authentication**
```python
scanner.clear_auth()
```

## 📊 **Report Generation**

### **Standard Security Report**
```python
# Generate JSON report
report_file = scanner.generate_api_security_report(results)

# Generate HTML report
report_file = scanner.generate_api_security_report(results, 'html')
```

### **OWASP API Top 10 Report**
```python
# Generate OWASP report
owasp_report = scanner.generate_owasp_report(results, 'html')

# Generate JSON OWASP report
owasp_report = scanner.generate_owasp_report(results, 'json')
```

## 🛠️ **Command Line Usage**

### **Basic Commands**
```bash
# Run demonstration
python run_scanner.py

# Run main scanner
python api_security_scanner.py

# Run with environment variables
API_TOKEN=your_token API_KEY=your_key python run_scanner.py
```

### **Environment Variables**
```bash
# Set authentication
export API_TOKEN="your_jwt_token"
export API_KEY="your_api_key"
export API_URL="https://api.example.com"
export SWAGGER_URL="https://api.example.com/swagger.json"

# Run scanner
python run_scanner.py
```

## 📁 **File Structure**
```
your_project/
├── api_security_scanner.py      # Main scanner
├── run_scanner.py              # Demo script
├── requirements.txt            # Dependencies
├── postman_collection.json     # Your collections (optional)
├── insomnia_collection.json    # Your collections (optional)
├── network_traffic.har         # Your HAR files (optional)
└── curl_commands.txt           # Your curl commands (optional)
```

## 🔧 **Troubleshooting**

### **Common Issues**

#### **1. Import Error**
```bash
ModuleNotFoundError: No module named 'requests'
```
**Solution**: Install dependencies
```bash
pip install requests pyyaml
```

#### **2. File Not Found**
```bash
Error: File not found: collection.json
```
**Solution**: Check file path and permissions

#### **3. Authentication Failed**
```bash
Error: 401 Unauthorized
```
**Solution**: Verify authentication configuration
```python
auth_info = scanner.get_auth_info()
print(auth_info)
```

#### **4. Network Error**
```bash
Error: Connection timeout
```
**Solution**: Check network connectivity and URL accessibility

### **Debug Mode**
```python
import logging
logging.basicConfig(level=logging.DEBUG)

scanner = APISecurityScanner()
results = scanner.scan_from_swagger_url("https://api.example.com/swagger.json")
```

## 📚 **Best Practices**

### **1. Environment Setup**
- Use test environments, not production
- Set up proper authentication credentials
- Use environment variables for sensitive data

### **2. Scanning Strategy**
- Start with unauthenticated scans
- Add authentication for protected endpoints
- Test different user roles
- Scan all API versions

### **3. Report Management**
- Generate both standard and OWASP reports
- Save reports with timestamps
- Review findings manually
- Track remediation progress

## 🎉 **Quick Test**

To quickly test the tool:

```bash
# 1. Install dependencies
pip install requests pyyaml

# 2. Run the demo
python run_scanner.py

# 3. Check generated reports
ls -la *.html *.json
```

The tool will automatically:
- ✅ Scan a public API
- ✅ Generate security reports
- ✅ Show OWASP compliance
- ✅ Demonstrate authentication options

This gives you a complete working example of the API Security Scanner in action! 