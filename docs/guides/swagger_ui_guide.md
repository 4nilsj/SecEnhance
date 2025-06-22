# 🌐 Swagger/OpenAPI Support in Web UI

## ✅ **Yes, it works with the UI app!**

The web interface fully supports Swagger and OpenAPI specifications through multiple methods.

## 🚀 **How to Use Swagger/OpenAPI with Web UI**

### **Step 1: Start the Web Interface**
```bash
python main.py web
```
Then open your browser to: `http://localhost:5000`

### **Method 1: Swagger URL (Recommended)**

1. **Select Scan Type:**
   - Choose "Swagger URL" from the dropdown

2. **Enter Swagger URL:**
   - **Example URLs:**
     - `https://petstore.swagger.io/v2/swagger.json` (Swagger 2.0)
     - `https://api.example.com/openapi.json` (OpenAPI 3.0)
     - `https://api.example.com/swagger.yaml` (YAML format)

3. **Enter Base URL:**
   - **Example:** `https://petstore.swagger.io`
   - This is the base URL where your API endpoints are hosted

4. **Configure Authentication (Optional):**
   - API Key
   - Bearer Token
   - Basic Auth
   - OAuth2

5. **Start Scan:**
   - Click "Start Security Scan"
   - Watch real-time progress
   - View results when complete

### **Method 2: JSON File Upload**

1. **Prepare Your File:**
   - Download your Swagger/OpenAPI JSON file
   - Or export from your API documentation tool

2. **Upload File:**
   - Select "JSON File" from the dropdown
   - Click "Choose File" and select your OpenAPI JSON
   - Enter the base URL

3. **Start Scan:**
   - Click "Start Security Scan"

### **Method 3: Collection Upload**

1. **Export from Postman/Insomnia:**
   - Export your API collection as JSON
   - Upload the collection file

2. **Configure:**
   - Select "Collection" from the dropdown
   - Upload your collection file
   - Enter base URL

## 📋 **Supported Formats**

| Format | File Extension | URL Support | File Upload |
|--------|----------------|-------------|-------------|
| **Swagger 2.0** | `.json`, `.yaml` | ✅ Yes | ✅ Yes |
| **OpenAPI 3.0** | `.json`, `.yaml` | ✅ Yes | ✅ Yes |
| **OpenAPI 3.1** | `.json`, `.yaml` | ✅ Yes | ✅ Yes |
| **Postman Collection** | `.json` | ❌ No | ✅ Yes |
| **Insomnia Collection** | `.json` | ❌ No | ✅ Yes |

## 🔍 **What Gets Tested**

When you scan a Swagger/OpenAPI specification, the scanner will:

1. **Parse all endpoints** from the specification
2. **Test each endpoint** for:
   - SQL Injection vulnerabilities
   - XSS (Cross-Site Scripting)
   - Authentication bypass
   - Information disclosure
   - Rate limiting issues

3. **Generate comprehensive reports** in JSON and HTML formats

## 📊 **Example Results**

After scanning a Swagger specification, you'll see:

- **Total endpoints found** from the spec
- **Endpoints successfully scanned**
- **Vulnerabilities discovered** with severity levels
- **Detailed reports** with evidence and recommendations

## 🎯 **Real-World Examples**

### **Example 1: Petstore API**
```
Swagger URL: https://petstore.swagger.io/v2/swagger.json
Base URL: https://petstore.swagger.io
```
**Result:** 20 endpoints scanned, vulnerabilities found and reported

### **Example 2: Custom API**
```
JSON File: my-api-spec.json
Base URL: https://api.mycompany.com
```
**Result:** All endpoints from your specification scanned

## 🔧 **Authentication Support**

The web UI supports all major authentication methods:

- **API Key:** Add to headers or query parameters
- **Bearer Token:** JWT or OAuth2 access tokens
- **Basic Auth:** Username/password
- **OAuth2:** Access tokens
- **Custom Headers:** Any custom authentication headers

## 📄 **Report Generation**

After scanning, you can:

1. **View results** in the web interface
2. **Download JSON report** for technical analysis
3. **Download HTML report** for OWASP Top 10 compliance
4. **View HTML report** directly in browser

## 🚨 **Important Notes**

1. **Base URL:** Make sure to enter the correct base URL where your API is hosted
2. **Authentication:** Configure authentication if your API requires it
3. **Rate Limiting:** The scanner respects rate limits and won't overwhelm your API
4. **Test Environment:** Always test on staging/test environments first

## 💡 **Pro Tips**

1. **Use Swagger URL** for public APIs or when you have direct access to the spec URL
2. **Use JSON File Upload** for private APIs or when you need to modify the spec
3. **Test authentication** before starting the scan
4. **Review results carefully** - not all findings are actual vulnerabilities
5. **Save reports** for compliance and documentation purposes

## 🎉 **Ready to Start?**

1. Start the web UI: `python main.py web`
2. Open browser to: `http://localhost:5000`
3. Choose your preferred method (Swagger URL or File Upload)
4. Enter your API specification details
5. Start scanning!

The web interface provides the same powerful scanning capabilities as the Python scripts, but with a user-friendly interface and real-time progress updates. 