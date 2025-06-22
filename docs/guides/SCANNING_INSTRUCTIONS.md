# API Security Scanner - Complete Scanning Instructions

This guide provides step-by-step instructions for performing API security scans using both the **Script Method** and **Web UI Method**.

## 📋 Prerequisites

Before starting, ensure you have:

1. **Python 3.8+** installed
2. **Dependencies installed**: `pip install -r requirements.txt`
3. **Project structure** properly set up
4. **Target API** ready for scanning (or use test endpoints)

---

## 🚀 Method 1: Script-Based Scanning

### Quick Start - Simple Endpoint Scan

```bash
# Basic endpoint scan
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://httpbin.org/get", "method": "GET"}]'
```

### Detailed Script Usage

#### 1. **Scan Specific Endpoints**

```bash
# Single endpoint
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}]'

# Multiple endpoints
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}, {"url": "https://api.example.com/users", "method": "POST"}]'

# With verbose output
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}]' --verbose
```

#### 2. **Scan Postman Collection**

```bash
# Basic collection scan
python run_api_scan.py --type collection --collection data/my_collection.json

# With base URL
python run_api_scan.py --type collection --collection data/my_collection.json --base-url https://api.example.com
```

#### 3. **Scan Swagger/OpenAPI Specification**

```bash
# From URL
python run_api_scan.py --type swagger --swagger-url https://petstore.swagger.io/v2/swagger.json

# With base URL
python run_api_scan.py --type swagger --swagger-url https://api.example.com/swagger.json --base-url https://api.example.com
```

#### 4. **Scan Raw JSON File**

```bash
# JSON file scan
python run_api_scan.py --type json --json-file data/endpoints.json --base-url https://api.example.com
```

### Script Output

The script will show:
- ✅ Real-time progress bar
- 📊 Scan results summary
- 🚨 Vulnerabilities found (if any)
- 📄 Generated report locations
- 🌐 Instructions for viewing in Web UI

---

## 🌐 Method 2: Web UI Scanning

### Step 1: Launch Web UI

```bash
# Start the web interface
python main.py web

# Or with custom port
python main.py web --port 8080
```

### Step 2: Access Web Interface

1. **Open browser** and go to: `http://localhost:5000`
2. **You'll see** the main dashboard with tabs:
   - **Scan**: Start new scans
   - **Reports**: View existing reports
   - **History**: Scan history

### Step 3: Perform Scans via Web UI

#### **Option A: Upload Collection File**

1. **Go to "Scan" tab**
2. **Select "Collection Upload"**
3. **Choose file type**:
   - Postman Collection (.json)
   - Insomnia Collection (.json)
4. **Upload your file**
5. **Enter Base URL** (optional)
6. **Click "Start Scan"**
7. **Monitor progress** in real-time

#### **Option B: Swagger/OpenAPI URL**

1. **Go to "Scan" tab**
2. **Select "Swagger/OpenAPI"**
3. **Enter the URL** to your Swagger/OpenAPI spec
4. **Enter Base URL** (optional)
5. **Click "Start Scan"**
6. **Watch progress** updates

#### **Option C: Direct Endpoints**

1. **Go to "Scan" tab**
2. **Select "Direct Endpoints"**
3. **Add endpoints** manually:
   ```
   URL: https://api.example.com/users
   Method: GET
   Description: Get users list
   ```
4. **Add more endpoints** as needed
5. **Click "Start Scan"**

### Step 4: View Results

1. **Real-time progress** shown during scan
2. **Results displayed** when complete
3. **Download reports** (JSON/HTML)
4. **View in browser** (HTML reports)

---

## 📊 Understanding Scan Results

### **What Gets Scanned**

The scanner tests for:
- 🔒 **Authentication Bypass**
- 🚨 **SQL Injection**
- ⚡ **XSS (Cross-Site Scripting)**
- 📡 **Information Disclosure**
- 🔐 **Authorization Issues**
- ⚙️ **Security Misconfigurations**
- 🛡️ **Missing Security Headers**
- 🌐 **CORS Issues**
- ⏱️ **Rate Limiting Problems**

### **Result Categories**

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **Critical** | Immediate security risk | Fix immediately |
| **High** | Significant vulnerability | Fix as soon as possible |
| **Medium** | Moderate risk | Fix when convenient |
| **Low** | Minor issue | Consider fixing |
| **Info** | Informational finding | Review and document |

### **Report Types**

1. **JSON Report**: Machine-readable format
2. **HTML Report**: Human-readable with visualizations
3. **OWASP Report**: Standardized OWASP format

---

## 🔧 Advanced Configuration

### **Authentication Setup**

#### **Bearer Token**
```bash
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}]' --auth-type bearer --bearer-token "your-token-here"
```

#### **API Key**
```bash
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}]' --auth-type apikey --api-key-name "X-API-Key" --api-key-value "your-api-key"
```

#### **Basic Auth**
```bash
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}]' --auth-type basic --basic-username "user" --basic-password "pass"
```

### **Custom Headers**
```bash
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://api.example.com/users", "method": "GET"}]' --auth-type custom --custom-header-key_0 "X-Custom-Header" --custom-header-value_0 "custom-value"
```

---

## 📁 File Locations

### **Generated Reports**
- **JSON Reports**: `reports/api_security_scan_*.json`
- **HTML Reports**: `reports/owasp_api_scan_*.html`

### **Uploaded Collections**
- **Location**: `uploads/` directory
- **Format**: JSON files

### **Logs**
- **Location**: `logs/` directory
- **Format**: Text files with timestamps

---

## 🚨 Troubleshooting

### **Common Issues**

#### **1. Import Errors**
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

#### **2. File Not Found**
```bash
# Solution: Check file path
ls data/your_collection.json
```

#### **3. Web UI Not Starting**
```bash
# Solution: Check port availability
python main.py web --port 8080
```

#### **4. Scan Failing**
```bash
# Solution: Check target API accessibility
curl https://api.example.com/health
```

### **Debug Mode**

Enable verbose logging:
```bash
# Script mode
python run_api_scan.py --type endpoints --endpoints '[...]' --verbose

# Web UI mode
export FLASK_DEBUG=1
python main.py web
```

---

## 📈 Best Practices

### **Before Scanning**

1. **✅ Get permission** to scan the target API
2. **✅ Use test environment** when possible
3. **✅ Backup important data**
4. **✅ Set appropriate rate limits**
5. **✅ Monitor system resources**

### **During Scanning**

1. **✅ Monitor scan progress**
2. **✅ Check for errors**
3. **✅ Verify target accessibility**
4. **✅ Review initial results**

### **After Scanning**

1. **✅ Review all findings**
2. **✅ Prioritize vulnerabilities**
3. **✅ Generate detailed reports**
4. **✅ Share results with team**
5. **✅ Plan remediation**

---

## 🎯 Quick Reference Commands

### **Most Common Scans**

```bash
# Quick test scan
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://httpbin.org/get", "method": "GET"}]'

# Collection scan
python run_api_scan.py --type collection --collection my_collection.json

# Swagger scan
python run_api_scan.py --type swagger --swagger-url https://api.example.com/swagger.json

# Start web UI
python main.py web
```

### **View Reports**

```bash
# List all reports
ls reports/

# View latest JSON report
cat reports/api_security_scan_*.json | tail -1

# Open HTML report in browser
start reports/owasp_api_scan_*.html
```

---

## 📞 Support

If you encounter issues:

1. **Check logs**: `logs/` directory
2. **Review documentation**: `docs/` directory
3. **Test with examples**: `examples/` directory
4. **Verify setup**: `python main.py --help`

---

**Happy Scanning! 🔍✨** 