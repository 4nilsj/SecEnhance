# Quick Start Guide - API Security Scanner

## 🚀 Get Scanning in 5 Minutes

### **Option 1: Script Method (Recommended for automation)**

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run a quick test scan
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://httpbin.org/get", "method": "GET"}]'

# 3. View results in terminal
```

### **Option 2: Web UI Method (Recommended for beginners)**

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start web interface
python main.py web

# 3. Open browser: http://localhost:5000

# 4. Click "Scan" tab and upload your collection or enter endpoints
```

---

## 📋 What You Need

- **Python 3.8+**
- **Your API endpoints** (or Postman collection)
- **5 minutes** of your time

---

## 🎯 Common Use Cases

### **Scan Your API Endpoints**
```bash
python run_api_scan.py --type endpoints --endpoints '[{"url": "https://your-api.com/users", "method": "GET"}]'
```

### **Scan Postman Collection**
```bash
python run_api_scan.py --type collection --collection my_collection.json
```

### **Scan Swagger/OpenAPI**
```bash
python run_api_scan.py --type swagger --swagger-url https://your-api.com/swagger.json
```

---

## 📊 What You'll Get

- ✅ **Security vulnerabilities** found
- 📄 **JSON and HTML reports**
- 🚨 **Detailed findings** with severity levels
- 🌐 **Web UI access** to view reports

---

## 🚨 Need Help?

- **Full instructions**: `docs/guides/SCANNING_INSTRUCTIONS.md`
- **Examples**: `examples/` directory
- **Web UI**: Start with `python main.py web`

---

**Ready to scan? Choose your method above! 🔍** 