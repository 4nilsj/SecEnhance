# 🔧 Burp Automation Tool - Structure Cleanup Plan

## 🚨 Issues Found

### 1. **Duplicate Folders**
- ❌ `bambdas/` (duplicate of `bambda/`)
- ❌ `bchecks/custom_checks/` (empty)
- ❌ `bchecks/templates/` (empty)

### 2. **Missing Files**
- ❌ `bchecks/api/__init__.py` (missing)
- ❌ `bambda/api/__init__.py` (missing)

### 3. **Inconsistent Organization**
- ❌ Mixed file types in wrong locations
- ❌ Missing proper package structure

## ✅ Cleanup Actions Needed

### **Step 1: Remove Duplicate/Empty Folders**
```bash
# Remove duplicate bambdas folder
Remove-Item -Recurse -Force bambdas/

# Remove empty folders
Remove-Item -Recurse -Force bchecks/custom_checks/
Remove-Item -Recurse -Force bchecks/templates/
```

### **Step 2: Ensure Proper Structure**
```
burp_automation_tool/
├── bchecks/
│   ├── __init__.py
│   ├── bcheck_loader.py
│   ├── README.md
│   ├── web/
│   │   ├── __init__.py
│   │   ├── sql_injection_bcheck.py
│   │   ├── xss_bcheck.py
│   │   ├── ssrf_bcheck.py
│   │   ├── authentication_bypass_bcheck.py
│   │   └── comprehensive_security_bcheck.py
│   └── api/
│       ├── __init__.py
│       ├── graphql_injection_bcheck.py
│       └── rate_limiting_bypass_bcheck.py
├── bambda/
│   ├── web/
│   │   ├── __init__.py
│   │   └── xss_detection.bambda
│   └── api/
│       ├── __init__.py
│       └── graphql_security.bambda
└── [other folders...]
```

### **Step 3: Verify Structure**
- ✅ All BChecks properly organized
- ✅ All Bambda rules in correct locations
- ✅ Proper package structure with __init__.py files
- ✅ Clean, organized directory structure

## 🎯 Expected Result

After cleanup:
- **7 BChecks** properly organized (5 web + 2 API)
- **2 Bambda rules** properly organized (1 web + 1 API)
- **Clean structure** without duplicates or empty folders
- **Proper package structure** for Python imports
