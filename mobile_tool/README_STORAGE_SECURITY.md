# Storage Security Testing Tool

A comprehensive Android APK storage security testing tool with enhanced analysis capabilities, designed to identify storage vulnerabilities, data leakage, and encryption implementation issues in Android applications.

## Features

### 🔐 Secure Storage Analysis
- **Android Keystore Detection**: Analysis of Android Keystore usage for secure key storage
- **Secure Storage Patterns**: Detection of secure storage implementation patterns
- **Insecure Storage Patterns**: Identification of insecure storage implementations
- **Encryption Implementation**: Analysis of encryption methods and algorithms
- **Key Management**: Assessment of cryptographic key management practices

### 🔍 Data Leakage Detection
- **Sensitive Data Logging**: Detection of sensitive data being logged to system logs
- **Data Leakage Patterns**: Identification of patterns that may lead to data exposure
- **Log Analysis**: Analysis of logging practices for security implications
- **PII Detection**: Detection of Personally Identifiable Information in logs
- **Credential Exposure**: Identification of credential logging patterns

### 💾 Storage Configuration Analysis
- **Backup Configuration**: Analysis of backup settings and security implications
- **External Storage Usage**: Detection of external storage usage and permissions
- **Cache Storage Analysis**: Assessment of cache storage security
- **Database Security**: Analysis of database encryption and security
- **SharedPreferences Security**: Assessment of SharedPreferences encryption

### 📊 Comprehensive Reporting
- **Storage Security Score**: Automated scoring (0-100) based on security posture
- **Vulnerability Classification**: Critical, High, Medium, Low, Info severity levels
- **Detailed Findings**: Specific storage security issues with file locations
- **Actionable Recommendations**: Security improvement suggestions
- **JSON Export**: Detailed results for further analysis

## Installation

### Prerequisites
- Python 3.7+
- Required Python packages (see requirements.txt)

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd mobile_tool

# Install dependencies
pip install -r requirements.txt

# Verify installation
python examples/storage_security_test.py
```

## Usage

### Basic Storage Security Analysis
```bash
# Analyze storage security of an APK
python examples/storage_security_test.py

# The tool will prompt for APK path and provide comprehensive analysis
```

### Using the Main Tool
```bash
# Analyze APK with storage analyzer
python src/mobile_security_tester.py --apk path/to/app.apk --storage

# Generate detailed storage report
python src/mobile_security_tester.py --apk path/to/app.apk --storage --report --output storage_report.json
```

## Storage Security Checks

### 1. Secure Storage Analysis
- **Android Keystore Usage**: Detection of Android Keystore implementation
- **Secure Storage Patterns**: 
  - `android.security.keystore.KeyStore`
  - `android.security.keystore.KeyGenParameterSpec`
  - `android.security.keystore.KeyProperties`
  - `javax.crypto.Cipher`
  - `javax.crypto.KeyGenerator`
  - `javax.crypto.SecretKey`

- **Insecure Storage Patterns**:
  - `SharedPreferences.edit()`
  - `getSharedPreferences`
  - `openFileOutput`
  - `openFileInput`
  - `FileOutputStream`
  - `FileInputStream`
  - `SQLiteDatabase.openOrCreateDatabase`

### 2. Data Leakage Detection
- **Sensitive Data Logging Patterns**:
  - `Log.d(password)`
  - `Log.v(token)`
  - `Log.i(api_key)`
  - `Log.w(secret)`
  - `System.out.println(password)`
  - `System.err.println(token)`

- **Sensitive Keywords Detection**:
  - password, token, api_key, secret, key, credential

### 3. External Storage Analysis
- **External Storage Permissions**:
  - `android.permission.READ_EXTERNAL_STORAGE`
  - `android.permission.WRITE_EXTERNAL_STORAGE`
  - `android.permission.MANAGE_EXTERNAL_STORAGE`

- **External Storage Operations**:
  - `Environment.getExternalStorageDirectory`
  - `Environment.getExternalStoragePublicDirectory`
  - `getExternalFilesDir`
  - `getExternalCacheDir`
  - `getExternalMediaDirs`

### 4. Cache Storage Analysis
- **Cache Operations**:
  - `getCacheDir`
  - `getExternalCacheDir`
  - `context.getCacheDir`
  - `context.getExternalCacheDir`
  - `File.createTempFile`

- **Sensitive Data in Cache**:
  - Detection of sensitive data patterns in cache operations

### 5. Database Security
- **Database Encryption**: Analysis of SQLite database encryption
- **Database Operations**: Detection of database creation and access patterns
- **Sensitive Data Storage**: Identification of sensitive data in databases

### 6. SharedPreferences Security
- **Encryption Status**: Analysis of SharedPreferences encryption
- **Sensitive Data**: Detection of sensitive data in SharedPreferences
- **Security Patterns**: Identification of secure SharedPreferences usage

### 7. File Storage Security
- **File Encryption**: Analysis of file storage encryption
- **File Operations**: Detection of file I/O operations
- **Security Patterns**: Identification of secure file storage patterns

## Output Format

### JSON Report Structure
```json
{
  "storage_config": {
    "backup_enabled": false,
    "allow_backup": true,
    "full_backup_content": false,
    "external_storage": false
  },
  "secure_storage_analysis": {
    "keystore_usage": true,
    "secure_storage_patterns": [
      {
        "file": "MainActivity.java",
        "pattern": "android.security.keystore.KeyStore",
        "usage": "Secure storage implementation detected"
      }
    ],
    "insecure_storage_patterns": [],
    "security_issues": []
  },
  "data_leakage_analysis": {
    "leakage_patterns": [],
    "sensitive_data_logging": [],
    "security_issues": []
  },
  "external_storage_analysis": {
    "external_storage_usage": false,
    "storage_permissions": [],
    "file_operations": [],
    "security_issues": []
  },
  "cache_analysis": {
    "cache_usage": true,
    "cache_operations": [],
    "sensitive_data_in_cache": [],
    "security_issues": []
  },
  "databases": [
    {
      "name": "user_data.db",
      "encrypted": true,
      "tables": ["users", "sessions"]
    }
  ],
  "shared_preferences": [
    {
      "name": "app_settings",
      "encrypted": false,
      "keys": ["theme", "language"]
    }
  ],
  "file_storage": [
    {
      "name": "config.json",
      "encrypted": true,
      "type": "configuration"
    }
  ],
  "vulnerabilities": [
    {
      "type": "No Secure Storage",
      "severity": "high",
      "description": "No Android Keystore usage detected",
      "recommendation": "Implement Android Keystore for secure key storage"
    }
  ],
  "security_issues": [],
  "recommendations": [
    "Implement Android Keystore for secure key storage",
    "Use encryption for all sensitive data"
  ]
}
```

## Storage Security Scoring

The tool calculates a storage security score from 0-100 based on:

- **Critical Issues**: 25 points each
- **High Severity**: 15 points each
- **Medium Severity**: 8 points each
- **Low Severity**: 3 points each
- **Info Severity**: 1 point each

### Security Score Levels
- **80-100**: Excellent
- **60-79**: Good
- **40-59**: Fair
- **20-39**: Poor
- **0-19**: Critical

## Examples

### Example 1: Storage Security Analysis
```bash
python examples/storage_security_test.py
```

Output:
```
================================================================================
COMPREHENSIVE STORAGE SECURITY ANALYSIS
================================================================================
Analyzing APK: sample.apk
Debug mode: Enabled
--------------------------------------------------------------------------------
Analysis completed in 2.45 seconds
--------------------------------------------------------------------------------

📁 STORAGE CONFIGURATION
----------------------------------------
Backup Enabled: ❌ Yes
Allow Backup: ❌ Yes
Full Backup Content: ✅ No
External Storage: ✅ No

🔐 SECURE STORAGE ANALYSIS
----------------------------------------
Android Keystore Usage: ❌ No
Secure Storage Patterns: 0
Insecure Storage Patterns: 5

🚨 Insecure Storage Patterns:
  • MainActivity.java: SharedPreferences.edit()
  • DatabaseHelper.java: SQLiteDatabase.openOrCreateDatabase
  • FileManager.java: FileOutputStream

🔍 DATA LEAKAGE ANALYSIS
----------------------------------------
Data Leakage Patterns: 2
Sensitive Data Logging: 1

🚨 Data Leakage Patterns:
  • LoginActivity.java: Log.d("password", userPassword)
  • ApiManager.java: System.out.println("token: " + apiToken)

💾 EXTERNAL STORAGE ANALYSIS
----------------------------------------
External Storage Usage: ✅ No
Storage Permissions: 0
File Operations: 0

🗂️  CACHE ANALYSIS
----------------------------------------
Cache Usage: ⚠️  Yes
Cache Operations: 3
Sensitive Data in Cache: 0

🗄️  DATABASE ANALYSIS
----------------------------------------
Total Databases: 2
Encrypted Databases: 0
Unencrypted Databases: 2

Database Details:
  • user_data.db: ❌ Unencrypted
  • app_cache.db: ❌ Unencrypted

🚨 STORAGE VULNERABILITIES
----------------------------------------
Total Vulnerabilities: 8
Security Issues: 0

Vulnerabilities by Severity:
  HIGH: 3
  MEDIUM: 4
  LOW: 1

🚨 Critical Vulnerabilities:
  • No Android Keystore usage detected
  • Found 2 data leakage patterns
  • Found 1 instances of sensitive data in cache

Storage Security Score: 35/100
Storage Security Status: 🚨 POOR
```

## Security Best Practices

### For Secure Storage Implementation
1. **Use Android Keystore**: Implement Android Keystore for secure key storage
2. **Encrypt Sensitive Data**: Encrypt all sensitive data before storage
3. **Use Internal Storage**: Store sensitive data in internal storage
4. **Implement Secure Backup**: Use encrypted backup or disable backup for sensitive data
5. **Secure Logging**: Avoid logging sensitive information

### For Data Protection
1. **Avoid External Storage**: Don't store sensitive data on external storage
2. **Encrypt Databases**: Use SQLCipher or similar for database encryption
3. **Secure SharedPreferences**: Use EncryptedSharedPreferences for sensitive data
4. **Clear Cache**: Regularly clear cache and avoid storing sensitive data in cache
5. **Implement Secure Deletion**: Use secure deletion methods for sensitive data

### For Development
1. **Code Review**: Regularly review storage-related code
2. **Security Testing**: Include storage security in testing
3. **Dependency Management**: Keep security libraries updated
4. **Documentation**: Document storage security practices
5. **Training**: Train developers on secure storage practices

## Troubleshooting

### Common Issues

1. **APK file not found**
   - Verify file path and permissions
   - Check file extension (.apk)

2. **Analysis errors**
   - Enable debug mode for detailed error information
   - Check APK file integrity
   - Verify Python dependencies

3. **Missing vulnerabilities**
   - Ensure storage analyzer is enabled
   - Check debug output for analysis steps
   - Verify APK structure and content

### Performance Optimization
- Process large APKs in smaller chunks
- Use SSD storage for better I/O performance
- Enable specific analyzers instead of all analyzers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your storage security enhancements
4. Update documentation
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the repository
- Check the documentation
- Review debug output for troubleshooting

## Disclaimer

This tool is for educational and security testing purposes only. Always obtain proper authorization before testing applications you don't own. The authors are not responsible for any misuse of this tool. 