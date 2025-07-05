# APK Security Testing Tool

A comprehensive Android APK security testing tool with enhanced static analysis capabilities, designed to identify security vulnerabilities, misconfigurations, and compliance issues in Android applications.

## Features

### 🔍 Enhanced Static Analysis
- **Deep Manifest Analysis**: Comprehensive analysis of AndroidManifest.xml
- **Permission Analysis**: Detection of dangerous and signature permissions
- **Component Security**: Analysis of exported components and their protection
- **Intent Filter Analysis**: Deep link and intent filter security assessment
- **Backup Configuration**: Analysis of backup settings and security implications
- **WebView Security**: Detection of WebView usage and security misconfigurations
- **Third-Party Libraries**: Identification of vulnerable and outdated libraries
- **Code Pattern Analysis**: Detection of security anti-patterns in code

### 🚨 Security Vulnerability Detection
- **Hardcoded Secrets**: Detection of API keys, passwords, and tokens in code
- **Insecure Cryptography**: Identification of weak cryptographic algorithms
- **SQL Injection Patterns**: Detection of potential SQL injection vulnerabilities
- **Path Traversal**: Identification of path traversal vulnerabilities
- **Command Injection**: Detection of command execution patterns
- **Unprotected Deep Links**: Analysis of deep link security
- **Export Component Vulnerabilities**: Detection of unprotected exported components

### 📊 Comprehensive Reporting
- **Risk Scoring**: Automated risk assessment (0-100 scale)
- **Severity Classification**: Critical, High, Medium, Low, Info
- **Detailed Findings**: Specific vulnerability details with file locations
- **Recommendations**: Actionable security improvement suggestions
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
python src/mobile_security_tester.py --help
```

## Usage

### Basic APK Analysis
```bash
# Analyze a single APK file
python examples/apk_security_test.py path/to/app.apk

# Enable debug mode for detailed output
python examples/apk_security_test.py path/to/app.apk --debug

# Save results to specific file
python examples/apk_security_test.py path/to/app.apk -o results.json
```

### Comprehensive APK Testing
```bash
# Run comprehensive analysis with detailed output
python examples/apk_comprehensive_test.py
```

### Using the Main Tool
```bash
# Analyze APK with all analyzers
python src/mobile_security_tester.py --apk path/to/app.apk --static --code --storage --network

# Generate detailed report
python src/mobile_security_tester.py --apk path/to/app.apk --report --output report.json
```

## Security Checks

### 1. Manifest Analysis
- **Package Information**: Version, SDK levels, package name
- **Application Attributes**: Debuggable, backup, cleartext traffic settings
- **Permission Analysis**: Dangerous and signature permission detection
- **Component Security**: Exported components and their protection

### 2. Deep Link Security
- **Scheme Analysis**: Custom URL schemes and their security
- **Host Validation**: Deep link host security assessment
- **Component Protection**: Deep link component security
- **Intent Filter Analysis**: Intent filter security configuration

### 3. Backup Configuration
- **Backup Settings**: Analysis of backup enablement
- **Backup Rules**: Custom backup rule assessment
- **Data Exposure**: Potential sensitive data exposure through backup

### 4. WebView Security
- **Usage Detection**: WebView component identification
- **Configuration Analysis**: Security settings assessment
- **JavaScript Security**: JavaScript enablement and security
- **File Access**: File access permission analysis

### 5. Third-Party Libraries
- **Library Detection**: Identification of third-party libraries
- **Version Analysis**: Library version assessment
- **Vulnerability Check**: Known vulnerability detection
- **Update Recommendations**: Security update suggestions

### 6. Code Security
- **Hardcoded Secrets**: API keys, passwords, tokens
- **Insecure Crypto**: MD5, SHA1, DES, RC4 usage
- **SQL Injection**: Raw query and string formatting patterns
- **Path Traversal**: Directory traversal patterns
- **Command Injection**: Runtime execution patterns

## Output Format

### JSON Report Structure
```json
{
  "file_info": {
    "file_path": "path/to/app.apk",
    "file_size": 1234567,
    "file_type": "APK",
    "total_files": 150
  },
  "manifest_analysis": {
    "package": "com.example.app",
    "version_code": "1",
    "version_name": "1.0.0",
    "min_sdk": "21",
    "target_sdk": "30"
  },
  "deep_analysis": {
    "application_attributes": {
      "debuggable": "false",
      "allowBackup": "true",
      "usesCleartextTraffic": "false"
    },
    "exported_components": [],
    "security_issues": []
  },
  "permissions": [
    {
      "name": "android.permission.INTERNET",
      "severity": "low",
      "description": "Internet access permission"
    }
  ],
  "vulnerabilities": [
    {
      "type": "backup_enabled",
      "severity": "medium",
      "description": "Application backup is enabled",
      "risk": "Sensitive data may be exposed through backup"
    }
  ],
  "security_summary": {
    "total_vulnerabilities": 5,
    "high_severity": 2,
    "medium_severity": 2,
    "low_severity": 1,
    "risk_score": 45,
    "overall_security_status": "Medium"
  },
  "recommendations": [
    "Disable backup or implement proper backup encryption",
    "Review and minimize dangerous permissions"
  ]
}
```

## Security Risk Scoring

The tool calculates a risk score from 0-100 based on:

- **Critical Issues**: 25 points each
- **High Severity**: 15 points each
- **Medium Severity**: 8 points each
- **Low Severity**: 3 points each
- **Info Severity**: 1 point each

### Risk Levels
- **0-19**: Good
- **20-39**: Low
- **40-59**: Medium
- **60-79**: High
- **80-100**: Critical

## Examples

### Example 1: Basic APK Analysis
```bash
python examples/apk_security_test.py sample.apk
```

Output:
```
============================================================
APK SECURITY ANALYSIS SUMMARY
============================================================
Overall Security Status: Medium
Risk Score: 45/100
Total Vulnerabilities: 5

Vulnerabilities by Severity:
  HIGH: 2
  MEDIUM: 2
  LOW: 1

Critical Issues:
  1. Application is debuggable
  2. Unprotected deep link: myapp://example.com

High Severity Issues:
  1. Dangerous permission: android.permission.READ_CONTACTS
  2. Exported component without permission: com.example.MainActivity
```

### Example 2: Comprehensive Analysis
```bash
python examples/apk_comprehensive_test.py
```

This provides detailed analysis including:
- File information and structure
- Deep manifest analysis
- Permission categorization
- Intent filter analysis
- Deep link security assessment
- Backup configuration analysis
- WebView security analysis
- Third-party library assessment
- Code pattern analysis
- Native library analysis
- Certificate analysis

## Debug Mode

Enable debug mode for detailed logging and analysis information:

```bash
python examples/apk_security_test.py app.apk --debug
```

Debug output includes:
- Detailed analysis steps
- File processing information
- Pattern matching results
- Error details and stack traces

## Configuration

### Customizing Security Checks
You can modify the security patterns in the static analyzer:

```python
# Add custom dangerous permissions
static_analyzer.dangerous_permissions.append("custom.permission.DANGEROUS")

# Add custom signature permissions
static_analyzer.signature_permissions.append("custom.permission.SIGNATURE")
```

### Custom Code Patterns
Extend the code pattern analysis with custom patterns:

```python
# Add custom security patterns
patterns = {
    "custom_vulnerability": [
        r'custom\.pattern\.vulnerable',
        r'another\.pattern\.issue'
    ]
}
```

## Best Practices

### For Security Analysts
1. **Always run with debug mode** for detailed analysis
2. **Review all findings** manually for false positives
3. **Validate vulnerabilities** with manual testing
4. **Use multiple tools** for comprehensive assessment
5. **Keep tools updated** for latest vulnerability databases

### For Developers
1. **Run analysis regularly** during development
2. **Address high/critical issues** before release
3. **Review permissions** and minimize access
4. **Implement secure coding practices**
5. **Use secure storage** for sensitive data

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
   - Ensure all analyzers are enabled
   - Check debug output for analysis steps
   - Verify APK structure and content

### Performance Optimization
- Use specific analyzers instead of all analyzers
- Process large APKs in smaller chunks
- Use SSD storage for better I/O performance

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your enhancements
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