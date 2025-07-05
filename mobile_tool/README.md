# Mobile Security Testing Tool

A comprehensive automated mobile client-side security testing tool similar to Drozer and MobSF, designed to perform security analysis of Android and iOS applications.

## 🚀 Features

### Core Security Testing
- **Static Analysis**: APK/IPA file analysis, manifest inspection, permission analysis (100+ security checks)
- **Dynamic Analysis**: Runtime behavior monitoring, network traffic analysis, device analysis
- **Code Analysis**: Source code review, vulnerability scanning, pattern detection
- **Network Analysis**: SSL/TLS testing, certificate pinning, API endpoint analysis
- **Storage Analysis**: Local storage analysis, sensitive data detection, cache analysis
- **Configuration Analysis**: Security settings, encryption implementation

### Advanced Capabilities
- **Automated Exploitation**: Proof-of-concept exploit generation
- **Reverse Engineering**: APK/IPA decompilation and analysis
- **Network Security**: SSL/TLS testing, certificate pinning bypass
- **Input Validation**: Fuzzing, injection testing
- **Session Management**: Token analysis, session hijacking tests
- **Cryptography**: Encryption algorithm analysis, key management

## 📋 Requirements

### System Requirements
- Python 3.8+
- Java 8+ (for APK analysis)
- Android SDK Platform Tools (for dynamic analysis)
- Android device or emulator (for dynamic analysis)

### Dependencies
```bash
pip install -r requirements.txt
```

## 🛠️ Installation

### Quick Start
```bash
# Navigate to the mobile tool directory
cd mobile_tool

# Install dependencies
pip install -r requirements.txt

# Test installation
python src/mobile_security_tester.py --help
```

### Advanced Setup
```bash
# Install additional tools for APK analysis
sudo apt-get install apktool dex2jar jadx
# or for macOS
brew install apktool dex2jar jadx

# For dynamic analysis, install Android SDK Platform Tools
# Download from: https://developer.android.com/studio/releases/platform-tools
# Add to PATH: export PATH=$PATH:/path/to/platform-tools
```

## 📖 Usage

### Basic Usage

#### Quick Security Analysis
```bash
# Basic analysis of an APK file
python src/mobile_security_tester.py app.apk

# With debug output
python src/mobile_security_tester.py app.apk --debug

# Save results to file
python src/mobile_security_tester.py app.apk --output results.json
```

#### Comprehensive Analysis
```bash
# Full security audit
python src/mobile_security_tester.py app.apk --analysis-type comprehensive

# With all output formats
python src/mobile_security_tester.py app.apk \
    --analysis-type comprehensive \
    --output results.json \
    --report report.html \
    --csv results.csv
```

### Specialized Analysis Types

#### Static Analysis Only
```bash
python src/mobile_security_tester.py app.apk --analysis-type static
```

#### Dynamic Analysis (requires connected device)
```bash
python src/mobile_security_tester.py app.apk --analysis-type dynamic
```

#### Network Analysis
```bash
python src/mobile_security_tester.py app.apk --analysis-type network
```

#### Storage Analysis
```bash
python src/mobile_security_tester.py app.apk --analysis-type storage
```

### Using Example Scripts

#### Basic Security Assessment
```bash
# Quick overview
python examples/basic_analysis.py app.apk

# With debug
python examples/basic_analysis.py app.apk --debug
```

#### Comprehensive Security Audit
```bash
# Full assessment
python examples/comprehensive_analysis.py app.apk --output audit_report.json

# With detailed analysis
python examples/comprehensive_analysis.py app.apk --detailed --output audit_report.json
```

#### APK-Specific Testing
```bash
# Deep APK analysis
python examples/apk_security_test.py app.apk --detailed

# Comprehensive APK assessment
python examples/apk_comprehensive_test.py app.apk --output apk_report.json
```

#### Storage Security Analysis
```bash
python examples/storage_security_test.py app.apk --scan-storage
```

#### Network Security Analysis
```bash
python examples/network_security_test.py app.apk --analyze-network
```

#### Dynamic Analysis (requires device)
```bash
# Analyze APK on device
python examples/dynamic_analysis_test.py app.apk

# Analyze connected device
python examples/dynamic_analysis_test.py dummy.apk --device

# Analyze specific app on device
python examples/dynamic_analysis_test.py dummy.apk --device --package com.example.app
```

### Batch Processing

```bash
# Analyze multiple APKs
python examples/batch_analysis.py /path/to/apk/directory/

# With parallel processing
python examples/batch_analysis.py /path/to/apk/directory/ --parallel --max-workers 4

# With summary report
python examples/batch_analysis.py /path/to/apk/directory/ --output batch_results.json --summary summary.txt
```

### Debug and Troubleshooting

```bash
# Enable debug mode
python src/mobile_security_tester.py app.apk --debug

# Debug specific components
python examples/debug_test.py app.apk --debug --component static

# Custom log level
python examples/debug_test.py app.apk --debug --log-level DEBUG
```

### Output Formats

#### JSON Output
```bash
python src/mobile_security_tester.py app.apk --output results.json
```

#### HTML Report
```bash
python src/mobile_security_tester.py app.apk --report report.html
```

#### CSV Output
```bash
python src/mobile_security_tester.py app.apk --csv results.csv
```

#### Multiple Formats
```bash
python src/mobile_security_tester.py app.apk \
    --output results.json \
    --report report.html \
    --csv results.csv
```

### Advanced Usage

#### Focus on Specific Areas
```bash
# Focus on static and network analysis
python src/mobile_security_tester.py app.apk --focus static,network

# Focus on storage and dynamic analysis
python src/mobile_security_tester.py app.apk --focus storage,dynamic
```

#### Custom Configuration
```bash
# Use custom config file
python src/mobile_security_tester.py app.apk --config custom_config.json
```

## 🔍 Security Tests

### Static Analysis (100+ Checks)
- **Manifest Analysis**: Permission review, component analysis, intent filters
- **Code Review**: Vulnerability scanning, hardcoded secrets, injection patterns
- **Resource Analysis**: Asset inspection, configuration files, third-party libraries
- **Dependency Analysis**: Third-party library vulnerabilities, outdated components
- **Platform Security**: Android/iOS specific security checks

### Dynamic Analysis
- **Runtime Monitoring**: Behavior analysis, API calls, permission usage
- **Network Traffic**: HTTP/HTTPS analysis, API testing, traffic patterns
- **File System**: Data storage analysis, sensitive files, cache analysis
- **Memory Analysis**: Memory dumps, sensitive data in memory, memory leaks
- **Device Analysis**: Root detection, emulator detection, device security

### Network Security
- **SSL/TLS Testing**: Certificate validation, cipher analysis, certificate pinning
- **API Security**: Endpoint testing, authentication bypass, API vulnerabilities
- **Traffic Analysis**: Request/response inspection, traffic patterns
- **Proxy Testing**: Man-in-the-middle attack simulation

### Data Security
- **Storage Analysis**: Local database, shared preferences, secure storage
- **Encryption**: Algorithm analysis, key management, cryptographic weaknesses
- **Sensitive Data**: PII detection, credential storage, data leakage
- **Backup Analysis**: Backup file security, data exposure

## 📊 Report Generation

### Report Formats
- **JSON**: Machine-readable format for integration
- **HTML**: Human-readable format with visualizations
- **CSV**: Data export for analysis

### Report Sections
- **Executive Summary**: High-level findings and risk assessment
- **Detailed Analysis**: Comprehensive test results
- **Vulnerabilities**: Categorized security issues by severity
- **Recommendations**: Remediation guidance
- **Technical Details**: Deep-dive analysis with evidence

## 🛡️ Security Categories

### Critical Vulnerabilities
- **Code Injection**: SQL injection, command injection, XSS
- **Authentication Bypass**: Weak authentication, session management
- **Data Exposure**: Sensitive data leakage, insecure storage
- **Network Vulnerabilities**: Man-in-the-middle, SSL/TLS issues

### High Severity
- **Input Validation**: Missing validation, injection vulnerabilities
- **Authorization Issues**: Privilege escalation, access control
- **Cryptographic Weaknesses**: Weak algorithms, poor key management
- **Configuration Issues**: Security misconfigurations

### Medium Severity
- **Information Disclosure**: Error messages, debug information
- **Session Management**: Weak session handling
- **Logging Issues**: Sensitive data in logs
- **Backup Vulnerabilities**: Insecure backup files

### Low Severity
- **Code Quality**: Best practice violations
- **Performance Issues**: Resource consumption
- **Documentation**: Missing security documentation

## 🧪 Real-World Examples

### Scenario 1: Quick Security Check
```bash
# For a quick security overview
python examples/basic_analysis.py my_app.apk --output quick_check.json
```

### Scenario 2: Compliance Audit
```bash
# For detailed compliance assessment
python examples/comprehensive_analysis.py my_app.apk \
    --detailed \
    --output compliance_audit.json \
    --report compliance_report.html
```

### Scenario 3: Development Testing
```bash
# For development security testing
python examples/apk_security_test.py my_app.apk --detailed --debug
```

### Scenario 4: Production Security Review
```bash
# For production security assessment
python examples/comprehensive_analysis.py my_app.apk \
    --analysis-type comprehensive \
    --output production_security.json \
    --report production_report.html \
    --csv production_data.csv
```

## 🔧 Configuration

### Configuration File
Create `config.json` for custom settings:
```json
{
  "analysis": {
    "static": true,
    "dynamic": false,
    "network": true,
    "storage": true
  },
  "output": {
    "json": true,
    "html": true,
    "csv": false
  },
  "debug": {
    "enabled": false,
    "level": "INFO"
  }
}
```

### Environment Variables
```bash
export DEBUG_LEVEL=DEBUG
export OUTPUT_DIR=./reports
```

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [Vulnerabilities Reference](docs/VULNERABILITIES.md)
- [API Reference](docs/API_REFERENCE.md)
- [Debug Guide](docs/DEBUG_GUIDE.md)
- [Dynamic Analysis Guide](docs/DYNAMIC_ANALYSIS.md)
- [Examples Guide](examples/README.md)

## 🛠️ Prerequisites for Dynamic Analysis

For dynamic analysis, you need:
- Android device or emulator
- USB debugging enabled
- ADB installed and configured
- Device connected and authorized

```bash
# Check device connection
adb devices

# Should show something like:
# List of devices attached
# 12345678    device
```

## ⚠️ Troubleshooting

### Common Issues

#### Import Errors
```bash
# Make sure you're in the right directory
cd mobile_tool
python src/mobile_security_tester.py app.apk
```

#### APK Not Found
```bash
# Check file path and permissions
ls -la app.apk
```

#### Device Connection Issues
```bash
# Check ADB connection
adb devices

# Restart ADB if needed
adb kill-server
adb start-server
```

#### Permission Errors
```bash
# Check file permissions and output directory access
chmod +x src/mobile_security_tester.py
mkdir -p reports
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any application. The authors are not responsible for any misuse of this tool. 