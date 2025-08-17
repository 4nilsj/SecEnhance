# BChecks for Web Application Security

A comprehensive collection of custom Burp Suite BChecks for advanced web application security testing. These BChecks provide enhanced detection capabilities for various vulnerability types commonly found in modern web applications.

## 🚀 Features

### Available BChecks

1. **SQL Injection BCheck** (`sql_injection_bcheck.py`)
   - Boolean-based SQL injection detection
   - Time-based SQL injection detection
   - Error-based SQL injection detection
   - Union-based SQL injection detection
   - Advanced SQL error pattern recognition

2. **Cross-Site Scripting BCheck** (`xss_bcheck.py`)
   - Reflected XSS detection
   - Stored XSS detection
   - DOM-based XSS detection
   - Encoded XSS payloads
   - Bypass technique detection

3. **Server-Side Request Forgery BCheck** (`ssrf_bcheck.py`)
   - Local network SSRF detection
   - Cloud metadata endpoint testing
   - Internal service enumeration
   - SSRF bypass techniques
   - Response analysis for SSRF indicators

4. **Authentication Bypass BCheck** (`auth_bypass_bcheck.py`)
   - IDOR (Insecure Direct Object Reference) detection
   - JWT token tampering
   - Session manipulation
   - Header-based authentication bypass
   - Parameter pollution attacks

5. **Comprehensive Security BCheck** (`comprehensive_security_bcheck.py`)
   - Command injection detection
   - Path traversal detection
   - NoSQL injection detection
   - XXE (XML External Entity) injection
   - Template injection detection
   - LDAP injection detection
   - Open redirect detection
   - Rate limiting bypass detection

## 📋 Requirements

- **Burp Suite Professional** (latest version recommended)
- **Python 3.7+** (for BCheck loader and utilities)
- **Java Runtime Environment** (JRE) - included with Burp Suite

## 🛠️ Installation

### Method 1: Direct Installation

1. **Copy BCheck Files**
   ```bash
   # Copy individual BCheck files to your Burp Suite extensions directory
   cp bchecks/*.py /path/to/burp/extensions/
   ```

2. **Load in Burp Suite**
   - Open Burp Suite Professional
   - Go to **Extender** → **Extensions**
   - Click **Add**
   - Select **Python** as the extension type
   - Choose the BCheck file you want to load
   - Click **Next** and then **Close**

### Method 2: Using BCheck Loader

1. **Install the BCheck Loader**
   ```bash
   cd burp_automation_tool
   python bchecks/bcheck_loader.py
   ```

2. **Test BCheck Discovery**
   ```bash
   python -c "
   from bchecks.bcheck_loader import BCheckLoader
   loader = BCheckLoader()
   discovered = loader.discover_bchecks()
   print(f'Discovered BChecks: {discovered}')
   "
   ```

## 🔧 Configuration

### BCheck Configuration

Each BCheck can be configured by modifying the payload and pattern arrays within the respective files:

```python
# Example: Modifying SQL injection payloads
self.sql_payloads = {
    'boolean_based': [
        "' OR 1=1--",
        "' OR '1'='1",
        # Add your custom payloads here
    ]
}
```

### Global Configuration

Create a `bcheck_config.yaml` file for global settings:

```yaml
# bcheck_config.yaml
bchecks:
  sql_injection:
    enabled: true
    timeout: 10
    max_payloads: 50
  
  xss:
    enabled: true
    timeout: 5
    max_payloads: 30
  
  ssrf:
    enabled: true
    timeout: 15
    max_payloads: 20
```

## 📖 Usage

### Basic Usage

1. **Load a BCheck in Burp Suite**
   - Navigate to **Extender** → **Extensions**
   - Click **Add** → Select **Python**
   - Choose your BCheck file
   - Ensure the extension loads without errors

2. **Run Active Scanning**
   - Select your target in **Target** tab
   - Right-click → **Actively scan this host**
   - The BCheck will automatically run during scanning

3. **Review Results**
   - Check **Issues** tab for findings
   - Review detailed vulnerability reports
   - Export results as needed

### Advanced Usage

#### Custom Payload Development

```python
# Example: Adding custom SQL injection payloads
class CustomSQLInjectionCheck(SQLInjectionCheck):
    def __init__(self, callbacks, helpers):
        super().__init__(callbacks, helpers)
        
        # Add custom payloads
        self.sql_payloads['custom'] = [
            "'; DROP TABLE users--",
            "' UNION SELECT password FROM users--",
            # Your custom payloads
        ]
```

#### Integration with Burp Automation Tool

```python
from bchecks.bcheck_loader import BCheckLoader
from utils.report_generator import ReportGenerator

# Load BChecks
loader = BCheckLoader()
loaded_bchecks = loader.load_all_bchecks()

# Generate reports
report_gen = ReportGenerator()
# Add your findings to the report generator
```

## 🔍 BCheck Details

### SQL Injection BCheck

**Detection Methods:**
- **Boolean-based**: Detects SQL injection through boolean logic
- **Time-based**: Uses time delays to detect blind SQL injection
- **Error-based**: Analyzes SQL error messages in responses
- **Union-based**: Tests UNION-based SQL injection techniques

**Key Features:**
- 50+ SQL injection payloads
- Advanced error pattern recognition
- Context-aware payload selection
- False positive reduction

### XSS BCheck

**Detection Methods:**
- **Reflected XSS**: Detects XSS in reflected responses
- **Stored XSS**: Identifies stored XSS vulnerabilities
- **DOM-based XSS**: Detects client-side XSS

**Key Features:**
- 40+ XSS payloads including bypass techniques
- Encoded payload variants
- Context-aware detection
- Comprehensive pattern matching

### SSRF BCheck

**Detection Methods:**
- **Local Network**: Tests access to internal networks
- **Cloud Metadata**: Tests cloud provider metadata endpoints
- **Internal Services**: Enumerates internal services

**Key Features:**
- Cloud provider-specific payloads
- Internal service enumeration
- Response analysis for SSRF indicators
- Bypass technique detection

### Authentication Bypass BCheck

**Detection Methods:**
- **IDOR**: Tests for insecure direct object references
- **JWT Tampering**: Tests JWT token manipulation
- **Session Manipulation**: Tests session-based bypasses

**Key Features:**
- JWT signature bypass techniques
- Session ID enumeration
- Header manipulation tests
- Parameter pollution attacks

### Comprehensive Security BCheck

**Detection Methods:**
- **Command Injection**: Tests OS command injection
- **Path Traversal**: Tests directory traversal
- **NoSQL Injection**: Tests NoSQL database injection
- **XXE Injection**: Tests XML external entity injection

**Key Features:**
- Multi-vector attack testing
- Advanced bypass techniques
- Comprehensive error analysis
- Context-aware payload generation

## 🚨 Security Considerations

### Testing Environment

⚠️ **Important**: Always test these BChecks in a controlled environment:

1. **Use Test Applications**: Only test against applications you own or have permission to test
2. **Isolated Environment**: Use isolated testing environments
3. **Backup Data**: Always backup data before testing
4. **Legal Compliance**: Ensure compliance with applicable laws and regulations

### False Positives

These BChecks may generate false positives. Always:

1. **Verify Findings**: Manually verify all reported vulnerabilities
2. **Context Analysis**: Consider the application context
3. **Business Logic**: Understand the business logic before reporting issues

## 📊 Performance Optimization

### BCheck Performance Tips

1. **Limit Payload Count**: Reduce payload arrays for faster scanning
2. **Adjust Timeouts**: Increase timeouts for slow applications
3. **Selective Scanning**: Use scope rules to limit scanning
4. **Resource Monitoring**: Monitor system resources during scanning

### Configuration Optimization

```yaml
# Optimized configuration example
bchecks:
  sql_injection:
    max_payloads: 20  # Reduced from 50
    timeout: 5        # Reduced timeout
  
  xss:
    max_payloads: 15  # Reduced from 30
    timeout: 3        # Reduced timeout
```

## 🐛 Troubleshooting

### Common Issues

1. **BCheck Not Loading**
   - Verify Python version compatibility
   - Check file permissions
   - Review Burp Suite logs

2. **Import Errors**
   - Ensure all required modules are available
   - Check Python path configuration
   - Verify Burp Suite API availability

3. **Performance Issues**
   - Reduce payload counts
   - Increase timeouts
   - Use selective scanning

### Debug Mode

Enable debug logging in Burp Suite:

1. Go to **Extender** → **Extensions**
2. Select your BCheck
3. Check **Output** tab for detailed logs

## 📈 Reporting

### Integration with Report Generator

```python
from utils.report_generator import ReportGenerator, VulnerabilityReport

# Create report
report_gen = ReportGenerator()

# Add BCheck findings
vuln = VulnerabilityReport(
    title="SQL Injection Detected",
    description="SQL injection vulnerability found in login form",
    severity="High",
    cvss_score=8.5,
    evidence="Payload: ' OR 1=1--",
    recommendations=["Use parameterized queries", "Input validation"]
)

report_gen.add_vulnerability(vuln)
report_gen.generate_html_report()
```

### Export Formats

- **HTML**: Interactive web-based reports
- **JSON**: Machine-readable format
- **CSV**: Spreadsheet-compatible format
- **XML**: Structured data format

## 🤝 Contributing

### Adding New BChecks

1. **Create BCheck File**
   ```python
   # new_vulnerability_bcheck.py
   from burp import IBurpExtender, IScannerCheck, IScanIssue
   
   class BurpExtender(IBurpExtender):
       def registerExtenderCallbacks(self, callbacks):
           # Your implementation
           pass
   ```

2. **Follow Naming Convention**
   - Use descriptive names: `vulnerability_type_bcheck.py`
   - Include proper documentation
   - Add version and author information

3. **Test Thoroughly**
   - Test against known vulnerable applications
   - Verify false positive rates
   - Document any limitations

### Code Standards

- Follow PEP 8 style guidelines
- Include comprehensive docstrings
- Add type hints where appropriate
- Include error handling
- Add logging for debugging

## 📚 References

### Documentation
- [Burp Suite Extender API](https://portswigger.net/burp/extender/api/)
- [Burp Suite BCheck Documentation](https://portswigger.net/burp/documentation/desktop/extensions)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any applications. The authors are not responsible for any misuse of this tool.

---

**Happy Security Testing! 🔒**
