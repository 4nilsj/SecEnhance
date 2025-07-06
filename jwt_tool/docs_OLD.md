# JWT Security Testing Tool Guide

A comprehensive guide for using the JWT Security Testing Tool to analyze and test JSON Web Token security.

## 🔑 Overview

The JWT Security Testing Tool is designed to help Application Security Engineers identify vulnerabilities in JWT implementations. It performs comprehensive security analysis including algorithm confusion attacks, signature verification, claim validation, and more.

## 🚀 Quick Start

### Installation

1. **Install dependencies:**
   ```bash
   pip install pyjwt cryptography
   ```

2. **Run the tool:**
   ```bash
   python src/jwt_security_tester.py --token "your.jwt.token"
   ```

### Basic Usage

#### Test a Single Token
```bash
# Test with a JWT token
python src/jwt_security_tester.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Test with a secret for signature verification
python src/jwt_security_tester.py --token "your.token" --secret "your-secret"
```

#### Test Multiple Tokens
```bash
# Test tokens from a file (one per line)
python src/jwt_security_tester.py --file tokens.txt

# Generate a report
python src/jwt_security_tester.py --file tokens.txt --output report.json
```

#### Run Specific Tests
```bash
# Test only structure analysis
python src/jwt_security_tester.py --token "your.token" --test structure

# Test only algorithm confusion
python src/jwt_security_tester.py --token "your.token" --test algorithm

# Test only signature verification
python src/jwt_security_tester.py --token "your.token" --test signature --secret "your-secret"
```

#### Interactive Mode
```bash
# Run in interactive mode
python src/jwt_security_tester.py
```

## 🧪 Test Types

### 1. Structure Analysis
- **Purpose:** Analyze JWT token structure and basic information
- **Tests:**
  - Token length and format
  - Header analysis (algorithm, type)
  - Payload structure and claims
  - Timestamp validation (exp, iat, nbf)

### 2. Algorithm Confusion
- **Purpose:** Detect algorithm confusion vulnerabilities
- **Tests:**
  - Algorithm 'none' attack
  - Weak algorithm detection
  - Algorithm downgrade attacks

### 3. Signature Verification
- **Purpose:** Test signature strength and verification
- **Tests:**
  - Weak secret detection
  - Common secret brute force
  - Signature bypass attempts

### 4. Claim Validation
- **Purpose:** Validate JWT claims for security issues
- **Tests:**
  - Missing required claims (exp, iat, iss, aud)
  - Expired token detection
  - Future IAT detection
  - Sensitive data in payload

### 5. Token Tampering
- **Purpose:** Test for privilege escalation vulnerabilities
- **Tests:**
  - User ID modification
  - Role modification
  - Permission escalation

### 6. Replay Attack
- **Purpose:** Test replay attack protection
- **Tests:**
  - Missing JTI claim
  - Missing nonce
  - No expiration time

## 📊 Output and Reporting

### Console Output
The tool provides real-time feedback during testing:
```
🔒 JWT Security Testing Tool
==========================================
🔍 Analyzing JWT token structure...
🔄 Testing algorithm confusion attacks...
🔐 Testing signature verification...
📋 Testing claim validation...
🔧 Testing token tampering...
🔄 Testing replay attack scenarios...

📋 JWT Security Test Summary
==========================================
🔍 Total Vulnerabilities: 3
🚨 Critical: 1
⚠️ High: 1
🔶 Medium: 1
🔵 Low: 0
🎯 Overall Risk: Critical
```

### JSON Report
Detailed reports are generated in JSON format:
```json
{
  "jwt_security_report": {
    "title": "JWT Security Analysis Report",
    "generated_date": "2024-01-15T10:30:00",
    "summary": {
      "total_vulnerabilities": 3,
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "overall_risk": "Critical"
    },
    "detailed_results": {
      "structure_analysis": { ... },
      "algorithm_confusion": { ... },
      "signature_verification": { ... },
      "claim_validation": { ... },
      "token_tampering": { ... },
      "replay_attack": { ... }
    }
  },
  "recommendations": [
    "🚨 CRITICAL: Immediate action required for critical vulnerabilities",
    "🔐 Always verify JWT signatures",
    "⏰ Set appropriate expiration times"
  ]
}
```

## 🔍 Common Vulnerabilities

### 1. Algorithm 'None' Attack
**Description:** Using 'none' algorithm to bypass signature verification
**Risk Level:** Critical
**Detection:** Tool creates a token with 'none' algorithm
**Remediation:** Always verify signatures and reject 'none' algorithm

### 2. Weak Secrets
**Description:** Using easily guessable secrets
**Risk Level:** Critical
**Detection:** Brute force with common secrets
**Remediation:** Use strong, random secrets

### 3. Missing Expiration
**Description:** Tokens without expiration time
**Risk Level:** High
**Detection:** Missing 'exp' claim
**Remediation:** Always set expiration time

### 4. Sensitive Data in Payload
**Description:** Storing sensitive information in JWT payload
**Risk Level:** High
**Detection:** Sensitive field names in payload
**Remediation:** Never store sensitive data in JWT

### 5. Token Tampering
**Description:** Modifying claims to escalate privileges
**Risk Level:** Critical
**Detection:** Tool creates tampered tokens
**Remediation:** Validate permissions server-side

## 🛠️ Advanced Usage

### Custom Secret Lists
You can extend the tool to test with custom secret lists:
```python
# Modify the load_common_secrets method in jwt_security_tester.py
def load_common_secrets(self):
    self.secrets_to_try = [
        "your-custom-secret",
        "another-secret",
        # Add more secrets...
    ]
```

### Integration with CI/CD
```yaml
# Example GitHub Actions workflow
name: JWT Security Test
on: [push, pull_request]
jobs:
  jwt-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.8
    - name: Install dependencies
      run: pip install pyjwt cryptography
    - name: Run JWT security test
      run: python src/jwt_security_tester.py --file tokens.txt --output report.json
    - name: Check for critical vulnerabilities
      run: |
        if grep -q '"critical": [1-9]' report.json; then
          echo "Critical vulnerabilities found!"
          exit 1
        fi
```

### Automated Testing
```python
# Example script for automated testing
from src.jwt_security_tester import JWTSecurityTester

def test_jwt_tokens(tokens_file):
    tester = JWTSecurityTester()
    
    with open(tokens_file, 'r') as f:
        tokens = [line.strip() for line in f if line.strip()]
    
    for token in tokens:
        results = tester.comprehensive_test(token)
        if results['summary']['critical'] > 0:
            print(f"Critical vulnerability found in token: {token[:20]}...")
            return False
    
    return True
```

## 📚 Best Practices

### 1. Regular Testing
- Test JWT tokens regularly in your applications
- Include JWT testing in your security testing pipeline
- Test both development and production tokens

### 2. Comprehensive Coverage
- Test all JWT endpoints in your application
- Test different user roles and permissions
- Test edge cases and error conditions

### 3. Secure Implementation
- Use strong algorithms (RS256, ES256)
- Set appropriate expiration times
- Include all required claims
- Validate permissions server-side

### 4. Monitoring and Alerting
- Monitor for JWT-related security events
- Set up alerts for suspicious JWT activity
- Log JWT validation failures

## 🔧 Troubleshooting

### Common Issues

1. **Import Error: No module named 'jwt'**
   ```bash
   pip install pyjwt
   ```

2. **Invalid Token Format**
   - Ensure the token is a valid JWT format
   - Check for proper base64 encoding

3. **Permission Denied**
   - Ensure you have write permissions for report files
   - Check file paths and permissions

### Debug Mode
Add debug output to see detailed information:
```python
# Modify the tool to add debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📖 Additional Resources

- [JWT.io](https://jwt.io/) - JWT debugger and documentation
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html)
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT specification
- [JWT Security Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This tool is provided as-is for educational and authorized security testing purposes. Users are responsible for ensuring they have proper authorization before using this tool.

## ⚠️ Disclaimer

This tool is designed for authorized security testing only. Users must ensure they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool. 