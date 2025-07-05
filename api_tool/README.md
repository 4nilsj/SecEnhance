# API Security Testing Tool

A comprehensive API security testing tool designed for senior AppSec engineers. Supports REST APIs, GraphQL, authentication bypass, business logic testing, and advanced fuzzing capabilities.

## 🚀 Features

### **REST API Security Testing**
- **Authentication Bypass**: Test various authentication mechanisms
- **Authorization Testing**: Role-based access control validation
- **Input Validation**: Parameter tampering and injection testing
- **Business Logic**: Workflow bypass and logic flaws
- **Rate Limiting**: Bypass techniques and abuse testing
- **OpenAPI Analysis**: Specification-based security testing

### **GraphQL Security Testing**
- **Introspection**: Information disclosure testing
- **Query Injection**: GraphQL-specific injection attacks
- **Depth Limiting**: Nested query abuse testing
- **Field Suggestions**: Information leakage testing
- **Batch Queries**: Query batching security analysis

### **Advanced Fuzzing**
- **Parameter Fuzzing**: Intelligent input mutation
- **Header Fuzzing**: HTTP header manipulation
- **Payload Fuzzing**: Request body manipulation
- **Boundary Testing**: Edge case and limit testing
- **Schema-based Fuzzing**: Structure-aware testing

### **Enterprise Features**
- **Batch Processing**: Multiple API analysis
- **Comprehensive Reporting**: Multiple output formats
- **Debug Mode**: Detailed logging and troubleshooting
- **Configuration Management**: YAML/JSON configuration
- **Integration Ready**: CI/CD pipeline integration

## 📋 Requirements

- Python 3.8+
- Network access to target APIs
- Optional: OpenAPI specifications
- Optional: GraphQL schemas

## 🛠️ Installation

```bash
# Clone the repository
git clone <repository-url>
cd api_tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Quick Start

### **REST API Testing**
```bash
# Basic REST API analysis
python src/api_security_tester.py --rest https://api.example.com

# With OpenAPI specification
python src/api_security_tester.py --rest https://api.example.com --openapi swagger.json

# Specific tests only
python src/api_security_tester.py --rest https://api.example.com --tests authentication,business_logic

# Debug mode
python src/api_security_tester.py --rest https://api.example.com --debug
```

### **GraphQL Testing**
```bash
# GraphQL endpoint analysis
python src/api_security_tester.py --graphql https://api.example.com/graphql

# With schema file
python src/api_security_tester.py --graphql https://api.example.com/graphql --schema schema.graphql

# Specific queries
python src/api_security_tester.py --graphql https://api.example.com/graphql --queries "query1,query2"
```

### **API Fuzzing**
```bash
# REST API fuzzing
python src/api_security_tester.py --fuzz https://api.example.com --api-type rest

# GraphQL fuzzing
python src/api_security_tester.py --fuzz https://api.example.com/graphql --api-type graphql

# Custom fuzzing configuration
python src/api_security_tester.py --fuzz https://api.example.com --fuzz-config fuzz_config.json
```

### **Batch Analysis**
```bash
# Analyze multiple APIs
python src/api_security_tester.py --batch apis.json --verbose
```

## 📊 Output Formats

The tool generates comprehensive reports in multiple formats:

- **JSON**: Machine-readable detailed results
- **HTML**: Interactive web-based reports
- **PDF**: Executive summary reports
- **CSV**: Spreadsheet-compatible data

## 🔧 Configuration

### **Configuration File Example**
```json
{
  "authentication": {
    "methods": ["bearer", "api_key", "oauth2"],
    "bypass_techniques": true
  },
  "fuzzing": {
    "iterations": 1000,
    "timeout": 30,
    "concurrent_requests": 10
  },
  "reporting": {
    "include_payloads": true,
    "include_headers": true,
    "risk_threshold": "medium"
  }
}
```

### **Batch Analysis File Example**
```json
[
  {
    "type": "rest",
    "url": "https://api1.example.com",
    "openapi_spec": "swagger1.json",
    "tests": ["authentication", "authorization"]
  },
  {
    "type": "graphql",
    "url": "https://api2.example.com/graphql",
    "schema": "schema2.graphql",
    "tests": ["introspection", "injection"]
  }
]
```

## 🎯 Advanced Usage

### **Custom Test Scenarios**
```python
from src.api_security_tester import APISecurityTester

# Initialize tester
tester = APISecurityTester(debug=True)

# Custom REST analysis
results = tester.analyze_rest_api(
    base_url="https://api.example.com",
    openapi_spec="swagger.json",
    endpoints=["/users", "/admin"],
    tests=["authentication", "business_logic"]
)

# Custom GraphQL analysis
results = tester.analyze_graphql(
    endpoint="https://api.example.com/graphql",
    schema="schema.graphql",
    tests=["introspection", "injection"]
)
```

### **Integration with CI/CD**
```yaml
# GitHub Actions example
- name: API Security Test
  run: |
    python src/api_security_tester.py \
      --rest ${{ secrets.API_URL }} \
      --tests authentication,authorization \
      --output api_security_report.json \
      --format json
```

## 🔍 Test Categories

### **Authentication Tests**
- Token validation bypass
- JWT manipulation
- API key exposure
- OAuth2 flow testing
- Session management

### **Authorization Tests**
- Role escalation
- Privilege bypass
- Resource access control
- API endpoint enumeration

### **Input Validation Tests**
- SQL injection
- NoSQL injection
- XSS in API responses
- Command injection
- Path traversal

### **Business Logic Tests**
- Workflow bypass
- State manipulation
- Race conditions
- Parameter pollution
- Mass assignment

### **Rate Limiting Tests**
- Bypass techniques
- Abuse detection
- Resource exhaustion
- Concurrent request testing

## 📈 Reporting

### **Executive Summary**
- Overall risk assessment
- Critical findings summary
- Compliance status
- Remediation priorities

### **Technical Details**
- Vulnerability descriptions
- Proof of concept payloads
- Affected endpoints
- Impact assessment

### **Remediation Guidance**
- Fix recommendations
- Code examples
- Security best practices
- Reference links

## 🛡️ Security Considerations

- **Legal Compliance**: Ensure you have authorization to test APIs
- **Rate Limiting**: Respect API rate limits during testing
- **Data Protection**: Avoid testing with production data
- **Environment Isolation**: Use staging/test environments
- **Reporting**: Report findings through proper channels

## 🔧 Troubleshooting

### **Common Issues**

**Connection Errors**
```bash
# Check network connectivity
curl -I https://api.example.com

# Verify SSL certificates
python -c "import requests; requests.get('https://api.example.com')"
```

**Authentication Issues**
```bash
# Test with debug mode
python src/api_security_tester.py --rest https://api.example.com --debug

# Check authentication headers
python -c "import requests; print(requests.get('https://api.example.com').headers)"
```

**Performance Issues**
```bash
# Reduce concurrent requests
python src/api_security_tester.py --rest https://api.example.com --config low_performance.json

# Use specific tests only
python src/api_security_tester.py --rest https://api.example.com --tests authentication
```

## 📚 Examples

See the `examples/` directory for:
- Sample API configurations
- Test scenario examples
- Integration examples
- Custom test cases

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check the docs/ directory
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always ensure you have proper authorization before testing any APIs. 