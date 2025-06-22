# API Security Scanner

A comprehensive API security scanning tool with web interface and CLI capabilities.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Required packages: `pip install -r requirements.txt`

### Running the Application

#### Web Interface (Recommended)
```bash
python main.py web
```
Access the web interface at: http://localhost:5000

#### CLI Mode
```bash
python main.py cli
```

## 📁 Project Structure

```
myproject/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── setup.py               # Package setup
├── README.md              # This file
├── .gitignore             # Git ignore rules
│
├── src/                   # Source code
│   ├── core/             # Core scanner functionality
│   ├── web/              # Web interface
│   ├── config/           # Configuration management
│   ├── utils/            # Utility functions
│   ├── scanners/         # Scanner implementations
│   ├── examples/         # Example usage
│   └── tests/            # Unit tests
│
├── tests/                # Integration and functional tests
│   ├── test_complete_scan.py
│   ├── test_misconfiguration_security.py
│   ├── test_swagger_openapi.py
│   └── ... (other test files)
│
├── demos/                # Demo scripts
│   └── demo_swagger_ui.py
│
├── examples/             # Example usage scripts
│   ├── simple_scan_demo.py
│   └── scan_vulnerable_api.py
│
├── tools/                # Utility tools
│   └── refresh_web_ui_reports.py
│
├── docs/                 # Documentation
│   ├── guides/           # User guides
│   │   ├── swagger_ui_guide.md
│   │   └── demo_delete_functionality.md
│   ├── reports/          # Report documentation
│   │   └── web_ui_reports_status.md
│   └── PROJECT_STRUCTURE.md
│
├── reports/              # Generated scan reports
├── logs/                 # Application logs
├── uploads/              # File uploads
├── data/                 # Test data
├── static/               # Static web assets
├── templates/            # Web templates
└── scripts/              # Additional scripts
```

## 🔧 Features

- **Comprehensive API Security Scanning**: Tests for OWASP Top 10 vulnerabilities
- **Multiple Input Formats**: Swagger/OpenAPI, Postman collections, direct endpoints
- **Web Interface**: User-friendly web UI with real-time scanning
- **CLI Support**: Command-line interface for automation
- **Report Generation**: JSON and HTML reports with detailed findings
- **Authentication Support**: Bearer tokens, API keys, Basic auth, OAuth2
- **Performance Optimization**: Configurable concurrency and timeouts

## 📊 Security Tests

The scanner performs comprehensive security tests including:

- **Injection Attacks**: SQL injection, NoSQL injection, Command injection
- **Authentication Bypass**: Missing authentication, weak authentication
- **Authorization Issues**: Missing authorization, privilege escalation
- **Information Disclosure**: Sensitive data exposure, error messages
- **Security Misconfigurations**: Missing security headers, CORS issues
- **Rate Limiting**: Missing or weak rate limiting
- **Input Validation**: Missing input validation, XSS vulnerabilities

## 🛠️ Usage Examples

### Basic Scan
```python
from src.core.api_security_scanner import APISecurityScanner

scanner = APISecurityScanner()
endpoints = [
    {'url': 'https://api.example.com/users', 'method': 'GET'},
    {'url': 'https://api.example.com/users', 'method': 'POST'}
]

results = scanner.scan_api_endpoints(endpoints)
```

### Collection Scan
```python
results = scanner.upload_and_scan_collection('postman_collection.json')
```

### Swagger/OpenAPI Scan
```python
results = scanner.scan_from_swagger_url('https://api.example.com/swagger.json')
```

## 📄 Reports

The scanner generates detailed reports in multiple formats:

- **JSON Reports**: Machine-readable format for integration
- **HTML Reports**: Human-readable format with visualizations
- **OWASP Reports**: Standardized OWASP format

## 🔍 Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test
python tests/test_complete_scan.py
```

## 📚 Documentation

- [Swagger UI Guide](docs/guides/swagger_ui_guide.md)
- [Delete Functionality Demo](docs/guides/demo_delete_functionality.md)
- [Web UI Reports Status](docs/reports/web_ui_reports_status.md)
- [Project Structure](docs/PROJECT_STRUCTURE.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details. 