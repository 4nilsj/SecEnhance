# API Security Scanner

A comprehensive API security testing tool that analyzes Postman collections for OWASP API Security Top 10 vulnerabilities and other security issues.

## Features

- **OWASP API Security Top 10 Testing**: Comprehensive testing against all OWASP API Security Top 10 vulnerabilities
- **Postman Collection Support**: Direct support for Postman collection JSON files
- **Multiple Output Formats**: JSON and HTML report generation
- **Web Interface**: User-friendly web UI for uploading and scanning collections
- **Performance Monitoring**: Built-in performance testing and optimization
- **Extensible Architecture**: Modular design for easy extension and customization

## Project Structure

```
api-security-scanner/
├── src/                    # Source code
│   ├── core/              # Core functionality
│   ├── scanners/          # Security scanners
│   ├── utils/             # Utility functions
│   ├── web/               # Web interface
│   ├── tests/             # Test modules
│   ├── config/            # Configuration files
│   ├── docs/              # Documentation
│   └── examples/          # Example usage
├── reports/               # Generated reports
│   ├── json/              # JSON reports
│   ├── html/              # HTML reports
│   └── logs/              # Log files
├── data/                  # Data files
├── scripts/               # Utility scripts
├── docs/                  # Project documentation
├── main.py                # Main entry point
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd api-security-scanner
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

#### Scan a Postman Collection
```bash
python main.py scan --collection path/to/collection.json
```

#### Scan with custom output directory
```bash
python main.py scan --collection collection.json --output reports/custom/
```

#### Start Web Interface
```bash
python main.py web --port 8080
```

### Web Interface

1. Start the web server:
```bash
python main.py web
```

2. Open your browser and navigate to `http://localhost:5000`

3. Upload your Postman collection and run the scan

## Configuration

The scanner can be configured using JSON configuration files. Default configuration is located at `src/config/default_config.json`.

### Key Configuration Options

- **Scan Settings**: Timeout values, retry attempts, concurrent requests
- **Security Tests**: Enable/disable specific security tests
- **Output Settings**: Report formats, output directories
- **Performance Settings**: Request limits, rate limiting

## Security Tests

The scanner performs the following security tests:

1. **Broken Object Level Authorization (BOLA)**
2. **Broken User Authentication**
3. **Excessive Data Exposure**
4. **Lack of Resources & Rate Limiting**
5. **Broken Function Level Authorization (BFLA)**
6. **Mass Assignment**
7. **Security Misconfiguration**
8. **Injection**
9. **Improper Assets Management**
10. **Insufficient Logging & Monitoring**

## Output Formats

### JSON Reports
Detailed JSON reports with vulnerability findings, severity levels, and remediation recommendations.

### HTML Reports
User-friendly HTML reports with visual charts and interactive elements.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue on the GitHub repository.

## Changelog

### Version 1.0.0
- Initial release
- OWASP API Security Top 10 testing
- Postman collection support
- Web interface
- JSON and HTML report generation 