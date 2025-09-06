# API Security Scanner - Quick Reference

This document provides quick reference information for the API Security Scanner.

## Table of Contents

1. [Installation Commands](#installation-commands)
2. [Basic Usage](#basic-usage)
3. [Progress Bar Options](#progress-bar-options)
4. [Custom Plugin Development](#custom-plugin-development)
5. [macOS Setup](#macos-setup)
6. [Troubleshooting](#troubleshooting)

## Installation Commands

### Prerequisites
```bash
# Python 3.7+ required
python3 --version

# Install dependencies
pip install -r requirements.txt
```

### OWASP ZAP Installation

#### Windows
```bash
# Download from https://www.zaproxy.org/download/
# Install and note the path: C:\Program Files\OWASP\Zed Attack Proxy\zap.bat
```

#### macOS
```bash
# Using Homebrew
brew install --cask owasp-zap

# Manual installation
# Download from https://www.zaproxy.org/download/
# Install to /Applications/ZAP 2.12.0.app/
```

#### Linux
```bash
# Ubuntu/Debian
sudo apt-get install zaproxy

# Or download from official website
```

## Basic Usage

### Command Structure
```bash
python main.py scan [OPTIONS]
```

### Essential Options
```bash
# Input options (choose one)
-f, --file TEXT          # Postman Collection or OpenAPI spec
-u, --curl TEXT          # Curl command string

# Authentication
-a, --auth-type [header|cookie|token]
-n, --auth-name TEXT     # Parameter name
-v, --auth-value TEXT    # Parameter value

# ZAP configuration
--zap-path TEXT          # Path to ZAP executable
--zap-port INTEGER       # ZAP proxy port (default: 8080)
--zap-host TEXT          # ZAP proxy host (default: 127.0.0.1)

# Output options
--export TEXT            # Export HTML report
--export-json TEXT       # Export JSON report
--performance-stats      # Show performance statistics

# Scan control
--no-zap                 # Skip ZAP scanning
--no-plugins             # Skip custom plugins
--max-scan-time INTEGER  # Maximum scan time in minutes
--no-progress            # Disable progress bars

# Logging
-v, --verbose            # Increase verbosity (-v for INFO, -vv for DEBUG)
--log-dir TEXT           # Log directory (default: logs)
```

### Common Commands

#### Basic Scan
```bash
# Scan with Postman collection
python main.py scan -f collection.json

# Scan with curl command
python main.py scan -u "curl -X GET https://api.example.com/users"

# Scan with authentication
python main.py scan -f api.yaml -a header -n "Authorization" -v "Bearer token123"
```

#### Custom ZAP Path
```bash
# Windows
python main.py scan -f api.yaml --zap-path "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"

# macOS
python main.py scan -f api.yaml --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Linux
python main.py scan -f api.yaml --zap-path "/usr/bin/zaproxy"
```

#### Report Generation
```bash
# Generate HTML report
python main.py scan -f api.yaml --export report.html

# Generate JSON report
python main.py scan -f api.yaml --export-json report.json

# Generate both reports
python main.py scan -f api.yaml --export report.html --export-json report.json
```

#### Performance Monitoring
```bash
# Show performance statistics
python main.py scan -f api.yaml --performance-stats

# Time-bound scanning
python main.py scan -f api.yaml --max-scan-time 30
```

## Progress Bar Options

### Progress Bar Control
```bash
# Default: Progress bars enabled
python main.py scan -f api.yaml

# Disable progress bars
python main.py scan -f api.yaml --no-progress

# Verbose mode (automatically disables progress bars)
python main.py scan -f api.yaml -v
python main.py scan -f api.yaml -vv
```

### Progress Bar Phases
The scanner shows progress for:
1. **Input Parsing** - Parsing requests from input files
2. **Authentication Setup** - Configuring authentication
3. **Database Initialization** - Setting up SQLite database
4. **Component Loading** - Loading ZAP and plugins
5. **ZAP Security Scan** - Spider, active scan, alerts retrieval
6. **Custom Plugin Scan** - Individual plugin execution
7. **Report Generation** - Creating HTML/JSON reports

## Custom Plugin Development

### Quick Plugin Template
```python
# plugins/my_plugin.py
from src.scanner_plugins import BasePlugin, Vulnerability, PluginResult

class MyPlugin(BasePlugin):
    name = "MyPlugin"
    description = "My custom security check"
    version = "1.0.0"
    author = "Your Name"
    
    def check(self, target_url, requests_data, auth_headers=None):
        vulnerabilities = []
        
        # Your security check logic
        for request in requests_data:
            if self._check_vulnerability(request):
                vulnerability = self.create_vulnerability(
                    vuln_id="unique-id",
                    name="Vulnerability Name",
                    description="Description",
                    risk="High",
                    cvss_score=7.5,
                    solution="Fix instructions",
                    references=["https://example.com"],
                    cwe_id="CWE-123",
                    wasc_id="WASC-45",
                    url=request['url'],
                    parameter="",
                    evidence="Evidence",
                    scan_id="",
                    request="HTTP request",
                    response="HTTP response"
                )
                vulnerabilities.append(vulnerability)
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
    
    def generate_poc(self, vulnerability_id):
        return None
    
    def _check_vulnerability(self, request):
        # Your check logic
        return False
```

### Plugin Testing
```bash
# Test plugin with scanner
python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap

# Test specific plugin
python -c "
from plugins.my_plugin import MyPlugin
plugin = MyPlugin()
result = plugin.check('https://example.com', [{'method': 'GET', 'url': 'https://httpbin.org/get'}])
print(f'Found {len(result.vulnerabilities)} vulnerabilities')
"
```

### Documentation
- **[Custom Plugin Development Guide](CUSTOM_PLUGIN_DEVELOPMENT.md)** - Complete development guide
- **[Plugin Interface Reference](CUSTOM_PLUGIN_DEVELOPMENT.md#plugin-interface-reference)** - API documentation
- **[Example Plugins](CUSTOM_PLUGIN_DEVELOPMENT.md#example-plugins)** - Real-world examples

## macOS Setup

### Quick Setup
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and ZAP
brew install python@3.11
brew install --cask owasp-zap

# Setup project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### ZAP Path Configuration
```bash
# Find ZAP installation
find /Applications -name "zap.sh" 2>/dev/null

# Create symlink for easy access
sudo ln -s "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh" /usr/local/bin/zap

# Test ZAP
zap.sh -version
```

### Environment Variables
```bash
# Add to ~/.zshrc
export ZAP_PATH="/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"
export ZAP_PORT=8080
export ZAP_HOST=127.0.0.1
```

### Documentation
- **[macOS Setup Guide](MACOS_SETUP_GUIDE.md)** - Complete setup instructions
- Includes troubleshooting, advanced configuration, and automation

## Troubleshooting

### Common Issues

#### ZAP Not Found
```bash
# Windows
python main.py scan -f api.yaml --zap-path "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"

# macOS
python main.py scan -f api.yaml --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Linux
python main.py scan -f api.yaml --zap-path "/usr/bin/zaproxy"
```

#### Permission Issues
```bash
# Fix ZAP permissions (macOS/Linux)
chmod +x "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Fix project permissions
chmod +x main.py
```

#### Port Conflicts
```bash
# Check what's using port 8080
lsof -i :8080  # macOS/Linux
netstat -ano | findstr :8080  # Windows

# Use different port
python main.py scan -f api.yaml --zap-port 8081
```

#### SSL Certificate Issues
```bash
# macOS - Install certificates
/Applications/Python\ 3.11/Install\ Certificates.command

# Disable SSL verification (not recommended)
export PYTHONHTTPSVERIFY=0
```

#### Virtual Environment Issues
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Debug Mode
```bash
# Enable debug logging
python main.py scan -f api.yaml -vv

# Check log files
tail -f logs/scanner.log
```

### Test Installation
```bash
# Run installation test
python test_installation.py

# Test CLI help
python main.py --help
python main.py scan --help
```

## File Structure

```
api_security_scanner/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── test_installation.py    # Installation test
├── src/                    # Core modules
│   ├── cli.py             # Command-line interface
│   ├── db_manager.py      # Database management
│   ├── report_generator.py # Report generation
│   ├── scanner_plugins.py # Plugin system
│   └── zap_manager.py     # ZAP integration
├── plugins/               # Custom plugins
│   ├── cors_checker.py
│   ├── rate_limiting_checker.py
│   ├── security_headers_checker.py
│   └── enhanced_security_checker.py
├── utils/                 # Utilities
│   ├── auth_handler.py
│   ├── input_parsers.py
│   └── logger.py
├── examples/              # Sample files
│   ├── sample_postman_collection.json
│   └── sample_openapi.yaml
├── docs/                  # Documentation
│   ├── CUSTOM_PLUGIN_DEVELOPMENT.md
│   ├── MACOS_SETUP_GUIDE.md
│   └── QUICK_REFERENCE.md
├── logs/                  # Log files
└── reports/               # Generated reports
```

## Support

For additional help:
1. Check the comprehensive documentation in the `docs/` directory
2. Review the main README.md file
3. Run `python main.py --help` for CLI options
4. Check log files in the `logs/` directory
5. Create an issue in the project repository
