# API Security Scanner

A highly customizable command-line interface (CLI) tool for automated API security scanning, with extensibility for new vulnerabilities and detailed operational logging.

## Features

- **Multiple Input Formats**: Supports Postman Collections, OpenAPI/Swagger specs, and curl commands
- **OWASP ZAP Integration**: Leverages OWASP ZAP for comprehensive security testing
- **Custom Plugin System**: Extensible architecture for custom vulnerability checks
- **Authentication Support**: Token, cookie, and header-based authentication
- **Performance Monitoring**: Detailed timing and performance statistics
- **Comprehensive Logging**: Multi-level logging with structured output
- **SQLite Storage**: Persistent storage of scan results and metrics
- **HTML/JSON Reports**: Detailed reporting with Jinja2 templates

## Installation

### Prerequisites

- Python 3.7 or higher
- OWASP ZAP (Zed Attack Proxy)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install OWASP ZAP

#### Windows
1. Download ZAP from [OWASP ZAP Downloads](https://www.zaproxy.org/download/)
2. Install and note the installation path

#### Linux/macOS
```bash
# Ubuntu/Debian
sudo apt-get install zaproxy

# macOS with Homebrew
brew install --cask owasp-zap

# Or download from the official website
```

## Quick Start

### Basic Scan

```bash
# Scan a Postman collection
python main.py scan -f collection.json

# Scan an OpenAPI spec
python main.py scan -f api-spec.yaml

# Scan a curl command
python main.py scan -u "curl -X GET https://api.example.com/users"
```

### Scan with Authentication

```bash
# API Key authentication
python main.py scan -f collection.json -a header -n "X-API-Key" -v "your-api-key"

# Bearer token authentication
python main.py scan -f collection.json -a token -n "Authorization" -v "Bearer your-token"

# Cookie authentication
python main.py scan -f collection.json -a cookie -n "session" -v "session-value"
```

### Advanced Scan with Reporting

```bash
python main.py scan -f collection.json \
  --auth-type header --auth-name "X-API-Key" --auth-value "your-key" \
  --performance-stats \
  --export report.html \
  --export-json report.json \
  -vv
```

## Command Reference

### Main Commands

- `scan` - Perform security scan
- `list-scans` - List recent scans
- `show-scan` - Show details of a specific scan
- `cleanup` - Clean up old scan data
- `stats` - Show database statistics
- `plugins` - List available custom plugins

### Scan Options

#### Input Options
- `-f, --file` - Path to Postman Collection or OpenAPI spec file
- `-u, --curl` - Curl command string to parse

#### Authentication Options
- `-a, --auth-type` - Authentication type (header, cookie, token)
- `-n, --auth-name` - Authentication parameter name
- `-v, --auth-value` - Authentication parameter value

#### ZAP Options
- `--zap-path` - Path to ZAP executable
- `--zap-port` - ZAP proxy port (default: 8080)
- `--zap-host` - ZAP proxy host (default: localhost)
- `--spider-depth` - Maximum spider depth (default: 5)
- `--spider-children` - Maximum children per spider node (default: 10)

#### Output Options
- `--export` - Export HTML report
- `--export-json` - Export JSON report
- `--performance-stats` - Show performance statistics
- `--db-path` - SQLite database path (default: scan_results.db)

#### Control Options
- `--no-zap` - Skip ZAP scanning (custom plugins only)
- `--no-plugins` - Skip custom plugin scanning (ZAP only)
- `-v, --verbose` - Increase verbosity (-v for INFO, -vv for DEBUG)
- `--log-dir` - Directory for log files (default: logs)

## Custom Plugins

The scanner supports custom plugins for additional security checks. Plugins are automatically discovered from the `plugins/` directory.

### Creating a Custom Plugin

Create a new Python file in the `plugins/` directory:

```python
from src.scanner_plugins import BasePlugin, PluginResult

class MyCustomPlugin(BasePlugin):
    name = "MyCustomPlugin"
    description = "My custom security check"
    version = "1.0.0"
    author = "Your Name"
    
    def check(self, target_url, requests_data, auth_headers=None):
        findings = []
        
        # Your security check logic here
        for request in requests_data:
            # Check something
            if self._check_something(request):
                findings.append(self.create_finding(
                    title="Security Issue Found",
                    description="Description of the issue",
                    severity="High",
                    evidence="Evidence of the issue",
                    recommendation="How to fix it",
                    url=request['url'],
                    method=request['method']
                ))
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            findings=findings
        )
    
    def _check_something(self, request):
        # Your check logic
        return False
```

### Built-in Plugins

The scanner comes with several built-in plugins:

1. **RateLimitingChecker** - Checks for rate limiting headers and mechanisms
2. **CORSChecker** - Checks for CORS misconfigurations
3. **SecurityHeadersChecker** - Checks for security headers implementation

## Database Schema

The scanner uses SQLite to store scan results with the following tables:

- `scans` - Scan metadata and status
- `zap_alerts` - ZAP security findings
- `custom_alerts` - Custom plugin findings
- `performance_stats` - Performance metrics
- `error_logs` - Error and exception logs

## Logging

The scanner provides comprehensive logging with multiple levels:

- **WARNING** (default) - Important warnings and errors
- **INFO** (-v) - General information about scan progress
- **DEBUG** (-vv) - Detailed debugging information

Logs are written to both console and files in the `logs/` directory:
- `scan_logs.log` - All log messages
- `error_logs.log` - Error and critical messages only

## Examples

### Example 1: Basic API Scan

```bash
python main.py scan -f examples/api-collection.json
```

### Example 2: Scan with Authentication and Reporting

```bash
python main.py scan -f examples/api-collection.json \
  --auth-type header --auth-name "Authorization" --auth-value "Bearer token123" \
  --performance-stats \
  --export reports/scan-report.html \
  -v
```

### Example 3: Scan Only Custom Plugins

```bash
python main.py scan -f examples/api-collection.json --no-zap
```

### Example 4: List Recent Scans

```bash
python main.py list-scans --limit 5
```

### Example 5: Show Scan Details

```bash
python main.py show-scan abc12345 --export detailed-report.html
```

## Configuration

### Environment Variables

- `ZAP_PATH` - Path to ZAP executable
- `ZAP_PORT` - ZAP proxy port
- `ZAP_HOST` - ZAP proxy host

### Configuration Files

The scanner can be configured using environment variables or command-line arguments. No separate configuration file is required.

## Troubleshooting

### Common Issues

1. **ZAP not found**: Ensure ZAP is installed and specify the path with `--zap-path`
2. **Permission errors**: Ensure the scanner has write permissions for logs and database
3. **Network issues**: Check firewall settings and network connectivity
4. **Authentication failures**: Verify authentication parameters and credentials

### Debug Mode

Use `-vv` for detailed debugging information:

```bash
python main.py scan -f collection.json -vv
```

### Log Files

Check log files in the `logs/` directory for detailed error information:
- `scan_logs.log` - Complete scan logs
- `error_logs.log` - Error messages only

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your custom plugins or improvements
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files for error details
3. Create an issue with detailed information
4. Include relevant log output and configuration details

## Changelog

### Version 1.0.0
- Initial release
- OWASP ZAP integration
- Custom plugin system
- Multiple input format support
- Comprehensive reporting
- SQLite storage
- Performance monitoring
