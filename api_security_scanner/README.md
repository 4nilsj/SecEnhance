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

### Option 1: Docker/Podman (Recommended)

The easiest way to run the API Security Scanner is using Docker or Podman containers.

#### Prerequisites
- Docker or Podman installed
- No need to install Python or ZAP separately

#### 🍎 macOS Users (No Admin Privileges Required)

If you're on macOS without administrator privileges, Docker is the perfect solution:

```bash
# Quick setup for macOS
./mac-docker-setup.sh

# Or manual setup:
./setup-container.sh
./build-docker.sh
docker-compose up -d zap
docker-compose run --rm scanner scan -f /workspace/your-collection.json
```

**Advantages for macOS users:**
- ✅ No admin privileges required
- ✅ No system-wide Python installation
- ✅ No ZAP installation needed
- ✅ Isolated environment
- ✅ Easy cleanup

#### Quick Setup
```bash
# Clone the repository
git clone <repository-url>
cd api_security_scanner

# Setup container environment (creates necessary directories)
# On Linux/macOS:
./setup-container.sh

# On Windows:
setup-container.bat

# Build the container
docker build -t api-security-scanner .

# Or with Podman:
podman build -t api-security-scanner .
```

#### Using Docker Compose (Recommended)
```bash
# Start ZAP and scanner services
docker-compose up -d zap

# Run a scan
docker-compose run --rm scanner scan -f /workspace/your-collection.json

# Or for standalone mode (with external ZAP):
docker-compose run --rm scanner-standalone scan -f /workspace/your-collection.json
```

### Option 2: Local Installation

#### Prerequisites

- Python 3.7 or higher
- OWASP ZAP (Zed Attack Proxy)

#### Install Dependencies

```bash
pip install -r requirements.txt
```

#### Install OWASP ZAP

##### Windows
1. Download ZAP from [OWASP ZAP Downloads](https://www.zaproxy.org/download/)
2. Install and note the installation path

##### Linux/macOS
```bash
# Ubuntu/Debian
sudo apt-get install zaproxy

# macOS with Homebrew
brew install --cask owasp-zap

# Or download from the official website
```

### macOS Setup

For detailed macOS installation instructions, see:
- **[macOS Setup Guide](docs/MACOS_SETUP_GUIDE.md)** - Complete setup guide for macOS users
- Includes Python installation, ZAP setup, troubleshooting, and advanced configuration

### Docker/Podman Setup

For comprehensive Docker and Podman usage instructions, see:
- **[Docker Usage Guide](docs/DOCKER_USAGE_GUIDE.md)** - Complete guide for containerized deployment
- Includes setup, configuration, troubleshooting, and advanced usage patterns

## Quick Start

### Configuration Setup

The scanner uses `.env` files for configuration management. Start by setting up your configuration:

```bash
# Copy the configuration template
cp env.template .env

# Edit the configuration (optional)
nano .env

# Show current configuration
python -m api_security_scanner.cli.main config --show-config

# Validate configuration
python -m api_security_scanner.cli.main config
```

For detailed configuration options, see [Environment Configuration Guide](docs/ENVIRONMENT_CONFIGURATION.md).

### Docker/Podman Usage

#### Basic Container Scan

```bash
# Scan a Postman collection
docker run --rm -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json

# Scan an OpenAPI spec
docker run --rm -v $(pwd):/workspace api-security-scanner scan -f /workspace/api-spec.yaml

# Scan a curl command
docker run --rm api-security-scanner scan -u "curl -X GET https://api.example.com/users"
```

#### Using Docker Compose

```bash
# Set up configuration
cp env.template .env
# Edit .env for Docker environment (ZAP_HOST=zap, ZAP_EXTERNAL=true)

# Start ZAP service
docker-compose up -d zap

# Run a scan (with integrated ZAP)
docker-compose run --rm scanner scan -f /workspace/collection.json

# Run a scan with authentication
docker-compose run --rm scanner scan -f /workspace/collection.json \
  -a header -n "X-API-Key" -v "your-api-key"

# Run a scan with custom plugins only (no ZAP)
docker-compose run --rm scanner scan -f /workspace/collection.json --no-zap

# List recent scans
docker-compose run --rm scanner list-scans

# Show scan details
docker-compose run --rm scanner show-scan abc12345
```

#### Container Environment Variables

```bash
# Custom ZAP configuration
docker run --rm -e ZAP_HOST=zap-proxy -e ZAP_PORT=8080 \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json

# Custom paths
docker run --rm -e SCAN_DB_PATH=/app/data/custom.db \
  -e LOG_DIR=/app/logs -e REPORTS_DIR=/app/reports \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json
```

#### Podman Usage

```bash
# Build with Podman
podman build -t api-security-scanner .

# Run with Podman
podman run --rm -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json

# Using Podman Compose
podman-compose up -d zap
podman-compose run --rm scanner scan -f /workspace/collection.json
```

### Local Installation Usage

#### Basic Scan

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

### Quick Reference

For comprehensive documentation and troubleshooting, see:
- **[Quick Reference Guide](docs/QUICK_REFERENCE.md)** - Command reference and common usage patterns
- **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** - Comprehensive troubleshooting for installation and scan issues

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

### Quick Start

Create a new Python file in the `plugins/` directory:

```python
from src.scanner_plugins import BasePlugin, Vulnerability, PluginResult

class MyCustomPlugin(BasePlugin):
    name = "MyCustomPlugin"
    description = "My custom security check"
    version = "1.0.0"
    author = "Your Name"
    
    def check(self, target_url, requests_data, auth_headers=None):
        vulnerabilities = []
        
        # Your security check logic here
        for request in requests_data:
            if self._check_something(request):
                vulnerability = self.create_vulnerability(
                    vuln_id="unique-id",
                    name="Security Issue Found",
                    description="Description of the issue",
                    risk="High",
                    cvss_score=7.5,
                    solution="How to fix it",
                    references=["https://example.com"],
                    cwe_id="CWE-123",
                    wasc_id="WASC-45",
                    url=request['url'],
                    parameter="",
                    evidence="Evidence of the issue",
                    scan_id="",  # Will be set by scanner
                    request="Full HTTP request",
                    response="Full HTTP response"
                )
                vulnerabilities.append(vulnerability)
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
    
    def generate_poc(self, vulnerability_id):
        """Generate proof-of-concept evidence."""
        return None
    
    def _check_something(self, request):
        # Your check logic
        return False
```

### Comprehensive Documentation

For detailed plugin development instructions, see:
- **[Custom Plugin Development Guide](docs/CUSTOM_PLUGIN_DEVELOPMENT.md)** - Complete guide for creating custom security plugins
- **[Plugin Interface Reference](docs/CUSTOM_PLUGIN_DEVELOPMENT.md#plugin-interface-reference)** - Detailed API documentation
- **[Example Plugins](docs/CUSTOM_PLUGIN_DEVELOPMENT.md#example-plugins)** - Real-world plugin examples

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

## Docker/Podman Troubleshooting

### Container-Specific Issues

#### ZAP Connectivity Issues
```bash
# Check if ZAP container is running
docker-compose ps zap

# Check ZAP logs
docker-compose logs zap

# Test ZAP connectivity from scanner container
docker-compose run --rm scanner curl -f http://zap:8080/JSON/core/view/version/

# Use external ZAP (if running ZAP on host)
docker run --rm --network host -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json --zap-host localhost
```

#### Volume Mount Issues
```bash
# Check volume mounts
docker run --rm -v $(pwd):/workspace api-security-scanner ls -la /workspace

# Fix permissions (Linux/macOS)
sudo chown -R $USER:$USER data logs reports workspace

# Windows: Run as Administrator or check Docker Desktop settings
```

#### Container Build Issues
```bash
# Clean build (no cache)
docker build --no-cache -t api-security-scanner .

# Check build logs
docker build -t api-security-scanner . 2>&1 | tee build.log

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t api-security-scanner .
```

#### Podman-Specific Issues
```bash
# Enable rootless mode
podman system migrate

# Check Podman version
podman version

# Use Podman with Docker Compose
export DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock
docker-compose up -d zap
```

### Container Environment Debugging

```bash
# Check container environment
docker run --rm api-security-scanner env

# Interactive shell for debugging
docker run --rm -it api-security-scanner bash

# Check container configuration
docker run --rm api-security-scanner check

# View container logs
docker logs <container-id>
```

## General Troubleshooting

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

## Troubleshooting

### Common Issues

**Installation Problems:**
```bash
# Test installation
python test_installation.py

# Check Python version
python --version  # Requires 3.7+

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

**ZAP Integration Issues:**
```bash
# Find ZAP installation
find /Applications -name "zap.sh" 2>/dev/null  # macOS
dir "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"  # Windows

# Use specific ZAP path
python main.py scan -f api.yaml --zap-path "/path/to/zap.sh"

# Test with different port
python main.py scan -f api.yaml --zap-port 8081
```

**Scan Execution Issues:**
```bash
# Test with simple example
python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap

# Enable debug logging
python main.py scan -f api.yaml -vv

# Check log files
tail -f logs/scanner.log
```

### Comprehensive Troubleshooting

For detailed troubleshooting information, see:
- **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** - Complete troubleshooting guide for installation and scan issues
- **[Quick Reference Guide](docs/QUICK_REFERENCE.md)** - Command reference and common solutions

## Support

For issues and questions:
1. Check the [troubleshooting guide](docs/TROUBLESHOOTING_GUIDE.md)
2. Review the [documentation](docs/)
3. Check the [examples](examples/)
4. Create an issue with detailed information
5. Include relevant log output and configuration details

## Changelog

### Version 1.0.0
- Initial release
- OWASP ZAP integration
- Custom plugin system
- Multiple input format support
- Comprehensive reporting
- SQLite storage
- Performance monitoring
