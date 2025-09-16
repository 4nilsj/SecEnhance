# API Security Scanner

A highly customizable command-line interface (CLI) tool for automated API security scanning, with extensibility for new vulnerabilities and detailed operational logging.

## Features

- **Multiple Input Formats**: Supports Postman Collections, OpenAPI/Swagger specs, curl commands, and HAR files
- **OWASP ZAP Integration**: Leverages OWASP ZAP for comprehensive security testing
- **🤖 AI-Powered Detection**: Machine learning-based vulnerability detection with anomaly detection, classification, and risk scoring
- **Custom Plugin System**: Extensible architecture for custom vulnerability checks
- **Authentication Support**: Token, cookie, and header-based authentication
- **Performance Monitoring**: Detailed timing and performance statistics
- **Comprehensive Logging**: Multi-level logging with structured output
- **SQLite Storage**: Persistent storage of scan results and metrics
- **Multi-Format Reports**: HTML, PDF, Excel, XML, and JSON reports with Jinja2 templates

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

# Scan a HAR file (from Insomnia, Postman, etc.)
docker run --rm -v $(pwd):/workspace api-security-scanner scan -f /workspace/insomnia-export.har
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

# Scan a HAR file (from Insomnia, Postman, etc.)
python main.py scan -f insomnia-export.har
```

### AI-Powered Detection

The scanner includes advanced AI-powered detection capabilities:

```bash
# Enable AI detection (default)
python main.py scan -f collection.json --ai-detection

# Disable AI detection
python main.py scan -f collection.json --no-ai-detection

# Configure specific AI features
python main.py scan -f collection.json \
  --ai-anomaly-detection \
  --ai-vulnerability-classification \
  --ai-risk-scoring \
  --ai-intelligent-fuzzing

# Run only AI security checker
python main.py scan -f collection.json --plugins AISecurityChecker
```

**AI Detection Features:**
- 🤖 **Anomaly Detection**: Identifies unusual patterns in API requests
- 🎯 **Vulnerability Classification**: Automatically classifies attack types (SQL injection, XSS, etc.)
- 📊 **Risk Scoring**: Calculates comprehensive risk scores based on multiple factors
- 💡 **Intelligent Fuzzing**: Suggests targeted fuzzing approaches
- 🧠 **Learning**: Improves detection accuracy over time

For detailed AI detection documentation, see:
- **[AI Detection Guide](docs/AI_DETECTION_GUIDE.md)** - Complete user guide
- **[AI Detection Quick Reference](docs/AI_DETECTION_QUICK_REFERENCE.md)** - Quick reference
- **[AI Detection Architecture](docs/AI_DETECTION_ARCHITECTURE.md)** - Technical details

### Scan with Authentication

```bash
# API Key authentication
python main.py scan -f collection.json -a header -n "X-API-Key" -v "your-api-key"

# Bearer token authentication
python main.py scan -f collection.json -a token -n "Authorization" -v "Bearer your-token"

# Cookie authentication
python main.py scan -f collection.json -a cookie -n "session" -v "session-value"
```

### HAR File Support

The scanner now supports HAR (HTTP Archive) files exported from various tools:

#### Supported Tools
- **Insomnia REST Client** - Export as HAR format
- **Postman** - Export collection as HAR
- **Browser DevTools** - Network tab export
- **Burp Suite** - Export as HAR
- **OWASP ZAP** - Export as HAR

#### HAR File Features
- ✅ **Automatic Detection** - Detects `.har` files and JSON files with HAR structure
- ✅ **Complete Request Data** - Extracts headers, body, query parameters, and cookies
- ✅ **JWT Token Detection** - Automatically detects JWT tokens in Authorization headers
- ✅ **Conditional Scanning** - Enables JWT security plugin when JWT tokens are found
- ✅ **Folder Organization** - Preserves request grouping from original tool

#### Example Usage

```bash
# Scan HAR file from Insomnia
python main.py scan -f insomnia-export.har

# Scan HAR file with authentication
python main.py scan -f postman-export.har -a header -n "X-API-Key" -v "your-key"

# Scan HAR file with ZAP only
python main.py scan -f browser-export.har --no-plugins

# Scan HAR file with custom plugins only
python main.py scan -f burp-export.har --no-zap
```

#### Creating HAR Files

**From Insomnia:**
1. Right-click on your workspace
2. Select "Export Data" → "HAR"
3. Save the file and use with the scanner

**From Postman:**
1. Click on your collection
2. Go to "Export" → "Collection v2.1"
3. Convert to HAR format using online tools or Postman's HAR export feature

**From Browser DevTools:**
1. Open DevTools (F12)
2. Go to Network tab
3. Right-click → "Save all as HAR with content"

### Multi-Format Report Generation

The scanner supports generating reports in multiple formats for different use cases:

#### Supported Report Formats

- **HTML** (Default) - Interactive web-based reports with charts and detailed findings
- **PDF** - Professional PDF reports for documentation and sharing
- **Excel** - Spreadsheet format with multiple sheets for data analysis
- **XML** - Machine-readable format for integration with other tools
- **JSON** (Default) - Structured data format for programmatic processing

#### Report Generation Examples

```bash
# Generate all report formats
python main.py scan -f collection.json \
  --export-pdf security-report.pdf \
  --export-excel security-data.xlsx \
  --export-xml security-findings.xml

# Generate specific formats only
python main.py scan -f api-spec.yaml --export-pdf executive-summary.pdf

# Generate Excel report for data analysis
python main.py scan -f har-export.har --export-excel detailed-analysis.xlsx

# Generate XML for CI/CD integration
python main.py scan -f postman-collection.json --export-xml ci-results.xml
```

#### Report Format Details

**PDF Reports:**
- Professional layout with tables and summaries
- Suitable for executive presentations
- Includes risk summaries and vulnerability details
- Limited to first 20 vulnerabilities for readability

**Excel Reports:**
- Multiple sheets: Summary, Vulnerabilities, Performance
- Full vulnerability data with descriptions and solutions
- Sortable and filterable data
- Suitable for detailed analysis and tracking

**XML Reports:**
- Machine-readable format
- Complete scan metadata and findings
- Suitable for integration with other security tools
- Structured data for automated processing

**JSON Reports:**
- Complete scan data in structured format
- Includes metadata, vulnerabilities, and performance stats
- Suitable for API integration and data processing
- Human-readable with proper formatting

### Plugin Selection

The scanner supports running only specific security plugins, giving you fine-grained control over which security checks to perform.

#### Available Plugins

List all available plugins:
```bash
python main.py plugins
```

#### Plugin Selection Examples

```bash
# Run only security headers plugin
python main.py scan -f collection.json --plugins SecurityHeadersChecker

# Run only JWT security plugin
python main.py scan -f collection.json --plugins JWTSecurityChecker

# Run OWASP API Top 10 security plugins
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker,BrokenAuthenticationChecker,ExcessiveDataExposureChecker

# Run GraphQL-specific security checks
python main.py scan -f graphql-collection.json --plugins GraphQLSecurityChecker

# Run gRPC security analysis
python main.py scan -f grpc-endpoints.json --plugins gRPCSecurityChecker

# Run AI-powered security detection
python main.py scan -f collection.json --plugins AISecurityChecker

# Run multiple specific plugins
python main.py scan -f collection.json --plugins SecurityHeadersChecker,CORSChecker,JWTSecurityChecker

# Run with curl command and specific plugins
python main.py scan -u "curl -X GET https://api.com" --plugins SecurityHeadersChecker

# Run with HAR file and JWT plugin only
python main.py scan -f export.har --plugins JWTSecurityChecker --export-pdf jwt-analysis.pdf

# Run comprehensive OWASP API Top 10 scan
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker,BrokenAuthenticationChecker,ExcessiveDataExposureChecker,GraphQLSecurityChecker
```

#### Plugin Selection Benefits

- **Faster Scans**: Run only the checks you need
- **Focused Analysis**: Target specific security areas
- **Reduced Noise**: Avoid irrelevant findings
- **Custom Workflows**: Create specialized scanning pipelines
- **Resource Optimization**: Use fewer system resources

#### Plugin Categories

**Core Security Plugins:**
- **SecurityHeadersChecker**: HTTP security headers analysis
- **CORSChecker**: Cross-Origin Resource Sharing security
- **JWTSecurityChecker**: JWT token and OAuth flow security
- **RateLimitingChecker**: API rate limiting analysis

**OWASP API Top 10 Security Plugins:**
- **BOLAChecker**: Broken Object Level Authorization (BOLA) and IDOR detection
- **SSRFSecurityChecker**: Server-Side Request Forgery (SSRF) vulnerability detection
- **BrokenAuthenticationChecker**: Authentication mechanism security analysis
- **ExcessiveDataExposureChecker**: Data exposure and information leakage detection

**Advanced Security Plugins:**
- **GraphQLSecurityChecker**: GraphQL-specific security vulnerabilities
- **gRPCSecurityChecker**: gRPC endpoint security analysis
- **AISecurityChecker**: AI-powered vulnerability detection and anomaly analysis

**General Security Plugins:**
- **ComprehensiveSecurityChecker**: General security analysis
- **EnhancedSecurityChecker**: Advanced security checks
- **ParameterPollutionChecker**: HTTP parameter pollution detection

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
- `-f, --file` - Path to Postman Collection, OpenAPI spec file, or HAR file
- `-u, --curl` - Curl command string to parse

#### Report Export Options
- `--export` - Export HTML report to specified file
- `--export-json` - Export JSON report to specified file
- `--export-pdf` - Export PDF report to specified file
- `--export-excel` - Export Excel report to specified file
- `--export-xml` - Export XML report to specified file

#### Plugin Selection Options
- `--plugins` - Comma-separated list of specific plugins to run (e.g., "SecurityHeadersChecker,JWTSecurityChecker")
- `--no-plugins` - Skip custom plugin scanning (ZAP only)

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

The scanner comes with a comprehensive set of built-in security plugins:

#### Core Security Plugins
1. **SecurityHeadersChecker** - HTTP security headers analysis and validation
2. **CORSChecker** - Cross-Origin Resource Sharing (CORS) misconfiguration detection
3. **JWTSecurityChecker** - JWT token security and OAuth flow analysis
4. **RateLimitingChecker** - API rate limiting headers and mechanism detection

#### OWASP API Top 10 Security Plugins
5. **BOLAChecker** - Broken Object Level Authorization (BOLA) and Insecure Direct Object Reference (IDOR) detection
6. **SSRFSecurityChecker** - Server-Side Request Forgery (SSRF) vulnerability detection and testing
7. **BrokenAuthenticationChecker** - Authentication mechanism security analysis and weak authentication detection
8. **ExcessiveDataExposureChecker** - Data exposure and information leakage detection in API responses

#### Advanced Security Plugins
9. **GraphQLSecurityChecker** - GraphQL-specific security vulnerabilities including introspection, query complexity, and injection attacks
10. **gRPCSecurityChecker** - gRPC endpoint security analysis, protobuf security, and streaming vulnerability detection
11. **AISecurityChecker** - AI-powered vulnerability detection with machine learning-based anomaly detection and risk scoring

#### General Security Plugins
12. **ComprehensiveSecurityChecker** - General security analysis and common vulnerability patterns
13. **EnhancedSecurityChecker** - Advanced security checks and comprehensive vulnerability scanning
14. **ParameterPollutionChecker** - HTTP parameter pollution detection and testing

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
