# API Security Scanner - Troubleshooting Guide

This comprehensive troubleshooting guide covers common issues during installation and scan execution, with solutions for Windows, macOS, and Linux.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Scan Execution Issues](#scan-execution-issues)
3. [ZAP Integration Issues](#zap-integration-issues)
4. [Database Issues](#database-issues)
5. [Plugin Issues](#plugin-issues)
6. [Network and Connectivity Issues](#network-and-connectivity-issues)
7. [Performance Issues](#performance-issues)
8. [Log Analysis](#log-analysis)
9. [Advanced Debugging](#advanced-debugging)
10. [Getting Help](#getting-help)

## Installation Issues

### Python Installation Problems

#### Issue: Python Not Found
**Symptoms:**
```
python: command not found
python3: command not found
'python' is not recognized as an internal or external command
```

**Solutions:**

**Windows:**
```bash
# Check if Python is installed
python --version
python3 --version

# If not found, download from python.org
# Or use Windows Store
# Or use Chocolatey
choco install python

# Add Python to PATH manually
# Go to System Properties > Environment Variables > PATH
# Add: C:\Users\YourUsername\AppData\Local\Programs\Python\Python311\
```

**macOS:**
```bash
# Check if Python is installed
python3 --version

# Install using Homebrew
brew install python@3.11

# Install using official installer
# Download from python.org

# Install using pyenv
brew install pyenv
pyenv install 3.11.5
pyenv global 3.11.5
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip

# Arch Linux
sudo pacman -S python python-pip
```

#### Issue: Wrong Python Version
**Symptoms:**
```
Python 3.6.9 (default, ...)
# But need Python 3.7+
```

**Solutions:**
```bash
# Check current version
python3 --version

# Install newer version
# Windows: Download from python.org
# macOS: brew install python@3.11
# Linux: Use package manager or pyenv

# Use specific version
python3.11 --version
```

### Dependency Installation Issues

#### Issue: pip Install Fails
**Symptoms:**
```
ERROR: Could not find a version that satisfies the requirement
ERROR: No matching distribution found
```

**Solutions:**
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install with specific index
pip install -r requirements.txt -i https://pypi.org/simple/

# Install with no cache
pip install -r requirements.txt --no-cache-dir

# Install with verbose output
pip install -r requirements.txt -v

# Install individual packages
pip install click python-owasp-zap-v2.4 requests pyyaml jinja2
```

#### Issue: Permission Denied During Installation
**Symptoms:**
```
PermissionError: [Errno 13] Permission denied
```

**Solutions:**
```bash
# Use user install
pip install --user -r requirements.txt

# Use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt

# Fix permissions (Linux/macOS)
sudo chown -R $USER:$USER ~/.local/lib/python3.11/site-packages/
```

#### Issue: SSL Certificate Errors
**Symptoms:**
```
SSL: CERTIFICATE_VERIFY_FAILED
urllib3.exceptions.SSLError
```

**Solutions:**
```bash
# macOS - Install certificates
/Applications/Python\ 3.11/Install\ Certificates.command

# Linux - Update certificates
sudo apt update && sudo apt install ca-certificates

# Windows - Update certificates
# Run Windows Update

# Temporary workaround (not recommended)
pip install --trusted-host pypi.org --trusted-host pypi.python.org -r requirements.txt
```

### Virtual Environment Issues

#### Issue: Virtual Environment Not Activating
**Symptoms:**
```
source: command not found
venv\Scripts\activate: The system cannot find the path specified
```

**Solutions:**

**Windows:**
```bash
# Use correct activation script
venv\Scripts\activate.bat
# Or
venv\Scripts\Activate.ps1

# If PowerShell execution policy blocks
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Linux/macOS:**
```bash
# Use correct activation command
source venv/bin/activate

# Check if virtual environment exists
ls -la venv/bin/activate

# Recreate if missing
rm -rf venv
python3 -m venv venv
source venv/bin/activate
```

#### Issue: Dependencies Not Found in Virtual Environment
**Symptoms:**
```
ModuleNotFoundError: No module named 'click'
```

**Solutions:**
```bash
# Ensure virtual environment is activated
# You should see (venv) in your prompt

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
pip list

# Check Python path
which python  # Should point to venv/bin/python
```

## Scan Execution Issues

### Basic Scan Failures

#### Issue: Input File Not Found
**Symptoms:**
```
FileNotFoundError: [Errno 2] No such file or directory: 'collection.json'
```

**Solutions:**
```bash
# Check if file exists
ls -la collection.json  # Linux/macOS
dir collection.json     # Windows

# Use absolute path
python main.py scan -f /full/path/to/collection.json

# Check file permissions
chmod 644 collection.json  # Linux/macOS
```

#### Issue: Invalid Input Format
**Symptoms:**
```
InputParserError: Invalid input format
JSONDecodeError: Expecting value
YAMLError: while parsing
```

**Solutions:**
```bash
# Validate JSON files
python -m json.tool collection.json

# Validate YAML files
python -c "import yaml; yaml.safe_load(open('api.yaml'))"

# Check file encoding
file collection.json

# Convert encoding if needed
iconv -f ISO-8859-1 -t UTF-8 collection.json > collection_utf8.json
```

#### Issue: Authentication Failures
**Symptoms:**
```
AuthenticationError: Invalid authentication configuration
401 Unauthorized
403 Forbidden
```

**Solutions:**
```bash
# Verify authentication parameters
python main.py scan -f api.yaml -a header -n "Authorization" -v "Bearer valid-token"

# Test authentication manually
curl -H "Authorization: Bearer token" https://api.example.com/users

# Check token expiration
# Regenerate API keys if needed

# Use different authentication method
python main.py scan -f api.yaml -a cookie -n "session" -v "session-value"
```

### Progress Bar Issues

#### Issue: Progress Bar Not Displaying
**Symptoms:**
```
# No progress bars shown during scan
```

**Solutions:**
```bash
# Check if tqdm is installed
pip install tqdm

# Ensure progress bars are not disabled
python main.py scan -f api.yaml  # Should show progress bars

# Check verbose mode (disables progress bars)
python main.py scan -f api.yaml -v  # Progress bars disabled

# Force enable progress bars
python main.py scan -f api.yaml --no-progress=false
```

#### Issue: Progress Bar Display Issues
**Symptoms:**
```
# Progress bars appear garbled or overlapping
```

**Solutions:**
```bash
# Use no-progress flag for clean output
python main.py scan -f api.yaml --no-progress

# Check terminal compatibility
echo $TERM  # Linux/macOS

# Use different terminal
# Try Windows Terminal, iTerm2, or standard terminal
```

## ZAP Integration Issues

### ZAP Installation Problems

#### Issue: ZAP Not Found
**Symptoms:**
```
ZAP executable not found
ZAPManagerError: Failed to start ZAP
```

**Solutions:**

**Windows:**
```bash
# Find ZAP installation
dir "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"
dir "C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat"

# Specify full path
python main.py scan -f api.yaml --zap-path "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat"

# Install ZAP if missing
# Download from https://www.zaproxy.org/download/
```

**macOS:**
```bash
# Find ZAP installation
find /Applications -name "zap.sh" 2>/dev/null

# Install using Homebrew
brew install --cask owasp-zap

# Create symlink
sudo ln -s "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh" /usr/local/bin/zap

# Specify full path
python main.py scan -f api.yaml --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"
```

**Linux:**
```bash
# Install ZAP
sudo apt install zaproxy  # Ubuntu/Debian
sudo yum install zaproxy  # CentOS/RHEL

# Find installation
which zaproxy
find /usr -name "zap.sh" 2>/dev/null

# Specify path
python main.py scan -f api.yaml --zap-path "/usr/bin/zaproxy"
```

#### Issue: ZAP Permission Denied
**Symptoms:**
```
Permission denied: '/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh'
```

**Solutions:**
```bash
# Fix permissions
chmod +x "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Check ownership
ls -la "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Fix ownership if needed
sudo chown $USER:staff "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"
```

### ZAP Runtime Issues

#### Issue: ZAP Port Already in Use
**Symptoms:**
```
Address already in use: 8080
ZAPManagerError: Failed to start ZAP proxy
```

**Solutions:**
```bash
# Check what's using port 8080
lsof -i :8080        # Linux/macOS
netstat -ano | findstr :8080  # Windows

# Kill process using port
kill -9 <PID>        # Linux/macOS
taskkill /PID <PID> /F  # Windows

# Use different port
python main.py scan -f api.yaml --zap-port 8081

# Check for existing ZAP instances
ps aux | grep zap    # Linux/macOS
tasklist | findstr zap  # Windows
```

#### Issue: ZAP Java Errors
**Symptoms:**
```
java.lang.OutOfMemoryError: Java heap space
java.lang.UnsupportedClassVersionError
```

**Solutions:**
```bash
# Increase Java heap size
export JAVA_OPTS="-Xmx2048m"  # Linux/macOS
set JAVA_OPTS=-Xmx2048m       # Windows

# Check Java version
java -version

# Install/update Java
# Windows: Download from Oracle or use OpenJDK
# macOS: brew install openjdk
# Linux: sudo apt install openjdk-11-jdk

# Use specific Java version
export JAVA_HOME=/path/to/java  # Linux/macOS
```

#### Issue: ZAP Spider/Scan Failures
**Symptoms:**
```
Spidering failed
Active scan failed
ZAPManagerError: Spider/scan operation failed
```

**Solutions:**
```bash
# Check target accessibility
curl -I https://target-url.com

# Verify ZAP proxy settings
# Check if target is behind firewall/proxy

# Increase timeouts
python main.py scan -f api.yaml --max-scan-time 60

# Check ZAP logs
tail -f ~/.ZAP/zap.log

# Test with simple target
python main.py scan -u "curl -X GET https://httpbin.org/get"
```

## Database Issues

### SQLite Database Problems

#### Issue: Database Locked
**Symptoms:**
```
sqlite3.OperationalError: database is locked
```

**Solutions:**
```bash
# Check for other processes using database
lsof scan_results.db  # Linux/macOS

# Kill processes using database
kill -9 <PID>

# Delete lock file
rm scan_results.db-journal

# Use different database file
python main.py scan -f api.yaml --db-path scan_results_new.db
```

#### Issue: Database Schema Errors
**Symptoms:**
```
sqlite3.OperationalError: no such table: vulnerabilities
sqlite3.OperationalError: near "references": syntax error
```

**Solutions:**
```bash
# Delete existing database to recreate schema
rm scan_results.db

# Run scan to recreate database
python main.py scan -f api.yaml

# Check database schema
sqlite3 scan_results.db ".schema"

# Manually fix schema if needed
sqlite3 scan_results.db "ALTER TABLE vulnerabilities RENAME COLUMN references TO refs;"
```

#### Issue: Database Permission Errors
**Symptoms:**
```
sqlite3.OperationalError: unable to open database file
```

**Solutions:**
```bash
# Check file permissions
ls -la scan_results.db

# Fix permissions
chmod 664 scan_results.db
chown $USER:$USER scan_results.db

# Check directory permissions
ls -la .

# Use different location
python main.py scan -f api.yaml --db-path /tmp/scan_results.db
```

## Plugin Issues

### Plugin Loading Problems

#### Issue: Plugin Import Errors
**Symptoms:**
```
ImportError: No module named 'plugins.my_plugin'
ModuleNotFoundError: No module named 'requests'
```

**Solutions:**
```bash
# Check plugin file exists
ls -la plugins/my_plugin.py

# Check plugin syntax
python -m py_compile plugins/my_plugin.py

# Install missing dependencies
pip install requests

# Check plugin class inheritance
# Ensure plugin inherits from BasePlugin

# Test plugin manually
python -c "from plugins.my_plugin import MyPlugin; print('OK')"
```

#### Issue: Plugin Execution Failures
**Symptoms:**
```
Plugin MyPlugin failed: 'MyPlugin' object has no attribute 'check'
Plugin execution error: generate_poc() missing 1 required positional argument
```

**Solutions:**
```bash
# Check plugin implements required methods
# Must implement: check() and generate_poc()

# Verify method signatures
def check(self, target_url, requests_data, auth_headers=None):
def generate_poc(self, vulnerability_id):

# Check plugin returns PluginResult
return PluginResult(plugin_name=self.name, success=True, vulnerabilities=[])

# Test plugin individually
python -c "
from plugins.my_plugin import MyPlugin
plugin = MyPlugin()
result = plugin.check('https://example.com', [])
print(result.success)
"
```

#### Issue: Plugin Performance Issues
**Symptoms:**
```
Plugin execution taking too long
Timeout during plugin execution
```

**Solutions:**
```bash
# Add timeouts to plugin requests
import requests
response = requests.get(url, timeout=30)

# Limit response sizes
response.text[:1000]  # Limit to first 1000 characters

# Use async operations for multiple requests
# See plugin development guide for async examples

# Profile plugin performance
import time
start_time = time.time()
# ... plugin logic ...
execution_time = time.time() - start_time
```

## Network and Connectivity Issues

### Connection Problems

#### Issue: Connection Timeouts
**Symptoms:**
```
requests.exceptions.ConnectTimeout
requests.exceptions.ReadTimeout
urllib3.exceptions.ConnectTimeoutError
```

**Solutions:**
```bash
# Test connectivity
ping target-url.com
curl -I https://target-url.com

# Check firewall settings
# Windows: Windows Defender Firewall
# macOS: System Preferences > Security & Privacy > Firewall
# Linux: ufw status, iptables -L

# Use proxy if behind corporate firewall
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# Increase timeouts
# Add timeout parameters to requests
```

#### Issue: SSL/TLS Certificate Errors
**Symptoms:**
```
SSL: CERTIFICATE_VERIFY_FAILED
urllib3.exceptions.SSLError
certificate verify failed: unable to get local issuer certificate
```

**Solutions:**
```bash
# Update certificates
# Windows: Windows Update
# macOS: /Applications/Python\ 3.11/Install\ Certificates.command
# Linux: sudo apt update && sudo apt install ca-certificates

# Verify certificate chain
openssl s_client -connect target-url.com:443

# Temporary workaround (not recommended for production)
export PYTHONHTTPSVERIFY=0

# Use custom CA bundle
export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt
```

#### Issue: DNS Resolution Problems
**Symptoms:**
```
NameResolutionError: Failed to resolve 'target-url.com'
socket.gaierror: [Errno -2] Name or service not known
```

**Solutions:**
```bash
# Test DNS resolution
nslookup target-url.com
dig target-url.com

# Check DNS settings
# Windows: ipconfig /all
# macOS/Linux: cat /etc/resolv.conf

# Use different DNS servers
# Windows: Change in Network Settings
# macOS: System Preferences > Network > Advanced > DNS
# Linux: Edit /etc/resolv.conf

# Test with IP address directly
python main.py scan -u "curl -X GET https://1.2.3.4/api"
```

## Performance Issues

### Memory Issues

#### Issue: Out of Memory Errors
**Symptoms:**
```
MemoryError: Unable to allocate array
java.lang.OutOfMemoryError: Java heap space
```

**Solutions:**
```bash
# Increase system memory limits
ulimit -v unlimited  # Linux/macOS

# Increase Java heap size for ZAP
export JAVA_OPTS="-Xmx4096m"

# Limit response sizes in plugins
response.text[:1000]  # Limit response processing

# Process requests in batches
# Split large input files into smaller chunks

# Monitor memory usage
top -p $(pgrep python)  # Linux/macOS
```

#### Issue: Slow Scan Performance
**Symptoms:**
```
Scan taking too long
Progress bars moving very slowly
```

**Solutions:**
```bash
# Use time-bound scanning
python main.py scan -f api.yaml --max-scan-time 30

# Skip ZAP for faster custom plugin testing
python main.py scan -f api.yaml --no-zap

# Reduce spider depth
python main.py scan -f api.yaml --spider-depth 2

# Use fewer concurrent requests
# Modify plugin code to limit concurrent requests

# Profile performance
python main.py scan -f api.yaml --performance-stats
```

### Disk Space Issues

#### Issue: Insufficient Disk Space
**Symptoms:**
```
No space left on device
OSError: [Errno 28] No space left on device
```

**Solutions:**
```bash
# Check disk space
df -h  # Linux/macOS
dir C:\  # Windows

# Clean up old scan results
rm scan_results_old.db
rm -rf logs/old_logs/

# Use different location for database
python main.py scan -f api.yaml --db-path /tmp/scan_results.db

# Clean up temporary files
rm -rf /tmp/zap_*
```

## Log Analysis

### Understanding Log Messages

#### Log Levels
- **DEBUG**: Detailed information for debugging
- **INFO**: General information about scan progress
- **WARNING**: Something unexpected happened but scan continues
- **ERROR**: An error occurred but scan may continue
- **CRITICAL**: A serious error occurred, scan may stop

#### Common Log Patterns

**Successful Scan:**
```
2024-01-01 10:00:00 | INFO | Starting scan with ID: abc123
2024-01-01 10:00:01 | INFO | Parsed 5 requests
2024-01-01 10:00:02 | INFO | ZAP scan completed successfully
2024-01-01 10:00:03 | INFO | Custom plugins completed: 3 issues found
2024-01-01 10:00:04 | INFO | Scan completed successfully
```

**Failed Scan:**
```
2024-01-01 10:00:00 | ERROR | ZAP error: Failed to start ZAP proxy
2024-01-01 10:00:01 | ERROR | Plugin MyPlugin failed: Connection timeout
2024-01-01 10:00:02 | CRITICAL | Scan failed: Unable to connect to target
```

### Log File Locations

```bash
# Main log file
logs/scanner.log

# ZAP logs
~/.ZAP/zap.log  # Linux/macOS
%USERPROFILE%\.ZAP\zap.log  # Windows

# Python logs
# Check console output or log files specified in configuration
```

### Log Analysis Commands

```bash
# View recent logs
tail -f logs/scanner.log

# Search for errors
grep -i error logs/scanner.log

# Search for specific scan ID
grep "abc123" logs/scanner.log

# Count error types
grep -c "ERROR" logs/scanner.log

# View logs from specific time
grep "2024-01-01 10:" logs/scanner.log
```

## Advanced Debugging

### Debug Mode

#### Enable Debug Logging
```bash
# Maximum verbosity
python main.py scan -f api.yaml -vv

# Debug specific components
export DEBUG=1
python main.py scan -f api.yaml

# Enable Python debug mode
python -u main.py scan -f api.yaml -vv
```

#### Debug Plugin Issues
```bash
# Test plugin in isolation
python -c "
import sys
sys.path.append('.')
from plugins.my_plugin import MyPlugin
plugin = MyPlugin()
print('Plugin loaded successfully')
"

# Debug plugin with pdb
python -c "
import pdb
from plugins.my_plugin import MyPlugin
plugin = MyPlugin()
pdb.set_trace()
result = plugin.check('https://example.com', [])
"
```

#### Debug ZAP Issues
```bash
# Start ZAP manually
/Applications/ZAP\ 2.12.0.app/Contents/Java/zap.sh -daemon -port 8080

# Check ZAP status
curl http://localhost:8080/JSON/core/view/version/

# Test ZAP API
curl "http://localhost:8080/JSON/spider/action/scan/?url=https://httpbin.org"

# View ZAP logs
tail -f ~/.ZAP/zap.log
```

### Network Debugging

#### Test Network Connectivity
```bash
# Test basic connectivity
ping target-url.com

# Test HTTP connectivity
curl -v https://target-url.com/api

# Test with different user agents
curl -H "User-Agent: Mozilla/5.0" https://target-url.com/api

# Test with authentication
curl -H "Authorization: Bearer token" https://target-url.com/api
```

#### Debug SSL Issues
```bash
# Test SSL connection
openssl s_client -connect target-url.com:443 -servername target-url.com

# Check certificate details
openssl x509 -in certificate.crt -text -noout

# Test with different SSL versions
curl --tlsv1.2 https://target-url.com/api
curl --tlsv1.3 https://target-url.com/api
```

## Getting Help

### Self-Help Resources

1. **Check Documentation**
   - [README.md](../README.md) - Main documentation
   - [Quick Reference Guide](QUICK_REFERENCE.md) - Command reference
   - [Custom Plugin Development Guide](CUSTOM_PLUGIN_DEVELOPMENT.md) - Plugin development
   - [macOS Setup Guide](MACOS_SETUP_GUIDE.md) - macOS installation

2. **Run Diagnostic Commands**
   ```bash
   # Test installation
   python test_installation.py
   
   # Check CLI help
   python main.py --help
   python main.py scan --help
   
   # Test with simple example
   python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap
   ```

3. **Check System Requirements**
   ```bash
   # Python version
   python --version
   
   # Dependencies
   pip list
   
   # System info
   uname -a  # Linux/macOS
   systeminfo  # Windows
   ```

### Collecting Debug Information

When reporting issues, collect the following information:

```bash
# System information
python --version
pip list
uname -a  # Linux/macOS

# Scanner information
python main.py --help
python test_installation.py

# Error logs
tail -50 logs/scanner.log

# ZAP information (if applicable)
/Applications/ZAP\ 2.12.0.app/Contents/Java/zap.sh -version

# Network information
ping target-url.com
curl -I https://target-url.com
```

### Reporting Issues

When creating an issue report, include:

1. **System Information**
   - Operating System and version
   - Python version
   - ZAP version (if applicable)

2. **Error Details**
   - Complete error message
   - Steps to reproduce
   - Input files (if applicable)

3. **Log Files**
   - Relevant log entries
   - Full error traceback

4. **Configuration**
   - Command used
   - Configuration files
   - Environment variables

### Community Support

- **GitHub Issues**: Create an issue in the project repository
- **Documentation**: Check existing documentation first
- **Examples**: Review example files in the `examples/` directory
- **Logs**: Always check log files for detailed error information

### Professional Support

For enterprise support or custom development:
- Contact the project maintainers
- Consider professional security consulting services
- Review commercial API security testing tools

---

## Quick Troubleshooting Checklist

### Before Reporting Issues

- [ ] Check Python version (3.7+ required)
- [ ] Verify all dependencies are installed
- [ ] Test with simple example (httpbin.org)
- [ ] Check log files for detailed errors
- [ ] Verify ZAP installation and path (if using ZAP)
- [ ] Test network connectivity to target
- [ ] Try with different input files
- [ ] Check file permissions and paths
- [ ] Verify virtual environment is activated
- [ ] Update to latest version

### Common Quick Fixes

```bash
# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Clear and recreate database
rm scan_results.db
python main.py scan -f api.yaml

# Test with minimal example
python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap

# Check ZAP path
python main.py scan -f api.yaml --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Use different port
python main.py scan -f api.yaml --zap-port 8081

# Enable debug logging
python main.py scan -f api.yaml -vv
```

This troubleshooting guide should help resolve most common issues. If you encounter problems not covered here, please create an issue with detailed information about your system and the specific error you're experiencing.
