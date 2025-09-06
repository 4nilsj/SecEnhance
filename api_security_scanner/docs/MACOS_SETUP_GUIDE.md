# macOS Setup Guide for API Security Scanner

This guide provides step-by-step instructions for setting up the API Security Scanner on macOS.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Python Installation](#python-installation)
3. [OWASP ZAP Installation](#owasp-zap-installation)
4. [Project Setup](#project-setup)
5. [Dependencies Installation](#dependencies-installation)
6. [Configuration](#configuration)
7. [Testing the Installation](#testing-the-installation)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Configuration](#advanced-configuration)

## Prerequisites

Before starting, ensure you have:

- macOS 10.14 (Mojave) or later
- Administrator access to install software
- Internet connection for downloading dependencies
- Terminal access (built into macOS)

## Python Installation

### Option 1: Using Homebrew (Recommended)

1. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install Python 3.11 or later**:
   ```bash
   brew install python@3.11
   ```

3. **Verify Python installation**:
   ```bash
   python3 --version
   pip3 --version
   ```

### Option 2: Using Official Python Installer

1. **Download Python** from [python.org](https://www.python.org/downloads/macos/)
2. **Run the installer** and follow the installation wizard
3. **Verify installation**:
   ```bash
   python3 --version
   pip3 --version
   ```

### Option 3: Using pyenv (For Multiple Python Versions)

1. **Install pyenv**:
   ```bash
   brew install pyenv
   ```

2. **Add pyenv to your shell profile**:
   ```bash
   echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
   echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
   echo 'eval "$(pyenv init -)"' >> ~/.zshrc
   source ~/.zshrc
   ```

3. **Install and use Python 3.11**:
   ```bash
   pyenv install 3.11.5
   pyenv global 3.11.5
   ```

## OWASP ZAP Installation

### Option 1: Using Homebrew (Recommended)

```bash
brew install --cask owasp-zap
```

### Option 2: Manual Installation

1. **Download ZAP** from [OWASP ZAP Downloads](https://www.zaproxy.org/download/)
2. **Extract the archive**:
   ```bash
   cd ~/Downloads
   unzip ZAP_2_12_0_mac.zip
   ```
3. **Move to Applications**:
   ```bash
   sudo mv ZAP_2.12.0.app /Applications/
   ```
4. **Create symlink for command-line access**:
   ```bash
   sudo ln -s /Applications/ZAP\ 2.12.0.app/Contents/Java/zap.sh /usr/local/bin/zap
   ```

### Option 3: Using Docker

```bash
# Pull the official ZAP Docker image
docker pull owasp/zap2docker-stable

# Create an alias for easy access
echo 'alias zap-docker="docker run -t owasp/zap2docker-stable zap.sh"' >> ~/.zshrc
source ~/.zshrc
```

## Project Setup

### 1. Clone or Download the Project

If you have the project in a Git repository:
```bash
git clone <repository-url>
cd api_security_scanner
```

If you have the project files locally:
```bash
cd /path/to/api_security_scanner
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation (you should see (venv) in your prompt)
which python
```

### 3. Upgrade pip

```bash
pip install --upgrade pip
```

## Dependencies Installation

### 1. Install Core Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install Additional macOS Dependencies

Some dependencies might need additional system libraries:

```bash
# Install system dependencies
brew install libffi openssl

# If you encounter SSL issues, install certificates
/Applications/Python\ 3.11/Install\ Certificates.command
```

### 3. Verify Installation

```bash
python test_installation.py
```

## Configuration

### 1. ZAP Configuration

Create a configuration file for ZAP:

```bash
# Create config directory
mkdir -p ~/.zap

# Create ZAP configuration
cat > ~/.zap/zap.conf << EOF
# ZAP Configuration for API Security Scanner
zap.path=/Applications/ZAP\ 2.12.0.app/Contents/Java/zap.sh
zap.port=8080
zap.host=127.0.0.1
zap.timeout=300
EOF
```

### 2. Scanner Configuration

Create a local configuration file:

```bash
cat > config.yaml << EOF
# API Security Scanner Configuration
zap:
  path: "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"
  port: 8080
  host: "127.0.0.1"
  timeout: 300

database:
  path: "scan_results.db"

logging:
  level: "INFO"
  file: "logs/scanner.log"

plugins:
  enabled: true
  directory: "plugins"
EOF
```

### 3. Environment Variables

Add environment variables to your shell profile:

```bash
# Add to ~/.zshrc or ~/.bash_profile
echo 'export ZAP_PATH="/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"' >> ~/.zshrc
echo 'export ZAP_PORT=8080' >> ~/.zshrc
echo 'export ZAP_HOST=127.0.0.1' >> ~/.zshrc
source ~/.zshrc
```

## Testing the Installation

### 1. Basic Functionality Test

```bash
# Test CLI help
python main.py --help

# Test scan command help
python main.py scan --help
```

### 2. Test with Sample Data

```bash
# Test with a simple curl command
python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap

# Test with sample Postman collection
python main.py scan -f examples/sample_postman_collection.json --no-zap
```

### 3. Test ZAP Integration

```bash
# Test with ZAP (requires ZAP to be running)
python main.py scan -u "curl -X GET https://httpbin.org/get" --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"
```

### 4. Test Custom Plugins

```bash
# Test custom plugins only
python main.py scan -u "curl -X GET https://httpbin.org/get" --no-zap --no-progress
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Python Version Issues

**Problem**: `python3: command not found`

**Solution**:
```bash
# Check if Python is installed
which python3

# If not found, reinstall Python
brew install python@3.11

# Add to PATH if needed
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

#### 2. ZAP Path Issues

**Problem**: `ZAP executable not found`

**Solution**:
```bash
# Find ZAP installation
find /Applications -name "zap.sh" 2>/dev/null

# Create symlink if needed
sudo ln -s /Applications/ZAP\ 2.12.0.app/Contents/Java/zap.sh /usr/local/bin/zap

# Or specify full path in command
python main.py scan -u "curl -X GET https://httpbin.org/get" --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"
```

#### 3. Permission Issues

**Problem**: `Permission denied` errors

**Solution**:
```bash
# Fix ZAP permissions
chmod +x "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Fix project permissions
chmod +x main.py
chmod +x run_scanner.bat
```

#### 4. SSL Certificate Issues

**Problem**: SSL verification errors

**Solution**:
```bash
# Install certificates
/Applications/Python\ 3.11/Install\ Certificates.command

# Or disable SSL verification (not recommended for production)
export PYTHONHTTPSVERIFY=0
```

#### 5. Port Conflicts

**Problem**: `Address already in use` for ZAP port

**Solution**:
```bash
# Check what's using the port
lsof -i :8080

# Kill the process if needed
kill -9 <PID>

# Or use a different port
python main.py scan -u "curl -X GET https://httpbin.org/get" --zap-port 8081
```

#### 6. Virtual Environment Issues

**Problem**: Dependencies not found in virtual environment

**Solution**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
pip list
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Run with debug logging
python main.py scan -u "curl -X GET https://httpbin.org/get" -vv

# Check log files
tail -f logs/scanner.log
```

## Advanced Configuration

### 1. Custom ZAP Configuration

Create a custom ZAP configuration file:

```bash
cat > ~/.zap/custom.conf << EOF
# Custom ZAP Configuration
zap.path=/Applications/ZAP\ 2.12.0.app/Contents/Java/zap.sh
zap.port=8080
zap.host=127.0.0.1
zap.timeout=600
zap.memory=2048
zap.threads=4
EOF
```

### 2. Proxy Configuration

If you're behind a corporate proxy:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1

# Configure pip to use proxy
pip install --proxy http://proxy.company.com:8080 -r requirements.txt
```

### 3. Custom Plugin Development

Set up development environment for custom plugins:

```bash
# Install development dependencies
pip install pytest black flake8 mypy

# Create plugin development directory
mkdir -p plugins/development

# Set up pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### 4. Performance Optimization

Optimize for better performance:

```bash
# Increase file limits
ulimit -n 4096

# Set optimal Python settings
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8

# Use faster JSON library
pip install orjson
```

### 5. Security Hardening

Secure your installation:

```bash
# Create dedicated user for running scans
sudo dscl . -create /Users/apiscanner
sudo dscl . -create /Users/apiscanner UserShell /bin/bash
sudo dscl . -create /Users/apiscanner RealName "API Scanner"
sudo dscl . -create /Users/apiscanner UniqueID 1001
sudo dscl . -create /Users/apiscanner PrimaryGroupID 20
sudo dscl . -create /Users/apiscanner NFSHomeDirectory /Users/apiscanner

# Set up proper permissions
chmod 755 /path/to/api_security_scanner
chmod 644 /path/to/api_security_scanner/*.py
chmod 755 /path/to/api_security_scanner/main.py
```

## Automation and Scripts

### 1. Create Launch Script

Create a convenient launch script:

```bash
cat > ~/bin/apiscanner << 'EOF'
#!/bin/bash
# API Security Scanner Launch Script

# Activate virtual environment
source /path/to/api_security_scanner/venv/bin/activate

# Change to project directory
cd /path/to/api_security_scanner

# Run the scanner with provided arguments
python main.py "$@"
EOF

chmod +x ~/bin/apiscanner

# Add to PATH
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 2. Create Cron Job

Set up automated scans:

```bash
# Edit crontab
crontab -e

# Add entry for daily scans (example)
0 2 * * * /Users/username/bin/apiscanner scan -f /path/to/daily_scan.json --export /path/to/reports/daily_$(date +\%Y\%m\%d).html
```

### 3. Create System Service

Create a system service for continuous operation:

```bash
cat > ~/Library/LaunchAgents/com.apiscanner.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apiscanner</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/api_security_scanner/venv/bin/python</string>
        <string>/path/to/api_security_scanner/main.py</string>
        <string>scan</string>
        <string>-f</string>
        <string>/path/to/scan_config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Load the service
launchctl load ~/Library/LaunchAgents/com.apiscanner.plist
```

## Conclusion

This guide provides comprehensive instructions for setting up the API Security Scanner on macOS. The setup includes:

- ✅ Python 3.11+ installation
- ✅ OWASP ZAP integration
- ✅ Virtual environment setup
- ✅ Dependency installation
- ✅ Configuration and testing
- ✅ Troubleshooting solutions
- ✅ Advanced configuration options

After following this guide, you should have a fully functional API Security Scanner running on your macOS system. For additional help, refer to the main README.md file or create an issue in the project repository.

## Quick Reference

### Essential Commands

```bash
# Activate virtual environment
source venv/bin/activate

# Run basic scan
python main.py scan -u "curl -X GET https://httpbin.org/get"

# Run with custom ZAP path
python main.py scan -f api_spec.yaml --zap-path "/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh"

# Run with progress bars disabled
python main.py scan -f api_spec.yaml --no-progress -v

# Test installation
python test_installation.py
```

### Important Paths

- **ZAP Installation**: `/Applications/ZAP 2.12.0.app/Contents/Java/zap.sh`
- **Python**: `/opt/homebrew/bin/python3` (Homebrew) or `/usr/bin/python3` (System)
- **Virtual Environment**: `./venv/`
- **Configuration**: `~/.zap/zap.conf`
- **Logs**: `./logs/scanner.log`
