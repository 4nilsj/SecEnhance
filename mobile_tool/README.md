# Mobile Security Testing Tool

A comprehensive automated mobile client-side security testing tool similar to Drozer and MobSF, designed to perform security analysis of Android and iOS applications.

## 🚀 Features

### Core Security Testing
- **Static Analysis**: APK/IPA file analysis, manifest inspection, permission analysis (100+ security checks)
- **Dynamic Analysis**: Runtime behavior monitoring, network traffic analysis, device analysis
- **Code Analysis**: Source code review, vulnerability scanning, pattern detection
- **Network Analysis**: SSL/TLS testing, certificate pinning, API endpoint analysis
- **Storage Analysis**: Local storage analysis, sensitive data detection, cache analysis
- **Configuration Analysis**: Security settings, encryption implementation

### Advanced Capabilities
- **Automated Exploitation**: Proof-of-concept exploit generation
- **Reverse Engineering**: APK/IPA decompilation and analysis
- **Network Security**: SSL/TLS testing, certificate pinning bypass
- **Input Validation**: Fuzzing, injection testing
- **Session Management**: Token analysis, session hijacking tests
- **Cryptography**: Encryption algorithm analysis, key management

## 📋 Requirements

### System Requirements
- **Python 3.8+** (required)
- **Java 8+** (required for APK analysis)
- **Android SDK Platform Tools** (required for dynamic analysis)
- **Android device or emulator** (required for dynamic analysis)

### Additional Tools Required

#### APK Analysis Tools
- **apktool** - APK decompilation and analysis
- **dex2jar** - Convert DEX to JAR files
- **jadx** - DEX to Java decompiler

#### Network Analysis Tools
- **tcpdump** - Network packet capture
- **wireshark** - Network protocol analyzer

### Installation Instructions

#### Option 1: Local Installation

##### Install Python Dependencies
```bash
# Navigate to the mobile tool directory
cd mobile_tool

# Install Python dependencies
pip install -r requirements.txt
```

##### Install System Tools

**Ubuntu/Debian:**
```bash
# Install APK analysis tools
sudo apt-get update
sudo apt-get install apktool dex2jar jadx

# Install network analysis tools
sudo apt-get install tcpdump wireshark

# Install Java (if not already installed)
sudo apt-get install openjdk-11-jdk
```

**macOS:**
```bash
# Install using Homebrew
brew install apktool dex2jar jadx
brew install tcpdump wireshark
brew install openjdk@11
```

**Windows:**
```bash
# Download and install manually:
# - apktool: https://ibotpeaches.github.io/Apktool/
# - dex2jar: https://github.com/pxb1988/dex2jar/releases
# - jadx: https://github.com/skylot/jadx/releases
# - Wireshark: https://www.wireshark.org/download.html
```

##### Install Android SDK Platform Tools
```bash
# Download from: https://developer.android.com/studio/releases/platform-tools
# Add to PATH:
# Linux/macOS: export PATH=$PATH:/path/to/platform-tools
# Windows: Add to System Environment Variables
```

#### Option 2: Docker Installation (Recommended)
```bash
# Build the Docker image (includes all tools)
docker build -t mobile-security-tester .

# Or use docker-compose
docker-compose build
```

### Verify Installation
```bash
# Test Python installation
python src/mobile_security_tester.py --help

# Test APK tools (if installed locally)
apktool --version
dex2jar --version
jadx --version

# Test Android tools
adb version
```

### Troubleshooting

#### Common Issues

**Java Not Found:**
```bash
# Set JAVA_HOME environment variable
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
export PATH=$PATH:$JAVA_HOME/bin
```

**APK Tools Not Found:**
```bash
# Add tools to PATH
export PATH=$PATH:/usr/local/bin/apktool
export PATH=$PATH:/usr/local/bin/dex2jar
export PATH=$PATH:/usr/local/bin/jadx
```

**Android SDK Not Found:**
```bash
# Set ANDROID_HOME environment variable
export ANDROID_HOME=/path/to/android-sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

**Permission Issues:**
```bash
# Fix permissions for APK tools
sudo chmod +x /usr/local/bin/apktool
sudo chmod +x /usr/local/bin/dex2jar
sudo chmod +x /usr/local/bin/jadx
```

#### Platform-Specific Notes

**Windows:**
- Use Windows Subsystem for Linux (WSL) for better compatibility
- Ensure all tools are in your system PATH
- Use PowerShell or Command Prompt with administrator privileges

**macOS:**
- Install Xcode Command Line Tools: `xcode-select --install`
- Use Homebrew for easier package management
- Grant necessary permissions to tools in System Preferences

**Linux:**
- Use package manager for system tools
- Ensure proper permissions for USB devices (for ADB)
- Add udev rules for Android devices if needed

## 📖 Usage

### CLI Mode

#### Basic Usage

#### Quick Security Analysis
```bash
# Basic analysis of an APK file
python src/mobile_security_tester.py --apk app.apk

# With debug output
python src/mobile_security_tester.py --apk app.apk --debug

# Save results to file
python src/mobile_security_tester.py --apk app.apk --output results.json

# Comprehensive analysis
python src/mobile_security_tester.py --apk app.apk --comprehensive

# Specific tests only
python src/mobile_security_tester.py --apk app.apk --tests static,network,storage
```

#### iOS Analysis
```bash
# Analyze IPA file
python src/mobile_security_tester.py --ipa app.ipa --comprehensive

# Device analysis
python src/mobile_security_tester.py --device ios --package com.example.app
```

#### Batch Analysis
```bash
# Analyze multiple APK files
python src/mobile_security_tester.py --batch /path/to/apks --output batch_results.json
```

### API Mode

#### Start API Server
```bash
# Start API server
python start_api.py

# Start with custom port
python start_api.py --port 8080

# Start with debug mode
python start_api.py --debug

# Using environment variable
export MOBILE_API_PORT=8080
python start_api.py
```

#### API Endpoints

**Health Check:**
```bash
curl http://localhost:5001/api/v1/health
```

**Start Scan:**
```bash
curl -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/app/uploads/app.apk",
    "tests": ["static", "network", "storage", "code"]
  }'
```

**Get Scan Status:**
```bash
curl http://localhost:5001/api/v1/scan/{scan_id}/status
```

**Download Report:**
```bash
curl http://localhost:5001/api/v1/scan/{scan_id}/report \
  -o mobile_scan_report.html
```

**List All Scans:**
```bash
curl http://localhost:5001/api/v1/scans
```

### Docker Usage

#### CLI Mode with Docker
```bash
# Basic analysis
docker-compose run mobile-tool-cli \
  python src/mobile_security_tester.py --apk /app/uploads/app.apk

# Comprehensive analysis
docker-compose run mobile-tool-comprehensive

# Interactive mode
docker-compose run mobile-tool-interactive
```

#### API Mode with Docker
```bash
# Start API server
docker-compose up mobile-api

# Start debug API server
docker-compose up mobile-api-debug

# Test API
curl http://localhost:5001/api/v1/health
```

#### Custom Port Configuration
```bash
# Change API port
export MOBILE_API_PORT=8080
docker-compose up mobile-api

# Or use docker-compose override
echo "version: '3.8'\nservices:\n  mobile-api:\n    ports:\n      - '8080:5001'" > docker-compose.override.yml
docker-compose up mobile-api
```

## 📊 Report Organization

### Directory Structure
```
mobile_tool/
├── reports/
│   ├── api/          # API-generated reports
│   │   └── api_scan_{scan_id}_{timestamp}.html
│   └── cli/          # CLI-generated reports
│       └── cli_scan_{timestamp}.html
├── uploads/          # Files for analysis
├── logs/             # Log files
└── config/           # Configuration files
```

### Report Naming Conventions

#### CLI Reports
- **Location**: `reports/cli/`
- **Naming**: `cli_scan_{timestamp}.html` or custom names
- **Formats**: JSON, HTML, PDF, CSV

#### API Reports
- **Location**: `reports/api/`
- **Naming**: `api_scan_{scan_id}_{timestamp}.html`
- **Format**: HTML (downloadable)

### Report Features
- **Separate Storage**: CLI and API reports are stored in different directories
- **No Conflicts**: Different naming conventions prevent conflicts
- **Timestamped**: All reports include timestamps for tracking
- **Multiple Formats**: Support for JSON, HTML, PDF, and CSV formats
- **Scan ID Tracking**: API reports include unique scan IDs

## 🔧 Configuration

### Environment Variables
- `MOBILE_API_PORT`: API server port (default: 5001)
- `MOBILE_API_DEBUG`: Enable debug mode (default: false)
- `MOBILE_MAX_FILE_SIZE`: Maximum file size (default: 100MB)
- `MOBILE_DEFAULT_TESTS`: Default tests to run
- `MOBILE_TIMEOUT`: Analysis timeout (default: 300s)

### Configuration Files
```bash
# Create custom configuration
cat > config/custom_config.json << EOF
{
  "api": {
    "port": 5001,
    "debug": false
  },
  "analysis": {
    "default_tests": ["static", "network", "storage", "code"],
    "timeout": 300
  }
}
EOF
```

## 🐛 Troubleshooting

### Port Conflicts
If port 5001 is already in use:
```bash
# Check what's using the port
netstat -tulpn | grep 5001

# Use a different port
export MOBILE_API_PORT=5002
python start_api.py
```

### Docker Issues
```bash
# Setup directories
python setup_docker_dirs.py

# Check container logs
docker-compose logs mobile-api

# Restart services
docker-compose down && docker-compose up mobile-api
```

### File Permissions
```bash
# Fix permissions
sudo chown -R $USER:$USER reports/ uploads/ logs/ config/

# Or run with proper permissions
docker-compose run --user $(id -u):$(id -g) mobile-tool-cli
```

## 📚 Additional Resources

- [Docker Usage Guide](DOCKER_USAGE.md) - Comprehensive Docker documentation
- [API Reference](docs/API_REFERENCE.md) - Detailed API documentation
- [Configuration Guide](docs/CONFIGURATION.md) - Configuration options
- [Reports Guide](docs/REPORTS.md) - Report generation and formats