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

### Local Usage

#### Basic Usage

#### Quick Security Analysis
```bash
# Basic analysis of an APK file
python src/mobile_security_tester.py app.apk

# With debug output
python src/mobile_security_tester.py app.apk --debug

# Save results to file
python src/mobile_security_tester.py app.apk --output results.json
```

### Docker Usage

#### Basic Docker Commands
```bash
# Run with Docker (mount APK file)
docker run --rm -v $(pwd)/app.apk:/app/input/app.apk mobile-security-tester /app/input/app.apk

# Run with volume for output
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input/app.apk --output /app/output/results.json

# Interactive mode
docker run --rm -it mobile-security-tester
```

#### Docker Compose Usage
```bash
# Basic analysis
docker-compose run --rm mobile-tool /app/input/app.apk

# Static analysis only
docker-compose run --rm mobile-tool-static

# Comprehensive analysis
docker-compose run --rm mobile-tool-comprehensive

# Interactive mode
docker-compose run --rm mobile-tool-interactive

# Batch processing
docker-compose run --rm mobile-tool-batch
```

#### Advanced Docker Examples
```bash
# Static analysis with output
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input/app.apk --analysis-type static --output /app/output/static_analysis.json

# Comprehensive analysis with all reports
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    -v $(pwd)/reports:/app/reports \
    mobile-security-tester \
    /app/input/app.apk \
    --analysis-type comprehensive \
    --output /app/output/comprehensive.json \
    --report /app/reports/report.html \
    --csv /app/output/results.csv

# Debug mode with detailed logging
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input/app.apk --debug --output /app/output/debug_report.json

# Batch processing multiple APKs
docker run --rm \
    -v $(pwd)/apks:/app/input \
    -v $(pwd)/output:/app/output \
    mobile-security-tester \
    /app/input --output /app/output/batch_results.json --summary /app/output/summary.txt
```

#### Docker with Custom Configuration
```bash
# Create directories
mkdir -p input output reports

# Copy APK to input directory
cp your_app.apk input/

# Run analysis
docker run --rm \
    -v $(pwd)/input:/app/input \
    -v $(pwd)/output:/app/output \
    -v $(pwd)/reports:/app/reports \
    mobile-security-tester \
    /app/input/your_app.apk \
    --analysis-type comprehensive \
    --output /app/output/analysis.json \
    --report /app/reports/report.html
```