# Installation Guide

This guide provides detailed instructions for installing and setting up the Mobile Security Testing Tool.

## Prerequisites

### System Requirements

- **Operating System**: Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+)
- **Python**: 3.8 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **Storage**: At least 2GB free space
- **Network**: Internet connection for downloading dependencies

### Required Tools

#### For Android Analysis
- **Java 8+**: Required for APK analysis tools
- **Android SDK** (optional): For advanced Android testing
- **ADB** (Android Debug Bridge): For device testing

#### For iOS Analysis
- **Xcode** (macOS only): For iOS development tools
- **libimobiledevice**: For iOS device communication
- **iOS SDK** (optional): For advanced iOS testing

## Installation Steps

### 1. Clone the Repository

```bash
git clone <repository-url>
cd mobile_tool
```

### 2. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Or install with specific version
pip install -r requirements.txt --upgrade
```

### 4. Install External Tools

#### On Ubuntu/Debian Linux

```bash
# Update package list
sudo apt update

# Install Java
sudo apt install openjdk-8-jdk

# Install Android tools
sudo apt install android-tools-adb android-tools-fastboot

# Install APK analysis tools
sudo apt install apktool dex2jar jadx

# Install additional dependencies
sudo apt install python3-dev build-essential libssl-dev libffi-dev
```

#### On macOS

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Java
brew install openjdk@8

# Install Android tools
brew install android-platform-tools

# Install APK analysis tools
brew install apktool dex2jar jadx

# Install iOS tools (macOS only)
brew install libimobiledevice ideviceinstaller
```

#### On Windows

```bash
# Install Chocolatey (if not already installed)
# Run PowerShell as Administrator and execute:
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install Java
choco install openjdk8

# Install Android tools
choco install android-sdk

# Install APK analysis tools
choco install apktool dex2jar jadx
```

### 5. Manual Tool Installation

If package managers don't work, you can install tools manually:

#### APKTool

```bash
# Download APKTool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O apktool.jar

# Create wrapper script
echo '#!/bin/bash' > apktool
echo 'java -jar "$(dirname "$0")/apktool.jar" "$@"' >> apktool
chmod +x apktool

# Move to system PATH
sudo mv apktool apktool.jar /usr/local/bin/
```

#### JADX

```bash
# Download JADX
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip
sudo mv jadx /usr/local/bin/
```

#### DEX2JAR

```bash
# Download DEX2JAR
wget https://github.com/pxb1988/dex2jar/releases/download/v2.1/dex2jar-2.1.zip
unzip dex2jar-2.1.zip
sudo mv dex2jar-2.1 /usr/local/bin/dex2jar
```

### 6. Verify Installation

```bash
# Test Python installation
python --version

# Test tool availability
apktool --version
jadx --version
d2j-dex2jar --version

# Test the mobile security tool
python src/mobile_security_tester.py --help
```

## Configuration

### 1. Create Configuration File

```bash
# Create sample configuration
python -c "
from src.utils.config_manager import ConfigManager
config = ConfigManager()
config.create_sample_config('config.json')
"
```

### 2. Edit Configuration

Edit the `config.json` file to customize settings:

```json
{
  "scanning": {
    "timeout": 300,
    "max_threads": 4,
    "enable_dynamic": true,
    "enable_network": true
  },
  "reporting": {
    "format": ["json", "html"],
    "include_evidence": true,
    "risk_threshold": "medium"
  },
  "tools": {
    "apktool_path": "/usr/local/bin/apktool",
    "jadx_path": "/usr/local/bin/jadx",
    "dex2jar_path": "/usr/local/bin/d2j-dex2jar"
  }
}
```

### 3. Environment Variables

You can also set configuration via environment variables:

```bash
export MOBILE_SCAN_TIMEOUT=300
export MOBILE_SCAN_THREADS=4
export MOBILE_REPORT_FORMAT=html
export MOBILE_ENABLE_DYNAMIC=true
```

## Android Device Setup

### 1. Enable Developer Options

1. Go to **Settings** > **About Phone**
2. Tap **Build Number** 7 times
3. Go back to **Settings** > **Developer Options**
4. Enable **USB Debugging**

### 2. Connect Device

```bash
# Check device connection
adb devices

# Install APK on device
adb install app.apk

# Uninstall APK
adb uninstall com.example.app
```

## iOS Device Setup (macOS only)

### 1. Install iOS Tools

```bash
# Install libimobiledevice
brew install libimobiledevice

# Install additional tools
brew install ideviceinstaller ideviceinfo
```

### 2. Trust Computer

1. Connect iOS device to Mac
2. Trust the computer when prompted
3. Enter device passcode

### 3. Verify Connection

```bash
# List connected devices
idevice_id -l

# Get device info
ideviceinfo
```

## Troubleshooting

### Common Issues

#### 1. Java Not Found

```bash
# Set JAVA_HOME environment variable
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
```

#### 2. APKTool Permission Denied

```bash
# Fix permissions
chmod +x /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool.jar
```

#### 3. ADB Device Not Found

```bash
# Restart ADB server
adb kill-server
adb start-server

# Check USB debugging is enabled
adb devices
```

#### 4. Python Import Errors

```bash
# Reinstall dependencies
pip uninstall -r requirements.txt
pip install -r requirements.txt

# Check Python path
python -c "import sys; print(sys.path)"
```

#### 5. Memory Issues

```bash
# Increase Java heap size
export JAVA_OPTS="-Xmx4g -Xms2g"

# Or modify APKTool script
java -Xmx4g -jar apktool.jar "$@"
```

### Platform-Specific Issues

#### Windows

- **Path Issues**: Ensure tools are in system PATH
- **Permission Issues**: Run as Administrator if needed
- **Antivirus**: Add tool directory to antivirus exclusions

#### macOS

- **Gatekeeper**: Allow apps from identified developers
- **Xcode**: Install Xcode Command Line Tools
- **Permissions**: Grant necessary permissions to tools

#### Linux

- **Dependencies**: Install build essentials
- **Permissions**: Use sudo for system-wide installation
- **Library Issues**: Install missing libraries

### Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review error logs in `mobile_security.log`
3. Run with debug mode: `python src/mobile_security_tester.py --debug`
4. Check tool versions and compatibility
5. Consult the documentation or create an issue

## Next Steps

After successful installation:

1. **Test the tool** with a sample APK/IPA file
2. **Review the documentation** for usage instructions
3. **Configure your environment** for your specific needs
4. **Set up reporting** to match your requirements
5. **Integrate with CI/CD** if needed

## Uninstallation

To remove the tool:

```bash
# Remove Python packages
pip uninstall -r requirements.txt

# Remove virtual environment
rm -rf venv

# Remove tool files
rm -rf mobile_tool

# Remove external tools (optional)
sudo apt remove apktool dex2jar jadx  # Ubuntu/Debian
brew uninstall apktool dex2jar jadx   # macOS
choco uninstall apktool dex2jar jadx  # Windows
``` 