# Enhanced Dynamic Analysis Guide

## Overview

The mobile security testing tool now includes enhanced dynamic analysis capabilities with full support for Nox emulator and other Android emulators. This guide will help you set up and use dynamic analysis effectively.

## Prerequisites

### 1. Nox Emulator Setup
- Install Nox emulator from [https://www.bignox.com/](https://www.bignox.com/)
- Enable ADB in Nox settings
- Start Nox emulator

### 2. ADB Setup
- Install Android SDK Platform Tools
- Ensure ADB is in your system PATH
- Connect to Nox emulator:
  ```bash
  adb connect 127.0.0.1:62001
  ```

### 3. Verify Connection
```bash
adb devices
```
You should see your Nox emulator listed.

## Usage

### Basic Dynamic Analysis

```bash
# Run comprehensive analysis including dynamic
python -m src.mobile_security_tester --apk your_app.apk --comprehensive

# Run only dynamic analysis
python -m src.mobile_security_tester --apk your_app.apk --tests dynamic

# Run with specific profile
python -m src.mobile_security_tester --apk your_app.apk --profile penetration
```

### Interactive Mode

```bash
# Launch interactive mode
python -m src.mobile_security_tester --interactive
```

### Device Analysis (without APK)

```bash
# Analyze connected device
python -m src.mobile_security_tester --device android

# Analyze specific app on device
python -m src.mobile_security_tester --device android --package com.example.app
```

## Scan Profiles

### Basic Profile
- Static analysis
- Network analysis
- Quick scan for common issues

### Standard Profile
- Static analysis
- Network analysis
- Storage analysis
- Code analysis
- Recommended for most use cases

### Comprehensive Profile
- All analysis types
- Dynamic analysis
- Deep scanning
- Best for thorough security assessment

### Compliance Profile
- All analysis types
- AI-powered detection
- Focus on compliance requirements
- Suitable for regulatory audits

### Penetration Profile
- All analysis types
- AI-powered detection
- Maximum security testing
- Best for penetration testing

## Dynamic Analysis Features

### 1. Device Detection
- Automatic Nox emulator detection
- Support for multiple emulator types
- Device information gathering
- Root status detection

### 2. Runtime Monitoring
- CPU usage monitoring
- Memory usage tracking
- Network activity analysis
- File system access monitoring
- System call tracking
- Logcat output analysis

### 3. App Behavior Analysis
- Activity monitoring
- Service analysis
- Permission usage tracking
- Runtime security checks

### 4. Network Analysis
- Network traffic monitoring
- Connection analysis
- Protocol detection
- Security assessment

### 5. File System Analysis
- File access patterns
- Storage security
- Data leakage detection
- Permission analysis

## Report Formats

The tool supports multiple report formats:

- **HTML**: Interactive web report (default)
- **JSON**: Machine-readable format
- **PDF**: Printable report
- **CSV**: Spreadsheet format
- **XML**: Structured data format
- **Markdown**: Documentation format
- **Dashboard**: Interactive dashboard

```bash
# Generate specific format
python -m src.mobile_security_tester --apk app.apk --format json
python -m src.mobile_security_tester --apk app.apk --format pdf
python -m src.mobile_security_tester --apk app.apk --format markdown
```

## Testing Dynamic Analysis

Use the provided test script to verify your setup:

```bash
python test_dynamic_analysis.py
```

This script will:
1. Test device connection
2. Display device information
3. Run dynamic analysis on available APK
4. Show results and generate report

## Troubleshooting

### Connection Issues
1. Ensure Nox emulator is running
2. Check ADB connection: `adb devices`
3. Try manual connection: `adb connect 127.0.0.1:62001`
4. Restart ADB server: `adb kill-server && adb start-server`

### Permission Issues
1. Enable USB debugging in Nox
2. Grant necessary permissions to apps
3. Check if device is rooted (may affect analysis)

### Analysis Failures
1. Check APK compatibility with emulator
2. Ensure sufficient storage space
3. Verify emulator has required Android version
4. Check logs for specific error messages

## Advanced Usage

### Custom Test Configuration
```bash
# Run specific tests
python -m src.mobile_security_tester --apk app.apk --tests static,dynamic,network

# Quick analysis
python -m src.mobile_security_tester --apk app.apk --quick

# Deep analysis
python -m src.mobile_security_tester --apk app.apk --deep
```

### Batch Analysis
```bash
# Analyze multiple APKs
python -m src.mobile_security_tester --batch /path/to/apks/
```

### Debug Mode
```bash
# Enable debug logging
python -m src.mobile_security_tester --apk app.apk --debug

# Verbose output
python -m src.mobile_security_tester --apk app.apk --verbose
```

## Security Considerations

1. **Isolation**: Run analysis in isolated environment
2. **Network**: Use isolated network for testing
3. **Data**: Be careful with sensitive data in test APKs
4. **Permissions**: Grant only necessary permissions
5. **Updates**: Keep emulator and tools updated

## Performance Tips

1. **Emulator Settings**: Allocate sufficient RAM and CPU
2. **Storage**: Ensure adequate storage space
3. **Network**: Use stable network connection
4. **Background Apps**: Close unnecessary background apps
5. **Analysis Duration**: Longer analysis provides better results

## Integration

The dynamic analysis can be integrated into CI/CD pipelines:

```bash
# Automated testing
python -m src.mobile_security_tester --apk app.apk --format json --no-report
```

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review debug logs with `--debug` flag
3. Test with the provided test script
4. Verify emulator and ADB setup

## Examples

### Example 1: Basic Security Assessment
```bash
python -m src.mobile_security_tester --apk myapp.apk --profile standard --format html
```

### Example 2: Compliance Testing
```bash
python -m src.mobile_security_tester --apk myapp.apk --profile compliance --format pdf
```

### Example 3: Penetration Testing
```bash
python -m src.mobile_security_tester --apk myapp.apk --profile penetration --format dashboard
```

### Example 4: Quick Check
```bash
python -m src.mobile_security_tester --apk myapp.apk --quick --format json
``` 