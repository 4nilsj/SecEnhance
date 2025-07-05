# Mobile Security Testing Examples

This directory contains example scripts and test scenarios for the Mobile Security Testing Tool.

## Overview

The examples demonstrate various use cases and testing scenarios for mobile application security analysis, including static analysis, dynamic analysis, network testing, storage analysis, and comprehensive security audits.

## Scripts Overview

### 1. Basic Analysis Scripts

#### `basic_analysis.py`
- **Purpose**: Performs basic security analysis on APK files
- **Features**: Static analysis, permission analysis, basic vulnerability detection
- **Usage**: `python basic_analysis.py app.apk`

#### `comprehensive_analysis.py`
- **Purpose**: Performs comprehensive security analysis
- **Features**: All analysis types, detailed reporting, multiple output formats
- **Usage**: `python comprehensive_analysis.py app.apk --output results.json`

#### `batch_analysis.py`
- **Purpose**: Analyzes multiple APK files in batch
- **Features**: Batch processing, summary reporting, parallel analysis
- **Usage**: `python batch_analysis.py /path/to/apks/ --output batch_results.json`

### 2. Specialized Analysis Scripts

#### `apk_security_test.py`
- **Purpose**: Specialized APK security testing
- **Features**: Deep manifest analysis, component security, intent filter analysis
- **Usage**: `python apk_security_test.py app.apk --detailed`

#### `apk_comprehensive_test.py`
- **Purpose**: Comprehensive APK security assessment
- **Features**: All APK-specific checks, detailed vulnerability analysis
- **Usage**: `python apk_comprehensive_test.py app.apk --output apk_report.json`

#### `storage_security_test.py`
- **Purpose**: Specialized storage security analysis
- **Features**: Secure storage analysis, data leakage detection, cache analysis
- **Usage**: `python storage_security_test.py app.apk --scan-storage`

#### `network_security_test.py`
- **Purpose**: Network security analysis
- **Features**: SSL/TLS analysis, certificate pinning, API endpoint analysis
- **Usage**: `python network_security_test.py app.apk --analyze-network`

#### `dynamic_analysis_test.py`
- **Purpose**: Dynamic analysis testing
- **Features**: Runtime behavior analysis, device analysis, real-time monitoring
- **Usage**: `python dynamic_analysis_test.py app.apk --device`

### 3. Debug and Testing Scripts

#### `debug_test.py`
- **Purpose**: Demonstrates debug functionality
- **Features**: Debug logging, verbose output, troubleshooting
- **Usage**: `python debug_test.py app.apk --debug`

## Usage Examples

### Basic Security Analysis

```bash
# Basic analysis of an APK
python basic_analysis.py sample_app.apk

# Basic analysis with debug output
python basic_analysis.py sample_app.apk --debug

# Basic analysis with custom output
python basic_analysis.py sample_app.apk --output basic_results.json
```

### Comprehensive Security Assessment

```bash
# Comprehensive analysis
python comprehensive_analysis.py sample_app.apk

# Comprehensive analysis with all output formats
python comprehensive_analysis.py sample_app.apk \
    --output results.json \
    --report report.html \
    --csv results.csv

# Comprehensive analysis with specific focus
python comprehensive_analysis.py sample_app.apk \
    --focus static,network \
    --detailed
```

### Batch Processing

```bash
# Analyze all APKs in a directory
python batch_analysis.py /path/to/apk/directory/

# Batch analysis with parallel processing
python batch_analysis.py /path/to/apk/directory/ \
    --parallel \
    --max-workers 4

# Batch analysis with summary report
python batch_analysis.py /path/to/apk/directory/ \
    --output batch_results.json \
    --summary summary_report.txt
```

### Specialized Testing

```bash
# APK-specific security testing
python apk_security_test.py sample_app.apk --detailed

# Storage security analysis
python storage_security_test.py sample_app.apk --scan-storage

# Network security analysis
python network_security_test.py sample_app.apk --analyze-network

# Dynamic analysis (requires device)
python dynamic_analysis_test.py sample_app.apk --device
```

### Debug and Troubleshooting

```bash
# Debug mode with verbose output
python debug_test.py sample_app.apk --debug

# Debug specific components
python debug_test.py sample_app.apk --debug --component static

# Debug with custom log level
python debug_test.py sample_app.apk --debug --log-level DEBUG
```

## Test Scenarios

### Scenario 1: Basic Security Assessment
**Objective**: Quick security overview of an APK
```bash
python basic_analysis.py app.apk --output basic_report.json
```

**Expected Output**:
- Permission analysis
- Basic vulnerability detection
- Security score
- Key findings summary

### Scenario 2: Comprehensive Security Audit
**Objective**: Detailed security assessment for compliance
```bash
python comprehensive_analysis.py app.apk \
    --output audit_report.json \
    --report audit_report.html \
    --detailed
```

**Expected Output**:
- Complete vulnerability analysis
- Detailed security report
- Compliance checklist
- Remediation recommendations

### Scenario 3: Batch Security Review
**Objective**: Security assessment of multiple applications
```bash
python batch_analysis.py /apps/ \
    --output batch_results.json \
    --summary batch_summary.txt \
    --parallel
```

**Expected Output**:
- Individual app reports
- Comparative analysis
- Summary statistics
- Risk assessment matrix

### Scenario 4: APK-Specific Security Testing
**Objective**: Deep APK security analysis
```bash
python apk_seprehensive_test.py app.apk \
    --output apk_security_report.json \
    --detailed
```

**Expected Output**:
- Manifest analysis
- Component security assessment
- Intent filter analysis
- Third-party library analysis

### Scenario 5: Storage Security Analysis
**Objective**: Focus on data storage security
```bash
python storage_security_test.py app.apk \
    --scan-storage \
    --output storage_report.json
```

**Expected Output**:
- Secure storage analysis
- Data leakage detection
- Cache security assessment
- Storage recommendations

### Scenario 6: Network Security Analysis
**Objective**: Network communication security
```bash
python network_security_test.py app.apk \
    --analyze-network \
    --output network_report.json
```

**Expected Output**:
- SSL/TLS configuration analysis
- Certificate pinning assessment
- API endpoint security
- Network traffic analysis

### Scenario 7: Dynamic Analysis
**Objective**: Runtime behavior analysis
```bash
python dynamic_analysis_test.py app.apk --device
```

**Expected Output**:
- Runtime permission analysis
- Dynamic code loading detection
- Root detection mechanisms
- Memory tampering analysis

## Output Formats

### JSON Output
```json
{
  "app_info": {
    "package_name": "com.example.app",
    "version": "1.0.0",
    "target_sdk": 30
  },
  "analysis_summary": {
    "total_vulnerabilities": 5,
    "high_severity": 2,
    "medium_severity": 2,
    "low_severity": 1
  },
  "vulnerabilities": [
    {
      "type": "insecure_storage",
      "severity": "high",
      "description": "Sensitive data stored in plain text",
      "location": "data/data/com.example.app/files/config.txt"
    }
  ],
  "recommendations": [
    "Use Android Keystore for sensitive data storage",
    "Implement proper SSL/TLS configuration"
  ]
}
```

### HTML Report
- Interactive vulnerability dashboard
- Detailed findings with code snippets
- Remediation guidance
- Executive summary

### CSV Output
- Vulnerability summary
- Component analysis
- Permission analysis
- Risk assessment

## Configuration

### Environment Setup
```bash
# Install dependencies
pip install -r ../requirements.txt

# Set up debug logging
export DEBUG_LEVEL=DEBUG

# Configure output directory
export OUTPUT_DIR=./reports
```

### Custom Configuration
Create `config.json` for custom settings:
```json
{
  "analysis": {
    "static": true,
    "dynamic": false,
    "network": true,
    "storage": true
  },
  "output": {
    "json": true,
    "html": true,
    "csv": false
  },
  "debug": {
    "enabled": false,
    "level": "INFO"
  }
}
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```
   ModuleNotFoundError: No module named 'analyzers'
   ```
   **Solution**: Ensure you're running from the examples directory

2. **APK Not Found**
   ```
   FileNotFoundError: APK file not found
   ```
   **Solution**: Check file path and permissions

3. **Permission Errors**
   ```
   PermissionError: [Errno 13] Permission denied
   ```
   **Solution**: Check file permissions and output directory access

4. **Device Connection Issues**
   ```
   Error: No device connected for dynamic analysis
   ```
   **Solution**: Connect device and run `adb devices`

### Debug Mode
Enable debug mode for detailed troubleshooting:
```bash
python any_script.py app.apk --debug --log-level DEBUG
```

## Best Practices

### Testing Workflow
1. Start with basic analysis
2. Run comprehensive analysis for detailed assessment
3. Use specialized scripts for specific concerns
4. Perform dynamic analysis when possible
5. Generate multiple output formats

### Security Considerations
- Test on isolated environments
- Use dedicated test devices
- Follow responsible disclosure
- Document all findings
- Maintain test data security

### Performance Optimization
- Use parallel processing for batch analysis
- Limit detailed analysis to critical apps
- Use appropriate debug levels
- Optimize output formats based on needs

## Integration

### CI/CD Integration
```yaml
# Example GitHub Actions workflow
- name: Mobile Security Analysis
  run: |
    python examples/comprehensive_analysis.py ${{ github.workspace }}/app.apk
    --output security_report.json
    --report security_report.html
```

### API Integration
```python
from examples.comprehensive_analysis import run_comprehensive_analysis

results = run_comprehensive_analysis("app.apk", output_format="json")
```

## Contributing

### Adding New Examples
1. Create new script in examples directory
2. Follow naming convention: `*_test.py`
3. Include proper documentation
4. Add to this README
5. Test with sample APKs

### Example Template
```python
#!/usr/bin/env python3
"""
Example Script Template
Description of what this script does.
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

def main():
    parser = argparse.ArgumentParser(description='Example Script')
    parser.add_argument('apk_path', help='Path to APK file')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    
    args = parser.parse_args()
    
    # Your analysis code here
    pass

if __name__ == "__main__":
    main()
```

## Support

For issues and questions:
1. Check troubleshooting section
2. Enable debug mode for detailed logs
3. Review documentation in `../docs/`
4. Check example outputs for reference 