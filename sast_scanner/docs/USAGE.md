# Usage Guide

This guide provides detailed instructions for using the AI-Enabled SAST Scanner effectively.

## Table of Contents

- [Quick Start](#quick-start)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [AI-Powered Features](#ai-powered-features)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Examples](#examples)
- [Best Practices](#best-practices)

## Quick Start

### First Scan

```bash
# Scan a single file
python sast_scanner_cli.py scan file app.py

# Scan a directory
python sast_scanner_cli.py scan directory ./src

# Generate HTML report
python sast_scanner_cli.py scan directory ./src --output html --output-file report.html
```

### Quick Test

```bash
# Run the quick start example
python quick_start.py

# Test AI features
python test_ai_standalone.py
```

## Basic Usage

### Command Structure

```bash
python sast_scanner_cli.py <command> <target> [options]
```

### Commands

- `scan` - Perform security scan
- `version` - Show version information
- `help` - Show help information
- `diagnose` - Run system diagnostics

### Targets

- `file <path>` - Scan a single file
- `directory <path>` - Scan a directory

### Basic Options

```bash
# Common options
--output <format>          # Output format (html, json, markdown, pdf)
--output-file <path>       # Output file path
--debug                    # Enable debug mode
--verbose                  # Verbose output
--max-workers <number>     # Number of worker threads
--patterns <patterns>      # File patterns to include
--exclude <patterns>       # File patterns to exclude
```

## Advanced Usage

### File Pattern Filtering

```bash
# Include specific file types
python sast_scanner_cli.py scan directory ./src --patterns "*.py,*.js,*.java"

# Exclude test files and dependencies
python sast_scanner_cli.py scan directory ./src --exclude "*test*,node_modules,venv"

# Complex pattern matching
python sast_scanner_cli.py scan directory ./src \
  --patterns "*.py,*.js,*.ts,*.jsx,*.tsx" \
  --exclude "*test*,*spec*,node_modules,dist,build,.git"
```

### Performance Optimization

```bash
# Use multiple worker threads
python sast_scanner_cli.py scan directory ./src --max-workers 8

# Generate summary only for large codebases
python sast_scanner_cli.py scan directory ./src --summary-only

# Skip AI analysis for faster scanning
python sast_scanner_cli.py scan directory ./src --no-ai

# Limit scan depth
python sast_scanner_cli.py scan directory ./src --max-depth 3
```

### Output Customization

```bash
# Generate multiple output formats
python sast_scanner_cli.py scan directory ./src \
  --output html --output-file report.html \
  --output json --output-file report.json

# Custom report template
python sast_scanner_cli.py scan directory ./src \
  --template custom_template.html

# Include/exclude specific vulnerability types
python sast_scanner_cli.py scan directory ./src \
  --include-vulns "sql_injection,xss,command_injection" \
  --exclude-vulns "debug_code,information_disclosure"
```

## AI-Powered Features

### Understanding AI Analysis

The SAST scanner uses AI to:

1. **Analyze code context** for better vulnerability detection
2. **Generate specific fixes** for found vulnerabilities
3. **Provide confidence scores** for detections and fixes
4. **Explain security implications** of vulnerabilities

### AI Configuration

```bash
# Enable/disable AI features
python sast_scanner_cli.py scan directory ./src --ai-enabled
python sast_scanner_cli.py scan directory ./src --no-ai

# Set AI model path
python sast_scanner_cli.py scan directory ./src --ai-model-path ./models

# Configure AI confidence threshold
python sast_scanner_cli.py scan directory ./src --ai-confidence 0.8
```

### AI-Generated Reports

AI-powered reports include:

- **Actual vulnerable code** with context
- **AI-generated specific fixes** with confidence scores
- **Detailed explanations** of why fixes are secure
- **Impact analysis** of vulnerabilities

Example AI report:
```markdown
#### SQL Injection

- **File:** `app.py`
- **Line:** 15
- **Severity:** High
- **AI Confidence:** 95.0%

**Actual Vulnerable Code:**
```python
>>> def get_user(user_input):
        query = f"SELECT * FROM users WHERE id = {user_input}"
>>>     cursor.execute(query)
```

**AI-Generated Fix (Confidence: 90.0%):**
```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```

**Fix Explanation:** This fix uses parameterized queries to prevent SQL injection.
```

## Output Formats

### HTML Reports

```bash
# Generate HTML report
python sast_scanner_cli.py scan directory ./src --output html --output-file report.html

# HTML report features:
# - Interactive vulnerability browser
# - Code highlighting
# - Severity filtering
# - Export capabilities
# - Responsive design
```

### JSON Reports

```bash
# Generate JSON report
python sast_scanner_cli.py scan directory ./src --output json --output-file report.json

# JSON structure:
{
  "scan_info": {
    "timestamp": "2024-01-01T12:00:00Z",
    "target": "./src",
    "files_scanned": 150,
    "vulnerabilities_found": 25
  },
  "vulnerabilities": [
    {
      "file": "app.py",
      "line": 15,
      "vulnerability": "sql_injection",
      "severity": "high",
      "description": "...",
      "ai_fix": "...",
      "confidence": 0.9
    }
  ]
}
```

### Markdown Reports

```bash
# Generate Markdown report
python sast_scanner_cli.py scan directory ./src --output markdown --output-file report.md

# Markdown features:
# - GitHub-compatible formatting
# - Code blocks with syntax highlighting
# - Table of contents
# - Severity-based organization
```

### PDF Reports

```bash
# Generate PDF report
python sast_scanner_cli.py scan directory ./src --output pdf --output-file report.pdf

# PDF features:
# - Professional formatting
# - Executive summary
# - Detailed vulnerability descriptions
# - Code snippets with highlighting
```

## Configuration

### Environment Variables

```bash
# Set environment variables
export SAST_DEBUG=true
export SAST_OUTPUT_DIR=./reports
export SAST_MAX_WORKERS=4
export SAST_AI_ENABLED=true
export SAST_LOG_LEVEL=INFO
```

### Configuration File

Create `sast_config.json`:

```json
{
  "max_workers": 4,
  "default_output_format": "html",
  "exclude_patterns": ["*test*", "*spec*", "node_modules"],
  "include_patterns": ["*.py", "*.js", "*.java"],
  "debug_mode": false,
  "ai_enabled": true,
  "ai_model_path": "./models",
  "log_level": "INFO",
  "output_directory": "./reports",
  "confidence_threshold": 0.8,
  "severity_filter": ["high", "medium"],
  "custom_patterns": {
    "custom_vuln": {
      "pattern": "dangerous_function\\(.*\\)",
      "severity": "medium",
      "description": "Custom vulnerability pattern"
    }
  }
}
```

### Command Line Configuration

```bash
# Use configuration file
python sast_scanner_cli.py scan directory ./src --config sast_config.json

# Override configuration
python sast_scanner_cli.py scan directory ./src --config sast_config.json --max-workers 8
```

## Examples

### Example 1: Web Application Scan

```bash
# Scan a Flask application
python sast_scanner_cli.py scan directory ./flask_app \
  --patterns "*.py,*.html,*.js" \
  --exclude "venv,__pycache__,*.pyc" \
  --output html \
  --output-file flask_security_report.html \
  --debug
```

### Example 2: Node.js Project Scan

```bash
# Scan a Node.js application
python sast_scanner_cli.py scan directory ./nodejs_app \
  --patterns "*.js,*.jsx,*.ts,*.tsx" \
  --exclude "node_modules,dist,build" \
  --output json \
  --output-file nodejs_security_report.json \
  --max-workers 6
```

### Example 3: Multi-language Project

```bash
# Scan a full-stack application
python sast_scanner_cli.py scan directory ./fullstack_app \
  --patterns "*.py,*.js,*.java,*.php,*.cpp,*.h" \
  --exclude "*test*,*spec*,node_modules,venv,build" \
  --output html \
  --output-file fullstack_report.html \
  --max-workers 8 \
  --ai-enabled
```

### Example 4: CI/CD Integration

```bash
# Generate JSON report for CI/CD
python sast_scanner_cli.py scan directory ./src \
  --output json \
  --output-file sast_results.json \
  --summary-only

# Check for high severity vulnerabilities
python -c "
import json
with open('sast_results.json') as f:
    data = json.load(f)
high_vulns = [v for v in data['vulnerabilities'] if v['severity'] == 'high']
if high_vulns:
    print(f'Found {len(high_vulns)} high severity vulnerabilities')
    exit(1)
else:
    print('No high severity vulnerabilities found')
"
```

### Example 5: Custom Vulnerability Patterns

```bash
# Create custom configuration
cat > custom_config.json << EOF
{
  "custom_patterns": {
    "hardcoded_api_key": {
      "pattern": "api_key\\s*=\\s*['\"][^'\"]{20,}['\"]",
      "severity": "high",
      "description": "Hardcoded API key detected"
    },
    "weak_password": {
      "pattern": "password\\s*=\\s*['\"]123456['\"]",
      "severity": "medium",
      "description": "Weak password detected"
    }
  }
}
EOF

# Scan with custom patterns
python sast_scanner_cli.py scan directory ./src \
  --config custom_config.json \
  --output html \
  --output-file custom_report.html
```

## Best Practices

### Scanning Strategy

1. **Start with a small scope** - Scan individual files first
2. **Use appropriate patterns** - Include only relevant file types
3. **Exclude unnecessary files** - Skip test files, dependencies, build artifacts
4. **Use multiple workers** - For large codebases, increase worker count
5. **Enable AI features** - For better detection and fix suggestions

### Performance Optimization

1. **Use summary mode** for large codebases
2. **Limit scan depth** for deep directory structures
3. **Exclude build artifacts** and dependencies
4. **Use appropriate worker count** based on system resources
5. **Consider incremental scanning** for large projects

### Report Management

1. **Use descriptive file names** for reports
2. **Generate multiple formats** for different use cases
3. **Archive old reports** for historical analysis
4. **Use version control** for configuration files
5. **Document scan parameters** for reproducibility

### Security Considerations

1. **Scan in isolated environment** for sensitive code
2. **Review AI-generated fixes** before applying
3. **Validate vulnerability reports** manually
4. **Follow responsible disclosure** practices
5. **Keep scanner updated** with latest patterns

### Integration Best Practices

1. **Automate scanning** in CI/CD pipelines
2. **Set appropriate thresholds** for automated blocking
3. **Generate actionable reports** for developers
4. **Track vulnerability trends** over time
5. **Integrate with issue tracking** systems

## Troubleshooting

### Common Issues

#### Performance Issues
```bash
# Reduce worker threads
python sast_scanner_cli.py scan directory ./src --max-workers 2

# Use summary mode
python sast_scanner_cli.py scan directory ./src --summary-only

# Exclude large directories
python sast_scanner_cli.py scan directory ./src --exclude "node_modules,venv,dist"
```

#### Memory Issues
```bash
# Limit memory usage
export SAST_MAX_MEMORY=2048

# Use smaller AI models
python sast_scanner_cli.py scan directory ./src --ai-model-size small
```

#### Output Issues
```bash
# Check file permissions
ls -la report.html

# Use absolute paths
python sast_scanner_cli.py scan directory ./src --output-file /absolute/path/report.html

# Enable debug mode
python sast_scanner_cli.py scan directory ./src --debug --verbose
```

### Getting Help

```bash
# Show help
python sast_scanner_cli.py help

# Show command help
python sast_scanner_cli.py scan help

# Run diagnostics
python sast_scanner_cli.py diagnose

# Check version
python sast_scanner_cli.py version
```

## Next Steps

After reading this usage guide:

1. **Try the [Quick Start](#quick-start)** examples
2. **Explore [AI-Powered Features](#ai-powered-features)**
3. **Review the [API Reference](API_REFERENCE.md)** for advanced usage
4. **Check the [Vulnerability Database](VULNERABILITIES.md)** for supported vulnerabilities
5. **Join the community** for support and updates 