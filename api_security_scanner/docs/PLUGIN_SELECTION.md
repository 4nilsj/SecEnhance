# Plugin Selection Guide

The API Security Scanner supports selective plugin execution, allowing you to run only specific security checks based on your needs. This provides fine-grained control over the scanning process and enables targeted security analysis.

## Overview

By default, the scanner runs all available plugins with intelligent conditional logic (e.g., JWT plugin only runs when JWT tokens are detected). However, you can override this behavior to run only specific plugins.

## Available Plugins

### Core Security Plugins

1. **SecurityHeadersChecker** - HTTP security headers analysis
   - Checks for missing security headers (HSTS, CSP, X-Frame-Options, etc.)
   - Identifies server version disclosure
   - Analyzes header configuration issues

2. **CORSChecker** - Cross-Origin Resource Sharing security
   - Detects CORS misconfigurations
   - Identifies wildcard origins
   - Checks for credentials with wildcard origins

3. **JWTSecurityChecker** - JWT token and OAuth flow security
   - Analyzes JWT token structure and algorithms
   - Detects weak JWT implementations
   - Identifies OAuth flow vulnerabilities

4. **RateLimitingChecker** - API rate limiting analysis
   - Tests for rate limiting implementation
   - Identifies missing rate limiting headers
   - Analyzes rate limiting effectiveness

5. **ComprehensiveSecurityChecker** - General security analysis
   - Authentication bypass detection
   - Input validation issues
   - Authorization problems

6. **EnhancedSecurityChecker** - Advanced security checks
   - Advanced vulnerability detection
   - Complex security pattern analysis
   - Enhanced reporting

## Usage

### List Available Plugins

```bash
python main.py plugins
```

This command shows all available plugins with descriptions and usage examples.

### Basic Plugin Selection

```bash
# Run only security headers plugin
python main.py scan -f collection.json --plugins SecurityHeadersChecker

# Run only JWT security plugin
python main.py scan -f collection.json --plugins JWTSecurityChecker

# Run multiple specific plugins
python main.py scan -f collection.json --plugins SecurityHeadersChecker,CORSChecker,JWTSecurityChecker
```

### Plugin Selection with Different Input Types

#### Postman Collections
```bash
python main.py scan -f postman-collection.json --plugins SecurityHeadersChecker,CORSChecker
```

#### OpenAPI/Swagger Specs
```bash
python main.py scan -f api-spec.yaml --plugins JWTSecurityChecker,RateLimitingChecker
```

#### HAR Files
```bash
python main.py scan -f export.har --plugins SecurityHeadersChecker --export-pdf headers-analysis.pdf
```

#### Curl Commands
```bash
python main.py scan -u "curl -X GET https://api.com" --plugins CORSChecker
```

### Plugin Selection with Reporting

```bash
# Run specific plugins with PDF report
python main.py scan -f collection.json --plugins SecurityHeadersChecker,JWTSecurityChecker --export-pdf security-analysis.pdf

# Run JWT plugin with Excel analysis
python main.py scan -f collection.json --plugins JWTSecurityChecker --export-excel jwt-analysis.xlsx

# Run CORS plugin with XML output
python main.py scan -f collection.json --plugins CORSChecker --export-xml cors-findings.xml
```

## Use Cases

### 1. Focused Security Audits

**Scenario**: You want to focus only on HTTP security headers
```bash
python main.py scan -f api-collection.json --plugins SecurityHeadersChecker --export-pdf headers-audit.pdf
```

**Benefits**:
- Faster scan execution
- Focused findings on headers
- Reduced noise from other checks

### 2. JWT-Specific Analysis

**Scenario**: Your API uses JWT tokens and you want to check for JWT vulnerabilities
```bash
python main.py scan -f collection.json --plugins JWTSecurityChecker --export-excel jwt-analysis.xlsx
```

**Benefits**:
- Targeted JWT security analysis
- Detailed JWT vulnerability reporting
- Faster execution for JWT-focused scans

### 3. CORS Security Review

**Scenario**: You need to verify CORS configuration
```bash
python main.py scan -f collection.json --plugins CORSChecker --export-pdf cors-review.pdf
```

**Benefits**:
- Comprehensive CORS analysis
- Clear CORS misconfiguration reporting
- Focused on cross-origin security

### 4. Rate Limiting Assessment

**Scenario**: You want to test API rate limiting implementation
```bash
python main.py scan -f collection.json --plugins RateLimitingChecker --export-excel rate-limiting-analysis.xlsx
```

**Benefits**:
- Dedicated rate limiting testing
- Performance impact analysis
- Rate limiting effectiveness assessment

### 5. Multi-Plugin Workflows

**Scenario**: You want to run a subset of security checks
```bash
python main.py scan -f collection.json --plugins SecurityHeadersChecker,CORSChecker,JWTSecurityChecker
```

**Benefits**:
- Custom security check combination
- Balanced coverage and performance
- Targeted security analysis

## Best Practices

### 1. Plugin Selection Strategy

- **Start Broad**: Run all plugins first to get comprehensive coverage
- **Focus Specific**: Use plugin selection for targeted analysis
- **Combine Related**: Group related plugins (e.g., SecurityHeadersChecker + CORSChecker)

### 2. Performance Optimization

- **Single Plugin**: Use one plugin for fastest execution
- **Related Plugins**: Combine plugins that check similar areas
- **Avoid Overlap**: Don't run plugins that check the same vulnerabilities

### 3. Reporting Strategy

- **PDF Reports**: Use for executive summaries and presentations
- **Excel Reports**: Use for detailed analysis and tracking
- **XML Reports**: Use for automated processing and CI/CD integration

### 4. Workflow Integration

```bash
# CI/CD Pipeline - Security Headers Check
python main.py scan -f api-spec.yaml --plugins SecurityHeadersChecker --export-xml headers-ci.xml

# Development Testing - JWT Security
python main.py scan -f collection.json --plugins JWTSecurityChecker --export-json jwt-dev.json

# Production Audit - Comprehensive Check
python main.py scan -f collection.json --plugins SecurityHeadersChecker,CORSChecker,RateLimitingChecker --export-pdf prod-audit.pdf
```

## Error Handling

### Invalid Plugin Names

If you specify a plugin that doesn't exist:
```bash
python main.py scan -f collection.json --plugins InvalidPlugin
```

**Result**: 
- Warning message about invalid plugin
- Scan continues with valid plugins
- No scan failure

### Plugin Conflicts

You cannot use `--plugins` with `--no-plugins`:
```bash
python main.py scan -f collection.json --plugins SecurityHeadersChecker --no-plugins
```

**Result**: 
- Error message
- Scan terminates
- Clear error explanation

## Advanced Usage

### Conditional Plugin Execution

When using plugin selection, the conditional logic is bypassed. For example:
- JWT plugin will run even if no JWT tokens are detected
- All selected plugins execute regardless of request analysis

### Plugin Dependencies

Some plugins may have implicit dependencies:
- **JWTSecurityChecker**: Works best with requests containing JWT tokens
- **CORSChecker**: More effective with cross-origin requests
- **RateLimitingChecker**: Requires multiple requests to test rate limiting

### Custom Plugin Development

You can create custom plugins and use them with the selection system:
```bash
python main.py scan -f collection.json --plugins CustomSecurityChecker
```

## Troubleshooting

### Common Issues

1. **No Plugins Loaded**
   - Check plugin names are correct
   - Verify plugins are in the plugins directory
   - Use `python main.py plugins` to list available plugins

2. **Plugin Execution Errors**
   - Check plugin compatibility
   - Verify input format support
   - Review plugin logs for specific errors

3. **Performance Issues**
   - Use fewer plugins for faster execution
   - Consider plugin-specific optimizations
   - Monitor resource usage

### Debug Information

Enable debug logging to see plugin selection details:
```bash
python main.py scan -f collection.json --plugins SecurityHeadersChecker --debug
```

This will show:
- Which plugins are loaded
- Which plugins are skipped
- Plugin execution details

## Integration Examples

### GitHub Actions

```yaml
- name: Security Headers Check
  run: |
    python main.py scan -f api-collection.json \
      --plugins SecurityHeadersChecker \
      --export-xml security-headers.xml

- name: JWT Security Analysis
  run: |
    python main.py scan -f api-collection.json \
      --plugins JWTSecurityChecker \
      --export-json jwt-analysis.json
```

### Docker Usage

```bash
# Run specific plugins in Docker
docker run --rm -v $(pwd):/workspace api-security-scanner \
  scan -f /workspace/collection.json \
  --plugins SecurityHeadersChecker,CORSChecker \
  --export-pdf /workspace/security-analysis.pdf
```

### Automated Scripts

```bash
#!/bin/bash
# Automated security testing script

COLLECTION="api-collection.json"
REPORT_DIR="security-reports"

# Security Headers Check
python main.py scan -f $COLLECTION \
  --plugins SecurityHeadersChecker \
  --export-pdf "$REPORT_DIR/headers-$(date +%Y%m%d).pdf"

# CORS Security Check
python main.py scan -f $COLLECTION \
  --plugins CORSChecker \
  --export-excel "$REPORT_DIR/cors-$(date +%Y%m%d).xlsx"

# JWT Security Check
python main.py scan -f $COLLECTION \
  --plugins JWTSecurityChecker \
  --export-xml "$REPORT_DIR/jwt-$(date +%Y%m%d).xml"
```

---

For more information, see the main [README.md](../README.md) or contact the development team.
