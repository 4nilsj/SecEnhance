# API Collection Testing Guide

This guide demonstrates how to use the API Security Scanner with various API collection formats including Postman collections, OpenAPI specifications, and curl commands.

## Overview

The API Security Scanner supports multiple input formats for comprehensive security testing:

- **Postman Collections** (JSON format)
- **OpenAPI/Swagger Specifications** (YAML/JSON format)
- **Curl Commands** (command-line format)

## Quick Start

### 1. Test with Postman Collection

```bash
python -m api_security_scanner.cli.main scan --file examples/sample_postman_collection.json
```

### 2. Test with OpenAPI Specification

```bash
python -m api_security_scanner.cli.main scan --file examples/sample_openapi.yaml
```

### 3. Test with Curl Command

```bash
python -m api_security_scanner.cli.main scan --curl "curl -X GET https://httpbin.org/get"
```

## Demo Scripts

### Simple Demo
Run the basic demonstration script:

```bash
python demo_api_collections.py
```

### Comprehensive Testing
Run the full test suite:

```bash
python test_api_collections.py
```

### Usage Examples
View all available usage examples:

```bash
python demo_api_collections.py --examples
```

## Supported Collection Formats

### Postman Collections

The scanner supports both Postman Collection v1 and v2.1 formats:

**Features:**
- Automatic request extraction from folders and subfolders
- Header parsing and authentication handling
- Body data extraction (raw, form-data, urlencoded)
- Variable substitution support

**Example Collection Structure:**
```json
{
  "info": {
    "name": "API Collection",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Users",
      "item": [
        {
          "name": "Get All Users",
          "request": {
            "method": "GET",
            "url": "{{base_url}}/api/users",
            "header": [
              {
                "key": "Accept",
                "value": "application/json"
              }
            ]
          }
        }
      ]
    }
  ],
  "variable": [
    {
      "key": "base_url",
      "value": "https://api.example.com"
    }
  ]
}
```

### OpenAPI/Swagger Specifications

Supports OpenAPI 3.0.x specifications in both YAML and JSON formats:

**Features:**
- Automatic endpoint discovery from paths
- Request body generation from schemas
- Parameter extraction (query, path, header)
- Security scheme handling
- Server URL resolution

**Example OpenAPI Structure:**
```yaml
openapi: 3.0.0
info:
  title: Sample API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /api/users:
    get:
      summary: Get all users
      responses:
        '200':
          description: Successful response
    post:
      summary: Create user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
```

### Curl Commands

Direct curl command parsing with full parameter support:

**Features:**
- HTTP method detection
- Header extraction
- Body data parsing
- Query parameter handling
- Authentication header support

**Example Curl Commands:**
```bash
# Simple GET request
curl -X GET "https://api.example.com/users"

# POST with JSON body
curl -X POST "https://api.example.com/users" \
  -H "Content-Type: application/json" \
  -d '{"name": "John", "email": "john@example.com"}'

# With authentication
curl -X GET "https://api.example.com/profile" \
  -H "Authorization: Bearer token123"
```

## Advanced Usage

### Authentication Support

The scanner supports various authentication methods:

```bash
# Header-based authentication
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --auth-type header \
  --auth-name Authorization \
  --auth-value "Bearer your-token-here"

# Cookie-based authentication
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --auth-type cookie \
  --auth-name session_id \
  --auth-value "abc123"

# Token-based authentication
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --auth-type token \
  --auth-name X-API-Key \
  --auth-value "your-api-key"
```

### Custom Reports

Generate custom reports with specific names:

```bash
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --export custom_report.html \
  --export-json custom_report.json
```

### Plugin Configuration

Control which security plugins to run:

```bash
# Run only custom plugins (skip ZAP)
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --no-zap

# Run only ZAP (skip custom plugins)
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --no-plugins

# Run with performance statistics
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  --performance-stats
```

## Test Collection Files

The `examples/` directory contains several test collection files:

### Available Test Files

1. **`sample_postman_collection.json`** - Basic Postman collection with user management endpoints
2. **`sample_openapi.yaml`** - OpenAPI specification with comprehensive API definition
3. **`test_collection.json`** - Extended Postman collection with various endpoint types
4. **`test_openapi.yaml`** - Comprehensive OpenAPI specification for testing

### Collection Features Tested

- **User Management**: Registration, login, profile management
- **Authentication**: Bearer tokens, API keys, basic auth
- **File Operations**: Upload, download, file management
- **Admin Functions**: User administration, system management
- **Public Endpoints**: Health checks, public data access

## Security Testing Results

The scanner performs comprehensive security testing including:

### Custom Security Plugins

1. **ComprehensiveSecurityChecker** - General security assessments
2. **CORSChecker** - Cross-Origin Resource Sharing validation
3. **EnhancedSecurityChecker** - Advanced security checks
4. **RateLimitingChecker** - Rate limiting and DoS protection
5. **SecurityHeadersChecker** - Security header validation

### ZAP Integration

- **Spider Scanning** - Automated endpoint discovery
- **Active Scanning** - Vulnerability detection
- **Passive Scanning** - Security policy validation

## Report Generation

The scanner generates comprehensive reports in multiple formats:

### HTML Reports
- Executive summary with risk assessment
- Detailed vulnerability information
- Proof-of-concept evidence
- Remediation recommendations
- Performance statistics

### JSON Reports
- Machine-readable format
- Complete scan metadata
- Structured vulnerability data
- Integration-friendly format

### Report Location
Reports are automatically saved to the `reports/` directory with timestamps:
```
reports/
├── scan_report_[scan_id]_[timestamp].html
├── scan_report_[scan_id]_[timestamp].json
└── ...
```

## Troubleshooting

### Common Issues

1. **DNS Resolution Errors**
   - Ensure target URLs are accessible
   - Check network connectivity
   - Verify URL format and variables

2. **Authentication Failures**
   - Verify authentication credentials
   - Check token expiration
   - Ensure proper header formatting

3. **Collection Parsing Errors**
   - Validate JSON/YAML syntax
   - Check collection format version
   - Verify required fields are present

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
python -m api_security_scanner.cli.main scan \
  --file collection.json \
  -vv  # Verbose debug output
```

## Best Practices

### Collection Preparation

1. **Use Real URLs**: Replace placeholder URLs with actual endpoints
2. **Include Authentication**: Add proper authentication headers/tokens
3. **Complete Requests**: Ensure all required fields are populated
4. **Test Connectivity**: Verify endpoints are accessible before scanning

### Security Testing

1. **Start with Custom Plugins**: Use `--no-zap` for faster initial testing
2. **Gradual Escalation**: Begin with low-risk endpoints
3. **Monitor Performance**: Use `--performance-stats` to track scan duration
4. **Review Reports**: Always examine generated reports for actionable insights

### Integration

1. **CI/CD Integration**: Use JSON reports for automated processing
2. **Scheduled Scanning**: Set up regular security assessments
3. **Report Archiving**: Maintain historical scan data
4. **Alert Integration**: Connect with monitoring systems

## Example Workflows

### Development Testing
```bash
# Quick security check during development
python -m api_security_scanner.cli.main scan \
  --file dev_collection.json \
  --no-zap \
  --export dev_security_report.html
```

### Production Assessment
```bash
# Comprehensive production security scan
python -m api_security_scanner.cli.main scan \
  --file prod_collection.json \
  --auth-type header \
  --auth-name Authorization \
  --auth-value "Bearer $PROD_TOKEN" \
  --performance-stats \
  --export prod_security_report.html
```

### API Documentation Testing
```bash
# Test against OpenAPI specification
python -m api_security_scanner.cli.main scan \
  --file api_spec.yaml \
  --export api_doc_security_report.html
```

## Conclusion

The API Security Scanner provides comprehensive security testing capabilities for various API collection formats. By following this guide, you can effectively test your APIs for security vulnerabilities and generate detailed reports for remediation.

For additional support or feature requests, please refer to the main project documentation or create an issue in the project repository.
