# OWASP API Top 10 Security Plugins

This document provides comprehensive information about the OWASP API Top 10 security plugins implemented in the API Security Scanner.

## Overview

The API Security Scanner includes dedicated plugins for detecting vulnerabilities from the OWASP API Top 10 list, providing comprehensive coverage of the most critical API security risks.

## Available Plugins

### 1. BOLAChecker - Broken Object Level Authorization

**OWASP Category**: API1: Broken Object Level Authorization

**Description**: Detects Broken Object Level Authorization (BOLA) vulnerabilities, including Insecure Direct Object References (IDOR) and unauthorized access to other users' resources.

**Key Features**:
- Sequential ID access testing
- Predictable ID pattern detection
- Other user resource access testing
- Horizontal privilege escalation detection
- Vertical privilege escalation detection

**Vulnerabilities Detected**:
- Access to other users' data by modifying object IDs
- Predictable object identifiers
- Missing authorization checks
- Privilege escalation vulnerabilities

**Example Usage**:
```bash
# Run BOLA security checks
python main.py scan -f collection.json --plugins BOLAChecker

# Run with authentication
python main.py scan -f collection.json --plugins BOLAChecker -a header -n "Authorization" -v "Bearer token"
```

### 2. SSRFSecurityChecker - Server-Side Request Forgery

**OWASP Category**: API8: Injection (SSRF)

**Description**: Detects Server-Side Request Forgery (SSRF) vulnerabilities where the API makes requests to external or internal resources based on user input.

**Key Features**:
- External URL access testing
- Localhost access detection
- File URL access testing
- Internal network access detection
- Cloud metadata access testing
- Protocol smuggling detection
- Port scanning detection

**Vulnerabilities Detected**:
- SSRF to external domains
- SSRF to localhost/internal networks
- File system access via file:// URLs
- Cloud metadata service access
- Protocol smuggling attacks
- Port scanning capabilities

**Example Usage**:
```bash
# Run SSRF security checks
python main.py scan -f collection.json --plugins SSRFSecurityChecker

# Test with specific parameters
python main.py scan -f collection.json --plugins SSRFSecurityChecker -a header -n "X-API-Key" -v "key"
```

### 3. BrokenAuthenticationChecker - Broken Authentication

**OWASP Category**: API2: Broken Authentication

**Description**: Detects authentication vulnerabilities including weak authentication mechanisms, session management issues, and authentication bypasses.

**Key Features**:
- Missing authentication detection
- Weak authentication mechanism analysis
- Session management security testing
- Password policy validation
- Authentication bypass detection
- SQL injection in authentication testing
- Role escalation detection
- Admin privilege escalation testing

**Vulnerabilities Detected**:
- Missing or weak authentication
- Session fixation vulnerabilities
- Weak password policies
- Authentication bypass techniques
- SQL injection in login forms
- Role escalation vulnerabilities
- Admin privilege escalation

**Example Usage**:
```bash
# Run authentication security checks
python main.py scan -f collection.json --plugins BrokenAuthenticationChecker

# Test with login endpoints
python main.py scan -f auth-endpoints.json --plugins BrokenAuthenticationChecker
```

### 4. ExcessiveDataExposureChecker - Excessive Data Exposure

**OWASP Category**: API3: Excessive Data Exposure

**Description**: Detects when APIs return more data than necessary, including sensitive information exposure in responses.

**Key Features**:
- Sensitive data pattern detection (credit cards, SSNs, emails, etc.)
- Response header analysis
- Error response information disclosure detection
- Unnecessary field detection
- Large dataset detection without pagination

**Vulnerabilities Detected**:
- Credit card number exposure
- Social Security Number (SSN) exposure
- Email address exposure
- Phone number exposure
- API key exposure
- Database connection string exposure
- Internal IP address exposure
- File path exposure
- JWT token exposure
- Password field exposure
- Detailed error information exposure
- Unnecessary debug fields

**Example Usage**:
```bash
# Run data exposure security checks
python main.py scan -f collection.json --plugins ExcessiveDataExposureChecker

# Focus on user data endpoints
python main.py scan -f user-endpoints.json --plugins ExcessiveDataExposureChecker
```

## Advanced Security Plugins

### 5. GraphQLSecurityChecker - GraphQL Security

**Description**: Detects GraphQL-specific security vulnerabilities including introspection, query complexity, and injection attacks.

**Key Features**:
- GraphQL endpoint detection
- Introspection query testing
- Query complexity analysis
- Query depth limit testing
- Alias and batch attack detection
- Fragment and union testing
- Directive security testing
- Subscription security testing
- Mutation security testing
- Injection attack detection
- Authorization bypass testing
- Information disclosure testing
- Rate limiting analysis

**Vulnerabilities Detected**:
- GraphQL introspection enabled
- Query complexity attacks
- Query depth limit bypass
- Alias and batch attacks
- Fragment and union attacks
- Directive manipulation
- Subscription vulnerabilities
- Mutation vulnerabilities
- GraphQL injection attacks
- Authorization bypasses
- Information disclosure
- Rate limiting issues

**Example Usage**:
```bash
# Run GraphQL security checks
python main.py scan -f graphql-collection.json --plugins GraphQLSecurityChecker

# Test GraphQL introspection
python main.py scan -f graphql-schema.json --plugins GraphQLSecurityChecker
```

### 6. gRPCSecurityChecker - gRPC Security

**Description**: Detects gRPC-specific security vulnerabilities including protobuf security, streaming vulnerabilities, and metadata security.

**Key Features**:
- gRPC endpoint detection
- Insecure transport detection
- Missing authentication detection
- Method enumeration testing
- Version disclosure detection
- Protobuf injection testing
- Deserialization security testing
- Field manipulation detection
- Size limit bypass testing
- Streaming DoS detection
- Resource exhaustion testing
- Timeout handling validation
- Metadata injection testing
- Reflection security testing

**Vulnerabilities Detected**:
- Insecure gRPC transport
- Missing authentication
- Method enumeration
- Version disclosure
- Protobuf injection
- Unsafe deserialization
- Field manipulation
- Size limit bypass
- Streaming DoS attacks
- Resource exhaustion
- Timeout vulnerabilities
- Metadata injection
- Reflection exposure

**Example Usage**:
```bash
# Run gRPC security checks
python main.py scan -f grpc-endpoints.json --plugins gRPCSecurityChecker

# Test gRPC reflection
python main.py scan -f grpc-reflection.json --plugins gRPCSecurityChecker
```

## Comprehensive Scanning

### Run All OWASP API Top 10 Plugins

```bash
# Run all OWASP API Top 10 security plugins
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker,BrokenAuthenticationChecker,ExcessiveDataExposureChecker

# Run with advanced plugins
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker,BrokenAuthenticationChecker,ExcessiveDataExposureChecker,GraphQLSecurityChecker,gRPCSecurityChecker
```

### Run with AI-Powered Detection

```bash
# Combine OWASP plugins with AI detection
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker,BrokenAuthenticationChecker,ExcessiveDataExposureChecker,AISecurityChecker

# Enable AI detection features
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker --ai-detection --ai-anomaly-detection --ai-vulnerability-classification
```

## Plugin Configuration

### Authentication Requirements

Some plugins require authentication to properly test authorization vulnerabilities:

```bash
# Run BOLA checks with authentication
python main.py scan -f collection.json --plugins BOLAChecker -a header -n "Authorization" -v "Bearer your-token"

# Run authentication checks with API key
python main.py scan -f collection.json --plugins BrokenAuthenticationChecker -a header -n "X-API-Key" -v "your-api-key"
```

### Output and Reporting

Generate detailed reports for OWASP API Top 10 findings:

```bash
# Generate HTML report
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker --export-html owasp-api-top10-report.html

# Generate PDF report
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker --export-pdf owasp-api-top10-report.pdf

# Generate Excel report
python main.py scan -f collection.json --plugins BOLAChecker,SSRFSecurityChecker --export-excel owasp-api-top10-report.xlsx
```

## Best Practices

### 1. Comprehensive Coverage
- Run all OWASP API Top 10 plugins for complete coverage
- Combine with traditional security plugins for comprehensive analysis
- Use AI-powered detection for advanced threat identification

### 2. Authentication Testing
- Always test with valid authentication tokens
- Test with different user roles and permissions
- Test both authenticated and unauthenticated scenarios

### 3. Environment-Specific Testing
- Test in development, staging, and production environments
- Use appropriate test data and endpoints
- Avoid testing against production systems with destructive payloads

### 4. Regular Scanning
- Integrate OWASP API Top 10 scanning into CI/CD pipelines
- Schedule regular security scans
- Monitor for new vulnerabilities and update plugins

## Troubleshooting

### Common Issues

1. **Authentication Failures**: Ensure valid authentication tokens are provided
2. **Rate Limiting**: Some plugins may trigger rate limiting; use appropriate delays
3. **False Positives**: Review findings and adjust plugin configurations as needed
4. **Performance**: Large collections may take time; consider running specific plugins

### Plugin-Specific Issues

- **BOLAChecker**: Requires valid user sessions to test authorization
- **SSRFSecurityChecker**: May trigger network monitoring alerts
- **GraphQLSecurityChecker**: Only activates when GraphQL endpoints are detected
- **gRPCSecurityChecker**: Requires gRPC-compatible endpoints

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: OWASP API Top 10 Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run OWASP API Top 10 Security Scan
        run: |
          python main.py scan -f api-collection.json \
            --plugins BOLAChecker,SSRFSecurityChecker,BrokenAuthenticationChecker,ExcessiveDataExposureChecker \
            --export-html security-report.html
      - name: Upload Security Report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.html
```

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP API Security Testing Guide](https://owasp.org/www-project-api-security-testing/)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)
