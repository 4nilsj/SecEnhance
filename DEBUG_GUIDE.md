# Debug Guide for Security Testing Tools

This guide explains how to use the debug functionality in both the JWT Security Testing Tool and the OAuth/OIDC Security Testing Tool.

## Overview

Both tools now include comprehensive debug functionality that provides detailed logging and troubleshooting information. Debug mode helps you:

- **Troubleshoot issues** during testing
- **Understand the testing process** step-by-step
- **Debug network requests** and responses
- **Track token processing** and validation
- **Monitor vulnerability detection** logic
- **Log all operations** for later analysis

## JWT Security Testing Tool Debug

### Enabling Debug Mode

#### Command Line
```bash
# Enable debug mode with --debug flag
python src/jwt_security_tester.py --token YOUR_JWT_TOKEN --debug

# Debug with specific test
python src/jwt_security_tester.py --token YOUR_JWT_TOKEN --test structure --debug

# Debug with batch processing
python src/jwt_security_tester.py --file tokens.txt --debug
```

#### Programmatic Usage
```python
from jwt_security_tester import JWTSecurityTester, setup_debug_logging

# Setup debug logging
setup_debug_logging(debug=True)

# Create tester with debug enabled
tester = JWTSecurityTester(debug=True)

# Run tests
result = tester.analyze_token_structure(token)
```

### Debug Output

When debug mode is enabled, you'll see detailed information like:

```
[DEBUG] JWT Security Tester starting
[DEBUG] Arguments: {'token': 'eyJ...', 'debug': True, ...}
[DEBUG] JWTSecurityTester initialized with debug=True
[DEBUG] Loading common JWT secrets for testing
[DEBUG] Loaded 20 common secrets
[DEBUG] Starting token structure analysis
[DEBUG] Decoding token without verification: eyJhbGciOiJIUzI1NiIs...
[DEBUG] Token parts: header=37, payload=97, signature=43
[DEBUG] Decoded header: {'alg': 'HS256', 'typ': 'JWT'}
[DEBUG] Decoded payload: {'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}
[DEBUG] Token analysis: length=179, algorithm=HS256, claims=3
[DEBUG] Timestamp claim iat: 2018-01-18T21:30:22
[DEBUG] Token structure analysis completed
```

### Debug Log File

Debug information is also saved to `jwt_debug.log`:

```
2024-12-01 14:30:22,123 - DEBUG - JWT Security Tester starting
2024-12-01 14:30:22,124 - DEBUG - Arguments: {'token': 'eyJ...', 'debug': True}
2024-12-01 14:30:22,125 - DEBUG - JWTSecurityTester initialized with debug=True
...
```

### Testing Debug Functionality

Run the test script to see debug functionality in action:

```bash
cd jwt_tool
python test_debug.py
```

## OAuth/OIDC Security Testing Tool Debug

### Enabling Debug Mode

#### Command Line
```bash
# Enable debug mode with --debug flag
python src/oauth_oidc_tester.py \
  --issuer https://accounts.google.com \
  --client-id your_client_id \
  --redirect-uri http://localhost:8080/callback \
  --debug

# Debug with client secret
python src/oauth_oidc_tester.py \
  --issuer https://your-oauth-provider.com \
  --client-id your_client_id \
  --client-secret your_client_secret \
  --redirect-uri http://localhost:8080/callback \
  --debug
```

#### Programmatic Usage
```python
from oauth_oidc_tester import discover_metadata, setup_debug_logging

# Setup debug logging
setup_debug_logging(debug=True)

# Run OIDC discovery with debug
result = discover_metadata("https://accounts.google.com", debug=True)
```

### Debug Output

When debug mode is enabled, you'll see detailed information like:

```
[DEBUG] OAuth/OIDC Security Testing Tool starting
[DEBUG] Arguments: {'issuer': 'https://accounts.google.com', 'debug': True, ...}
[DEBUG] Starting OIDC metadata discovery
[DEBUG] Starting OIDC metadata discovery for issuer: https://accounts.google.com
[DEBUG] Configuration URL: https://accounts.google.com/.well-known/openid-configuration
[DEBUG] Making HTTP request to OIDC configuration endpoint
[DEBUG] Response status: 200
[DEBUG] Response headers: {'content-type': 'application/json', ...}
[DEBUG] OIDC metadata received: {'authorization_endpoint': '...', ...}
[DEBUG] Endpoint authorization_endpoint: https://accounts.google.com/o/oauth2/auth
[DEBUG] Endpoint token_endpoint: https://oauth2.googleapis.com/token
[DEBUG] Fetching JWKS from: https://www.googleapis.com/oauth2/v3/certs
[DEBUG] JWKS response status: 200
[DEBUG] JWKS keys received: 3 keys
[DEBUG] OIDC metadata discovery completed successfully
```

### Debug Log File

Debug information is also saved to `oauth_debug.log`:

```
2024-12-01 14:30:22,123 - DEBUG - OAuth/OIDC Security Testing Tool starting
2024-12-01 14:30:22,124 - DEBUG - Arguments: {'issuer': 'https://accounts.google.com', ...}
2024-12-01 14:30:22,125 - DEBUG - Starting OIDC metadata discovery
...
```

### Testing Debug Functionality

Run the test script to see debug functionality in action:

```bash
cd oauth_tool
python test_debug.py
```

## Debug Features

### 1. HTTP Request/Response Logging

Both tools log detailed HTTP information:

```
[DEBUG] Making HTTP request to OIDC configuration endpoint
[DEBUG] Response status: 200
[DEBUG] Response headers: {'content-type': 'application/json', 'cache-control': 'public, max-age=3600'}
[DEBUG] Response body: {"authorization_endpoint":"https://..."}
```

### 2. Token Processing

JWT tool logs token processing steps:

```
[DEBUG] Decoding token without verification: eyJhbGciOiJIUzI1NiIs...
[DEBUG] Token parts: header=37, payload=97, signature=43
[DEBUG] Decoded header: {'alg': 'HS256', 'typ': 'JWT'}
[DEBUG] Decoded payload: {'sub': '1234567890', 'name': 'John Doe'}
```

### 3. OAuth Flow Tracking

OAuth tool logs the complete authorization flow:

```
[DEBUG] Starting OAuth authorization flow simulation
[DEBUG] Generated state: abc123def456
[DEBUG] Generated nonce: xyz789uvw012
[DEBUG] Authorization URL parameters: {'client_id': '...', 'redirect_uri': '...'}
[DEBUG] Authorization URL: https://accounts.google.com/o/oauth2/auth?...
[DEBUG] Received authorization code: 4/0AfJohXn...
[DEBUG] Starting token handling and validation
[DEBUG] Token endpoint: https://oauth2.googleapis.com/token
[DEBUG] Token request data: {'grant_type': 'authorization_code', ...}
[DEBUG] Making token exchange request
[DEBUG] Token exchange response status: 200
[DEBUG] Token response received: {'access_token': '...', 'id_token': '...'}
```

### 4. Vulnerability Testing

Both tools log vulnerability testing steps:

```
[DEBUG] Testing for algorithm confusion attacks...
[DEBUG] Testing algorithm: none
[DEBUG] Testing algorithm: HS256
[DEBUG] Testing for open redirects...
[DEBUG] Testing malicious redirect: https://attacker.com/callback
[DEBUG] Response status: 302
[DEBUG] Location header: https://attacker.com/callback?code=...
```

### 5. Error Tracking

Detailed error information is logged:

```
[DEBUG] Error decoding token: Invalid JWT format
[DEBUG] Token exchange failed: 400 Bad Request
[DEBUG] OIDC metadata discovery failed: Connection timeout
```

## Debug Configuration

### Environment Variables

You can control debug behavior with environment variables:

```bash
# Set debug level
export DEBUG_LEVEL=DEBUG

# Set log file location
export DEBUG_LOG_FILE=./debug.log

# Enable verbose output
export VERBOSE=1
```

### Log File Management

Debug logs are automatically created in the current directory:

- `jwt_debug.log` - JWT tool debug logs
- `oauth_debug.log` - OAuth tool debug logs

To manage log files:

```bash
# Clear old debug logs
rm -f jwt_debug.log oauth_debug.log

# Archive debug logs
mv jwt_debug.log jwt_debug_$(date +%Y%m%d_%H%M%S).log
mv oauth_debug.log oauth_debug_$(date +%Y%m%d_%H%M%S).log
```

## Troubleshooting with Debug Mode

### Common Issues and Debug Solutions

#### 1. Network Connectivity Issues

**Problem**: OIDC discovery fails
**Debug Solution**: Check HTTP request/response logs

```bash
python src/oauth_oidc_tester.py --issuer https://example.com --client-id test --redirect-uri http://localhost/callback --debug
```

Look for:
```
[DEBUG] Making HTTP request to OIDC configuration endpoint
[DEBUG] Response status: 404  # or other error codes
```

#### 2. JWT Token Issues

**Problem**: Token validation fails
**Debug Solution**: Check token processing logs

```bash
python src/jwt_security_tester.py --token YOUR_TOKEN --debug
```

Look for:
```
[DEBUG] Decoding token without verification: eyJ...
[DEBUG] Token parts: header=37, payload=97, signature=43
[DEBUG] Decoded header: {'alg': 'HS256', 'typ': 'JWT'}
```

#### 3. OAuth Flow Issues

**Problem**: Authorization flow fails
**Debug Solution**: Check OAuth flow logs

```bash
python src/oauth_oidc_tester.py --issuer https://accounts.google.com --client-id YOUR_CLIENT_ID --redirect-uri http://localhost/callback --debug
```

Look for:
```
[DEBUG] Starting OAuth authorization flow simulation
[DEBUG] Authorization URL: https://accounts.google.com/o/oauth2/auth?...
[DEBUG] Token exchange response status: 400
```

#### 4. Vulnerability Detection Issues

**Problem**: Expected vulnerabilities not detected
**Debug Solution**: Check vulnerability testing logs

Look for:
```
[DEBUG] Testing for open redirects...
[DEBUG] Testing malicious redirect: https://attacker.com/callback
[DEBUG] Response status: 302
[DEBUG] Location header: https://attacker.com/callback?code=...
```

## Performance Considerations

### Debug Mode Impact

Debug mode adds some overhead:

- **Logging overhead**: ~5-10% performance impact
- **File I/O**: Additional disk writes for log files
- **Memory usage**: Slight increase due to debug data storage

### Production Usage

For production environments:

1. **Disable debug mode** in production
2. **Use selective logging** for specific issues
3. **Monitor log file sizes** and rotate as needed
4. **Secure log files** as they may contain sensitive information

### Selective Debugging

You can enable debug mode for specific operations:

```python
# Debug only token processing
tester = JWTSecurityTester(debug=False)
result = tester.analyze_token_structure(token)  # No debug
debug_print("Custom debug message", debug=True)  # Debug only this
```

## Best Practices

### 1. Use Debug Mode During Development

- Enable debug mode when developing new features
- Use debug output to understand tool behavior
- Debug mode helps identify issues early

### 2. Debug in Isolated Environment

- Test debug functionality in development/staging
- Avoid running debug mode on production systems
- Use test tokens and endpoints for debugging

### 3. Secure Debug Information

- Debug logs may contain sensitive information
- Secure log files with appropriate permissions
- Rotate and archive debug logs regularly
- Don't commit debug logs to version control

### 4. Use Debug for Troubleshooting

- Enable debug mode when encountering issues
- Check debug logs for error details
- Use debug output to verify tool behavior
- Debug mode helps identify configuration issues

## Examples

### Complete Debug Example - JWT Tool

```bash
# Run JWT tool with debug
python src/jwt_security_tester.py \
  --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c \
  --test all \
  --debug
```

### Complete Debug Example - OAuth Tool

```bash
# Run OAuth tool with debug
python src/oauth_oidc_tester.py \
  --issuer https://accounts.google.com \
  --client-id your_client_id \
  --client-secret your_client_secret \
  --redirect-uri http://localhost:8080/callback \
  --debug
```

### Programmatic Debug Example

```python
# JWT Tool
from jwt_security_tester import JWTSecurityTester, setup_debug_logging

setup_debug_logging(debug=True)
tester = JWTSecurityTester(debug=True)
result = tester.comprehensive_test(token)

# OAuth Tool
from oauth_oidc_tester import discover_metadata, setup_debug_logging

setup_debug_logging(debug=True)
result = discover_metadata("https://accounts.google.com", debug=True)
```

## Conclusion

Debug functionality provides comprehensive visibility into the security testing process. Use it to:

- **Troubleshoot issues** quickly and effectively
- **Understand tool behavior** and processing steps
- **Verify test results** and vulnerability detection
- **Develop and test** new features
- **Monitor performance** and identify bottlenecks

Remember to use debug mode responsibly and secure debug logs appropriately. 