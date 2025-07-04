# OAuth/OIDC Security Testing Tool - Usage Guide

This guide provides comprehensive instructions for using the OAuth/OIDC Security Testing Tool effectively.

## Quick Start

### Basic Command Structure
```bash
python src/oauth_oidc_tester.py --issuer <OAuth_PROVIDER_URL> --client-id <YOUR_CLIENT_ID> --redirect-uri <CALLBACK_URL>
```

### Example: Test Google OAuth
```bash
python src/oauth_oidc_tester.py \
  --issuer https://accounts.google.com \
  --client-id your_google_client_id \
  --client-secret your_google_client_secret \
  --redirect-uri http://localhost:8080/callback \
  --output google_oauth_report.json
```

## Command Line Options

### Required Parameters
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--issuer` | OIDC issuer base URL | `https://accounts.google.com` |
| `--client-id` | OAuth client ID | `123456789.apps.googleusercontent.com` |
| `--redirect-uri` | OAuth redirect URI | `http://localhost:8080/callback` |

### Optional Parameters
| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--client-secret` | OAuth client secret | None | `your_secret_here` |
| `--scope` | OAuth scopes | `openid profile email` | `openid profile email admin` |
| `--output` | Output report file | Auto-generated | `my_report.json` |
| `--mode` | Run mode | `cli` | `interactive` |

## Usage Scenarios

### Scenario 1: Basic Discovery and Vulnerability Check

**Objective**: Test OIDC discovery and basic vulnerability scanning without full OAuth flow.

```bash
# Step 1: Run discovery only
python src/oauth_oidc_tester.py \
  --issuer https://your-oauth-provider.com \
  --client-id your_client_id \
  --redirect-uri http://localhost:8080/callback

# This will:
# ✅ Discover OIDC metadata
# ✅ Fetch JWKS keys
# ✅ Test for common vulnerabilities
# ✅ Generate a report
```

**Expected Output**:
```
🔒 OAuth/OIDC Security Testing Tool
============================================================
🔍 Discovering OIDC metadata for: https://your-oauth-provider.com
✅ OIDC metadata fetched
authorization_endpoint: https://your-oauth-provider.com/oauth/authorize
token_endpoint: https://your-oauth-provider.com/oauth/token
jwks_uri: https://your-oauth-provider.com/.well-known/jwks.json
✅ JWKS keys fetched (3 keys)
🔍 Checking for common OAuth/OIDC vulnerabilities...
⚠️ Testing for open redirects...
⚠️ Testing for CSRF vulnerabilities...
⚠️ Testing for scope escalation...
📊 OAuth/OIDC Security Test Summary
============================================================
🔍 Total Vulnerabilities: 2
🚨 High Severity: 1
⚠️ Medium Severity: 1
🎯 Overall Risk: Critical
✅ Comprehensive report saved: oauth_oidc_security_report_20241201_143022.json
```

### Scenario 2: Complete OAuth Flow Testing

**Objective**: Test the complete OAuth authorization code flow with token exchange.

```bash
# Step 1: Run with client secret for token exchange
python src/oauth_oidc_tester.py \
  --issuer https://your-oauth-provider.com \
  --client-id your_client_id \
  --client-secret your_client_secret \
  --redirect-uri http://localhost:8080/callback \
  --scope "openid profile email" \
  --output complete_flow_report.json
```

**Manual Steps Required**:
1. The tool will display an authorization URL
2. Open the URL in your browser
3. Complete the OAuth authentication
4. Copy the authorization code from the redirect URL
5. Paste it back into the tool
6. The tool will exchange the code for tokens and analyze them

### Scenario 3: Interactive Mode

**Objective**: Step-by-step testing with user interaction.

```bash
# Step 1: Run in interactive mode
python src/oauth_oidc_tester.py \
  --issuer https://your-oauth-provider.com \
  --client-id your_client_id \
  --redirect-uri http://localhost:8080/callback \
  --mode interactive
```

**Interactive Flow**:
```
🔒 OAuth/OIDC Security Testing Tool - Interactive Mode
==================================================
🔍 Discovering OIDC metadata for: https://your-oauth-provider.com
✅ OIDC metadata fetched

Choose your next action:
1. Run vulnerability checks
2. Test authorization flow
3. Fuzz parameters
4. Generate report
5. Exit

Enter your choice (1-5): 1
```

### Scenario 4: Focused Vulnerability Testing

**Objective**: Test specific vulnerability types.

```bash
# Test for open redirects
python src/oauth_oidc_tester.py \
  --issuer https://your-oauth-provider.com \
  --client-id your_client_id \
  --redirect-uri https://attacker.com/callback \
  --output open_redirect_test.json

# Test for scope escalation
python src/oauth_oidc_tester.py \
  --issuer https://your-oauth-provider.com \
  --client-id your_client_id \
  --redirect-uri http://localhost:8080/callback \
  --scope "admin root superuser" \
  --output scope_escalation_test.json
```

## OAuth Provider-Specific Examples

### Google OAuth 2.0
```bash
python src/oauth_oidc_tester.py \
  --issuer https://accounts.google.com \
  --client-id "123456789.apps.googleusercontent.com" \
  --client-secret "your_google_client_secret" \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "openid profile email" \
  --output google_oauth_report.json
```

### Microsoft Azure AD
```bash
python src/oauth_oidc_tester.py \
  --issuer "https://login.microsoftonline.com/your_tenant_id/v2.0" \
  --client-id "your_azure_client_id" \
  --client-secret "your_azure_client_secret" \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "openid profile email" \
  --output azure_ad_report.json
```

### Okta
```bash
python src/oauth_oidc_tester.py \
  --issuer "https://your-domain.okta.com" \
  --client-id "your_okta_client_id" \
  --client-secret "your_okta_client_secret" \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "openid profile email" \
  --output okta_report.json
```

### Auth0
```bash
python src/oauth_oidc_tester.py \
  --issuer "https://your-domain.auth0.com" \
  --client-id "your_auth0_client_id" \
  --client-secret "your_auth0_client_secret" \
  --redirect-uri "http://localhost:8080/callback" \
  --scope "openid profile email" \
  --output auth0_report.json
```

## Understanding the Output

### Console Output
The tool provides real-time feedback during testing:

```
🔍 Discovering OIDC metadata for: https://example.com
✅ OIDC metadata fetched
⚠️ Testing for open redirects...
⚠️ Testing for CSRF vulnerabilities...
⚠️ Testing for scope escalation...
⚠️ Testing for PKCE downgrade...
⚠️ Testing for CORS misconfigurations...
📊 OAuth/OIDC Security Test Summary
============================================================
🔍 Total Vulnerabilities: 3
🚨 High Severity: 1
⚠️ Medium Severity: 2
🎯 Overall Risk: Critical
```

### JSON Report Structure
```json
{
  "oauth_oidc_security_report": {
    "title": "OAuth/OIDC Security Analysis Report",
    "generated_date": "2024-12-01T14:30:22.123456",
    "executive_summary": {
      "total_vulnerabilities": 3,
      "high_severity": 1,
      "medium_severity": 2,
      "low_severity": 0,
      "overall_risk_level": "Critical"
    },
    "detailed_results": {
      "metadata": { /* OIDC discovery results */ },
      "vulnerabilities": { /* Vulnerability findings */ },
      "fuzzing": { /* Fuzzing test results */ }
    },
    "recommendations": [
      "🚨 CRITICAL: Immediate action required for high-severity vulnerabilities",
      "🔐 Always use HTTPS for all OAuth/OIDC endpoints",
      "🛡️ Implement proper state parameter validation"
    ]
  }
}
```

## Best Practices

### 1. Testing Environment
- ✅ Test in development/staging environments first
- ✅ Use dedicated test OAuth applications
- ✅ Avoid testing production systems without permission
- ✅ Use virtual environments for isolation

### 2. OAuth Application Setup
- ✅ Create separate OAuth apps for testing
- ✅ Use appropriate redirect URIs (localhost for testing)
- ✅ Configure minimal required scopes
- ✅ Use strong client secrets

### 3. Security Considerations
- ⚠️ Never commit client secrets to version control
- ⚠️ Use environment variables for sensitive data
- ⚠️ Rotate client secrets regularly
- ⚠️ Monitor for suspicious activity

### 4. Report Analysis
- 📊 Review all vulnerability findings
- 📊 Prioritize high-severity issues
- 📊 Document remediation steps
- 📊 Share findings with development team

## Troubleshooting

### Common Issues

#### Issue 1: Discovery Fails
```bash
# Check if issuer URL is correct
curl https://your-oauth-provider.com/.well-known/openid-configuration

# Verify network connectivity
ping your-oauth-provider.com
```

#### Issue 2: Authentication Errors
```bash
# Verify client credentials
# Check OAuth app configuration
# Ensure redirect URI matches exactly
```

#### Issue 3: Token Exchange Fails
```bash
# Verify client secret is correct
# Check if PKCE is required
# Ensure authorization code is valid
```

#### Issue 4: Permission Denied
```bash
# Check OAuth app permissions
# Verify scopes are configured correctly
# Ensure user has necessary permissions
```

### Debug Mode
For detailed debugging, you can modify the source code to add more verbose output:

```python
# Add debug prints in the source code
print(f"DEBUG: Requesting URL: {url}")
print(f"DEBUG: Response status: {resp.status_code}")
print(f"DEBUG: Response headers: {resp.headers}")
```

## Advanced Usage

### Custom Fuzzing
You can extend the fuzzing vectors by modifying the source code:

```python
# In fuzz_and_manipulate function
custom_fuzz_vectors = {
    "state": ["custom_payload_1", "custom_payload_2"],
    "nonce": ["custom_nonce_1", "custom_nonce_2"]
}
```

### Batch Testing
For testing multiple OAuth providers:

```bash
#!/bin/bash
# batch_test.sh
providers=(
    "https://accounts.google.com"
    "https://login.microsoftonline.com/tenant_id/v2.0"
    "https://your-domain.okta.com"
)

for provider in "${providers[@]}"; do
    echo "Testing $provider"
    python src/oauth_oidc_tester.py \
        --issuer "$provider" \
        --client-id "your_client_id" \
        --redirect-uri "http://localhost:8080/callback" \
        --output "report_$(basename $provider).json"
done
```

### Integration with CI/CD
```yaml
# .github/workflows/oauth-security-test.yml
name: OAuth Security Test
on: [push, pull_request]
jobs:
  oauth-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - name: Install dependencies
        run: |
          pip install -r oauth_tool/requirements.txt
      - name: Run OAuth security test
        run: |
          python oauth_tool/src/oauth_oidc_tester.py \
            --issuer ${{ secrets.OAUTH_ISSUER }} \
            --client-id ${{ secrets.OAUTH_CLIENT_ID }} \
            --redirect-uri ${{ secrets.OAUTH_REDIRECT_URI }} \
            --output security_report.json
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: oauth-security-report
          path: security_report.json
```

## Next Steps

After mastering basic usage:

1. **Explore Examples**: Review `examples/test_scenarios.py`
2. **Customize Tests**: Modify fuzzing vectors and vulnerability checks
3. **Integrate with Tools**: Connect with other security testing tools
4. **Automate Testing**: Set up automated security testing pipelines
5. **Contribute**: Improve the tool with new features and tests

For additional help, refer to the examples directory or the main README.md file. 