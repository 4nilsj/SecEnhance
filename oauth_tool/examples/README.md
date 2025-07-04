# OAuth/OIDC Test Scenarios

This directory contains example test scenarios for the OAuth/OIDC Security Testing Tool.

## Available Scenarios

### 1. **Provider-Specific Tests**
- **Google OAuth** (`test_google_oauth()`): Test Google's OAuth 2.0/OIDC implementation
- **Azure AD** (`test_azure_ad()`): Test Microsoft Azure AD OAuth 2.0/OIDC
- **Okta** (`test_okta()`): Test Okta's OAuth 2.0/OIDC implementation

### 2. **Vulnerability-Specific Tests**
- **Open Redirect** (`test_open_redirect_scenario()`): Test for open redirect vulnerabilities
- **CSRF** (`test_csrf_scenario()`): Test for CSRF vulnerabilities
- **Scope Escalation** (`test_scope_escalation_scenario()`): Test for scope escalation
- **PKCE** (`test_pkce_scenario()`): Test PKCE implementation

### 3. **Comprehensive Audit**
- **Full Security Audit** (`test_comprehensive_security_audit()`): Complete end-to-end security assessment

## Setup Instructions

### 1. Install Dependencies
```bash
cd oauth_tool
pip install -r requirements.txt
```

### 2. Configure Your OAuth Application
Before running the tests, you need to:

1. **Create an OAuth application** in your chosen provider (Google, Azure AD, Okta, etc.)
2. **Get your credentials**:
   - Client ID
   - Client Secret (if applicable)
   - Redirect URI
3. **Update the configuration** in the test scenario you want to run

### 3. Example Configuration
```python
config = {
    "issuer": "https://accounts.google.com",  # Your OAuth provider
    "client_id": "your_actual_client_id",     # Replace with your client ID
    "client_secret": "your_actual_secret",    # Replace with your secret
    "redirect_uri": "http://localhost:8080/callback",
    "scope": "openid profile email"
}
```

## Running the Tests

### Method 1: Run Specific Scenario
```bash
cd oauth_tool/examples
python test_scenarios.py
```

Then uncomment the scenario you want to run in the `main()` function:
```python
# Uncomment the scenario you want to run:
test_comprehensive_security_audit()
# test_google_oauth()
# test_azure_ad()
# test_okta()
```

### Method 2: Run from Python Console
```python
from test_scenarios import test_comprehensive_security_audit
test_comprehensive_security_audit()
```

### Method 3: Use the CLI Tool Directly
```bash
cd oauth_tool
python src/oauth_oidc_tester.py --issuer https://your-provider.com --client-id your_client_id --redirect-uri http://localhost:8080/callback
```

## Test Scenarios Explained

### Google OAuth Test
- Tests Google's OAuth 2.0/OIDC implementation
- Requires Google Cloud Console OAuth 2.0 credentials
- Tests discovery, vulnerability checks, and fuzzing

### Azure AD Test
- Tests Microsoft Azure AD OAuth 2.0/OIDC
- Requires Azure AD app registration
- Tests enterprise OAuth implementations

### Okta Test
- Tests Okta's OAuth 2.0/OIDC implementation
- Requires Okta developer account
- Tests modern OAuth provider security

### Vulnerability-Specific Tests
These tests focus on specific attack vectors:
- **Open Redirect**: Tests if malicious redirect URIs are accepted
- **CSRF**: Tests if state parameter validation is properly implemented
- **Scope Escalation**: Tests if escalated scopes can be requested
- **PKCE**: Tests PKCE implementation and downgrade attacks

### Comprehensive Audit
Runs all tests in sequence:
1. Discovery and metadata analysis
2. Authorization flow testing
3. Token handling and validation
4. Vulnerability assessment
5. Fuzzing and parameter manipulation
6. Comprehensive report generation

## Expected Output

Each test will generate:
- Console output showing test progress
- Detailed JSON report with findings
- Risk assessment and recommendations
- Technical details and remediation steps

## Security Notice

⚠️ **IMPORTANT**: 
- Only test OAuth/OIDC implementations you own or have explicit permission to test
- These tests are for security research and assessment purposes
- Some tests may trigger security alerts in production systems
- Always follow responsible disclosure practices

## Troubleshooting

### Common Issues

1. **Discovery Failed**: Check if the issuer URL is correct and accessible
2. **Authentication Errors**: Verify your client ID and secret are correct
3. **Network Errors**: Ensure you have internet access and the OAuth provider is reachable
4. **Permission Errors**: Make sure your OAuth app has the necessary permissions

### Getting Help

If you encounter issues:
1. Check the console output for error messages
2. Verify your OAuth application configuration
3. Ensure all dependencies are installed
4. Check network connectivity to the OAuth provider

## Customization

You can customize the tests by:
- Modifying the configuration parameters
- Adding new test scenarios
- Adjusting fuzzing vectors
- Customizing vulnerability checks
- Modifying report formats 