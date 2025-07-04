# OAuth/OIDC Security Testing Tool - API Reference

This document provides a comprehensive API reference for the OAuth/OIDC Security Testing Tool, including all functions, classes, and their parameters.

## Core Classes

### OAuthOIDCTester

The main class that orchestrates the OAuth/OIDC security testing process.

```python
class OAuthOIDCTester:
    def __init__(self, issuer: str, client_id: str, redirect_uri: str, 
                 client_secret: str = None, scope: str = "openid profile email"):
        """
        Initialize the OAuth/OIDC security tester.
        
        Args:
            issuer (str): OIDC issuer base URL
            client_id (str): OAuth client ID
            redirect_uri (str): OAuth redirect URI
            client_secret (str, optional): OAuth client secret
            scope (str, optional): OAuth scopes. Defaults to "openid profile email"
        """
```

#### Methods

##### `discover_oidc_metadata()`
Discovers OIDC metadata from the issuer.

```python
def discover_oidc_metadata(self) -> dict:
    """
    Discover OIDC metadata from the issuer.
    
    Returns:
        dict: OIDC metadata including endpoints and configuration
        
    Raises:
        OAuthDiscoveryError: If discovery fails
    """
```

**Returns**: Dictionary containing OIDC metadata
- `authorization_endpoint`: Authorization endpoint URL
- `token_endpoint`: Token endpoint URL
- `jwks_uri`: JWKS endpoint URL
- `issuer`: Issuer identifier
- `response_types_supported`: Supported response types
- `subject_types_supported`: Supported subject types
- `id_token_signing_alg_values_supported`: Supported signing algorithms

##### `fetch_jwks()`
Fetches JSON Web Key Set from the JWKS endpoint.

```python
def fetch_jwks(self) -> dict:
    """
    Fetch JSON Web Key Set from the JWKS endpoint.
    
    Returns:
        dict: JWKS containing public keys
        
    Raises:
        OAuthDiscoveryError: If JWKS fetch fails
    """
```

**Returns**: Dictionary containing JWKS data
- `keys`: List of JSON Web Keys
- `kid`: Key ID for each key
- `kty`: Key type (RSA, EC, etc.)
- `use`: Key usage (sig, enc)
- `alg`: Algorithm (RS256, ES256, etc.)

##### `check_vulnerabilities()`
Performs comprehensive vulnerability checks.

```python
def check_vulnerabilities(self) -> dict:
    """
    Perform comprehensive OAuth/OIDC vulnerability checks.
    
    Returns:
        dict: Vulnerability assessment results
    """
```

**Returns**: Dictionary containing vulnerability results
- `open_redirects`: Open redirect vulnerability findings
- `csrf`: CSRF vulnerability findings
- `scope_escalation`: Scope escalation findings
- `pkce_downgrade`: PKCE downgrade findings
- `missing_nonce`: Missing nonce validation findings
- `insecure_redirects`: Insecure redirect URI findings
- `cors_misconfig`: CORS misconfiguration findings

##### `fuzz_and_manipulate()`
Performs parameter fuzzing and manipulation tests.

```python
def fuzz_and_manipulate(self) -> dict:
    """
    Perform parameter fuzzing and manipulation tests.
    
    Returns:
        dict: Fuzzing test results
    """
```

**Returns**: Dictionary containing fuzzing results
- `authorization_params`: Authorization parameter fuzzing results
- `token_params`: Token parameter fuzzing results
- `token_manipulation`: Token manipulation test results
- `request_replay`: Request replay test results

##### `generate_report()`
Generates a comprehensive security report.

```python
def generate_report(self, output_file: str = None) -> dict:
    """
    Generate a comprehensive security report.
    
    Args:
        output_file (str, optional): Output file path. If None, auto-generates filename.
        
    Returns:
        dict: Complete security report
    """
```

**Returns**: Dictionary containing the complete security report
- `executive_summary`: High-level findings and risk assessment
- `detailed_results`: Detailed test results
- `recommendations`: Security recommendations
- `technical_details`: Technical implementation details

## Vulnerability Checker Classes

### OpenRedirectChecker

Checks for open redirect vulnerabilities.

```python
class OpenRedirectChecker:
    def __init__(self, authorization_endpoint: str, client_id: str, redirect_uri: str):
        """
        Initialize open redirect checker.
        
        Args:
            authorization_endpoint (str): Authorization endpoint URL
            client_id (str): OAuth client ID
            redirect_uri (str): Base redirect URI
        """
```

#### Methods

##### `test_malicious_redirects()`
Tests for malicious redirect URI acceptance.

```python
def test_malicious_redirects(self) -> list:
    """
    Test for malicious redirect URI acceptance.
    
    Returns:
        list: List of vulnerable redirect URIs
    """
```

**Returns**: List of dictionaries containing:
- `redirect_uri`: The malicious redirect URI tested
- `vulnerable`: Boolean indicating if vulnerable
- `response_code`: HTTP response code
- `response_body`: Response body content

### CSRFChecker

Checks for CSRF vulnerabilities.

```python
class CSRFChecker:
    def __init__(self, authorization_endpoint: str, client_id: str, redirect_uri: str):
        """
        Initialize CSRF checker.
        
        Args:
            authorization_endpoint (str): Authorization endpoint URL
            client_id (str): OAuth client ID
            redirect_uri (str): Redirect URI
        """
```

#### Methods

##### `test_state_validation()`
Tests state parameter validation.

```python
def test_state_validation(self) -> dict:
    """
    Test state parameter validation.
    
    Returns:
        dict: State validation test results
    """
```

**Returns**: Dictionary containing:
- `missing_state`: Boolean indicating if missing state is accepted
- `weak_state`: Boolean indicating if weak state is accepted
- `recommendations`: List of recommendations

### ScopeEscalationChecker

Checks for scope escalation vulnerabilities.

```python
class ScopeEscalationChecker:
    def __init__(self, authorization_endpoint: str, client_id: str, redirect_uri: str):
        """
        Initialize scope escalation checker.
        
        Args:
            authorization_endpoint (str): Authorization endpoint URL
            client_id (str): OAuth client ID
            redirect_uri (str): Redirect URI
        """
```

#### Methods

##### `test_escalated_scopes()`
Tests for scope escalation vulnerabilities.

```python
def test_escalated_scopes(self) -> list:
    """
    Test for scope escalation vulnerabilities.
    
    Returns:
        list: List of escalated scopes that were accepted
    """
```

**Returns**: List of dictionaries containing:
- `scope`: The escalated scope tested
- `accepted`: Boolean indicating if accepted
- `response_code`: HTTP response code
- `severity`: Severity level (high, medium, low)

## Fuzzing Classes

### AuthorizationFuzzer

Performs authorization parameter fuzzing.

```python
class AuthorizationFuzzer:
    def __init__(self, authorization_endpoint: str, client_id: str, redirect_uri: str):
        """
        Initialize authorization fuzzer.
        
        Args:
            authorization_endpoint (str): Authorization endpoint URL
            client_id (str): OAuth client ID
            redirect_uri (str): Redirect URI
        """
```

#### Methods

##### `fuzz_parameters()`
Fuzzes authorization parameters.

```python
def fuzz_parameters(self) -> dict:
    """
    Fuzz authorization parameters.
    
    Returns:
        dict: Fuzzing results for each parameter
    """
```

**Returns**: Dictionary containing fuzzing results for:
- `response_type`: Response type parameter fuzzing
- `client_id`: Client ID parameter fuzzing
- `redirect_uri`: Redirect URI parameter fuzzing
- `scope`: Scope parameter fuzzing
- `state`: State parameter fuzzing
- `nonce`: Nonce parameter fuzzing

### TokenFuzzer

Performs token parameter fuzzing.

```python
class TokenFuzzer:
    def __init__(self, token_endpoint: str, client_id: str, client_secret: str = None):
        """
        Initialize token fuzzer.
        
        Args:
            token_endpoint (str): Token endpoint URL
            client_id (str): OAuth client ID
            client_secret (str, optional): OAuth client secret
        """
```

#### Methods

##### `fuzz_token_parameters()`
Fuzzes token exchange parameters.

```python
def fuzz_token_parameters(self) -> dict:
    """
    Fuzz token exchange parameters.
    
    Returns:
        dict: Token parameter fuzzing results
    """
```

**Returns**: Dictionary containing fuzzing results for:
- `grant_type`: Grant type parameter fuzzing
- `code`: Authorization code parameter fuzzing
- `redirect_uri`: Redirect URI parameter fuzzing
- `client_id`: Client ID parameter fuzzing
- `client_secret`: Client secret parameter fuzzing

## Token Handler Classes

### TokenHandler

Handles OAuth token operations.

```python
class TokenHandler:
    def __init__(self, token_endpoint: str, client_id: str, client_secret: str = None):
        """
        Initialize token handler.
        
        Args:
            token_endpoint (str): Token endpoint URL
            client_id (str): OAuth client ID
            client_secret (str, optional): OAuth client secret
        """
```

#### Methods

##### `exchange_code_for_tokens()`
Exchanges authorization code for tokens.

```python
def exchange_code_for_tokens(self, authorization_code: str, 
                           redirect_uri: str, code_verifier: str = None) -> dict:
    """
    Exchange authorization code for tokens.
    
    Args:
        authorization_code (str): Authorization code from OAuth flow
        redirect_uri (str): Redirect URI used in authorization
        code_verifier (str, optional): PKCE code verifier
        
    Returns:
        dict: Token response containing access_token, id_token, etc.
        
    Raises:
        TokenExchangeError: If token exchange fails
    """
```

**Returns**: Dictionary containing:
- `access_token`: OAuth access token
- `id_token`: OpenID Connect ID token
- `refresh_token`: OAuth refresh token (if provided)
- `token_type`: Token type (usually "Bearer")
- `expires_in`: Token expiration time in seconds

##### `validate_tokens()`
Validates OAuth tokens.

```python
def validate_tokens(self, access_token: str = None, id_token: str = None) -> dict:
    """
    Validate OAuth tokens.
    
    Args:
        access_token (str, optional): OAuth access token
        id_token (str, optional): OpenID Connect ID token
        
    Returns:
        dict: Token validation results
    """
```

**Returns**: Dictionary containing validation results:
- `access_token_valid`: Boolean indicating if access token is valid
- `id_token_valid`: Boolean indicating if ID token is valid
- `access_token_claims`: Access token claims (if decodable)
- `id_token_claims`: ID token claims
- `validation_errors`: List of validation errors

## Report Generator Classes

### ReportGenerator

Generates comprehensive security reports.

```python
class ReportGenerator:
    def __init__(self, issuer: str, client_id: str):
        """
        Initialize report generator.
        
        Args:
            issuer (str): OIDC issuer
            client_id (str): OAuth client ID
        """
```

#### Methods

##### `generate_executive_summary()`
Generates executive summary of findings.

```python
def generate_executive_summary(self, vulnerabilities: dict, fuzzing_results: dict) -> dict:
    """
    Generate executive summary of findings.
    
    Args:
        vulnerabilities (dict): Vulnerability assessment results
        fuzzing_results (dict): Fuzzing test results
        
    Returns:
        dict: Executive summary
    """
```

**Returns**: Dictionary containing:
- `total_vulnerabilities`: Total number of vulnerabilities found
- `high_severity`: Number of high severity vulnerabilities
- `medium_severity`: Number of medium severity vulnerabilities
- `low_severity`: Number of low severity vulnerabilities
- `overall_risk_level`: Overall risk assessment (Critical, High, Medium, Low)

##### `generate_recommendations()`
Generates security recommendations.

```python
def generate_recommendations(self, vulnerabilities: dict) -> list:
    """
    Generate security recommendations based on findings.
    
    Args:
        vulnerabilities (dict): Vulnerability assessment results
        
    Returns:
        list: List of security recommendations
    """
```

**Returns**: List of recommendation strings, prioritized by severity

## Utility Classes

### HTTPClient

Handles HTTP requests for the security testing tool.

```python
class HTTPClient:
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        """
        Initialize HTTP client.
        
        Args:
            timeout (int): Request timeout in seconds
            max_retries (int): Maximum number of retries
        """
```

#### Methods

##### `get()`
Performs HTTP GET request.

```python
def get(self, url: str, headers: dict = None, params: dict = None) -> requests.Response:
    """
    Perform HTTP GET request.
    
    Args:
        url (str): Request URL
        headers (dict, optional): Request headers
        params (dict, optional): Query parameters
        
    Returns:
        requests.Response: HTTP response
        
    Raises:
        HTTPRequestError: If request fails
    """
```

##### `post()`
Performs HTTP POST request.

```python
def post(self, url: str, data: dict = None, headers: dict = None, 
         json: dict = None) -> requests.Response:
    """
    Perform HTTP POST request.
    
    Args:
        url (str): Request URL
        data (dict, optional): Form data
        headers (dict, optional): Request headers
        json (dict, optional): JSON data
        
    Returns:
        requests.Response: HTTP response
        
    Raises:
        HTTPRequestError: If request fails
    """
```

### JWTValidator

Validates JWT tokens.

```python
class JWTValidator:
    def __init__(self, jwks: dict):
        """
        Initialize JWT validator.
        
        Args:
            jwks (dict): JSON Web Key Set
        """
```

#### Methods

##### `validate_token()`
Validates a JWT token.

```python
def validate_token(self, token: str, audience: str = None, 
                  issuer: str = None) -> dict:
    """
    Validate a JWT token.
    
    Args:
        token (str): JWT token to validate
        audience (str, optional): Expected audience
        issuer (str, optional): Expected issuer
        
    Returns:
        dict: Validation results
    """
```

**Returns**: Dictionary containing:
- `valid`: Boolean indicating if token is valid
- `claims`: Token claims
- `header`: Token header
- `errors`: List of validation errors

## Error Classes

### OAuthDiscoveryError
Raised when OIDC discovery fails.

```python
class OAuthDiscoveryError(Exception):
    """Raised when OIDC discovery fails."""
    pass
```

### TokenExchangeError
Raised when token exchange fails.

```python
class TokenExchangeError(Exception):
    """Raised when token exchange fails."""
    pass
```

### HTTPRequestError
Raised when HTTP requests fail.

```python
class HTTPRequestError(Exception):
    """Raised when HTTP requests fail."""
    pass
```

### ValidationError
Raised when validation fails.

```python
class ValidationError(Exception):
    """Raised when validation fails."""
    pass
```

## Configuration

### Environment Variables

The tool supports the following environment variables:

```bash
# OAuth Configuration
OAUTH_ISSUER="https://your-oauth-provider.com"
OAUTH_CLIENT_ID="your_client_id"
OAUTH_CLIENT_SECRET="your_client_secret"
OAUTH_REDIRECT_URI="http://localhost:8080/callback"

# HTTP Configuration
HTTP_TIMEOUT=10
HTTP_MAX_RETRIES=3

# Output Configuration
OUTPUT_DIR="./reports"
LOG_LEVEL="INFO"
```

### Configuration File

You can also use a configuration file (`config.json`):

```json
{
  "oauth": {
    "issuer": "https://your-oauth-provider.com",
    "client_id": "your_client_id",
    "client_secret": "your_client_secret",
    "redirect_uri": "http://localhost:8080/callback",
    "scope": "openid profile email"
  },
  "http": {
    "timeout": 10,
    "max_retries": 3,
    "user_agent": "OAuth-Security-Tester/1.0"
  },
  "output": {
    "directory": "./reports",
    "format": "json",
    "include_timestamps": true
  },
  "testing": {
    "enable_fuzzing": true,
    "enable_vulnerability_checks": true,
    "enable_token_validation": true,
    "max_fuzz_iterations": 100
  }
}
```

## Usage Examples

### Basic Usage

```python
from oauth_oidc_tester import OAuthOIDCTester

# Initialize tester
tester = OAuthOIDCTester(
    issuer="https://accounts.google.com",
    client_id="your_client_id",
    redirect_uri="http://localhost:8080/callback"
)

# Run discovery
metadata = tester.discover_oidc_metadata()
print(f"Authorization endpoint: {metadata['authorization_endpoint']}")

# Check vulnerabilities
vulnerabilities = tester.check_vulnerabilities()
print(f"Found {len(vulnerabilities)} vulnerabilities")

# Generate report
report = tester.generate_report("security_report.json")
print("Report generated successfully")
```

### Advanced Usage

```python
from oauth_oidc_tester import OAuthOIDCTester, OpenRedirectChecker, CSRFChecker

# Initialize tester with client secret
tester = OAuthOIDCTester(
    issuer="https://your-oauth-provider.com",
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="http://localhost:8080/callback"
)

# Run comprehensive testing
metadata = tester.discover_oidc_metadata()
jwks = tester.fetch_jwks()
vulnerabilities = tester.check_vulnerabilities()
fuzzing_results = tester.fuzz_and_manipulate()

# Generate detailed report
report = tester.generate_report("comprehensive_report.json")

# Access specific results
open_redirects = vulnerabilities.get('open_redirects', [])
csrf_findings = vulnerabilities.get('csrf', {})
scope_escalation = vulnerabilities.get('scope_escalation', [])

print(f"Open redirects found: {len(open_redirects)}")
print(f"CSRF vulnerable: {csrf_findings.get('vulnerable', False)}")
print(f"Scope escalation attempts: {len(scope_escalation)}")
```

### Custom Vulnerability Checks

```python
from oauth_oidc_tester import OpenRedirectChecker, ScopeEscalationChecker

# Custom open redirect check
redirect_checker = OpenRedirectChecker(
    authorization_endpoint="https://oauth-provider.com/oauth/authorize",
    client_id="your_client_id",
    redirect_uri="http://localhost:8080/callback"
)

malicious_redirects = [
    "https://attacker.com/callback",
    "javascript:alert('xss')",
    "data:text/html,<script>alert('xss')</script>"
]

for redirect in malicious_redirects:
    result = redirect_checker.test_single_redirect(redirect)
    if result['vulnerable']:
        print(f"Vulnerable to open redirect: {redirect}")

# Custom scope escalation check
scope_checker = ScopeEscalationChecker(
    authorization_endpoint="https://oauth-provider.com/oauth/authorize",
    client_id="your_client_id",
    redirect_uri="http://localhost:8080/callback"
)

escalated_scopes = ["admin", "root", "superuser", "all"]
results = scope_checker.test_escalated_scopes()

for result in results:
    if result['accepted']:
        print(f"Scope escalation possible: {result['scope']}")
```

## Error Handling

### Common Error Scenarios

```python
from oauth_oidc_tester import OAuthOIDCTester, OAuthDiscoveryError, TokenExchangeError

try:
    tester = OAuthOIDCTester(
        issuer="https://invalid-issuer.com",
        client_id="invalid_client",
        redirect_uri="http://localhost:8080/callback"
    )
    
    metadata = tester.discover_oidc_metadata()
    
except OAuthDiscoveryError as e:
    print(f"Discovery failed: {e}")
    # Handle discovery failure
    
except TokenExchangeError as e:
    print(f"Token exchange failed: {e}")
    # Handle token exchange failure
    
except Exception as e:
    print(f"Unexpected error: {e}")
    # Handle other errors
```

### Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

tester = OAuthOIDCTester(
    issuer="https://your-oauth-provider.com",
    client_id="your_client_id",
    redirect_uri="http://localhost:8080/callback"
)

# Debug information will be logged
metadata = tester.discover_oidc_metadata()
```

## Performance Considerations

### Timeout Configuration

```python
# Configure timeouts for different operations
tester = OAuthOIDCTester(
    issuer="https://your-oauth-provider.com",
    client_id="your_client_id",
    redirect_uri="http://localhost:8080/callback"
)

# Set custom timeouts
tester.http_client.timeout = 30  # 30 seconds
tester.http_client.max_retries = 5  # 5 retries
```

### Batch Processing

```python
# Test multiple OAuth providers
providers = [
    "https://accounts.google.com",
    "https://login.microsoftonline.com/tenant_id/v2.0",
    "https://your-domain.okta.com"
]

results = {}

for provider in providers:
    try:
        tester = OAuthOIDCTester(
            issuer=provider,
            client_id="your_client_id",
            redirect_uri="http://localhost:8080/callback"
        )
        
        results[provider] = {
            'metadata': tester.discover_oidc_metadata(),
            'vulnerabilities': tester.check_vulnerabilities()
        }
        
    except Exception as e:
        results[provider] = {'error': str(e)}

# Save batch results
import json
with open('batch_results.json', 'w') as f:
    json.dump(results, f, indent=2)
```

This API reference provides comprehensive documentation for all classes, methods, and parameters in the OAuth/OIDC Security Testing Tool. For additional examples and use cases, refer to the examples directory and usage documentation. 