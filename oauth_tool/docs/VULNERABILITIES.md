# OAuth/OIDC Vulnerabilities Guide

This document provides detailed information about the OAuth/OIDC vulnerabilities that the security testing tool detects, including their technical details, impact assessment, and remediation strategies.

## Vulnerability Categories

### 🔴 Critical Vulnerabilities

#### 1. Open Redirect Vulnerabilities

**Description**: The OAuth provider accepts malicious redirect URIs, allowing attackers to redirect users to phishing sites or steal authorization codes.

**Technical Details**:
- **Attack Vector**: Manipulation of `redirect_uri` parameter
- **Detection Method**: Testing with malicious redirect URIs
- **Risk Level**: Critical

**Test Cases**:
```bash
# Malicious redirect URIs tested:
- https://attacker.com/callback
- javascript:alert('xss')
- data:text/html,<script>alert('xss')</script>
- https://evil.com/steal?token=stolen
```

**Impact**:
- 🚨 Authorization code theft
- 🚨 User session hijacking
- 🚨 Phishing attacks
- 🚨 Account compromise

**Remediation**:
```javascript
// ✅ Secure implementation
const allowedRedirectUris = [
  'https://myapp.com/callback',
  'https://myapp.com/auth/callback'
];

function validateRedirectUri(redirectUri) {
  return allowedRedirectUris.includes(redirectUri);
}
```

#### 2. Scope Escalation

**Description**: The OAuth provider allows clients to request escalated scopes beyond their intended permissions.

**Technical Details**:
- **Attack Vector**: Manipulation of `scope` parameter
- **Detection Method**: Testing with escalated scope values
- **Risk Level**: Critical

**Test Cases**:
```bash
# Escalated scopes tested:
- admin
- root
- superuser
- all
- *
```

**Impact**:
- 🚨 Privilege escalation
- 🚨 Unauthorized access to sensitive data
- 🚨 Administrative access compromise
- 🚨 Data breach

**Remediation**:
```javascript
// ✅ Secure implementation
const allowedScopes = ['openid', 'profile', 'email'];
const clientScopes = {
  'client_id_1': ['openid', 'profile'],
  'client_id_2': ['openid', 'profile', 'email']
};

function validateScope(clientId, requestedScope) {
  const allowed = clientScopes[clientId] || [];
  const requested = requestedScope.split(' ');
  return requested.every(scope => allowed.includes(scope));
}
```

### 🟡 High Severity Vulnerabilities

#### 3. CSRF (Cross-Site Request Forgery)

**Description**: The OAuth provider doesn't properly validate the `state` parameter, making it vulnerable to CSRF attacks.

**Technical Details**:
- **Attack Vector**: Missing or weak state parameter validation
- **Detection Method**: Testing authorization requests without state parameter
- **Risk Level**: High

**Test Cases**:
```bash
# CSRF test scenarios:
- Authorization request without state parameter
- Weak state parameter (predictable values)
- Missing state validation on callback
```

**Impact**:
- 🚨 Unauthorized authorization
- 🚨 Account linking attacks
- 🚨 Session fixation
- 🚨 User impersonation

**Remediation**:
```javascript
// ✅ Secure implementation
const crypto = require('crypto');

// Generate secure state parameter
function generateState() {
  return crypto.randomBytes(32).toString('hex');
}

// Validate state parameter
function validateState(originalState, receivedState) {
  return crypto.timingSafeEqual(
    Buffer.from(originalState, 'hex'),
    Buffer.from(receivedState, 'hex')
  );
}
```

#### 4. PKCE (Proof Key for Code Exchange) Downgrade

**Description**: The OAuth provider accepts authorization requests without PKCE, even for public clients.

**Technical Details**:
- **Attack Vector**: Authorization code interception
- **Detection Method**: Testing authorization requests without PKCE parameters
- **Risk Level**: High

**Test Cases**:
```bash
# PKCE downgrade test:
- Authorization request without code_challenge
- Authorization request without code_challenge_method
- Token exchange without code_verifier
```

**Impact**:
- 🚨 Authorization code interception
- 🚨 Token theft
- 🚨 Account compromise
- 🚨 Man-in-the-middle attacks

**Remediation**:
```javascript
// ✅ Secure implementation
const crypto = require('crypto');

// Require PKCE for public clients
function validatePKCE(clientType, codeChallenge, codeVerifier) {
  if (clientType === 'public' && !codeChallenge) {
    throw new Error('PKCE required for public clients');
  }
  
  if (codeChallenge) {
    const expectedChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    
    return codeChallenge === expectedChallenge;
  }
  
  return true;
}
```

### 🟠 Medium Severity Vulnerabilities

#### 5. Missing Nonce Validation

**Description**: The OAuth provider doesn't require or validate the `nonce` parameter for ID token requests.

**Technical Details**:
- **Attack Vector**: ID token replay attacks
- **Detection Method**: Testing ID token requests without nonce
- **Risk Level**: Medium

**Test Cases**:
```bash
# Nonce validation test:
- ID token request without nonce parameter
- Missing nonce validation in ID token
- Replay of ID tokens
```

**Impact**:
- 🚨 ID token replay attacks
- 🚨 Session fixation
- 🚨 Authentication bypass
- 🚨 User impersonation

**Remediation**:
```javascript
// ✅ Secure implementation
const crypto = require('crypto');

// Generate nonce
function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

// Validate nonce in ID token
function validateNonce(expectedNonce, idTokenNonce) {
  return expectedNonce === idTokenNonce;
}
```

#### 6. Insecure Redirect URIs

**Description**: The OAuth provider accepts HTTP redirect URIs, which are vulnerable to man-in-the-middle attacks.

**Technical Details**:
- **Attack Vector**: HTTP redirect URIs
- **Detection Method**: Testing with HTTP redirect URIs
- **Risk Level**: Medium

**Test Cases**:
```bash
# Insecure redirect URI test:
- http://localhost/callback
- http://127.0.0.1/callback
- http://example.com/callback
```

**Impact**:
- 🚨 Man-in-the-middle attacks
- 🚨 Authorization code interception
- 🚨 Token theft
- 🚨 Network sniffing

**Remediation**:
```javascript
// ✅ Secure implementation
function validateRedirectUri(redirectUri) {
  // Require HTTPS
  if (!redirectUri.startsWith('https://')) {
    throw new Error('HTTPS required for redirect URIs');
  }
  
  // Validate against allowed URIs
  const allowedUris = [
    'https://myapp.com/callback',
    'https://myapp.com/auth/callback'
  ];
  
  return allowedUris.some(uri => redirectUri.startsWith(uri));
}
```

#### 7. CORS Misconfiguration

**Description**: The OAuth provider has overly permissive CORS settings, allowing cross-origin attacks.

**Technical Details**:
- **Attack Vector**: Cross-origin requests
- **Detection Method**: Testing CORS headers with malicious origins
- **Risk Level**: Medium

**Test Cases**:
```bash
# CORS misconfiguration test:
- OPTIONS request with malicious origin
- Check for Access-Control-Allow-Origin: *
- Validate CORS headers
```

**Impact**:
- 🚨 Cross-origin attacks
- 🚨 Information disclosure
- 🚨 Token leakage
- 🚨 API abuse

**Remediation**:
```javascript
// ✅ Secure implementation
const allowedOrigins = [
  'https://myapp.com',
  'https://admin.myapp.com'
];

function validateCORS(origin) {
  return allowedOrigins.includes(origin);
}

// Set CORS headers
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (validateCORS(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  next();
});
```

### 🔵 Low Severity Vulnerabilities

#### 8. Token Substitution

**Description**: The OAuth provider doesn't properly validate token ownership or client association.

**Technical Details**:
- **Attack Vector**: Token manipulation and substitution
- **Detection Method**: Manual testing with modified tokens
- **Risk Level**: Low

**Test Cases**:
```bash
# Token substitution test:
- Use tokens from other clients
- Modify token claims
- Replay expired tokens
- Use tokens with different audiences
```

**Impact**:
- 🚨 Unauthorized access
- 🚨 Data leakage
- 🚨 Privilege escalation
- 🚨 Session hijacking

**Remediation**:
```javascript
// ✅ Secure implementation
function validateToken(token, clientId) {
  const decoded = jwt.verify(token, publicKey);
  
  // Validate client ID
  if (decoded.aud !== clientId) {
    throw new Error('Invalid client ID');
  }
  
  // Validate issuer
  if (decoded.iss !== expectedIssuer) {
    throw new Error('Invalid issuer');
  }
  
  // Validate expiration
  if (decoded.exp < Date.now() / 1000) {
    throw new Error('Token expired');
  }
  
  return decoded;
}
```

#### 9. ID Token Injection

**Description**: The OAuth provider doesn't properly validate ID token signatures or claims.

**Technical Details**:
- **Attack Vector**: ID token manipulation
- **Detection Method**: Manual testing with modified ID tokens
- **Risk Level**: Low

**Test Cases**:
```bash
# ID token injection test:
- Modify ID token claims
- Use ID tokens with different algorithms
- Inject malicious claims
- Replay ID tokens
```

**Impact**:
- 🚨 User impersonation
- 🚨 Privilege escalation
- 🚨 Authentication bypass
- 🚨 Data manipulation

**Remediation**:
```javascript
// ✅ Secure implementation
function validateIDToken(idToken, nonce) {
  const decoded = jwt.verify(idToken, publicKey, {
    algorithms: ['RS256'],
    issuer: expectedIssuer,
    audience: clientId
  });
  
  // Validate nonce
  if (decoded.nonce !== nonce) {
    throw new Error('Invalid nonce');
  }
  
  // Validate signature
  if (!decoded.signature) {
    throw new Error('Invalid signature');
  }
  
  return decoded;
}
```

#### 10. Mix-up Attacks

**Description**: The OAuth provider doesn't properly validate the authorization server, allowing mix-up attacks.

**Technical Details**:
- **Attack Vector**: Multiple authorization servers
- **Detection Method**: Configuration analysis
- **Risk Level**: Low

**Test Cases**:
```bash
# Mix-up attack test:
- Check for multiple authorization servers
- Validate issuer consistency
- Test authorization server confusion
```

**Impact**:
- 🚨 Authorization server confusion
- 🚨 Token theft
- 🚨 Account compromise
- 🚨 Man-in-the-middle attacks

**Remediation**:
```javascript
// ✅ Secure implementation
const trustedIssuers = [
  'https://accounts.google.com',
  'https://login.microsoftonline.com'
];

function validateIssuer(issuer) {
  return trustedIssuers.includes(issuer);
}

// Store issuer in session
req.session.expectedIssuer = issuer;
```

## Testing Methodology

### Automated Testing
The tool performs automated tests for most vulnerabilities:

1. **Discovery Phase**: Fetch OIDC metadata and JWKS
2. **Vulnerability Scanning**: Test for common vulnerabilities
3. **Fuzzing**: Test parameter variations
4. **Report Generation**: Generate detailed security report

### Manual Testing
Some vulnerabilities require manual testing:

1. **Token Analysis**: Manual inspection of tokens
2. **Flow Testing**: Complete OAuth flow testing
3. **Configuration Review**: Manual review of OAuth configuration

## Remediation Priority

### Immediate Action Required (Critical)
1. **Open Redirect Vulnerabilities**
2. **Scope Escalation**
3. **CSRF Vulnerabilities**

### High Priority (Within 30 Days)
1. **PKCE Downgrade**
2. **Missing Nonce Validation**
3. **Insecure Redirect URIs**

### Medium Priority (Within 90 Days)
1. **CORS Misconfiguration**
2. **Token Substitution**
3. **ID Token Injection**

### Low Priority (Ongoing)
1. **Mix-up Attacks**
2. **Configuration Hardening**
3. **Monitoring and Logging**

## Security Best Practices

### OAuth Provider Configuration
```javascript
// ✅ Secure OAuth configuration
const oauthConfig = {
  // Require HTTPS
  requireHttps: true,
  
  // Validate redirect URIs
  validateRedirectUri: true,
  
  // Require state parameter
  requireState: true,
  
  // Require PKCE for public clients
  requirePKCE: true,
  
  // Validate nonce for ID tokens
  validateNonce: true,
  
  // Restrict scopes
  restrictScopes: true,
  
  // Set appropriate timeouts
  tokenExpiry: 3600,
  refreshTokenExpiry: 2592000
};
```

### Client Application Security
```javascript
// ✅ Secure client implementation
class SecureOAuthClient {
  constructor(config) {
    this.config = config;
    this.state = this.generateState();
    this.nonce = this.generateNonce();
    this.codeVerifier = this.generateCodeVerifier();
  }
  
  generateState() {
    return crypto.randomBytes(32).toString('hex');
  }
  
  generateNonce() {
    return crypto.randomBytes(16).toString('hex');
  }
  
  generateCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
  }
  
  generateCodeChallenge() {
    return crypto
      .createHash('sha256')
      .update(this.codeVerifier)
      .digest('base64url');
  }
  
  validateCallback(state, code) {
    if (state !== this.state) {
      throw new Error('Invalid state parameter');
    }
    
    return code;
  }
}
```

## Monitoring and Detection

### Security Monitoring
```javascript
// ✅ Security monitoring
const securityEvents = {
  // Monitor for suspicious activity
  suspiciousRedirects: [],
  failedAuthentications: [],
  scopeEscalations: [],
  tokenAbuse: []
};

function logSecurityEvent(event) {
  securityEvents[event.type].push({
    timestamp: new Date(),
    clientId: event.clientId,
    ipAddress: event.ipAddress,
    details: event.details
  });
  
  // Alert on critical events
  if (event.severity === 'critical') {
    sendSecurityAlert(event);
  }
}
```

### Logging Requirements
- Log all OAuth requests and responses
- Log security events and violations
- Log token usage and abuse attempts
- Monitor for unusual patterns

## Compliance and Standards

### OAuth 2.0 Security Best Practices
- Follow RFC 6819 (OAuth 2.0 Threat Model)
- Implement PKCE for public clients
- Validate all parameters and tokens
- Use secure redirect URIs

### OpenID Connect Security
- Follow OIDC security guidelines
- Validate ID tokens properly
- Use nonce for replay protection
- Implement proper session management

### Industry Standards
- OWASP OAuth 2.0 Security Cheat Sheet
- NIST Digital Identity Guidelines
- ISO/IEC 27001 Information Security
- SOC 2 Type II Compliance

## Additional Resources

### Documentation
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/rfc6819)
- [OpenID Connect Security](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Cheat_Sheet.html)

### Tools and Libraries
- [OAuth 2.0 Security Validator](https://github.com/oauth-2-security-validator)
- [JWT Security Library](https://github.com/auth0/node-jsonwebtoken)
- [OAuth 2.0 Client Libraries](https://oauth.net/code/)

### Security Testing
- [OAuth 2.0 Security Testing Guide](https://oauth.net/security-testing/)
- [Penetration Testing OAuth](https://owasp.org/www-project-web-security-testing-guide/)
- [Security Headers Testing](https://securityheaders.com/) 