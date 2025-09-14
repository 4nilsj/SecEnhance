"""
JWT Security Checker Plugin
Comprehensive JWT token vulnerability detection and OAuth flow analysis.
"""

import re
import json
import base64
import hashlib
import hmac
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept, format_http_request, format_http_response


class JWTSecurityChecker(BasePlugin):
    """Comprehensive JWT security analysis plugin with OAuth flow detection."""
    
    name = "JWTSecurityChecker"
    description = "JWT token vulnerability detection and OAuth flow security analysis"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def __init__(self, zap=None, target=None):
        super().__init__(zap=zap, target=target)
        self.jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        self.bearer_pattern = re.compile(r'Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', re.IGNORECASE)
        self.oauth_patterns = {
            'authorization_code': re.compile(r'authorization_code', re.IGNORECASE),
            'client_credentials': re.compile(r'client_credentials', re.IGNORECASE),
            'password': re.compile(r'password', re.IGNORECASE),
            'refresh_token': re.compile(r'refresh_token', re.IGNORECASE),
            'implicit': re.compile(r'implicit', re.IGNORECASE)
        }
        
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform JWT security analysis on requests and responses."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request with authentication
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                response = self.make_request(url, method, headers, request.get('body') or '')
                
                if response:
                    # First, check if this request/response contains JWT or OAuth flows
                    if self._contains_jwt_or_oauth(request, response):
                        self.logger.info(f"JWT/OAuth detected in {url}, running security analysis")
                        
                        # Analyze JWT tokens in request
                        jwt_vulns = self._analyze_jwt_tokens(request, response, url, method, headers)
                        vulnerabilities.extend(jwt_vulns)
                        
                        # Analyze OAuth flows
                        oauth_vulns = self._analyze_oauth_flows(request, response, url, method, headers)
                        vulnerabilities.extend(oauth_vulns)
                        
                        # Check for JWT implementation vulnerabilities
                        impl_vulns = self._check_jwt_implementation_vulnerabilities(request, response, url, method, headers)
                        vulnerabilities.extend(impl_vulns)
                        
                        # Check for token storage vulnerabilities
                        storage_vulns = self._check_token_storage_vulnerabilities(request, response, url, method, headers)
                        vulnerabilities.extend(storage_vulns)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=f"JWT security check failed: {str(e)}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities,
            error=None
        )
    
    def _contains_jwt_or_oauth(self, request: Dict[str, Any], response: Any) -> bool:
        """Check if request/response contains JWT tokens or OAuth flows."""
        # Check request headers for JWT tokens
        headers = request.get('headers', {})
        for header_name, header_value in headers.items():
            if self._is_jwt_token(header_value):
                return True
        
        # Check request body for OAuth flows
        body = request.get('body', '')
        if body:
            try:
                if isinstance(body, str):
                    # Check for OAuth grant types
                    for grant_type, pattern in self.oauth_patterns.items():
                        if pattern.search(body):
                            return True
                    
                    # Check for JWT in body
                    if self._is_jwt_token(body):
                        return True
            except:
                pass
        
        # Check response for JWT tokens
        if response and hasattr(response, 'text'):
            response_text = response.text
            if self._is_jwt_token(response_text):
                return True
            
            # Check for OAuth-related content
            oauth_indicators = ['access_token', 'refresh_token', 'id_token', 'token_type', 'expires_in']
            for indicator in oauth_indicators:
                if indicator in response_text.lower():
                    return True
        
        return False
    
    def _is_jwt_token(self, text: str) -> bool:
        """Check if text contains a JWT token."""
        if not text:
            return False
        
        # Check for Bearer token format
        bearer_match = self.bearer_pattern.search(text)
        if bearer_match:
            return bool(self.jwt_pattern.match(bearer_match.group(1)))
        
        # Check for standalone JWT pattern
        return bool(self.jwt_pattern.search(text))
    
    def _extract_jwt_tokens(self, request: Dict[str, Any], response: Any) -> List[Dict[str, str]]:
        """Extract JWT tokens from request and response."""
        tokens = []
        
        # Extract from request headers
        headers = request.get('headers', {})
        for header_name, header_value in headers.items():
            if self._is_jwt_token(header_value):
                bearer_match = self.bearer_pattern.search(header_value)
                if bearer_match:
                    tokens.append({
                        'token': bearer_match.group(1),
                        'location': f'Request Header: {header_name}',
                        'type': 'request'
                    })
        
        # Extract from request body
        body = request.get('body', '')
        if body and self._is_jwt_token(body):
            jwt_match = self.jwt_pattern.search(body)
            if jwt_match:
                tokens.append({
                    'token': jwt_match.group(0),
                    'location': 'Request Body',
                    'type': 'request'
                })
        
        # Extract from response
        if response and hasattr(response, 'text'):
            response_text = response.text
            jwt_matches = self.jwt_pattern.findall(response_text)
            for token in jwt_matches:
                tokens.append({
                    'token': token,
                    'location': 'Response Body',
                    'type': 'response'
                })
        
        return tokens
    
    def _analyze_jwt_tokens(self, request: Dict[str, Any], response: Any, 
                           url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Analyze JWT tokens for security vulnerabilities."""
        vulnerabilities = []
        tokens = self._extract_jwt_tokens(request, response)
        
        for token_info in tokens:
            token = token_info['token']
            location = token_info['location']
            
            try:
                # Decode JWT token
                header, payload, signature = token.split('.')
                
                # Decode header and payload
                header_data = self._decode_jwt_part(header)
                payload_data = self._decode_jwt_part(payload)
                
                # Check for weak algorithms
                alg_vulns = self._check_weak_algorithms(header_data, token, url, method, headers, location)
                vulnerabilities.extend(alg_vulns)
                
                # Check for missing or weak signatures
                sig_vulns = self._check_signature_vulnerabilities(header_data, payload_data, signature, token, url, method, headers, location)
                vulnerabilities.extend(sig_vulns)
                
                # Check for token expiration issues
                exp_vulns = self._check_token_expiration(payload_data, token, url, method, headers, location)
                vulnerabilities.extend(exp_vulns)
                
                # Check for sensitive data in tokens
                data_vulns = self._check_sensitive_data_in_token(payload_data, token, url, method, headers, location)
                vulnerabilities.extend(data_vulns)
                
                # Check for algorithm confusion attacks
                conf_vulns = self._check_algorithm_confusion(header_data, payload_data, token, url, method, headers, location)
                vulnerabilities.extend(conf_vulns)
                
            except Exception as e:
                # Invalid JWT format
                vuln = self.create_vulnerability(
                    vuln_id=f"jwt-invalid-format-{uuid.uuid4().hex[:8]}",
                    name="Invalid JWT Token Format",
                    description=f"JWT token found in {location} has invalid format: {str(e)}",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Ensure JWT tokens follow the correct format: header.payload.signature",
                    references=["https://tools.ietf.org/html/rfc7519"],
                    cwe_id="CWE-345",
                    wasc_id="WASC-15",
                    url=url,
                    parameter=location,
                    evidence=f"Invalid JWT: {token[:50]}...",
                    scan_id="jwt-scan",
                    request=format_http_request(method, url, headers, request.get('body', '')),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _analyze_oauth_flows(self, request: Dict[str, Any], response: Any, 
                            url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Analyze OAuth flows for security vulnerabilities."""
        vulnerabilities = []
        
        # Check for OAuth grant type vulnerabilities
        grant_vulns = self._check_oauth_grant_types(request, response, url, method, headers)
        vulnerabilities.extend(grant_vulns)
        
        # Check for OAuth redirect URI vulnerabilities
        redirect_vulns = self._check_oauth_redirect_uri(request, response, url, method, headers)
        vulnerabilities.extend(redirect_vulns)
        
        # Check for OAuth scope vulnerabilities
        scope_vulns = self._check_oauth_scope_vulnerabilities(request, response, url, method, headers)
        vulnerabilities.extend(scope_vulns)
        
        # Check for OAuth state parameter vulnerabilities
        state_vulns = self._check_oauth_state_parameter(request, response, url, method, headers)
        vulnerabilities.extend(state_vulns)
        
        return vulnerabilities
    
    def _check_weak_algorithms(self, header_data: Dict[str, Any], token: str, 
                              url: str, method: str, headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Check for weak JWT algorithms."""
        vulnerabilities = []
        
        if not header_data:
            return vulnerabilities
        
        algorithm = header_data.get('alg', '').upper()
        
        # Check for 'none' algorithm
        if algorithm == 'NONE':
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-none-algorithm-{uuid.uuid4().hex[:8]}",
                name="JWT None Algorithm Vulnerability",
                description=f"JWT token uses 'none' algorithm, making it unsigned and vulnerable to tampering. Found in {location}",
                risk="High",
                cvss_score=8.1,
                solution="Use a strong signing algorithm like RS256, ES256, or HS256 with a secure key",
                references=[
                    "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                    "https://tools.ietf.org/html/rfc7519"
                ],
                cwe_id="CWE-345",
                wasc_id="WASC-15",
                url=url,
                parameter=location,
                evidence=f"Algorithm: {algorithm}",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=""
            )
            vulnerabilities.append(vuln)
        
        # Check for weak HMAC algorithms
        elif algorithm in ['HS256', 'HS384', 'HS512']:
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-weak-hmac-{uuid.uuid4().hex[:8]}",
                name="JWT Weak HMAC Algorithm",
                description=f"JWT token uses HMAC algorithm ({algorithm}) which is vulnerable to brute force attacks if the secret key is weak. Found in {location}",
                risk="Medium",
                cvss_score=6.5,
                solution="Use asymmetric algorithms like RS256 or ES256, or ensure HMAC secret is cryptographically strong",
                references=[
                    "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                    "https://tools.ietf.org/html/rfc7518"
                ],
                cwe_id="CWE-327",
                wasc_id="WASC-15",
                url=url,
                parameter=location,
                evidence=f"Algorithm: {algorithm}",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_signature_vulnerabilities(self, header_data: Dict[str, Any], payload_data: Dict[str, Any], 
                                        signature: str, token: str, url: str, method: str, 
                                        headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Check for JWT signature vulnerabilities."""
        vulnerabilities = []
        
        if not header_data:
            return vulnerabilities
        
        algorithm = header_data.get('alg', '').upper()
        
        # Check for missing signature
        if not signature or signature == '':
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-missing-signature-{uuid.uuid4().hex[:8]}",
                name="JWT Missing Signature",
                description=f"JWT token is missing signature, making it unsigned and vulnerable to tampering. Found in {location}",
                risk="High",
                cvss_score=8.1,
                solution="Always include a valid signature in JWT tokens",
                references=["https://tools.ietf.org/html/rfc7519"],
                cwe_id="CWE-345",
                wasc_id="WASC-15",
                url=url,
                parameter=location,
                evidence="Missing signature",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=""
            )
            vulnerabilities.append(vuln)
        
        # Check for weak signature (if we can detect it)
        elif len(signature) < 32:  # Very short signature might indicate weak implementation
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-weak-signature-{uuid.uuid4().hex[:8]}",
                name="JWT Weak Signature",
                description=f"JWT token signature appears to be weak or improperly implemented. Found in {location}",
                risk="Medium",
                cvss_score=6.5,
                solution="Ensure JWT signatures are properly generated with strong cryptographic methods",
                references=["https://tools.ietf.org/html/rfc7519"],
                cwe_id="CWE-327",
                wasc_id="WASC-15",
                url=url,
                parameter=location,
                evidence=f"Signature length: {len(signature)}",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_token_expiration(self, payload_data: Dict[str, Any], token: str, 
                               url: str, method: str, headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Check for JWT token expiration issues."""
        vulnerabilities = []
        
        if not payload_data:
            return vulnerabilities
        
        # Check for missing expiration
        if 'exp' not in payload_data:
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-missing-expiration-{uuid.uuid4().hex[:8]}",
                name="JWT Missing Expiration",
                description=f"JWT token does not include expiration time (exp claim), making it valid indefinitely. Found in {location}",
                risk="Medium",
                cvss_score=6.5,
                solution="Always include expiration time (exp claim) in JWT tokens",
                references=["https://tools.ietf.org/html/rfc7519"],
                cwe_id="CWE-613",
                wasc_id="WASC-15",
                url=url,
                parameter=location,
                evidence="Missing exp claim",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=""
            )
            vulnerabilities.append(vuln)
        
        # Check for very long expiration times
        elif 'exp' in payload_data:
            try:
                exp_timestamp = int(payload_data['exp'])
                exp_time = datetime.fromtimestamp(exp_timestamp)
                current_time = datetime.now()
                
                if exp_time > current_time + timedelta(days=365):  # More than 1 year
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-long-expiration-{uuid.uuid4().hex[:8]}",
                        name="JWT Long Expiration Time",
                        description=f"JWT token has very long expiration time ({exp_time.strftime('%Y-%m-%d %H:%M:%S')}), increasing security risk. Found in {location}",
                        risk="Low",
                        cvss_score=4.3,
                        solution="Use shorter expiration times for JWT tokens (recommended: 15 minutes to 1 hour)",
                        references=["https://tools.ietf.org/html/rfc7519"],
                        cwe_id="CWE-613",
                        wasc_id="WASC-15",
                        url=url,
                        parameter=location,
                        evidence=f"Expiration: {exp_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, ""),
                        response=""
                    )
                    vulnerabilities.append(vuln)
            except (ValueError, TypeError):
                pass
        
        return vulnerabilities
    
    def _check_sensitive_data_in_token(self, payload_data: Dict[str, Any], token: str, 
                                      url: str, method: str, headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Check for sensitive data in JWT payload."""
        vulnerabilities = []
        
        if not payload_data:
            return vulnerabilities
        
        # Check for common sensitive data patterns
        sensitive_patterns = {
            'password': re.compile(r'password|passwd|pwd', re.IGNORECASE),
            'secret': re.compile(r'secret|key|private', re.IGNORECASE),
            'ssn': re.compile(r'ssn|social_security', re.IGNORECASE),
            'credit_card': re.compile(r'credit_card|card_number|cc_number', re.IGNORECASE),
            'email': re.compile(r'email|mail', re.IGNORECASE)
        }
        
        for claim_name, claim_value in payload_data.items():
            for pattern_name, pattern in sensitive_patterns.items():
                if pattern.search(claim_name) or (isinstance(claim_value, str) and pattern.search(claim_value)):
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-sensitive-data-{uuid.uuid4().hex[:8]}",
                        name="JWT Contains Sensitive Data",
                        description=f"JWT token contains potentially sensitive data ({pattern_name}) in claim '{claim_name}'. Found in {location}",
                        risk="Medium",
                        cvss_score=6.5,
                        solution="Avoid storing sensitive data in JWT tokens. Use tokens only for authentication/authorization claims",
                        references=["https://tools.ietf.org/html/rfc7519"],
                        cwe_id="CWE-200",
                        wasc_id="WASC-15",
                        url=url,
                        parameter=location,
                        evidence=f"Claim: {claim_name}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, ""),
                        response=""
                    )
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    def _check_algorithm_confusion(self, header_data: Dict[str, Any], payload_data: Dict[str, Any], 
                                  token: str, url: str, method: str, headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Check for algorithm confusion vulnerabilities."""
        vulnerabilities = []
        
        if not header_data:
            return vulnerabilities
        
        algorithm = header_data.get('alg', '').upper()
        
        # Check for algorithm confusion (RS256 -> HS256)
        if algorithm == 'HS256':
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-algorithm-confusion-{uuid.uuid4().hex[:8]}",
                name="JWT Algorithm Confusion Vulnerability",
                description=f"JWT token uses HS256 algorithm which is vulnerable to algorithm confusion attacks. Found in {location}",
                risk="High",
                cvss_score=8.1,
                solution="Use RS256 or ES256 algorithms and validate the algorithm on the server side",
                references=[
                    "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                    "https://tools.ietf.org/html/rfc7519"
                ],
                cwe_id="CWE-327",
                wasc_id="WASC-15",
                url=url,
                parameter=location,
                evidence=f"Algorithm: {algorithm}",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_oauth_grant_types(self, request: Dict[str, Any], response: Any, 
                                url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for OAuth grant type vulnerabilities."""
        vulnerabilities = []
        
        body = request.get('body', '')
        if not body:
            return vulnerabilities
        
        try:
            # Parse body as JSON or form data
            if isinstance(body, str):
                if body.strip().startswith('{'):
                    data = json.loads(body)
                else:
                    data = dict(parse_qs(body))
            else:
                data = body
            
            grant_type = None
            if isinstance(data, dict):
                grant_type = data.get('grant_type')
                if isinstance(grant_type, list):
                    grant_type = grant_type[0] if grant_type else None
            
            if grant_type and isinstance(grant_type, str):
                # Check for password grant type
                if grant_type.lower() == 'password':
                    vuln = self.create_vulnerability(
                        vuln_id=f"oauth-password-grant-{uuid.uuid4().hex[:8]}",
                        name="OAuth Password Grant Type",
                        description="OAuth flow uses password grant type which is deprecated and insecure",
                        risk="High",
                        cvss_score=7.5,
                        solution="Use authorization code grant type with PKCE instead of password grant",
                        references=["https://tools.ietf.org/html/rfc6749"],
                        cwe_id="CWE-287",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="grant_type",
                        evidence=f"Grant type: {grant_type}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                    )
                    vulnerabilities.append(vuln)
                
                # Check for implicit grant type
                elif grant_type.lower() == 'implicit':
                    vuln = self.create_vulnerability(
                        vuln_id=f"oauth-implicit-grant-{uuid.uuid4().hex[:8]}",
                        name="OAuth Implicit Grant Type",
                        description="OAuth flow uses implicit grant type which is deprecated and insecure",
                        risk="Medium",
                        cvss_score=6.5,
                        solution="Use authorization code grant type with PKCE instead of implicit grant",
                        references=["https://tools.ietf.org/html/rfc6749"],
                        cwe_id="CWE-287",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="grant_type",
                        evidence=f"Grant type: {grant_type}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                    )
                    vulnerabilities.append(vuln)
        
        except (json.JSONDecodeError, ValueError):
            pass
        
        return vulnerabilities
    
    def _check_oauth_redirect_uri(self, request: Dict[str, Any], response: Any, 
                                 url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for OAuth redirect URI vulnerabilities."""
        vulnerabilities = []
        
        # Check for open redirect vulnerabilities in OAuth flows
        if 'oauth' in url.lower() or 'authorize' in url.lower():
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if 'redirect_uri' in query_params:
                redirect_uri = query_params['redirect_uri'][0]
                
                # Check for wildcard redirect URIs
                if '*' in redirect_uri or 'localhost' in redirect_uri:
                    vuln = self.create_vulnerability(
                        vuln_id=f"oauth-open-redirect-{uuid.uuid4().hex[:8]}",
                        name="OAuth Open Redirect Vulnerability",
                        description=f"OAuth redirect URI contains wildcard or localhost: {redirect_uri}",
                        risk="High",
                        cvss_score=7.5,
                        solution="Use specific, whitelisted redirect URIs and avoid wildcards",
                        references=["https://tools.ietf.org/html/rfc6749"],
                        cwe_id="CWE-601",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="redirect_uri",
                        evidence=f"Redirect URI: {redirect_uri}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, ""),
                        response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_oauth_scope_vulnerabilities(self, request: Dict[str, Any], response: Any, 
                                          url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for OAuth scope vulnerabilities."""
        vulnerabilities = []
        
        # This would require more context about the OAuth implementation
        # For now, we'll check for overly broad scopes in responses
        if response and hasattr(response, 'text'):
            response_text = response.text.lower()
            
            # Check for overly broad scopes
            broad_scopes = ['admin', 'root', 'all', 'full', 'write', 'delete']
            for scope in broad_scopes:
                if scope in response_text:
                    vuln = self.create_vulnerability(
                        vuln_id=f"oauth-broad-scope-{uuid.uuid4().hex[:8]}",
                        name="OAuth Overly Broad Scope",
                        description=f"OAuth scope appears to be overly broad: {scope}",
                        risk="Medium",
                        cvss_score=6.5,
                        solution="Use principle of least privilege for OAuth scopes",
                        references=["https://tools.ietf.org/html/rfc6749"],
                        cwe_id="CWE-250",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="scope",
                        evidence=f"Broad scope: {scope}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, ""),
                        response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                    )
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    def _check_oauth_state_parameter(self, request: Dict[str, Any], response: Any, 
                                    url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for OAuth state parameter vulnerabilities."""
        vulnerabilities = []
        
        # Check for missing state parameter in OAuth authorization requests
        if 'oauth' in url.lower() or 'authorize' in url.lower():
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if 'state' not in query_params:
                vuln = self.create_vulnerability(
                    vuln_id=f"oauth-missing-state-{uuid.uuid4().hex[:8]}",
                    name="OAuth Missing State Parameter",
                    description="OAuth authorization request is missing state parameter, vulnerable to CSRF attacks",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Always include a cryptographically random state parameter in OAuth requests",
                    references=["https://tools.ietf.org/html/rfc6749"],
                    cwe_id="CWE-352",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="state",
                    evidence="Missing state parameter",
                    scan_id="jwt-scan",
                    request=format_http_request(method, url, headers, ""),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_jwt_implementation_vulnerabilities(self, request: Dict[str, Any], response: Any, 
                                                 url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for JWT implementation vulnerabilities."""
        vulnerabilities = []
        
        # Check for JWT in URL parameters (insecure)
        if 'jwt' in url.lower() or 'token' in url.lower():
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-url-parameter-{uuid.uuid4().hex[:8]}",
                name="JWT Token in URL Parameter",
                description="JWT token appears to be passed in URL parameters, which is insecure",
                risk="Medium",
                cvss_score=6.5,
                solution="Pass JWT tokens in Authorization header, not in URL parameters",
                references=["https://tools.ietf.org/html/rfc7519"],
                cwe_id="CWE-200",
                wasc_id="WASC-15",
                url=url,
                parameter="URL",
                evidence="JWT token in URL",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=format_http_response(response.status_code, response.headers, response.text) if response else ""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_token_storage_vulnerabilities(self, request: Dict[str, Any], response: Any, 
                                            url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for token storage vulnerabilities."""
        vulnerabilities = []
        
        # Check for tokens in cookies without secure flags
        cookies = headers.get('Cookie', '') or headers.get('cookie', '')
        if 'jwt' in cookies.lower() or 'token' in cookies.lower():
            if 'secure' not in cookies.lower() or 'httponly' not in cookies.lower():
                vuln = self.create_vulnerability(
                    vuln_id=f"jwt-insecure-cookie-{uuid.uuid4().hex[:8]}",
                    name="JWT Token in Insecure Cookie",
                    description="JWT token is stored in cookie without Secure or HttpOnly flags",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Use Secure and HttpOnly flags for cookies containing JWT tokens",
                    references=["https://tools.ietf.org/html/rfc6265"],
                    cwe_id="CWE-614",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Cookie",
                    evidence="JWT in cookie without security flags",
                    scan_id="jwt-scan",
                    request=format_http_request(method, url, headers, ""),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _decode_jwt_part(self, part: str) -> Dict[str, Any]:
        """Decode a JWT part (header or payload)."""
        try:
            # Add padding if needed
            missing_padding = len(part) % 4
            if missing_padding:
                part += '=' * (4 - missing_padding)
            
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded.decode('utf-8'))
        except Exception:
            return {}
    
    def generate_poc(self, vulnerability_id: str) -> ProofOfConcept:
        """Generate proof-of-concept for JWT vulnerabilities."""
        # This would generate specific PoCs based on the vulnerability type
        # For now, return a generic PoC
        return ProofOfConcept(
            vulnerability_id=vulnerability_id,
            request_method="GET",
            request_url="https://example.com/api/protected",
            request_headers={"Authorization": "Bearer <JWT_TOKEN>"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"message": "JWT vulnerability detected"}',
            timestamp=datetime.now(),
            evidence_description="JWT token contains security vulnerability"
        )
