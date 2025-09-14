"""
Broken Authentication Security Checker Plugin.

This plugin detects broken authentication mechanisms,
including weak passwords, session management issues,
and authentication bypass vulnerabilities.
"""

import uuid
import json
import re
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from api_security_scanner.core.scanner_plugins import (
    BasePlugin, PluginResult, Vulnerability, ProofOfConcept,
    format_http_request, format_http_response
)


class BrokenAuthenticationChecker(BasePlugin):
    """Detects broken authentication vulnerabilities."""
    
    name = "BrokenAuthenticationChecker"
    description = "Detects broken authentication mechanisms and vulnerabilities"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform broken authentication detection."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                headers = request.get('headers', {}).copy()
                body = request.get('body', '')
                
                if auth_headers:
                    headers.update(auth_headers)
                
                # Test for authentication vulnerabilities
                auth_vulns = self._test_authentication_vulnerabilities(url, method, headers, body)
                vulnerabilities.extend(auth_vulns)
                
                # Test for session management issues
                session_vulns = self._test_session_management(url, method, headers, body)
                vulnerabilities.extend(session_vulns)
                
                # Test for weak authentication
                weak_auth_vulns = self._test_weak_authentication(url, method, headers, body)
                vulnerabilities.extend(weak_auth_vulns)
                
                # Test for authentication bypass
                bypass_vulns = self._test_authentication_bypass(url, method, headers, body)
                vulnerabilities.extend(bypass_vulns)
        
        except Exception as e:
            self.logger.error(f"Error in broken authentication checker: {e}")
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=str(e),
                execution_time=0.0
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities,
            execution_time=0.0
        )
    
    def _test_authentication_vulnerabilities(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for general authentication vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for missing authentication
            if not self._has_authentication(headers, body):
                vuln_id = f"auth-missing-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Missing Authentication",
                    description="API endpoint does not require authentication",
                    risk="High",
                    cvss_score=7.5,
                    solution="Implement proper authentication mechanisms for all sensitive endpoints",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-306",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "No authentication required"),
                    url=url,
                    parameter="authentication",
                    evidence="Endpoint accessible without authentication",
                            scan_id="",
                    timestamp=datetime.now()
                ))
            
            # Check for weak authentication mechanisms
            weak_auth = self._check_weak_authentication_mechanisms(headers, body)
            if weak_auth:
                vuln_id = f"auth-weak-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Weak Authentication Mechanism",
                    description=f"Weak authentication mechanism detected: {weak_auth}",
                    risk="Medium",
                    cvss_score=6.0,
                    solution="Use strong authentication mechanisms like OAuth 2.0, JWT with proper validation, or multi-factor authentication",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-307",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Weak authentication detected"),
                    url=url,
                    parameter="authentication",
                    evidence=f"Weak authentication mechanism: {weak_auth}",
                            scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing authentication vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _test_session_management(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for session management vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for session fixation
            session_fixation = self._check_session_fixation(headers)
            if session_fixation:
                vuln_id = f"session-fixation-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Session Fixation Vulnerability",
                    description="Session fixation vulnerability detected",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Regenerate session IDs after authentication and implement proper session management",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-384",
                    wasc_id="WASC-37",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Session fixation detected"),
                    url=url,
                    parameter="session",
                    evidence="Session ID not regenerated after authentication",
                            scan_id="",
                    timestamp=datetime.now()
                ))
            
            # Check for session timeout issues
            session_timeout = self._check_session_timeout(headers)
            if session_timeout:
                vuln_id = f"session-timeout-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Insecure Session Timeout",
                    description="Session timeout not properly configured",
                    risk="Low",
                    cvss_score=4.0,
                    solution="Implement proper session timeout and automatic logout mechanisms",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-613",
                    wasc_id="WASC-37",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Session timeout issue detected"),
                    url=url,
                    parameter="session",
                    evidence="Session timeout not properly configured",
                            scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing session management: {e}")
        
        return vulnerabilities
    
    def _test_weak_authentication(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for weak authentication mechanisms."""
        vulnerabilities = []
        
        try:
            # Check for weak passwords
            weak_passwords = self._check_weak_passwords(body)
            if weak_passwords:
                vuln_id = f"weak-password-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Weak Password Policy",
                    description="Weak password policy detected",
                    risk="Medium",
                    cvss_score=5.0,
                    solution="Implement strong password policies with minimum length, complexity requirements, and regular rotation",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-521",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Weak password policy detected"),
                    url=url,
                    parameter="password",
                    evidence="Weak password policy allows weak passwords",
                            scan_id="",
                    timestamp=datetime.now()
                ))
            
            # Check for password in URL
            password_in_url = self._check_password_in_url(url)
            if password_in_url:
                vuln_id = f"password-url-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Password in URL",
                    description="Password transmitted in URL parameters",
                    risk="High",
                    cvss_score=7.0,
                    solution="Never transmit passwords in URL parameters. Use POST body or secure headers",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Password in URL detected"),
                    url=url,
                    parameter="password",
                    evidence="Password found in URL parameters",
                            scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing weak authentication: {e}")
        
        return vulnerabilities
    
    def _test_authentication_bypass(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for authentication bypass techniques
            bypass_techniques = self._test_bypass_techniques(url, method, headers, body)
            vulnerabilities.extend(bypass_techniques)
            
            # Test for privilege escalation
            privilege_escalation = self._test_privilege_escalation(url, method, headers, body)
            vulnerabilities.extend(privilege_escalation)
        
        except Exception as e:
            self.logger.error(f"Error testing authentication bypass: {e}")
        
        return vulnerabilities
    
    def _has_authentication(self, headers: Dict[str, str], body: str) -> bool:
        """Check if request has authentication."""
        # Check for common authentication headers
        auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token', 'X-Session-Token']
        for header in auth_headers:
            if header in headers:
                return True
        
        # Check for authentication in body
        if body:
            try:
                body_data = json.loads(body)
                auth_fields = ['token', 'api_key', 'session_id', 'auth_token']
                for field in auth_fields:
                    if field in body_data:
                        return True
            except (json.JSONDecodeError, TypeError):
                pass
        
        return False
    
    def _check_weak_authentication_mechanisms(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Check for weak authentication mechanisms."""
        # Check for Basic Auth without HTTPS
        if 'Authorization' in headers:
            auth_header = headers['Authorization']
            if auth_header.startswith('Basic '):
                return "Basic Authentication without HTTPS"
        
        # Check for API key in URL
        if 'api_key' in str(headers) or 'apikey' in str(headers):
            return "API key in URL or headers"
        
        return None
    
    def _check_session_fixation(self, headers: Dict[str, str]) -> bool:
        """Check for session fixation vulnerability."""
        # This is a simplified check - in reality, you'd need to test the full authentication flow
        session_headers = ['Set-Cookie', 'X-Session-ID', 'X-Session-Token']
        return any(header in headers for header in session_headers)
    
    def _check_session_timeout(self, headers: Dict[str, str]) -> bool:
        """Check for session timeout issues."""
        # Check for session timeout headers
        timeout_headers = ['X-Session-Timeout', 'X-Token-Expiry']
        return not any(header in headers for header in timeout_headers)
    
    def _check_weak_passwords(self, body: str) -> bool:
        """Check for weak password policy."""
        if not body:
            return False
        
        try:
            body_data = json.loads(body)
            if 'password' in body_data:
                password = body_data['password']
                # Check for weak passwords
                weak_patterns = [
                    r'^.{1,7}$',  # Less than 8 characters
                    r'^[a-zA-Z]+$',  # Only letters
                    r'^[0-9]+$',  # Only numbers
                    r'^(password|123456|admin|qwerty)$',  # Common weak passwords
                ]
                
                for pattern in weak_patterns:
                    if re.match(pattern, password, re.IGNORECASE):
                        return True
        except (json.JSONDecodeError, TypeError):
            pass
        
        return False
    
    def _check_password_in_url(self, url: str) -> bool:
        """Check if password is in URL."""
        password_params = ['password', 'pass', 'pwd', 'passwd']
        return any(param in url.lower() for param in password_params)
    
    def _test_bypass_techniques(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for authentication bypass techniques."""
        vulnerabilities = []
        
        try:
            # Test with empty authentication
            empty_auth_vulns = self._test_empty_authentication(url, method, headers, body)
            vulnerabilities.extend(empty_auth_vulns)
            
            # Test with malformed authentication
            malformed_auth_vulns = self._test_malformed_authentication(url, method, headers, body)
            vulnerabilities.extend(malformed_auth_vulns)
            
            # Test with SQL injection in authentication
            sql_auth_vulns = self._test_sql_injection_auth(url, method, headers, body)
            vulnerabilities.extend(sql_auth_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing bypass techniques: {e}")
        
        return vulnerabilities
    
    def _test_privilege_escalation(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test with different user roles
            role_vulns = self._test_role_escalation(url, method, headers, body)
            vulnerabilities.extend(role_vulns)
            
            # Test with admin privileges
            admin_vulns = self._test_admin_escalation(url, method, headers, body)
            vulnerabilities.extend(admin_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing privilege escalation: {e}")
        
        return vulnerabilities
    
    def _test_empty_authentication(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test with empty authentication."""
        vulnerabilities = []
        
        try:
            # Remove authentication headers
            modified_headers = headers.copy()
            auth_headers = ['Authorization', 'X-API-Key', 'X-Auth-Token']
            for header in auth_headers:
                if header in modified_headers:
                    del modified_headers[header]
            
            # Test without authentication
            response = self.make_request(url, method, modified_headers, body)
            
            if response and response.status_code in [200, 201, 202]:
                vuln_id = f"auth-bypass-empty-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Authentication Bypass - Empty Authentication",
                    description="API allows access with empty authentication",
                    risk="High",
                    cvss_score=8.0,
                    solution="Implement proper authentication validation and reject requests without valid authentication",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-287",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, modified_headers, body),
                    response=format_http_response(200, {}, "Empty authentication accepted"),
                    url=url,
                    parameter="authentication",
                    evidence="Request accepted without authentication",
                            scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing empty authentication: {e}")
        
        return vulnerabilities
    
    def _test_malformed_authentication(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test with malformed authentication."""
        vulnerabilities = []
        
        try:
            # Test with malformed authentication headers
            malformed_headers = [
                'Authorization: Bearer ',
                'Authorization: Basic ',
                'X-API-Key: ',
                'X-Auth-Token: ',
            ]
            
            for malformed_header in malformed_headers:
                header_name, header_value = malformed_header.split(': ', 1)
                modified_headers = headers.copy()
                modified_headers[header_name] = header_value
                
                response = self.make_request(url, method, modified_headers, body)
                
                if response and response.status_code in [200, 201, 202]:
                    vuln_id = f"auth-bypass-malformed-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Authentication Bypass - Malformed Authentication",
                        description=f"API allows access with malformed authentication: {malformed_header}",
                        risk="High",
                        cvss_score=8.0,
                        solution="Implement proper authentication validation and reject malformed authentication tokens",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                        ],
                        cwe_id="CWE-287",
                        wasc_id="WASC-1",
                        request=format_http_request(method, url, modified_headers, body),
                        response=format_http_response(200, {}, "Malformed authentication accepted"),
                        url=url,
                        parameter="authentication",
                        evidence=f"Request accepted with malformed authentication: {malformed_header}",
                            scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing malformed authentication: {e}")
        
        return vulnerabilities
    
    def _test_sql_injection_auth(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for SQL injection in authentication."""
        vulnerabilities = []
        
        try:
            # Test SQL injection payloads in authentication
            sql_payloads = [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT 1--",
            ]
            
            for payload in sql_payloads:
                # Test in headers
                modified_headers = headers.copy()
                if 'Authorization' in modified_headers:
                    modified_headers['Authorization'] = f"Bearer {payload}"
                
                response = self.make_request(url, method, modified_headers, body)
                
                if response and response.status_code in [200, 201, 202]:
                    vuln_id = f"auth-sql-injection-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Authentication Bypass - SQL Injection",
                        description=f"API vulnerable to SQL injection in authentication: {payload}",
                        risk="Critical",
                        cvss_score=9.0,
                        solution="Implement parameterized queries and proper input validation for authentication",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                        ],
                        cwe_id="CWE-89",
                        wasc_id="WASC-19",
                        request=format_http_request(method, url, modified_headers, body),
                        response=format_http_response(200, {}, "SQL injection in authentication"),
                        url=url,
                        parameter="authentication",
                        evidence=f"SQL injection payload successful: {payload}",
                            scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing SQL injection in authentication: {e}")
        
        return vulnerabilities
    
    def _test_role_escalation(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for role escalation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test with different user roles
            roles = ['admin', 'user', 'guest', 'moderator', 'superuser']
            
            for role in roles:
                modified_headers = headers.copy()
                modified_headers['X-User-Role'] = role
                modified_headers['X-Role'] = role
                
                response = self.make_request(url, method, modified_headers, body)
                
                if response and response.status_code in [200, 201, 202]:
                    vuln_id = f"role-escalation-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Role Escalation Vulnerability",
                        description=f"API allows role escalation to: {role}",
                        risk="High",
                        cvss_score=8.5,
                        solution="Implement proper role validation and authorization checks",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                        ],
                        cwe_id="CWE-269",
                        wasc_id="WASC-1",
                        request=format_http_request(method, url, modified_headers, body),
                        response=format_http_response(200, {}, "Role escalation successful"),
                        url=url,
                        parameter="role",
                        evidence=f"Successfully escalated to role: {role}",
                            scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing role escalation: {e}")
        
        return vulnerabilities
    
    def _test_admin_escalation(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for admin privilege escalation."""
        vulnerabilities = []
        
        try:
            # Test with admin privileges
            admin_headers = {
                'X-Admin': 'true',
                'X-Is-Admin': 'true',
                'X-User-Role': 'admin',
                'X-Privilege-Level': 'admin',
                'X-Access-Level': 'admin'
            }
            
            modified_headers = headers.copy()
            modified_headers.update(admin_headers)
            
            response = self.make_request(url, method, modified_headers, body)
            
            if response and response.status_code in [200, 201, 202]:
                vuln_id = f"admin-escalation-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="Admin Privilege Escalation",
                    description="API allows admin privilege escalation via headers",
                    risk="Critical",
                    cvss_score=9.0,
                    solution="Implement proper privilege validation and never trust client-side role indicators",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"
                    ],
                    cwe_id="CWE-269",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, modified_headers, body),
                    response=format_http_response(200, {}, "Admin escalation successful"),
                    url=url,
                    parameter="admin_headers",
                    evidence="Successfully escalated to admin privileges",
                            scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing admin escalation: {e}")
        
        return vulnerabilities
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof of concept for broken authentication vulnerability."""
        return None  # Broken authentication vulnerabilities don't typically have specific POCs
