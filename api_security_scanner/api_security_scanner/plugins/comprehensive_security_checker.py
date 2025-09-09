"""
Comprehensive security checker with extensive vulnerability detection.
"""

import re
import uuid
import json
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, ProofOfConcept, format_http_request, format_http_response


class ComprehensiveSecurityChecker(BasePlugin):
    """Comprehensive security plugin covering multiple vulnerability categories."""
    
    name = "ComprehensiveSecurityChecker"
    description = "Comprehensive security analysis covering authentication, authorization, input validation, and more"
    version = "3.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Comprehensive security analysis."""
        findings = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request for analysis
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                response = self.make_request(url, method, headers)
                
                if response:
                    # Authentication and Authorization checks
                    auth_issues = self._check_authentication_issues(response, url, method, headers)
                    findings.extend(auth_issues)
                    
                    # Input validation checks
                    input_validation = self._check_input_validation(response, url, method, headers)
                    findings.extend(input_validation)
                    
                    # Information disclosure checks
                    info_disclosure = self._check_information_disclosure(response, url, method, headers)
                    findings.extend(info_disclosure)
                    
                    # Error handling checks
                    error_handling = self._check_error_handling(response, url, method, headers)
                    findings.extend(error_handling)
                    
                    # Session management checks
                    session_issues = self._check_session_management(response, url, method, headers)
                    findings.extend(session_issues)
                    
                    # API versioning checks
                    versioning_issues = self._check_api_versioning(response, url, method, headers)
                    findings.extend(versioning_issues)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"Comprehensive security check failed: {e}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=findings
        )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof-of-concept evidence for a specific vulnerability."""
        return None
    
    def _check_authentication_issues(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for authentication and authorization issues."""
        findings = []
        
        # Check if sensitive endpoints are accessible without authentication
        sensitive_paths = ['/admin', '/api/admin', '/user', '/api/user', '/config', '/api/config', '/internal']
        is_sensitive = any(path in url.lower() for path in sensitive_paths)
        
        if is_sensitive and response.status_code == 200:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Sensitive Endpoint Without Authentication",
                description="Sensitive endpoint is accessible without proper authentication",
                risk="High",
                cvss_score=7.5,
                solution="Implement proper authentication for sensitive endpoints",
                references=["https://owasp.org/www-community/controls/Authentication"],
                cwe_id="CWE-287",
                wasc_id="WASC-1",
                url=url,
                parameter="",
                evidence=f"Sensitive endpoint {url} returned 200 without authentication",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        # Check for weak authentication mechanisms
        if 'Authorization' in headers:
            auth_header = headers['Authorization']
            if auth_header.startswith('Basic '):
                # Check if Basic auth is used (weak for APIs)
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Weak Authentication Method",
                    description="API uses Basic authentication which is not recommended for APIs",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Use OAuth 2.0, JWT, or API keys instead of Basic authentication",
                    references=["https://owasp.org/www-community/controls/Authentication"],
                    cwe_id="CWE-287",
                    wasc_id="WASC-1",
                    url=url,
                    parameter="",
                    evidence="Authorization header uses Basic authentication",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _check_input_validation(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for input validation issues."""
        findings = []
        
        # Test for SQL injection patterns
        sql_payloads = ["'", "''", "1' OR '1'='1", "1' UNION SELECT 1--", "'; DROP TABLE users--"]
        sql_vulnerable_payloads = []
        
        for payload in sql_payloads:
            test_url = f"{url}?id={payload}"
            try:
                test_response = self.make_request(test_url, method, headers)
                if test_response and self._detect_sql_error(test_response.text):
                    sql_vulnerable_payloads.append(payload)
            except Exception:
                continue
        
        # Create single SQL injection vulnerability if any payloads were successful
        if sql_vulnerable_payloads:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(200, {}, "SQL injection tests performed")
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="SQL Injection Vulnerability",
                description=f"API is vulnerable to SQL injection attacks. {len(sql_vulnerable_payloads)} payloads triggered SQL errors",
                risk="Critical",
                cvss_score=9.8,
                solution="Implement proper input validation and use parameterized queries",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                cwe_id="CWE-89",
                wasc_id="WASC-19",
                url=url,
                parameter="id",
                evidence=f"Vulnerable payloads: {', '.join(sql_vulnerable_payloads)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        # Test for NoSQL injection
        nosql_payloads = ['{"$ne": null}', '{"$gt": ""}', '{"$where": "this.username == this.password"}']
        nosql_vulnerable_payloads = []
        
        for payload in nosql_payloads:
            test_headers = headers.copy()
            test_headers['Content-Type'] = 'application/json'
            try:
                test_response = self.make_request(url, 'POST', test_headers, payload)
                if test_response and self._detect_nosql_error(test_response.text):
                    nosql_vulnerable_payloads.append(payload)
            except Exception:
                continue
        
        # Create single NoSQL injection vulnerability if any payloads were successful
        if nosql_vulnerable_payloads:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request('POST', url, headers)
            response_str = format_http_response(200, {}, "NoSQL injection tests performed")
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="NoSQL Injection Vulnerability",
                description=f"API is vulnerable to NoSQL injection attacks. {len(nosql_vulnerable_payloads)} payloads triggered NoSQL errors",
                risk="Critical",
                cvss_score=9.8,
                solution="Implement proper input validation for NoSQL queries",
                references=["https://owasp.org/www-community/attacks/NoSQL_Injection"],
                cwe_id="CWE-943",
                wasc_id="WASC-19",
                url=url,
                parameter="",
                evidence=f"Vulnerable payloads: {', '.join(nosql_vulnerable_payloads)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings
    
    def _check_information_disclosure(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for information disclosure issues."""
        findings = []
        
        # Check response body for sensitive information
        response_text = response.text.lower()
        
        sensitive_patterns = {
            'database_credentials': r'(password|pwd|pass)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            'api_keys': r'(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            'tokens': r'(token|jwt|bearer)\s*[:=]\s*["\']?[^"\'\s]+["\']?',
            'database_errors': r'(mysql|postgresql|oracle|sqlite|mongodb).*error',
            'stack_traces': r'(traceback|stack trace|exception|error.*line)',
            'internal_paths': r'(/home/|/var/|/usr/|c:\\|d:\\)',
            'email_addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone_numbers': r'(\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'credit_cards': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        }
        
        # Group findings by risk level
        high_risk_findings = []
        medium_risk_findings = []
        
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                if pattern_name in ['database_credentials', 'api_keys', 'tokens']:
                    high_risk_findings.append({
                        'name': pattern_name,
                        'count': len(matches),
                        'matches': matches[:3]  # Show first 3 matches
                    })
                else:
                    medium_risk_findings.append({
                        'name': pattern_name,
                        'count': len(matches),
                        'matches': matches[:3]  # Show first 3 matches
                    })
        
        # Create consolidated high-risk information disclosure vulnerability
        if high_risk_findings:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            finding_names = [f['name'].replace('_', ' ').title() for f in high_risk_findings]
            total_count = sum(f['count'] for f in high_risk_findings)
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="High Risk Information Disclosure",
                description=f"Response contains {total_count} instances of high-risk sensitive information: {', '.join(finding_names)}",
                risk="High",
                cvss_score=7.5,
                solution="Remove sensitive information from API responses",
                references=["https://owasp.org/www-community/controls/Information_Exposure"],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=url,
                parameter="",
                evidence=f"High-risk patterns found: {', '.join(finding_names)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        # Create consolidated medium-risk information disclosure vulnerability
        if medium_risk_findings:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            finding_names = [f['name'].replace('_', ' ').title() for f in medium_risk_findings]
            total_count = sum(f['count'] for f in medium_risk_findings)
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Medium Risk Information Disclosure",
                description=f"Response contains {total_count} instances of medium-risk sensitive information: {', '.join(finding_names)}",
                risk="Medium",
                cvss_score=5.3,
                solution="Remove sensitive information from API responses",
                references=["https://owasp.org/www-community/controls/Information_Exposure"],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=url,
                parameter="",
                evidence=f"Medium-risk patterns found: {', '.join(finding_names)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings
    
    def _check_error_handling(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for error handling issues."""
        findings = []
        
        # Test for error handling with invalid input
        error_payloads = [
            "invalid_json",
            "null",
            "undefined",
            "NaN",
            "Infinity",
            "{}",
            "[]",
            "true",
            "false"
        ]
        
        for payload in error_payloads:
            test_headers = headers.copy()
            test_headers['Content-Type'] = 'application/json'
            try:
                test_response = self.make_request(url, 'POST', test_headers, payload)
                if test_response and test_response.status_code >= 500:
                    vuln_id = str(uuid.uuid4())
                    request_str = format_http_request('POST', url, test_headers, payload)
                    response_str = format_http_response(test_response.status_code, dict(test_response.headers), test_response.text[:1000])
                    
                    findings.append(self.create_vulnerability(
                        vuln_id=vuln_id,
                        name="Poor Error Handling",
                        description="API returns 500 error for invalid input instead of proper validation",
                        risk="Medium",
                        cvss_score=5.3,
                        solution="Implement proper input validation and return appropriate error codes",
                        references=["https://owasp.org/www-community/controls/Error_Handling"],
                        cwe_id="CWE-755",
                        wasc_id="WASC-10",
                        url=url,
                        parameter="",
                        evidence=f"500 error returned for payload: {payload}",
                        scan_id="",
                        request=request_str,
                        response=response_str
                    ))
                    break
            except Exception:
                continue
        
        return findings
    
    def _check_session_management(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for session management issues."""
        findings = []
        
        # Check for session cookies without secure flags
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
        if not set_cookie_headers and 'Set-Cookie' in response.headers:
            set_cookie_headers = [response.headers['Set-Cookie']]
        
        for cookie in set_cookie_headers:
            if 'secure' not in cookie.lower() and 'httponly' not in cookie.lower():
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Insecure Session Cookie",
                    description="Session cookie missing Secure and HttpOnly flags",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Set Secure and HttpOnly flags on session cookies",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    cwe_id="CWE-614",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"Insecure cookie: {cookie}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _check_api_versioning(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for API versioning issues."""
        findings = []
        
        # Check if API version is missing
        if '/v1/' not in url and '/v2/' not in url and '/api/v1/' not in url and '/api/v2/' not in url:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Missing API Versioning",
                description="API endpoint does not include version information",
                risk="Low",
                cvss_score=3.7,
                solution="Implement API versioning to manage breaking changes",
                references=["https://restfulapi.net/versioning/"],
                cwe_id="CWE-1104",
                wasc_id="WASC-15",
                url=url,
                parameter="",
                evidence="API endpoint lacks version information",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Detect SQL error messages in response."""
        sql_error_patterns = [
            r'mysql_fetch_array',
            r'mysql_num_rows',
            r'mysql_query',
            r'ORA-\d+',
            r'Microsoft.*ODBC.*SQL Server',
            r'SQLServer JDBC Driver',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql_',
            r'valid MySQL result',
            r'MySqlClient\.',
            r'SQL syntax.*MySQL',
            r'Warning.*\Wmysql_',
            r'MySQLSyntaxErrorException',
            r'valid MySQL result',
            r'check the manual that corresponds to your MySQL server version'
        ]
        
        for pattern in sql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
    
    def _detect_nosql_error(self, response_text: str) -> bool:
        """Detect NoSQL error messages in response."""
        nosql_error_patterns = [
            r'mongodb.*error',
            r'mongo.*exception',
            r'couchdb.*error',
            r'elasticsearch.*error',
            r'redis.*error',
            r'nosql.*error'
        ]
        
        for pattern in nosql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
