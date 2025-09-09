"""
Enhanced security checker plugin demonstrating the new vulnerability model
with proof-of-concept evidence generation.
"""

import uuid
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept, format_http_request, format_http_response


class EnhancedSecurityChecker(BasePlugin):
    """Enhanced plugin demonstrating comprehensive vulnerability reporting."""
    
    name = "EnhancedSecurityChecker"
    description = "Comprehensive security checks with detailed vulnerability reporting"
    version = "2.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform comprehensive security checks."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request with authentication
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                response = self.make_request(url, method, headers, request.get('body'))
                
                if response:
                    # Check for various security issues
                    vulns = self._check_information_disclosure(response, url, method, headers)
                    vulnerabilities.extend(vulns)
                    
                    vulns = self._check_insecure_headers(response, url, method, headers)
                    vulnerabilities.extend(vulns)
                    
                    vulns = self._check_authentication_bypass(response, url, method, headers)
                    vulnerabilities.extend(vulns)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"Enhanced security check failed: {e}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof-of-concept evidence for a specific vulnerability."""
        # This would typically retrieve stored request/response data from database
        # For demonstration, return a sample PoC
        return ProofOfConcept(
            vulnerability_id=vulnerability_id,
            request_method="GET",
            request_url="https://example.com/api/test",
            request_headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json", "Server": "nginx/1.18.0"},
            response_body='{"error": "Internal server error details exposed"}',
            timestamp=datetime.now(),
            evidence_description="Demonstrates information disclosure vulnerability"
        )
    
    def _check_information_disclosure(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for information disclosure vulnerabilities."""
        vulnerabilities = []
        
        # Check for error messages that reveal sensitive information
        if response.text and any(keyword in response.text.lower() for keyword in 
                               ['error', 'exception', 'stack trace', 'debug', 'internal']):
            
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            vulnerabilities.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Information Disclosure in Error Messages",
                description="The API returns detailed error messages that may reveal sensitive information about the system architecture, database structure, or internal operations.",
                risk="Medium",
                cvss_score=5.3,
                solution="Implement generic error messages for production environments. Log detailed errors server-side only.",
                references=[
                    "https://owasp.org/www-community/Improper_Error_Handling",
                    "https://cwe.mitre.org/data/definitions/209.html"
                ],
                cwe_id="CWE-209",
                wasc_id="WASC-15",
                url=url,
                parameter="",
                evidence=f"Error message contains sensitive information: {response.text[:200]}...",
                scan_id="",  # Will be set by the scanner
                request=request_str,
                response=response_str
            ))
        
        return vulnerabilities
    
    def _check_insecure_headers(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for insecure HTTP headers."""
        vulnerabilities = []
        response_headers = response.headers
        
        # Check for missing security headers
        security_headers = {
            'Strict-Transport-Security': {
                'risk': 'High',
                'cvss': 7.5,
                'description': 'Missing HSTS header allows protocol downgrade attacks'
            },
            'X-Content-Type-Options': {
                'risk': 'Medium',
                'cvss': 6.1,
                'description': 'Missing X-Content-Type-Options header allows MIME type sniffing'
            },
            'X-Frame-Options': {
                'risk': 'Medium',
                'cvss': 6.1,
                'description': 'Missing X-Frame-Options header allows clickjacking attacks'
            }
        }
        
        for header, info in security_headers.items():
            if header not in response_headers:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name=f"Missing Security Header: {header}",
                    description=info['description'],
                    risk=info['risk'],
                    cvss_score=info['cvss'],
                    solution=f"Add the {header} header to all responses with appropriate values.",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
                    ],
                    cwe_id="CWE-693",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"Missing {header} header in response",
                    scan_id="",  # Will be set by the scanner
                    request=request_str,
                    response=response_str
                ))
        
        return vulnerabilities
    
    def _check_authentication_bypass(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for potential authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        # Check if protected endpoint returns data without authentication
        if response.status_code == 200 and not any(auth_header in headers for auth_header in 
                                                  ['Authorization', 'X-API-Key', 'Cookie']):
            
            # Check if response contains sensitive data
            sensitive_indicators = ['user', 'admin', 'password', 'token', 'secret', 'key']
            if any(indicator in response.text.lower() for indicator in sensitive_indicators):
                
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Potential Authentication Bypass",
                    description="The endpoint appears to return sensitive data without proper authentication, potentially allowing unauthorized access to protected resources.",
                    risk="High",
                    cvss_score=8.1,
                    solution="Implement proper authentication and authorization checks. Ensure all sensitive endpoints require valid authentication tokens.",
                    references=[
                        "https://owasp.org/www-community/controls/Authentication",
                        "https://cwe.mitre.org/data/definitions/287.html"
                    ],
                    cwe_id="CWE-287",
                    wasc_id="WASC-1",
                    url=url,
                    parameter="",
                    evidence=f"Endpoint returned sensitive data without authentication: {response.text[:200]}...",
                    scan_id="",  # Will be set by the scanner
                    request=request_str,
                    response=response_str
                ))
        
        return vulnerabilities
