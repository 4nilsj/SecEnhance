"""
Enhanced security headers checker with comprehensive vulnerability detection.
"""

import re
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, ProofOfConcept, format_http_request, format_http_response


class SecurityHeadersChecker(BasePlugin):
    """Enhanced plugin to check for security headers implementation with detailed analysis."""
    
    name = "SecurityHeadersChecker"
    description = "Comprehensive security headers analysis with vulnerability detection"
    version = "2.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Comprehensive security headers analysis."""
        findings = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request to check security headers
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                response = self.make_request(url, method, headers)
                
                if response:
                    # Check for missing security headers
                    missing_headers = self._check_missing_security_headers(response, url, method, headers)
                    findings.extend(missing_headers)
                    
                    # Check for misconfigured security headers
                    misconfigured_headers = self._check_misconfigured_headers(response, url, method, headers)
                    findings.extend(misconfigured_headers)
                    
                    # Check for information disclosure headers
                    info_disclosure = self._check_information_disclosure_headers(response, url, method, headers)
                    findings.extend(info_disclosure)
                    
                    # Check for weak security configurations
                    weak_configs = self._check_weak_security_configurations(response, url, method, headers)
                    findings.extend(weak_configs)
                    
                    # Check for server information disclosure
                    server_info = self._check_server_information_disclosure(response, url, method, headers)
                    findings.extend(server_info)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"Security headers check failed: {e}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=findings
        )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof-of-concept evidence for a specific vulnerability."""
        return None
    
    def _check_missing_security_headers(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for missing critical security headers."""
        findings = []
        response_headers = response.headers
        
        # Critical security headers with detailed analysis
        critical_headers = {
            'Strict-Transport-Security': {
                'risk': 'High',
                'cvss_score': 7.5,
                'cwe_id': 'CWE-319',
                'wasc_id': 'WASC-15',
                'description': 'HTTP Strict Transport Security (HSTS) header missing',
                'solution': 'Implement HSTS with max-age directive to prevent MITM attacks and protocol downgrade attacks.',
                'references': ['https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security']
            },
            'X-Content-Type-Options': {
                'risk': 'Medium',
                'cvss_score': 6.1,
                'cwe_id': 'CWE-693',
                'wasc_id': 'WASC-15',
                'description': 'X-Content-Type-Options header missing',
                'solution': 'Set X-Content-Type-Options to "nosniff" to prevent MIME type sniffing attacks.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
            },
            'X-Frame-Options': {
                'risk': 'Medium',
                'cvss_score': 6.1,
                'cwe_id': 'CWE-693',
                'wasc_id': 'WASC-15',
                'description': 'X-Frame-Options header missing',
                'solution': 'Set X-Frame-Options to "DENY" or "SAMEORIGIN" to prevent clickjacking attacks.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
            },
            'Content-Security-Policy': {
                'risk': 'High',
                'cvss_score': 8.1,
                'cwe_id': 'CWE-693',
                'wasc_id': 'WASC-15',
                'description': 'Content Security Policy (CSP) header missing',
                'solution': 'Implement CSP to prevent XSS attacks and other code injection vulnerabilities.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            },
            'X-XSS-Protection': {
                'risk': 'Low',
                'cvss_score': 4.3,
                'cwe_id': 'CWE-79',
                'wasc_id': 'WASC-8',
                'description': 'X-XSS-Protection header missing',
                'solution': 'Set X-XSS-Protection to "1; mode=block" to enable XSS filtering.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection']
            },
            'Referrer-Policy': {
                'risk': 'Low',
                'cvss_score': 3.7,
                'cwe_id': 'CWE-200',
                'wasc_id': 'WASC-13',
                'description': 'Referrer-Policy header missing',
                'solution': 'Set Referrer-Policy to control referrer information sent with requests.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
            },
            'Permissions-Policy': {
                'risk': 'Low',
                'cvss_score': 3.7,
                'cwe_id': 'CWE-693',
                'wasc_id': 'WASC-15',
                'description': 'Permissions Policy header missing',
                'solution': 'Implement Permissions Policy to control browser features and APIs.',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy']
            }
        }
        
        # Group missing headers by risk level
        missing_headers = {
            'High': [],
            'Medium': [],
            'Low': []
        }
        
        for header_name, header_info in critical_headers.items():
            if header_name not in response_headers:
                missing_headers[header_info['risk']].append({
                    'name': header_name,
                    'info': header_info
                })
        
        # Create consolidated vulnerabilities by risk level
        for risk_level, headers_list in missing_headers.items():
            if headers_list:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                # Use the highest CVSS score for the risk level
                max_cvss = max(header['info']['cvss_score'] for header in headers_list)
                header_names = [header['name'] for header in headers_list]
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name=f"Missing {risk_level} Risk Security Headers",
                    description=f"API is missing {len(headers_list)} {risk_level.lower()} risk security headers: {', '.join(header_names)}",
                    risk=risk_level,
                    cvss_score=max_cvss,
                    solution=f"Implement the following security headers: {', '.join(header_names)}",
                    references=headers_list[0]['info']['references'],  # Use first header's references
                    cwe_id=headers_list[0]['info']['cwe_id'],  # Use first header's CWE
                    wasc_id=headers_list[0]['info']['wasc_id'],  # Use first header's WASC
                    url=url,
                    parameter="",
                    evidence=f"Missing headers: {', '.join(header_names)}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _check_misconfigured_headers(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for misconfigured security headers."""
        findings = []
        response_headers = response.headers
        
        # Check HSTS configuration
        if 'Strict-Transport-Security' in response_headers:
            hsts_value = response_headers['Strict-Transport-Security']
            if 'max-age' not in hsts_value:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Misconfigured HSTS Header",
                    description="HSTS header present but missing max-age directive",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Add max-age directive to HSTS header (e.g., max-age=31536000)",
                    references=["https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security"],
                    cwe_id="CWE-319",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"HSTS header value: {hsts_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        # Check X-Content-Type-Options configuration
        if 'X-Content-Type-Options' in response_headers:
            xcto_value = response_headers['X-Content-Type-Options']
            if xcto_value.lower() != 'nosniff':
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Misconfigured X-Content-Type-Options",
                    description="X-Content-Type-Options header not set to 'nosniff'",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Set X-Content-Type-Options to 'nosniff'",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                    cwe_id="CWE-693",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"X-Content-Type-Options value: {xcto_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        # Check X-Frame-Options configuration
        if 'X-Frame-Options' in response_headers:
            xfo_value = response_headers['X-Frame-Options']
            if xfo_value.upper() not in ['DENY', 'SAMEORIGIN']:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Misconfigured X-Frame-Options",
                    description="X-Frame-Options header not set to 'DENY' or 'SAMEORIGIN'",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                    cwe_id="CWE-693",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"X-Frame-Options value: {xfo_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _check_information_disclosure_headers(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for information disclosure through headers."""
        findings = []
        response_headers = response.headers
        
        # Check for server information disclosure
        if 'Server' in response_headers:
            server_value = response_headers['Server']
            # Check for version information in server header
            if re.search(r'\d+\.\d+', server_value):
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Server Version Disclosure",
                    description="Server header contains version information",
                    risk="Low",
                    cvss_score=3.7,
                    solution="Remove version information from Server header",
                    references=["https://owasp.org/www-community/controls/Information_Exposure"],
                    cwe_id="CWE-200",
                    wasc_id="WASC-13",
                    url=url,
                    parameter="",
                    evidence=f"Server header: {server_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        # Check for X-Powered-By header
        if 'X-Powered-By' in response_headers:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Technology Stack Disclosure",
                description="X-Powered-By header reveals technology stack information",
                risk="Low",
                cvss_score=3.7,
                solution="Remove X-Powered-By header to hide technology stack",
                references=["https://owasp.org/www-community/controls/Information_Exposure"],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=url,
                parameter="",
                evidence=f"X-Powered-By header: {response_headers['X-Powered-By']}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings
    
    def _check_weak_security_configurations(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for weak security configurations."""
        findings = []
        response_headers = response.headers
        
        # Check for weak CSP configuration
        if 'Content-Security-Policy' in response_headers:
            csp_value = response_headers['Content-Security-Policy']
            if "'unsafe-inline'" in csp_value or "'unsafe-eval'" in csp_value:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Weak Content Security Policy",
                    description="CSP contains unsafe directives (unsafe-inline or unsafe-eval)",
                    risk="Medium",
                    cvss_score=6.1,
                    solution="Remove unsafe-inline and unsafe-eval from CSP",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    cwe_id="CWE-693",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"CSP value: {csp_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        # Check for weak HSTS configuration
        if 'Strict-Transport-Security' in response_headers:
            hsts_value = response_headers['Strict-Transport-Security']
            if 'includeSubDomains' not in hsts_value:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Incomplete HSTS Configuration",
                    description="HSTS header missing includeSubDomains directive",
                    risk="Low",
                    cvss_score=4.3,
                    solution="Add includeSubDomains directive to HSTS header",
                    references=["https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security"],
                    cwe_id="CWE-319",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="",
                    evidence=f"HSTS value: {hsts_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _check_server_information_disclosure(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for additional server information disclosure."""
        findings = []
        response_headers = response.headers
        
        # Check for X-AspNet-Version header
        if 'X-AspNet-Version' in response_headers:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="ASP.NET Version Disclosure",
                description="X-AspNet-Version header reveals ASP.NET version",
                risk="Low",
                cvss_score=3.7,
                solution="Remove X-AspNet-Version header",
                references=["https://owasp.org/www-community/controls/Information_Exposure"],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=url,
                parameter="",
                evidence=f"X-AspNet-Version: {response_headers['X-AspNet-Version']}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        # Check for X-AspNetMvc-Version header
        if 'X-AspNetMvc-Version' in response_headers:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="ASP.NET MVC Version Disclosure",
                description="X-AspNetMvc-Version header reveals ASP.NET MVC version",
                risk="Low",
                cvss_score=3.7,
                solution="Remove X-AspNetMvc-Version header",
                references=["https://owasp.org/www-community/controls/Information_Exposure"],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=url,
                parameter="",
                evidence=f"X-AspNetMvc-Version: {response_headers['X-AspNetMvc-Version']}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings