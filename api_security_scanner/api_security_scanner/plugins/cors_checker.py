"""
Enhanced CORS checker with comprehensive vulnerability detection.
"""

import re
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, ProofOfConcept, format_http_request, format_http_response


class CORSChecker(BasePlugin):
    """Enhanced plugin to check for CORS misconfigurations and security issues."""
    
    name = "CORSChecker"
    description = "Comprehensive CORS security analysis with vulnerability detection"
    version = "2.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Comprehensive CORS security analysis."""
        findings = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request to check CORS headers
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                response = self.make_request(url, method, headers)
                
                if response:
                    # Check for CORS misconfigurations
                    cors_misconfigs = self._check_cors_misconfigurations(response, url, method, headers)
                    findings.extend(cors_misconfigs)
                    
                    # Check for overly permissive CORS
                    permissive_cors = self._check_permissive_cors(response, url, method, headers)
                    findings.extend(permissive_cors)
                    
                    # Check for missing CORS headers
                    missing_cors = self._check_missing_cors_headers(response, url, method, headers)
                    findings.extend(missing_cors)
                    
                    # Test CORS with different origins
                    origin_tests = self._test_cors_origins(url, method, headers)
                    findings.extend(origin_tests)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"CORS check failed: {e}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=findings
        )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof-of-concept evidence for a specific vulnerability."""
        return None
    
    def _check_cors_misconfigurations(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for CORS misconfigurations."""
        findings = []
        response_headers = response.headers
        
        # Check for wildcard Access-Control-Allow-Origin
        if 'Access-Control-Allow-Origin' in response_headers:
            acao_value = response_headers['Access-Control-Allow-Origin']
            
            if acao_value == '*':
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="CORS Wildcard Origin",
                    description="Access-Control-Allow-Origin header set to wildcard (*)",
                    risk="High",
                    cvss_score=7.5,
                    solution="Set Access-Control-Allow-Origin to specific domains instead of wildcard",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                    cwe_id="CWE-942",
                    wasc_id="WASC-14",
                    url=url,
                    parameter="",
                    evidence=f"Access-Control-Allow-Origin: {acao_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
            
            # Check for null origin
            elif acao_value == 'null':
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="CORS Null Origin",
                    description="Access-Control-Allow-Origin header set to null",
                    risk="High",
                    cvss_score=7.5,
                    solution="Remove null from Access-Control-Allow-Origin header",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                    cwe_id="CWE-942",
                    wasc_id="WASC-14",
                    url=url,
                    parameter="",
                    evidence=f"Access-Control-Allow-Origin: {acao_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _check_permissive_cors(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for overly permissive CORS configurations."""
        findings = []
        response_headers = response.headers
        
        # Check for wildcard Access-Control-Allow-Methods
        if 'Access-Control-Allow-Methods' in response_headers:
            acam_value = response_headers['Access-Control-Allow-Methods']
            if '*' in acam_value:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="CORS Wildcard Methods",
                    description="Access-Control-Allow-Methods contains wildcard (*)",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Specify exact HTTP methods instead of using wildcard",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                    cwe_id="CWE-942",
                    wasc_id="WASC-14",
                    url=url,
                    parameter="",
                    evidence=f"Access-Control-Allow-Methods: {acam_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        # Check for wildcard Access-Control-Allow-Headers
        if 'Access-Control-Allow-Headers' in response_headers:
            acah_value = response_headers['Access-Control-Allow-Headers']
            if '*' in acah_value:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request(method, url, headers)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="CORS Wildcard Headers",
                    description="Access-Control-Allow-Headers contains wildcard (*)",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Specify exact headers instead of using wildcard",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                    cwe_id="CWE-942",
                    wasc_id="WASC-14",
                    url=url,
                    parameter="",
                    evidence=f"Access-Control-Allow-Headers: {acah_value}",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        
        # Check for Access-Control-Allow-Credentials with wildcard origin
        if 'Access-Control-Allow-Credentials' in response_headers:
            acac_value = response_headers['Access-Control-Allow-Credentials']
            if acac_value.lower() == 'true' and 'Access-Control-Allow-Origin' in response_headers:
                acao_value = response_headers['Access-Control-Allow-Origin']
                if acao_value == '*':
                    vuln_id = str(uuid.uuid4())
                    request_str = format_http_request(method, url, headers)
                    response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                    
                    findings.append(self.create_vulnerability(
                        vuln_id=vuln_id,
                        name="CORS Credentials with Wildcard Origin",
                        description="Access-Control-Allow-Credentials is true with wildcard origin",
                        risk="Critical",
                        cvss_score=9.0,
                        solution="Either remove Access-Control-Allow-Credentials or set specific origin",
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                        cwe_id="CWE-942",
                        wasc_id="WASC-14",
                        url=url,
                        parameter="",
                        evidence=f"Access-Control-Allow-Credentials: {acac_value}, Access-Control-Allow-Origin: {acao_value}",
                        scan_id="",
                        request=request_str,
                        response=response_str
                    ))
        
        return findings
    
    def _check_missing_cors_headers(self, response, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for missing CORS headers when CORS is expected."""
        findings = []
        response_headers = response.headers
        
        # Check if CORS headers are missing entirely
        cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 
                       'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']
        
        missing_headers = [h for h in cors_headers if h not in response_headers]
        
        if missing_headers:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Missing CORS Headers",
                description=f"Missing CORS headers: {', '.join(missing_headers)}",
                risk="Medium",
                cvss_score=5.3,
                solution="Implement proper CORS headers for cross-origin requests",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                cwe_id="CWE-942",
                wasc_id="WASC-14",
                url=url,
                parameter="",
                evidence=f"Missing headers: {', '.join(missing_headers)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings
    
    def _test_cors_origins(self, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test CORS with different origins."""
        findings = []
        
        # Test origins that might be allowed
        test_origins = [
            'https://evil.com',
            'http://localhost',
            'https://attacker.com',
            'null',
            'https://subdomain.evil.com'
        ]
        
        allowed_origins = []
        evidence_instances = []
        
        for origin in test_origins:
            test_headers = headers.copy()
            test_headers['Origin'] = origin
            
            try:
                response = self.make_request(url, method, test_headers)
                if response and 'Access-Control-Allow-Origin' in response.headers:
                    acao_value = response.headers['Access-Control-Allow-Origin']
                    
                    if acao_value == origin or acao_value == '*':
                        allowed_origins.append(origin)
                        evidence_instances.append(f"Origin: {origin}, Access-Control-Allow-Origin: {acao_value}")
            except Exception:
                continue
        
        # Create single vulnerability for all allowed suspicious origins
        if allowed_origins:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(200, {}, "Multiple CORS origin tests performed")
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="CORS Allows Suspicious Origins",
                description=f"API allows requests from {len(allowed_origins)} suspicious origins: {', '.join(allowed_origins)}",
                risk="High",
                cvss_score=7.5,
                solution="Restrict Access-Control-Allow-Origin to trusted domains only",
                references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                cwe_id="CWE-942",
                wasc_id="WASC-14",
                url=url,
                parameter="",
                evidence=f"Allowed origins: {', '.join(allowed_origins)}. Evidence: {'; '.join(evidence_instances)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings