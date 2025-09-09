"""
Enhanced rate limiting checker with comprehensive vulnerability detection.
"""

import re
import uuid
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, ProofOfConcept, format_http_request, format_http_response


class RateLimitingChecker(BasePlugin):
    """Enhanced plugin to check for rate limiting implementation and vulnerabilities."""
    
    name = "RateLimitingChecker"
    description = "Comprehensive rate limiting analysis with vulnerability detection"
    version = "2.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Comprehensive rate limiting analysis."""
        findings = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request to check rate limiting
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                # Check for rate limiting headers
                rate_limit_headers = self._check_rate_limiting_headers(url, method, headers)
                findings.extend(rate_limit_headers)
                
                # Test rate limiting behavior
                rate_limit_behavior = self._test_rate_limiting_behavior(url, method, headers)
                findings.extend(rate_limit_behavior)
                
                # Check for DDoS vulnerabilities
                ddos_vulnerabilities = self._check_ddos_vulnerabilities(url, method, headers)
                findings.extend(ddos_vulnerabilities)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"Rate limiting check failed: {e}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=findings
        )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof-of-concept evidence for a specific vulnerability."""
        return None
    
    def _check_rate_limiting_headers(self, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for rate limiting headers in response."""
        findings = []
        
        response = self.make_request(url, method, headers)
        if not response:
            return findings
        
        response_headers = response.headers
        
        # Check for missing rate limiting headers
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'RateLimit-Reset',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
            'X-Rate-Limit-Reset'
        ]
        
        missing_headers = [h for h in rate_limit_headers if h not in response_headers]
        
        if missing_headers:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Missing Rate Limiting Headers",
                description="API does not provide rate limiting information in response headers",
                risk="Medium",
                cvss_score=5.3,
                solution="Implement rate limiting headers to inform clients about rate limits",
                references=["https://tools.ietf.org/id/draft-polli-ratelimit-headers-00.html"],
                cwe_id="CWE-770",
                wasc_id="WASC-21",
                url=url,
                parameter="",
                evidence=f"Missing headers: {', '.join(missing_headers)}",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        # Check for weak rate limiting values
        if 'X-RateLimit-Limit' in response_headers:
            try:
                limit = int(response_headers['X-RateLimit-Limit'])
                if limit > 1000:  # Very high limit
                    vuln_id = str(uuid.uuid4())
                    request_str = format_http_request(method, url, headers)
                    response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                    
                    findings.append(self.create_vulnerability(
                        vuln_id=vuln_id,
                        name="Weak Rate Limiting Configuration",
                        description=f"Rate limit is very high: {limit} requests",
                        risk="Medium",
                        cvss_score=5.3,
                        solution="Implement stricter rate limiting to prevent abuse",
                        references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                        cwe_id="CWE-770",
                        wasc_id="WASC-21",
                        url=url,
                        parameter="",
                        evidence=f"X-RateLimit-Limit: {limit}",
                        scan_id="",
                        request=request_str,
                        response=response_str
                    ))
            except ValueError:
                pass
        
        return findings
    
    def _test_rate_limiting_behavior(self, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Test actual rate limiting behavior by making multiple requests."""
        findings = []
        
        # Make multiple rapid requests to test rate limiting
        rapid_requests = 10
        status_codes = []
        responses = []
        
        for i in range(rapid_requests):
            try:
                response = self.make_request(url, method, headers)
                if response:
                    status_codes.append(response.status_code)
                    responses.append(response)
                time.sleep(0.1)  # Small delay between requests
            except Exception:
                continue
        
        if not status_codes:
            return findings
        
        # Check if all requests succeeded (potential lack of rate limiting)
        if all(code == 200 for code in status_codes):
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(200, {}, "All requests succeeded")
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="No Rate Limiting Detected",
                description=f"All {rapid_requests} rapid requests returned 200 status code",
                risk="Medium",
                cvss_score=5.3,
                solution="Implement rate limiting to prevent abuse and DDoS attacks",
                references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                cwe_id="CWE-770",
                wasc_id="WASC-21",
                url=url,
                parameter="",
                evidence=f"All {rapid_requests} requests returned 200 status code",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        # Check for 429 (Too Many Requests) responses
        if 429 in status_codes:
            vuln_id = str(uuid.uuid4())
            request_str = format_http_request(method, url, headers)
            response_str = format_http_response(429, {}, "Rate limit exceeded")
            
            findings.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Rate Limiting Enforced",
                description="API returns 429 status code when rate limit is exceeded",
                risk="Informational",
                cvss_score=0.0,
                solution="Rate limiting is properly implemented",
                references=["https://tools.ietf.org/html/rfc6585"],
                cwe_id="CWE-770",
                wasc_id="WASC-21",
                url=url,
                parameter="",
                evidence="API returns 429 status code for rate limit exceeded",
                scan_id="",
                request=request_str,
                response=response_str
            ))
        
        return findings
    
    def _check_ddos_vulnerabilities(self, url: str, method: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for DDoS vulnerabilities."""
        findings = []
        
        # Test with different HTTP methods
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        for test_method in methods_to_test:
            try:
                response = self.make_request(url, test_method, headers)
                if response and response.status_code == 200:
                    # Check if the API accepts all methods without proper restrictions
                    if test_method in ['PUT', 'DELETE', 'PATCH']:
                        vuln_id = str(uuid.uuid4())
                        request_str = format_http_request(test_method, url, headers)
                        response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                        
                        findings.append(self.create_vulnerability(
                            vuln_id=vuln_id,
                            name=f"Unrestricted {test_method} Method",
                            description=f"API accepts {test_method} method without proper restrictions",
                            risk="Medium",
                            cvss_score=5.3,
                            solution=f"Restrict {test_method} method or implement proper authentication/authorization",
                            references=["https://owasp.org/www-community/attacks/HTTP_Method_Override"],
                            cwe_id="CWE-770",
                            wasc_id="WASC-21",
                            url=url,
                            parameter="",
                            evidence=f"{test_method} method returned 200 status code",
                            scan_id="",
                            request=request_str,
                            response=response_str
                        ))
            except Exception:
                continue
        
        # Test with large payload
        large_payload = "A" * 10000  # 10KB payload
        large_headers = headers.copy()
        large_headers['Content-Type'] = 'application/json'
        
        try:
            response = self.make_request(url, 'POST', large_headers, large_payload)
            if response and response.status_code == 200:
                vuln_id = str(uuid.uuid4())
                request_str = format_http_request('POST', url, large_headers, large_payload)
                response_str = format_http_response(response.status_code, dict(response.headers), response.text[:1000])
                
                findings.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Large Payload Accepted",
                    description="API accepts large payloads without size restrictions",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Implement payload size limits to prevent resource exhaustion",
                    references=["https://owasp.org/www-community/attacks/Denial_of_Service"],
                    cwe_id="CWE-770",
                    wasc_id="WASC-21",
                    url=url,
                    parameter="",
                    evidence="API accepted 10KB payload without restrictions",
                    scan_id="",
                    request=request_str,
                    response=response_str
                ))
        except Exception:
            pass
        
        return findings