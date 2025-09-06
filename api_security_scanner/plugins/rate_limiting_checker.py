"""
Custom plugin to check for rate limiting headers and mechanisms.
"""

import re
from typing import Dict, List, Any, Optional

from src.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept
import uuid


class RateLimitingChecker(BasePlugin):
    """Plugin to check for rate limiting implementation."""
    
    name = "RateLimitingChecker"
    description = "Checks for rate limiting headers and mechanisms"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Check for rate limiting implementation."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Make request to check for rate limiting headers
                headers = request.get('headers', {}).copy()
                if auth_headers:
                    headers.update(auth_headers)
                
                response = self.make_request(url, method, headers)
                
                if response:
                    # Check for rate limiting headers
                    rate_limit_vulns = self._check_rate_limit_headers(response, url, method, headers)
                    if rate_limit_vulns:
                        vulnerabilities.extend(rate_limit_vulns)
                    
                    # Check for rate limiting behavior
                    rate_limit_behavior = self._check_rate_limit_behavior(url, method, headers)
                    if rate_limit_behavior:
                        vulnerabilities.extend(rate_limit_behavior)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                error=f"Rate limiting check failed: {e}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities
        )
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof-of-concept evidence for a specific vulnerability."""
        # This would typically retrieve stored request/response data
        # For now, return None as PoC data is stored during vulnerability creation
        return None
    
    def _check_rate_limit_headers(self, response, url: str, method: str, request_headers: Dict[str, str]) -> List[Vulnerability]:
        """Check response headers for rate limiting information."""
        vulnerabilities = []
        headers = response.headers
        
        # Common rate limiting headers
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'X-RateLimit-Reset-After',
            'Retry-After',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
            'X-Rate-Limit-Reset'
        ]
        
        found_headers = []
        for header in rate_limit_headers:
            if header in headers:
                found_headers.append(f"{header}: {headers[header]}")
        
        if found_headers:
            vuln_id = str(uuid.uuid4())
            request_str = self.format_http_request(method, url, request_headers)
            response_str = self.format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            vulnerabilities.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="Rate Limiting Headers Present",
                description="The API returns rate limiting headers, indicating rate limiting is implemented.",
                risk="Informational",
                cvss_score=0.0,
                solution="Verify that rate limiting is properly configured and enforced.",
                references=["https://tools.ietf.org/html/rfc6585"],
                cwe_id="CWE-770",
                wasc_id="WASC-19",
                url=url,
                parameter="",
                evidence=f"Headers found: {', '.join(found_headers)}",
                scan_id="",  # Will be set by the scanner
                request=request_str,
                response=response_str
            ))
        else:
            vuln_id = str(uuid.uuid4())
            request_str = self.format_http_request(method, url, request_headers)
            response_str = self.format_http_response(response.status_code, dict(response.headers), response.text[:1000])
            
            vulnerabilities.append(self.create_vulnerability(
                vuln_id=vuln_id,
                name="No Rate Limiting Headers",
                description="The API does not return standard rate limiting headers.",
                risk="Medium",
                cvss_score=5.3,
                solution="Consider implementing rate limiting and returning appropriate headers to inform clients of limits.",
                references=["https://tools.ietf.org/html/rfc6585"],
                cwe_id="CWE-770",
                wasc_id="WASC-19",
                url=url,
                parameter="",
                evidence="No rate limiting headers found in response",
                scan_id="",  # Will be set by the scanner
                request=request_str,
                response=response_str
            ))
        
        return vulnerabilities
    
    def _check_rate_limit_behavior(self, url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for rate limiting behavior by making multiple requests."""
        vulnerabilities = []
        
        try:
            # Make multiple rapid requests to test rate limiting
            responses = []
            for i in range(5):
                response = self.make_request(url, method, headers)
                if response:
                    responses.append(response)
            
            # Analyze responses for rate limiting behavior
            status_codes = [r.status_code for r in responses]
            
            # Check for 429 (Too Many Requests) responses
            if 429 in status_codes:
                vuln_id = str(uuid.uuid4())
                request_str = self.format_http_request(method, url, headers)
                response_str = self.format_http_response(429, {}, "Rate limit exceeded")
                
                vulnerabilities.append(self.create_vulnerability(
                    vuln_id=vuln_id,
                    name="Rate Limiting Enforced",
                    description="The API returns 429 status code when rate limit is exceeded.",
                    risk="Informational",
                    cvss_score=0.0,
                    solution="Rate limiting is properly implemented. Ensure limits are appropriate for your use case.",
                    references=["https://tools.ietf.org/html/rfc6585"],
                    cwe_id="CWE-770",
                    wasc_id="WASC-19",
                    url=url,
                    parameter="",
                    evidence=f"Received 429 status code after {len(responses)} requests",
                    scan_id="",  # Will be set by the scanner
                    request=request_str,
                    response=response_str
                ))
            else:
                # Check if all requests succeeded (potential lack of rate limiting)
                if all(code == 200 for code in status_codes):
                    vuln_id = str(uuid.uuid4())
                    request_str = self.format_http_request(method, url, headers)
                    response_str = self.format_http_response(200, {}, "All requests succeeded")
                    
                    vulnerabilities.append(self.create_vulnerability(
                        vuln_id=vuln_id,
                        name="No Rate Limiting Detected",
                        description="Multiple rapid requests all succeeded, suggesting no rate limiting is enforced.",
                        risk="Medium",
                        cvss_score=5.3,
                        solution="Implement rate limiting to prevent abuse and ensure fair usage.",
                        references=["https://tools.ietf.org/html/rfc6585"],
                        cwe_id="CWE-770",
                        wasc_id="WASC-19",
                        url=url,
                        parameter="",
                        evidence=f"All {len(responses)} rapid requests returned 200 status code",
                        scan_id="",  # Will be set by the scanner
                        request=request_str,
                        response=response_str
                    ))
        
        except Exception as e:
            # Don't fail the entire check if rate limiting test fails
            pass
        
        return vulnerabilities
