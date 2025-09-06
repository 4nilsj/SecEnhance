"""
Custom plugin to check for CORS (Cross-Origin Resource Sharing) misconfigurations.
"""

import re
from typing import Dict, List, Any, Optional

from src.scanner_plugins import BasePlugin, PluginResult, ProofOfConcept


class CORSChecker(BasePlugin):
    """Plugin to check for CORS misconfigurations."""
    
    name = "CORSChecker"
    description = "Checks for CORS misconfigurations and security issues"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Check for CORS misconfigurations."""
        findings = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                
                # Check CORS with different origins
                cors_findings = self._check_cors_headers(url, method, request.get('headers', {}), auth_headers)
                findings.extend(cors_findings)
        
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
        # This would typically retrieve stored request/response data
        # For now, return None as PoC data is stored during vulnerability creation
        return None
    
    def _check_cors_headers(self, url: str, method: str, headers: Dict[str, str], 
                           auth_headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Check CORS headers with different origins."""
        findings = []
        
        # Test origins
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'http://localhost:3000',
            'https://subdomain.evil.com',
            'null'
        ]
        
        # First, make a normal request to see baseline CORS headers
        request_headers = headers.copy()
        if auth_headers:
            request_headers.update(auth_headers)
        
        baseline_response = self.make_request(url, method, request_headers)
        if not baseline_response:
            return findings
        
        baseline_cors_headers = self._extract_cors_headers(baseline_response)
        
        # Test with different origins
        for origin in test_origins:
            test_headers = request_headers.copy()
            test_headers['Origin'] = origin
            
            # Make preflight request
            preflight_response = self.make_request(url, 'OPTIONS', test_headers)
            if preflight_response:
                cors_headers = self._extract_cors_headers(preflight_response)
                cors_findings = self._analyze_cors_headers(origin, cors_headers, url, method)
                findings.extend(cors_findings)
        
        # Check for wildcard CORS
        if baseline_cors_headers.get('Access-Control-Allow-Origin') == '*':
            findings.append(self.create_finding(
                title="Wildcard CORS Policy",
                description="The API allows requests from any origin using wildcard (*) CORS policy.",
                severity="High",
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Replace wildcard CORS with specific allowed origins. Wildcard CORS can lead to data theft and CSRF attacks.",
                url=url,
                method=method,
                headers=dict(baseline_response.headers),
                response_code=baseline_response.status_code,
                response_body=baseline_response.text[:500] if baseline_response.text else None
            ))
        
        return findings
    
    def _extract_cors_headers(self, response) -> Dict[str, str]:
        """Extract CORS-related headers from response."""
        cors_headers = {}
        headers = response.headers
        
        cors_header_names = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Credentials',
            'Access-Control-Max-Age',
            'Access-Control-Expose-Headers'
        ]
        
        for header in cors_header_names:
            if header in headers:
                cors_headers[header] = headers[header]
        
        return cors_headers
    
    def _analyze_cors_headers(self, origin: str, cors_headers: Dict[str, str], 
                             url: str, method: str) -> List[Dict[str, Any]]:
        """Analyze CORS headers for security issues."""
        findings = []
        
        allow_origin = cors_headers.get('Access-Control-Allow-Origin')
        allow_credentials = cors_headers.get('Access-Control-Allow-Credentials')
        allow_methods = cors_headers.get('Access-Control-Allow-Methods')
        allow_headers = cors_headers.get('Access-Control-Allow-Headers')
        
        # Check for wildcard with credentials
        if allow_origin == '*' and allow_credentials == 'true':
            findings.append(self.create_finding(
                title="Dangerous CORS Configuration",
                description="The API allows credentials with wildcard origin, which is a serious security vulnerability.",
                severity="Critical",
                evidence=f"Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true for origin {origin}",
                recommendation="Never use wildcard origin with credentials. Specify exact origins or implement proper origin validation.",
                url=url,
                method=method,
                headers=cors_headers,
                response_code=200
            ))
        
        # Check for overly permissive methods
        if allow_methods and '*' in allow_methods:
            findings.append(self.create_finding(
                title="Overly Permissive CORS Methods",
                description="The API allows all HTTP methods via CORS wildcard.",
                severity="Medium",
                evidence=f"Access-Control-Allow-Methods: {allow_methods} for origin {origin}",
                recommendation="Specify only the HTTP methods that are actually needed for your API.",
                url=url,
                method=method,
                headers=cors_headers,
                response_code=200
            ))
        
        # Check for overly permissive headers
        if allow_headers and '*' in allow_headers:
            findings.append(self.create_finding(
                title="Overly Permissive CORS Headers",
                description="The API allows all headers via CORS wildcard.",
                severity="Medium",
                evidence=f"Access-Control-Allow-Headers: {allow_headers} for origin {origin}",
                recommendation="Specify only the headers that are actually needed for your API.",
                url=url,
                method=method,
                headers=cors_headers,
                response_code=200
            ))
        
        # Check for null origin with credentials
        if origin == 'null' and allow_credentials == 'true':
            findings.append(self.create_finding(
                title="Null Origin with Credentials",
                description="The API allows credentials for null origin, which can be exploited.",
                severity="High",
                evidence=f"Access-Control-Allow-Credentials: true for null origin",
                recommendation="Do not allow credentials for null origin. This can be exploited by malicious websites.",
                url=url,
                method=method,
                headers=cors_headers,
                response_code=200
            ))
        
        # Check for missing CORS headers
        if not cors_headers:
            findings.append(self.create_finding(
                title="No CORS Headers",
                description="The API does not return CORS headers, which may cause issues for web applications.",
                severity="Low",
                evidence=f"No CORS headers found for origin {origin}",
                recommendation="Implement proper CORS headers if the API is intended to be used by web applications.",
                url=url,
                method=method,
                headers={},
                response_code=200
            ))
        
        return findings
