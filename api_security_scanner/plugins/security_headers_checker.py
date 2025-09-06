"""
Custom plugin to check for security headers implementation.
"""

from typing import Dict, List, Any, Optional

from src.scanner_plugins import BasePlugin, PluginResult, ProofOfConcept


class SecurityHeadersChecker(BasePlugin):
    """Plugin to check for security headers implementation."""
    
    name = "SecurityHeadersChecker"
    description = "Checks for security headers implementation"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Check for security headers implementation."""
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
                    security_findings = self._check_security_headers(response)
                    findings.extend(security_findings)
        
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
        # This would typically retrieve stored request/response data
        # For now, return None as PoC data is stored during vulnerability creation
        return None
    
    def _check_security_headers(self, response) -> List[Dict[str, Any]]:
        """Check response for security headers."""
        findings = []
        headers = response.headers
        
        # Define security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'High',
                'description': 'HTTP Strict Transport Security (HSTS) header',
                'recommendation': 'Implement HSTS to prevent man-in-the-middle attacks and protocol downgrade attacks.'
            },
            'X-Content-Type-Options': {
                'severity': 'Medium',
                'description': 'X-Content-Type-Options header',
                'recommendation': 'Set X-Content-Type-Options to "nosniff" to prevent MIME type sniffing attacks.'
            },
            'X-Frame-Options': {
                'severity': 'Medium',
                'description': 'X-Frame-Options header',
                'recommendation': 'Set X-Frame-Options to "DENY" or "SAMEORIGIN" to prevent clickjacking attacks.'
            },
            'X-XSS-Protection': {
                'severity': 'Low',
                'description': 'X-XSS-Protection header',
                'recommendation': 'Set X-XSS-Protection to "1; mode=block" to enable XSS filtering.'
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'description': 'Referrer-Policy header',
                'recommendation': 'Set Referrer-Policy to control referrer information sent with requests.'
            },
            'Content-Security-Policy': {
                'severity': 'High',
                'description': 'Content Security Policy (CSP) header',
                'recommendation': 'Implement CSP to prevent XSS attacks and other code injection vulnerabilities.'
            },
            'Permissions-Policy': {
                'severity': 'Low',
                'description': 'Permissions Policy header',
                'recommendation': 'Implement Permissions Policy to control browser features and APIs.'
            }
        }
        
        # Check for missing security headers
        for header_name, header_info in security_headers.items():
            if header_name not in headers:
                findings.append(self.create_finding(
                    title=f"Missing {header_name}",
                    description=f"The API does not return the {header_info['description']}.",
                    severity=header_info['severity'],
                    evidence=f"Header {header_name} not found in response",
                    recommendation=header_info['recommendation'],
                    url=response.url,
                    method="GET",
                    headers=dict(response.headers),
                    response_code=response.status_code,
                    response_body=response.text[:500] if response.text else None
                ))
            else:
                # Check for proper values
                header_value = headers[header_name]
                value_findings = self._check_header_value(header_name, header_value, response)
                findings.extend(value_findings)
        
        # Check for dangerous headers
        dangerous_headers = self._check_dangerous_headers(headers, response)
        findings.extend(dangerous_headers)
        
        return findings
    
    def _check_header_value(self, header_name: str, header_value: str, response) -> List[Dict[str, Any]]:
        """Check if security header has proper value."""
        findings = []
        
        if header_name == 'X-Content-Type-Options':
            if header_value.lower() != 'nosniff':
                findings.append(self.create_finding(
                    title="Incorrect X-Content-Type-Options Value",
                    description=f"X-Content-Type-Options should be 'nosniff' but found '{header_value}'.",
                    severity="Medium",
                    evidence=f"X-Content-Type-Options: {header_value}",
                    recommendation="Set X-Content-Type-Options to 'nosniff' to prevent MIME type sniffing.",
                    url=response.url,
                    method="GET",
                    headers=dict(response.headers),
                    response_code=response.status_code
                ))
        
        elif header_name == 'X-Frame-Options':
            valid_values = ['deny', 'sameorigin', 'allow-from']
            if not any(header_value.lower().startswith(val) for val in valid_values):
                findings.append(self.create_finding(
                    title="Incorrect X-Frame-Options Value",
                    description=f"X-Frame-Options should be 'DENY', 'SAMEORIGIN', or 'ALLOW-FROM' but found '{header_value}'.",
                    severity="Medium",
                    evidence=f"X-Frame-Options: {header_value}",
                    recommendation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking.",
                    url=response.url,
                    method="GET",
                    headers=dict(response.headers),
                    response_code=response.status_code
                ))
        
        elif header_name == 'X-XSS-Protection':
            if header_value != '1; mode=block':
                findings.append(self.create_finding(
                    title="Incorrect X-XSS-Protection Value",
                    description=f"X-XSS-Protection should be '1; mode=block' but found '{header_value}'.",
                    severity="Low",
                    evidence=f"X-XSS-Protection: {header_value}",
                    recommendation="Set X-XSS-Protection to '1; mode=block' for better XSS protection.",
                    url=response.url,
                    method="GET",
                    headers=dict(response.headers),
                    response_code=response.status_code
                ))
        
        elif header_name == 'Strict-Transport-Security':
            if 'max-age' not in header_value.lower():
                findings.append(self.create_finding(
                    title="Incomplete HSTS Header",
                    description=f"HSTS header should include 'max-age' directive but found '{header_value}'.",
                    severity="High",
                    evidence=f"Strict-Transport-Security: {header_value}",
                    recommendation="Include 'max-age' directive in HSTS header with appropriate value (e.g., 'max-age=31536000').",
                    url=response.url,
                    method="GET",
                    headers=dict(response.headers),
                    response_code=response.status_code
                ))
        
        return findings
    
    def _check_dangerous_headers(self, headers: Dict[str, str], response) -> List[Dict[str, Any]]:
        """Check for dangerous or information-disclosing headers."""
        findings = []
        
        # Check for server information disclosure
        if 'Server' in headers:
            server_value = headers['Server']
            if any(version_info in server_value.lower() for version_info in ['version', 'v1.', 'v2.', '/1.', '/2.']):
                findings.append(self.create_finding(
                    title="Server Information Disclosure",
                    description="The Server header reveals version information that could be used by attackers.",
                    severity="Low",
                    evidence=f"Server: {server_value}",
                    recommendation="Remove or minimize server information in the Server header to prevent information disclosure.",
                    url=response.url,
                    method="GET",
                    headers=dict(response.headers),
                    response_code=response.status_code
                ))
        
        # Check for X-Powered-By header
        if 'X-Powered-By' in headers:
            findings.append(self.create_finding(
                title="Technology Information Disclosure",
                description="The X-Powered-By header reveals technology information that could be used by attackers.",
                severity="Low",
                evidence=f"X-Powered-By: {headers['X-Powered-By']}",
                recommendation="Remove the X-Powered-By header to prevent technology information disclosure.",
                url=response.url,
                method="GET",
                headers=dict(response.headers),
                response_code=response.status_code
            ))
        
        # Check for X-AspNet-Version header
        if 'X-AspNet-Version' in headers:
            findings.append(self.create_finding(
                title="ASP.NET Version Disclosure",
                description="The X-AspNet-Version header reveals ASP.NET version information.",
                severity="Low",
                evidence=f"X-AspNet-Version: {headers['X-AspNet-Version']}",
                recommendation="Remove the X-AspNet-Version header to prevent version information disclosure.",
                url=response.url,
                method="GET",
                headers=dict(response.headers),
                response_code=response.status_code
            ))
        
        return findings
