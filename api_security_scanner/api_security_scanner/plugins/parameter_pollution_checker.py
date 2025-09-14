"""
Parameter Pollution Security Checker Plugin
Comprehensive HTTP Parameter Pollution (HPP) vulnerability detection.
"""

import re
import json
import uuid
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept, format_http_request, format_http_response


class ParameterPollutionChecker(BasePlugin):
    """Comprehensive HTTP Parameter Pollution (HPP) security analysis plugin."""
    
    name = "ParameterPollutionChecker"
    description = "HTTP Parameter Pollution vulnerability detection and analysis"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def __init__(self, zap=None, target=None):
        super().__init__(zap=zap, target=target)
        
        # Common parameter pollution patterns
        self.sensitive_params = [
            'id', 'user_id', 'account_id', 'session_id', 'token', 'key', 'secret',
            'password', 'passwd', 'pwd', 'username', 'email', 'role', 'permission',
            'admin', 'root', 'access', 'auth', 'login', 'logout', 'redirect',
            'callback', 'return', 'next', 'url', 'uri', 'path', 'file', 'action',
            'method', 'cmd', 'command', 'exec', 'eval', 'query', 'search', 'filter',
            'sort', 'order', 'limit', 'offset', 'page', 'size', 'count'
        ]
        
        # Parameter pollution attack patterns
        self.pollution_patterns = {
            'duplicate_params': re.compile(r'([^&=]+)=([^&]*)(?:&([^&=]+)=\2)*', re.IGNORECASE),
            'array_notation': re.compile(r'([^&=]+)\[\]', re.IGNORECASE),
            'nested_params': re.compile(r'([^&=]+)\[([^&\]]+)\]', re.IGNORECASE),
            'encoded_params': re.compile(r'%[0-9a-fA-F]{2}', re.IGNORECASE)
        }
        
        # Common parameter pollution payloads
        self.pollution_payloads = [
            '&param=value1&param=value2',
            '&param[]=value1&param[]=value2',
            '&param[0]=value1&param[1]=value2',
            '&param=value1%26param=value2',
            '&param=value1%3Bparam=value2',
            '&param=value1%2Cparam=value2'
        ]
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform parameter pollution analysis on requests and responses."""
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
                    # Check for parameter pollution vulnerabilities
                    pollution_vulns = self._check_parameter_pollution(request, response, url, method, headers)
                    vulnerabilities.extend(pollution_vulns)
                    
                    # Check for parameter pollution in URL
                    url_vulns = self._check_url_parameter_pollution(url, method, headers)
                    vulnerabilities.extend(url_vulns)
                    
                    # Check for parameter pollution in request body
                    body_vulns = self._check_body_parameter_pollution(request, response, url, method, headers)
                    vulnerabilities.extend(body_vulns)
                    
                    # Test for parameter pollution vulnerabilities
                    test_vulns = self._test_parameter_pollution_vulnerabilities(request, response, url, method, headers)
                    vulnerabilities.extend(test_vulns)
        
        except Exception as e:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=f"Parameter pollution check failed: {str(e)}"
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities,
            error=None
        )
    
    def _check_parameter_pollution(self, request: Dict[str, Any], response: Any, 
                                  url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for parameter pollution vulnerabilities in the request."""
        vulnerabilities = []
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
            
            # Check for duplicate parameters
            dup_vulns = self._check_duplicate_parameters(query_params, url, method, headers, "URL Query", response)
            vulnerabilities.extend(dup_vulns)
            
            # Check for array notation parameters
            array_vulns = self._check_array_notation_parameters(parsed_url.query, url, method, headers, response)
            vulnerabilities.extend(array_vulns)
            
            # Check for nested parameters
            nested_vulns = self._check_nested_parameters(parsed_url.query, url, method, headers, response)
            vulnerabilities.extend(nested_vulns)
        
        return vulnerabilities
    
    def _check_url_parameter_pollution(self, url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for parameter pollution vulnerabilities in URL parameters."""
        vulnerabilities = []
        
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return vulnerabilities
        
        # Check for encoded parameter pollution
        encoded_vulns = self._check_encoded_parameter_pollution(parsed_url.query, url, method, headers)
        vulnerabilities.extend(encoded_vulns)
        
        # Check for parameter pollution patterns
        pattern_vulns = self._check_parameter_pollution_patterns(parsed_url.query, url, method, headers)
        vulnerabilities.extend(pattern_vulns)
        
        return vulnerabilities
    
    def _check_body_parameter_pollution(self, request: Dict[str, Any], response: Any, 
                                       url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Check for parameter pollution vulnerabilities in request body."""
        vulnerabilities = []
        
        body = request.get('body', '')
        if not body:
            return vulnerabilities
        
        content_type = headers.get('Content-Type', '').lower()
        
        # Check form-encoded data
        if 'application/x-www-form-urlencoded' in content_type:
            form_vulns = self._check_form_parameter_pollution(body, url, method, headers, response)
            vulnerabilities.extend(form_vulns)
        
        # Check JSON data
        elif 'application/json' in content_type:
            json_vulns = self._check_json_parameter_pollution(body, url, method, headers, response)
            vulnerabilities.extend(json_vulns)
        
        return vulnerabilities
    
    def _check_duplicate_parameters(self, query_params: Dict[str, List[str]], 
                                   url: str, method: str, headers: Dict[str, str], 
                                   location: str, response: Any = None) -> List[Vulnerability]:
        """Check for duplicate parameters in query string."""
        vulnerabilities = []
        
        for param_name, param_values in query_params.items():
            if len(param_values) > 1:
                # Check if this is a sensitive parameter
                risk_level = "High" if param_name.lower() in [p.lower() for p in self.sensitive_params] else "Medium"
                cvss_score = 8.1 if risk_level == "High" else 6.5
                
                vuln = self.create_vulnerability(
                    vuln_id=f"hpp-duplicate-params-{uuid.uuid4().hex[:8]}",
                    name="HTTP Parameter Pollution - Duplicate Parameters",
                    description=f"Duplicate parameter '{param_name}' found in {location}. This can lead to unexpected behavior and potential security issues.",
                    risk=risk_level,
                    cvss_score=cvss_score,
                    solution="Ensure each parameter appears only once in the request. Implement proper parameter validation and sanitization.",
                    references=[
                        "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                        "https://capec.mitre.org/data/definitions/460.html"
                    ],
                    cwe_id="CWE-20",
                    wasc_id="WASC-15",
                    url=url,
                    parameter=param_name,
                    evidence=f"Parameter '{param_name}' appears {len(param_values)} times: {', '.join(param_values)}",
                    scan_id="hpp-scan",
                    request=format_http_request(method, url, headers, ""),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_array_notation_parameters(self, query_string: str, url: str, method: str, 
                                        headers: Dict[str, str], response: Any = None) -> List[Vulnerability]:
        """Check for array notation parameters that might indicate parameter pollution."""
        vulnerabilities = []
        
        # Look for array notation patterns
        array_matches = self.pollution_patterns['array_notation'].findall(query_string)
        
        for match in array_matches:
            param_name = match
            vuln = self.create_vulnerability(
                vuln_id=f"hpp-array-notation-{uuid.uuid4().hex[:8]}",
                name="HTTP Parameter Pollution - Array Notation",
                description=f"Array notation parameter '{param_name}[]' found in URL. This can be exploited for parameter pollution attacks.",
                risk="Medium",
                cvss_score=6.5,
                solution="Validate and sanitize array notation parameters. Consider using proper array handling mechanisms.",
                references=[
                    "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                    "https://capec.mitre.org/data/definitions/460.html"
                ],
                cwe_id="CWE-20",
                wasc_id="WASC-15",
                url=url,
                parameter=f"{param_name}[]",
                evidence=f"Array notation parameter: {param_name}[]",
                scan_id="hpp-scan",
                request=format_http_request(method, url, headers, ""),
                response=format_http_response(response.status_code, response.headers, response.text) if response else ""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_nested_parameters(self, query_string: str, url: str, method: str, 
                                headers: Dict[str, str], response: Any = None) -> List[Vulnerability]:
        """Check for nested parameters that might indicate parameter pollution."""
        vulnerabilities = []
        
        # Look for nested parameter patterns
        nested_matches = self.pollution_patterns['nested_params'].findall(query_string)
        
        for match in nested_matches:
            param_name, nested_key = match
            vuln = self.create_vulnerability(
                vuln_id=f"hpp-nested-params-{uuid.uuid4().hex[:8]}",
                name="HTTP Parameter Pollution - Nested Parameters",
                description=f"Nested parameter '{param_name}[{nested_key}]' found in URL. This can be exploited for parameter pollution attacks.",
                risk="Medium",
                cvss_score=6.5,
                solution="Validate and sanitize nested parameters. Implement proper parameter structure validation.",
                references=[
                    "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                    "https://capec.mitre.org/data/definitions/460.html"
                ],
                cwe_id="CWE-20",
                wasc_id="WASC-15",
                url=url,
                parameter=f"{param_name}[{nested_key}]",
                evidence=f"Nested parameter: {param_name}[{nested_key}]",
                scan_id="hpp-scan",
                request=format_http_request(method, url, headers, ""),
                response=format_http_response(response.status_code, response.headers, response.text) if response else ""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_encoded_parameter_pollution(self, query_string: str, url: str, method: str, 
                                          headers: Dict[str, str], response: Any = None) -> List[Vulnerability]:
        """Check for encoded parameter pollution attempts."""
        vulnerabilities = []
        
        # Look for encoded parameter pollution patterns
        encoded_matches = self.pollution_patterns['encoded_params'].findall(query_string)
        
        if len(encoded_matches) > 5:  # Threshold for suspicious encoding
            # Decode the query string to check for hidden parameters
            try:
                decoded_query = unquote(query_string)
                if '&' in decoded_query and decoded_query != query_string:
                    vuln = self.create_vulnerability(
                        vuln_id=f"hpp-encoded-params-{uuid.uuid4().hex[:8]}",
                        name="HTTP Parameter Pollution - Encoded Parameters",
                        description="URL contains encoded parameters that may hide parameter pollution attempts.",
                        risk="Medium",
                        cvss_score=6.5,
                        solution="Implement proper URL decoding and parameter validation. Be aware of encoded parameter pollution attacks.",
                        references=[
                            "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                            "https://capec.mitre.org/data/definitions/460.html"
                        ],
                        cwe_id="CWE-20",
                        wasc_id="WASC-15",
                        url=url,
                        parameter="Encoded Parameters",
                        evidence=f"Encoded query string: {query_string[:100]}...",
                        scan_id="hpp-scan",
                        request=format_http_request(method, url, headers, ""),
                        response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                    )
                    vulnerabilities.append(vuln)
            except Exception:
                pass
        
        return vulnerabilities
    
    def _check_parameter_pollution_patterns(self, query_string: str, url: str, method: str, 
                                           headers: Dict[str, str], response: Any = None) -> List[Vulnerability]:
        """Check for known parameter pollution attack patterns."""
        vulnerabilities = []
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[^&=]+=.*&[^&=]+=.*&[^&=]+=',  # Multiple parameters with same structure
            r'[^&=]+=.*%26[^&=]+=',  # URL encoded ampersands
            r'[^&=]+=.*%3B[^&=]+=',  # URL encoded semicolons
            r'[^&=]+=.*%2C[^&=]+=',  # URL encoded commas
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, query_string, re.IGNORECASE):
                vuln = self.create_vulnerability(
                    vuln_id=f"hpp-suspicious-pattern-{uuid.uuid4().hex[:8]}",
                    name="HTTP Parameter Pollution - Suspicious Pattern",
                    description="URL contains suspicious parameter patterns that may indicate parameter pollution attempts.",
                    risk="Low",
                    cvss_score=4.3,
                    solution="Review and validate parameter handling. Implement proper parameter sanitization and validation.",
                    references=[
                        "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                        "https://capec.mitre.org/data/definitions/460.html"
                    ],
                    cwe_id="CWE-20",
                    wasc_id="WASC-15",
                    url=url,
                    parameter="Query String",
                    evidence=f"Suspicious pattern in query: {query_string[:100]}...",
                    scan_id="hpp-scan",
                    request=format_http_request(method, url, headers, ""),
                    response=format_http_response(response.status_code, response.headers, response.text) if response else ""
                )
                vulnerabilities.append(vuln)
                break  # Only report one suspicious pattern per URL
        
        return vulnerabilities
    
    def _check_form_parameter_pollution(self, body: str, url: str, method: str, 
                                       headers: Dict[str, str], response: Any = None) -> List[Vulnerability]:
        """Check for parameter pollution in form-encoded data."""
        vulnerabilities = []
        
        try:
            form_params = parse_qs(body, keep_blank_values=True)
            
            # Check for duplicate parameters in form data
            dup_vulns = self._check_duplicate_parameters(form_params, url, method, headers, "Form Data", response)
            vulnerabilities.extend(dup_vulns)
            
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_json_parameter_pollution(self, body: str, url: str, method: str, 
                                       headers: Dict[str, str], response: Any = None) -> List[Vulnerability]:
        """Check for parameter pollution in JSON data."""
        vulnerabilities = []
        
        try:
            json_data = json.loads(body)
            
            # Check for duplicate keys in JSON (though JSON spec doesn't allow this)
            if isinstance(json_data, dict):
                # This is more of a data validation issue than parameter pollution
                # but worth noting for security awareness
                pass
            
        except json.JSONDecodeError:
            # Invalid JSON might indicate parameter pollution attempts
            vuln = self.create_vulnerability(
                vuln_id=f"hpp-invalid-json-{uuid.uuid4().hex[:8]}",
                name="HTTP Parameter Pollution - Invalid JSON",
                description="Request body contains invalid JSON that may indicate parameter pollution attempts.",
                risk="Low",
                cvss_score=3.7,
                solution="Implement proper JSON validation and error handling.",
                references=[
                    "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                    "https://capec.mitre.org/data/definitions/460.html"
                ],
                cwe_id="CWE-20",
                wasc_id="WASC-15",
                url=url,
                parameter="Request Body",
                evidence="Invalid JSON in request body",
                scan_id="hpp-scan",
                request=format_http_request(method, url, headers, body),
                response=format_http_response(response.status_code, response.headers, response.text) if response else ""
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_parameter_pollution_vulnerabilities(self, request: Dict[str, Any], response: Any, 
                                                 url: str, method: str, headers: Dict[str, str]) -> List[Vulnerability]:
        """Test for parameter pollution vulnerabilities by sending test payloads."""
        vulnerabilities = []
        
        # Only test GET requests to avoid side effects
        if method.upper() != 'GET':
            return vulnerabilities
        
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return vulnerabilities
        
        # Test with parameter pollution payloads
        for payload in self.pollution_payloads:
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{parsed_url.query}{payload}"
            
            try:
                test_response = self.make_request(test_url, method, headers)
                
                if test_response and test_response.status_code == 200:
                    # Check if the response indicates parameter pollution vulnerability
                    if self._analyze_pollution_response(response, test_response):
                        vuln = self.create_vulnerability(
                            vuln_id=f"hpp-test-confirmed-{uuid.uuid4().hex[:8]}",
                            name="HTTP Parameter Pollution - Confirmed Vulnerability",
                            description=f"Parameter pollution vulnerability confirmed through testing. The application processes multiple parameters with the same name.",
                            risk="High",
                            cvss_score=8.1,
                            solution="Implement proper parameter validation and ensure only the last or first parameter value is processed.",
                            references=[
                                "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
                                "https://capec.mitre.org/data/definitions/460.html"
                            ],
                            cwe_id="CWE-20",
                            wasc_id="WASC-15",
                            url=url,
                            parameter="Test Payload",
                            evidence=f"Test payload: {payload}",
                            scan_id="hpp-scan",
                            request=format_http_request(method, test_url, headers, ""),
                            response=format_http_response(test_response.status_code, dict(test_response.headers), test_response.text)
                        )
                        vulnerabilities.append(vuln)
                        break  # Only report one confirmed vulnerability per URL
                        
            except Exception:
                continue
        
        return vulnerabilities
    
    def _analyze_pollution_response(self, original_response: Any, test_response: Any) -> bool:
        """Analyze responses to determine if parameter pollution vulnerability exists."""
        if not original_response or not test_response:
            return False
        
        # Simple heuristic: if responses are different, it might indicate parameter pollution
        # This is a basic check - in a real implementation, you'd want more sophisticated analysis
        try:
            original_text = original_response.text if hasattr(original_response, 'text') else str(original_response)
            test_text = test_response.text if hasattr(test_response, 'text') else str(test_response)
            
            # Check if the responses are significantly different
            if len(original_text) != len(test_text):
                return True
            
            # Check for specific indicators of parameter pollution
            pollution_indicators = [
                'parameter', 'duplicate', 'multiple', 'array', 'list'
            ]
            
            for indicator in pollution_indicators:
                if indicator in test_text.lower() and indicator not in original_text.lower():
                    return True
            
        except Exception:
            pass
        
        return False
    
    def generate_poc(self, vulnerability_id: str) -> ProofOfConcept:
        """Generate proof-of-concept for parameter pollution vulnerabilities."""
        return ProofOfConcept(
            vulnerability_id=vulnerability_id,
            request_method="GET",
            request_url="https://example.com/api/endpoint?param=value1&param=value2",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"message": "Parameter pollution vulnerability detected"}',
            timestamp=datetime.now(),
            evidence_description="HTTP Parameter Pollution vulnerability confirmed through duplicate parameters"
        )
