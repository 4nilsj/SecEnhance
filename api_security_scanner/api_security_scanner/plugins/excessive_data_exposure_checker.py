"""
Excessive Data Exposure Security Checker Plugin

This plugin implements OWASP API Top 10 #3 - Excessive Data Exposure detection.
It identifies when APIs return more data than necessary, including:
- Sensitive data exposure in responses
- Unnecessary data fields in API responses
- Data over-exposure in error messages
- Sensitive information in logs or debug output
- PII exposure in API responses
- Internal system information disclosure
"""

import re
import json
import logging
import uuid
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from api_security_scanner.core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept, format_http_request, format_http_response

logger = logging.getLogger(__name__)


@dataclass
class SensitiveDataPattern:
    """Pattern for detecting sensitive data in responses"""
    name: str
    pattern: str
    risk: str
    cvss_score: float
    description: str
    category: str


class ExcessiveDataExposureChecker(BasePlugin):
    """
    Plugin for detecting excessive data exposure vulnerabilities in API responses.
    
    This plugin analyzes API responses to identify when sensitive or unnecessary
    data is being exposed to clients.
    """
    
    def __init__(self):
        super().__init__()
        self.name = "ExcessiveDataExposureChecker"
        self.description = "Detects excessive data exposure in API responses (OWASP API Top 10 #3)"
        self.version = "1.0.0"
        
        # Sensitive data patterns to detect
        self.sensitive_patterns = [
            SensitiveDataPattern(
                name="Credit Card Numbers",
                pattern=r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                risk="High",
                cvss_score=8.1,
                description="Credit card numbers detected in response",
                category="Financial Data"
            ),
            SensitiveDataPattern(
                name="SSN",
                pattern=r'\b\d{3}-?\d{2}-?\d{4}\b',
                risk="High",
                cvss_score=8.1,
                description="Social Security Numbers detected in response",
                category="PII"
            ),
            SensitiveDataPattern(
                name="Email Addresses",
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                risk="Medium",
                cvss_score=5.3,
                description="Email addresses detected in response",
                category="PII"
            ),
            SensitiveDataPattern(
                name="Phone Numbers",
                pattern=r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                risk="Medium",
                cvss_score=5.3,
                description="Phone numbers detected in response",
                category="PII"
            ),
            SensitiveDataPattern(
                name="API Keys",
                pattern=r'\b[A-Za-z0-9]{20,}\b',
                risk="High",
                cvss_score=8.1,
                description="Potential API keys detected in response",
                category="Credentials"
            ),
            SensitiveDataPattern(
                name="Database Connection Strings",
                pattern=r'(?:jdbc:|mongodb:|postgresql:|mysql:).*',
                risk="High",
                cvss_score=8.1,
                description="Database connection strings detected in response",
                category="System Information"
            ),
            SensitiveDataPattern(
                name="Internal IPs",
                pattern=r'\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
                risk="Medium",
                cvss_score=5.3,
                description="Internal IP addresses detected in response",
                category="System Information"
            ),
            SensitiveDataPattern(
                name="File Paths",
                pattern=r'[C-Z]:\\[^\\/:*?"<>|]+\\.*|/[^/]*/.*',
                risk="Low",
                cvss_score=3.7,
                description="File system paths detected in response",
                category="System Information"
            ),
            SensitiveDataPattern(
                name="JWT Tokens",
                pattern=r'\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b',
                risk="High",
                cvss_score=8.1,
                description="JWT tokens detected in response",
                category="Credentials"
            ),
            SensitiveDataPattern(
                name="Passwords",
                pattern=r'(?i)"(?:password|pwd|pass)"\s*:\s*"[^"]+"',
                risk="High",
                cvss_score=8.1,
                description="Password fields detected in response",
                category="Credentials"
            )
        ]
        
        # Common sensitive field names
        self.sensitive_fields = {
            'password', 'pwd', 'pass', 'secret', 'key', 'token', 'auth',
            'ssn', 'social_security', 'credit_card', 'card_number',
            'email', 'phone', 'address', 'zip', 'postal_code',
            'internal_id', 'system_id', 'admin_id', 'user_id',
            'session_id', 'cookie', 'jwt', 'bearer',
            'database_url', 'connection_string', 'db_password',
            'api_key', 'access_key', 'secret_key', 'private_key'
        }
        
        # Common debug/development fields that shouldn't be exposed
        self.debug_fields = {
            'debug', 'trace', 'stack_trace', 'error_details', 'exception',
            'internal_error', 'system_error', 'dev_mode', 'test_mode',
            'build_number', 'commit_hash', 'environment',
            'config', 'settings', 'secrets', 'credentials'
        }

    def check(self, requests: List[Dict[str, Any]]) -> PluginResult:
        """
        Check for excessive data exposure vulnerabilities.
        
        Args:
            requests: List of request/response pairs to analyze
            
        Returns:
            PluginResult with detected vulnerabilities
        """
        logger.info(f"Starting excessive data exposure check on {len(requests)} requests")
        
        vulnerabilities = []
        errors = []
        
        try:
            for i, request_data in enumerate(requests):
                try:
                    # Extract response data
                    response = request_data.get('response', {})
                    if not response:
                        continue
                        
                    # Check for sensitive data in response body
                    body_vulns = self._check_response_body(request_data, i)
                    vulnerabilities.extend(body_vulns)
                    
                    # Check for sensitive data in headers
                    header_vulns = self._check_response_headers(request_data, i)
                    vulnerabilities.extend(header_vulns)
                    
                    # Check for excessive data in error responses
                    error_vulns = self._check_error_responses(request_data, i)
                    vulnerabilities.extend(error_vulns)
                    
                    # Check for unnecessary fields in successful responses
                    field_vulns = self._check_unnecessary_fields(request_data, i)
                    vulnerabilities.extend(field_vulns)
                    
                    # Check for data over-exposure in list endpoints
                    list_vulns = self._check_list_endpoints(request_data, i)
                    vulnerabilities.extend(list_vulns)
                    
                except Exception as e:
                    error_msg = f"Error processing request {i}: {str(e)}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            # Generate summary
            summary = self._generate_summary(vulnerabilities)
            
            return PluginResult(
                plugin_name=self.name,
                success=len(errors) == 0,
                vulnerabilities=vulnerabilities,
                error="; ".join(errors) if errors else None
            )
            
        except Exception as e:
            error_msg = f"Critical error in excessive data exposure check: {str(e)}"
            logger.error(error_msg)
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=error_msg
            )

    def _check_response_body(self, request_data: Dict[str, Any], request_index: int) -> List[Vulnerability]:
        """Check response body for sensitive data exposure"""
        vulnerabilities = []
        
        response = request_data.get('response', {})
        body = response.get('body', '')
        
        if not body:
            return vulnerabilities
            
        # Convert to string if needed
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2)
        
        # Check against sensitive data patterns
        for pattern in self.sensitive_patterns:
            matches = re.findall(pattern.pattern, body, re.IGNORECASE)
            if matches:
                # Limit matches to avoid overwhelming output
                sample_matches = matches[:3]
                
                vuln = self.create_vulnerability(
                    vuln_id=str(uuid.uuid4()),
                    name=f"Excessive Data Exposure: {pattern.name}",
                    description=f"{pattern.description}. Found {len(matches)} occurrence(s).",
                    risk=pattern.risk,
                    cvss_score=pattern.cvss_score,
                    solution="Remove or mask sensitive data from API responses",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    cwe_id="CWE-200",  # Information Exposure
                    wasc_id="WASC-13",  # Information Leakage
                    url=request_data.get('url', ''),
                    parameter="",
                    evidence=f"Detected {pattern.name} in response body",
                    scan_id="",
                    request=format_http_request(request_data.get('method', ''), request_data.get('url', ''), request_data.get('headers', {})),
                    response=format_http_response(response.get('status_code', 0), response.get('headers', {}), body[:1000] + "..." if len(body) > 1000 else body)
                )
                
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_response_headers(self, request_data: Dict[str, Any], request_index: int) -> List[Vulnerability]:
        """Check response headers for sensitive data exposure"""
        vulnerabilities = []
        
        response = request_data.get('response', {})
        headers = response.get('headers', {})
        
        # Check for sensitive headers
        sensitive_headers = {
            'x-api-key', 'x-auth-token', 'x-access-token', 'authorization',
            'x-user-id', 'x-session-id', 'x-internal-id', 'x-debug',
            'x-version', 'x-build', 'x-environment', 'x-config'
        }
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            
            # Check if header name suggests sensitive data
            if any(sensitive in header_lower for sensitive in sensitive_headers):
                vuln = self.create_vulnerability(
                    vuln_id=str(uuid.uuid4()),
                    name="Sensitive Data in Response Headers",
                    description=f"Sensitive data exposed in response header: {header_name}",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Remove sensitive data from response headers",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-13",
                    url=request_data.get('url', ''),
                    parameter="",
                    evidence=f"Header: {header_name} = {header_value}",
                    scan_id="",
                    request=format_http_request(request_data.get('method', ''), request_data.get('url', ''), request_data.get('headers', {})),
                    response=format_http_response(response.get('status_code', 0), {header_name: header_value}, "")
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_error_responses(self, request_data: Dict[str, Any], request_index: int) -> List[Vulnerability]:
        """Check error responses for excessive data exposure"""
        vulnerabilities = []
        
        response = request_data.get('response', {})
        status_code = response.get('status_code', 0)
        
        # Focus on error responses (4xx, 5xx)
        if status_code < 400:
            return vulnerabilities
            
        body = response.get('body', '')
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=2)
        
        # Check for stack traces or detailed error information
        error_indicators = [
            r'stack trace',
            r'at \w+\.\w+\([^)]+\)',
            r'line \d+',
            r'file: [^\s]+',
            r'Exception in thread',
            r'Caused by:',
            r'java\.lang\.',
            r'python\.',
            r'node_modules',
            r'Traceback \(most recent call last\)'
        ]
        
        for indicator in error_indicators:
            if re.search(indicator, body, re.IGNORECASE):
                vuln = self.create_vulnerability(
                    vuln_id=str(uuid.uuid4()),
                    name="Excessive Data in Error Response",
                    description="Error response contains detailed system information or stack traces",
                    risk="Medium",
                    cvss_score=5.3,
                    solution="Return generic error messages without system details",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-13",
                    url=request_data.get('url', ''),
                    parameter="",
                    evidence=f"Error response contains: {indicator}",
                    scan_id="",
                    request=format_http_request(request_data.get('method', ''), request_data.get('url', ''), request_data.get('headers', {})),
                    response=format_http_response(status_code, response.get('headers', {}), body[:1000] + "..." if len(body) > 1000 else body)
                )
                vulnerabilities.append(vuln)
                break  # Only report once per error response
        
        return vulnerabilities

    def _check_unnecessary_fields(self, request_data: Dict[str, Any], request_index: int) -> List[Vulnerability]:
        """Check for unnecessary fields in successful responses"""
        vulnerabilities = []
        
        response = request_data.get('response', {})
        status_code = response.get('status_code', 0)
        
        # Focus on successful responses
        if status_code < 200 or status_code >= 300:
            return vulnerabilities
            
        body = response.get('body', '')
        
        # Parse JSON response
        try:
            if isinstance(body, str):
                data = json.loads(body)
            else:
                data = body
        except (json.JSONDecodeError, TypeError):
            return vulnerabilities
        
        # Check for sensitive or unnecessary fields
        unnecessary_fields = self._find_unnecessary_fields(data, [])
        
        if unnecessary_fields:
            vuln = self.create_vulnerability(
                vuln_id=str(uuid.uuid4()),
                name="Unnecessary Data Fields in Response",
                description=f"Response contains {len(unnecessary_fields)} unnecessary or sensitive fields",
                risk="Low",
                cvss_score=3.7,
                solution="Remove unnecessary fields from API responses",
                references=[
                    "https://owasp.org/www-project-api-security/",
                    "https://cwe.mitre.org/data/definitions/200.html"
                ],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=request_data.get('url', ''),
                parameter="",
                evidence=f"Fields: {', '.join(unnecessary_fields)}",
                scan_id="",
                request=format_http_request(request_data.get('method', ''), request_data.get('url', ''), request_data.get('headers', {})),
                response=format_http_response(status_code, response.get('headers', {}), json.dumps(data, indent=2)[:1000] + "..." if len(json.dumps(data)) > 1000 else json.dumps(data, indent=2))
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _find_unnecessary_fields(self, data: Any, path: List[str]) -> List[str]:
        """Recursively find unnecessary or sensitive fields in data structure"""
        unnecessary_fields = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = path + [key]
                field_path = '.'.join(current_path)
                
                # Check if field name suggests sensitive or unnecessary data
                key_lower = key.lower()
                if (key_lower in self.sensitive_fields or 
                    key_lower in self.debug_fields or
                    any(debug in key_lower for debug in self.debug_fields)):
                    unnecessary_fields.append(field_path)
                
                # Recursively check nested objects
                if isinstance(value, (dict, list)):
                    unnecessary_fields.extend(self._find_unnecessary_fields(value, current_path))
                    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    unnecessary_fields.extend(self._find_unnecessary_fields(item, path + [str(i)]))
        
        return unnecessary_fields

    def _check_list_endpoints(self, request_data: Dict[str, Any], request_index: int) -> List[Vulnerability]:
        """Check list endpoints for data over-exposure"""
        vulnerabilities = []
        
        url = request_data.get('url', '').lower()
        method = request_data.get('method', '').upper()
        
        # Check if this is a list endpoint
        list_indicators = ['/users', '/accounts', '/orders', '/products', '/items', '/list', '/all']
        if not any(indicator in url for indicator in list_indicators):
            return vulnerabilities
            
        response = request_data.get('response', {})
        status_code = response.get('status_code', 0)
        
        if status_code < 200 or status_code >= 300:
            return vulnerabilities
            
        body = response.get('body', '')
        
        try:
            if isinstance(body, str):
                data = json.loads(body)
            else:
                data = body
        except (json.JSONDecodeError, TypeError):
            return vulnerabilities
        
        # Check if response contains a large list
        if isinstance(data, list) and len(data) > 100:
            vuln = self.create_vulnerability(
                vuln_id=str(uuid.uuid4()),
                name="Large Data Set in List Endpoint",
                description=f"List endpoint returns {len(data)} items without pagination",
                risk="Low",
                cvss_score=3.7,
                solution="Implement pagination for list endpoints",
                references=[
                    "https://owasp.org/www-project-api-security/",
                    "https://cwe.mitre.org/data/definitions/200.html"
                ],
                cwe_id="CWE-200",
                wasc_id="WASC-13",
                url=request_data.get('url', ''),
                parameter="",
                evidence=f"Large dataset: {len(data)} items",
                scan_id="",
                request=format_http_request(method, request_data.get('url', ''), request_data.get('headers', {})),
                response=format_http_response(status_code, response.get('headers', {}), f"Response contains {len(data)} items (truncated)")
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> str:
        """Generate summary of detected vulnerabilities"""
        if not vulnerabilities:
            return "No excessive data exposure vulnerabilities detected"
        
        high_count = sum(1 for v in vulnerabilities if v.risk == "High")
        medium_count = sum(1 for v in vulnerabilities if v.risk == "Medium")
        low_count = sum(1 for v in vulnerabilities if v.risk == "Low")
        
        return (f"Detected {len(vulnerabilities)} excessive data exposure vulnerabilities: "
                f"{high_count} high, {medium_count} medium, {low_count} low severity")

    def generate_poc(self, vulnerability: Vulnerability) -> Optional[ProofOfConcept]:
        """Generate proof of concept for a vulnerability"""
        return None  # Excessive data exposure vulnerabilities don't typically have specific POCs
