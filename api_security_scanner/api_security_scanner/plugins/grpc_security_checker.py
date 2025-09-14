"""
gRPC Security Checker Plugin.

This plugin detects security vulnerabilities specific to gRPC endpoints,
including protocol buffer security issues, streaming vulnerabilities,
and gRPC-specific attack vectors.
"""

import uuid
import json
import base64
import struct
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

from api_security_scanner.core.scanner_plugins import (
    BasePlugin, PluginResult, Vulnerability, ProofOfConcept,
    format_http_request, format_http_response
)


class GRPCSecurityChecker(BasePlugin):
    """Detects gRPC-specific security vulnerabilities."""
    
    name = "GRPCSecurityChecker"
    description = "Detects gRPC-specific security vulnerabilities and protocol issues"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform gRPC security vulnerability detection."""
        vulnerabilities = []
        has_errors = False
        error_messages = []
        
        try:
            for request in requests_data:
                try:
                    url = request.get('url', '')
                    method = request.get('method', 'GET')
                    headers = request.get('headers', {}).copy()
                    body = request.get('body', '')
                    
                    if auth_headers:
                        headers.update(auth_headers)
                    
                    # Test for gRPC-specific vulnerabilities
                    grpc_vulns = self._test_grpc_vulnerabilities(url, method, headers, body)
                    vulnerabilities.extend(grpc_vulns)
                    
                    # Test for protocol buffer security issues
                    protobuf_vulns = self._test_protobuf_security(url, method, headers, body)
                    vulnerabilities.extend(protobuf_vulns)
                    
                    # Test for streaming vulnerabilities
                    streaming_vulns = self._test_streaming_vulnerabilities(url, method, headers, body)
                    vulnerabilities.extend(streaming_vulns)
                    
                    # Test for metadata security issues
                    metadata_vulns = self._test_metadata_security(url, method, headers, body)
                    vulnerabilities.extend(metadata_vulns)
                    
                    # Test for reflection security
                    reflection_vulns = self._test_reflection_security(url, method, headers, body)
                    vulnerabilities.extend(reflection_vulns)
                
                except Exception as e:
                    self.logger.error(f"Error processing request {url}: {e}")
                    has_errors = True
                    error_messages.append(f"Error processing {url}: {str(e)}")
                    # Continue with other requests even if one fails
                    continue
        
        except Exception as e:
            self.logger.error(f"Error in gRPC security checker: {e}")
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=str(e),
                execution_time=0.0
            )
        
        # Return success=False if there were any errors during processing
        if has_errors:
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=vulnerabilities,
                error="; ".join(error_messages),
                execution_time=0.0
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities,
            execution_time=0.0
        )
    
    def _test_grpc_vulnerabilities(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for general gRPC vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check if this is a gRPC endpoint
            if not self._is_grpc_endpoint(url, headers):
                return vulnerabilities
            
            # Test for insecure gRPC configuration
            insecure_vulns = self._test_insecure_grpc_config(url, method, headers, body)
            vulnerabilities.extend(insecure_vulns)
            
            # Test for gRPC method enumeration
            enumeration_vulns = self._test_method_enumeration(url, method, headers, body)
            vulnerabilities.extend(enumeration_vulns)
            
            # Test for gRPC version detection
            version_vulns = self._test_version_disclosure(url, method, headers, body)
            vulnerabilities.extend(version_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing gRPC vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _test_protobuf_security(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for protocol buffer security issues."""
        vulnerabilities = []
        
        try:
            # Test for protobuf injection
            injection_vulns = self._test_protobuf_injection(url, method, headers, body)
            vulnerabilities.extend(injection_vulns)
            
            # Test for protobuf deserialization issues
            deserialization_vulns = self._test_protobuf_deserialization(url, method, headers, body)
            vulnerabilities.extend(deserialization_vulns)
            
            # Test for protobuf field manipulation
            field_vulns = self._test_protobuf_field_manipulation(url, method, headers, body)
            vulnerabilities.extend(field_vulns)
            
            # Test for protobuf size limits
            size_vulns = self._test_protobuf_size_limits(url, method, headers, body)
            vulnerabilities.extend(size_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing protobuf security: {e}")
        
        return vulnerabilities
    
    def _test_streaming_vulnerabilities(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC streaming vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for streaming DoS
            dos_vulns = self._test_streaming_dos(url, method, headers, body)
            vulnerabilities.extend(dos_vulns)
            
            # Test for streaming resource exhaustion
            resource_vulns = self._test_streaming_resource_exhaustion(url, method, headers, body)
            vulnerabilities.extend(resource_vulns)
            
            # Test for streaming timeout issues
            timeout_vulns = self._test_streaming_timeouts(url, method, headers, body)
            vulnerabilities.extend(timeout_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing streaming vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _test_metadata_security(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC metadata security issues."""
        vulnerabilities = []
        
        try:
            # Test for metadata injection
            injection_vulns = self._test_metadata_injection(url, method, headers, body)
            vulnerabilities.extend(injection_vulns)
            
            # Test for metadata size limits
            size_vulns = self._test_metadata_size_limits(url, method, headers, body)
            vulnerabilities.extend(size_vulns)
            
            # Test for sensitive metadata exposure
            exposure_vulns = self._test_metadata_exposure(url, method, headers, body)
            vulnerabilities.extend(exposure_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing metadata security: {e}")
        
        return vulnerabilities
    
    def _test_reflection_security(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC reflection security issues."""
        vulnerabilities = []
        
        try:
            # Test for reflection service exposure
            reflection_vulns = self._test_reflection_exposure(url, method, headers, body)
            vulnerabilities.extend(reflection_vulns)
            
            # Test for service enumeration via reflection
            enumeration_vulns = self._test_reflection_enumeration(url, method, headers, body)
            vulnerabilities.extend(enumeration_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing reflection security: {e}")
        
        return vulnerabilities
    
    def _is_grpc_endpoint(self, url: str, headers: Dict[str, str]) -> bool:
        """Check if the endpoint is a gRPC service."""
        # Check for gRPC-specific headers
        grpc_headers = ['grpc-encoding', 'grpc-status', 'grpc-message']
        for header in grpc_headers:
            if header in headers:
                return True
        
        # Check for gRPC content type
        content_type = headers.get('content-type', '').lower()
        if 'application/grpc' in content_type:
            return True
        
        # Check URL for gRPC indicators
        if '/grpc/' in url.lower() or url.endswith('.grpc'):
            return True
        
        return False
    
    def _test_insecure_grpc_config(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for insecure gRPC configuration."""
        vulnerabilities = []
        
        try:
            # Test for HTTP/2 without TLS
            if url.startswith('http://') and self._is_grpc_endpoint(url, headers):
                vuln_id = f"grpc-insecure-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Insecure Transport",
                    description="gRPC service is accessible over HTTP without TLS encryption",
                    risk="High",
                    cvss_score=7.5,
                    solution="Use HTTPS/TLS for gRPC services to encrypt communication",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-319",
                    wasc_id="WASC-4",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "gRPC over HTTP detected"),
                    url=url,
                    parameter="transport",
                    evidence="gRPC service accessible over HTTP without TLS",
                    scan_id="",
                    timestamp=datetime.now()
                ))
            
            # Test for missing authentication
            if not self._has_grpc_authentication(headers):
                vuln_id = f"grpc-no-auth-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Missing Authentication",
                    description="gRPC service does not require authentication",
                    risk="High",
                    cvss_score=8.0,
                    solution="Implement proper authentication for gRPC services using interceptors or metadata",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-306",
                    wasc_id="WASC-1",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "No authentication required"),
                    url=url,
                    parameter="authentication",
                    evidence="gRPC service accessible without authentication",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing insecure gRPC config: {e}")
        
        return vulnerabilities
    
    def _test_method_enumeration(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC method enumeration."""
        vulnerabilities = []
        
        try:
            # Test common gRPC methods
            common_methods = [
                'ListServices', 'ListMethods', 'GetService', 'GetMethod',
                'DescribeService', 'DescribeMethod', 'Health', 'Status'
            ]
            
            for grpc_method in common_methods:
                if self._test_grpc_method_access(url, method, headers, body, grpc_method):
                    vuln_id = f"grpc-method-enum-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="gRPC Method Enumeration",
                        description=f"gRPC method '{grpc_method}' is accessible and may expose service information",
                        risk="Medium",
                        cvss_score=5.0,
                        solution="Disable or restrict access to administrative gRPC methods",
                        references=[
                            "https://grpc.io/docs/guides/auth/",
                            "https://owasp.org/www-project-api-security/"
                        ],
                        cwe_id="CWE-200",
                        wasc_id="WASC-13",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, f"gRPC method {grpc_method} accessible"),
                        url=url,
                        parameter="method",
                        evidence=f"gRPC method {grpc_method} is accessible",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing method enumeration: {e}")
        
        return vulnerabilities
    
    def _test_version_disclosure(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC version disclosure."""
        vulnerabilities = []
        
        try:
            # Check for version in headers
            user_agent = headers.get('user-agent', '').lower()
            if 'grpc' in user_agent:
                vuln_id = f"grpc-version-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Version Disclosure",
                    description="gRPC version information is disclosed in User-Agent header",
                    risk="Low",
                    cvss_score=3.0,
                    solution="Remove or obfuscate version information from gRPC headers",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-13",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Version information disclosed"),
                    url=url,
                    parameter="user-agent",
                    evidence=f"gRPC version disclosed: {user_agent}",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing version disclosure: {e}")
        
        return vulnerabilities
    
    def _test_protobuf_injection(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for protocol buffer injection vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for protobuf field injection
            injection_payloads = [
                b'\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01',  # Invalid varint
                b'\x12\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',  # Invalid length
                b'\x1a\x00',  # Empty string with length
                b'\x22\xff\xff\xff\xff',  # Invalid embedded message
            ]
            
            for payload in injection_payloads:
                if self._test_protobuf_payload(url, method, headers, body, payload):
                    vuln_id = f"protobuf-injection-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Protocol Buffer Injection",
                        description="gRPC service is vulnerable to protocol buffer injection attacks",
                        risk="High",
                        cvss_score=8.0,
                        solution="Implement proper protobuf validation and sanitization",
                        references=[
                            "https://developers.google.com/protocol-buffers/docs/security",
                            "https://owasp.org/www-project-api-security/"
                        ],
                        cwe_id="CWE-20",
                        wasc_id="WASC-20",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Protobuf injection successful"),
                        url=url,
                        parameter="protobuf",
                        evidence=f"Protobuf injection payload successful: {payload.hex()}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing protobuf injection: {e}")
        
        return vulnerabilities
    
    def _test_protobuf_deserialization(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for protobuf deserialization vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for deserialization of untrusted data
            malicious_payloads = [
                b'\x0a\x04test\x12\x00',  # Basic protobuf structure
                b'\x12\x08\x08\x01\x12\x04test',  # Nested message
                b'\x1a\x10\x08\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01',  # Large varint
            ]
            
            for payload in malicious_payloads:
                if self._test_protobuf_payload(url, method, headers, body, payload):
                    vuln_id = f"protobuf-deserialization-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Unsafe Protocol Buffer Deserialization",
                        description="gRPC service deserializes untrusted protocol buffer data without validation",
                        risk="High",
                        cvss_score=8.5,
                        solution="Implement proper input validation and use safe deserialization methods",
                        references=[
                            "https://developers.google.com/protocol-buffers/docs/security",
                            "https://owasp.org/www-project-api-security/"
                        ],
                        cwe_id="CWE-502",
                        wasc_id="WASC-25",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Unsafe deserialization detected"),
                        url=url,
                        parameter="protobuf",
                        evidence=f"Unsafe protobuf deserialization: {payload.hex()}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing protobuf deserialization: {e}")
        
        return vulnerabilities
    
    def _test_protobuf_field_manipulation(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for protobuf field manipulation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for field number manipulation
            field_payloads = [
                b'\x08\x01',  # Field 1
                b'\x10\x01',  # Field 2
                b'\x18\x01',  # Field 3
                b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x01',  # Large field number
            ]
            
            for payload in field_payloads:
                if self._test_protobuf_payload(url, method, headers, body, payload):
                    vuln_id = f"protobuf-field-manip-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Protocol Buffer Field Manipulation",
                        description="gRPC service accepts manipulated protocol buffer field numbers",
                        risk="Medium",
                        cvss_score=6.0,
                        solution="Implement strict protobuf schema validation",
                        references=[
                            "https://developers.google.com/protocol-buffers/docs/security",
                            "https://owasp.org/www-project-api-security/"
                        ],
                        cwe_id="CWE-20",
                        wasc_id="WASC-20",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Field manipulation successful"),
                        url=url,
                        parameter="protobuf",
                        evidence=f"Protobuf field manipulation: {payload.hex()}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing protobuf field manipulation: {e}")
        
        return vulnerabilities
    
    def _test_protobuf_size_limits(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for protobuf size limit vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for large protobuf messages
            large_payloads = [
                b'\x0a' + b'\x41' * 1000000,  # 1MB string field
                b'\x12' + b'\x08\x01' * 100000,  # Many repeated fields
            ]
            
            for payload in large_payloads:
                if self._test_protobuf_payload(url, method, headers, body, payload):
                    vuln_id = f"protobuf-size-limit-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="Protocol Buffer Size Limit Bypass",
                        description="gRPC service accepts oversized protocol buffer messages",
                        risk="Medium",
                        cvss_score=5.0,
                        solution="Implement proper message size limits and validation",
                        references=[
                            "https://developers.google.com/protocol-buffers/docs/security",
                            "https://owasp.org/www-project-api-security/"
                        ],
                        cwe_id="CWE-770",
                        wasc_id="WASC-42",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Oversized message accepted"),
                        url=url,
                        parameter="protobuf",
                        evidence=f"Oversized protobuf message accepted: {len(payload)} bytes",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing protobuf size limits: {e}")
        
        return vulnerabilities
    
    def _test_streaming_dos(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for streaming DoS vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for streaming DoS by sending many small messages
            if self._test_streaming_attack(url, method, headers, body):
                vuln_id = f"grpc-streaming-dos-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Streaming DoS",
                    description="gRPC service is vulnerable to streaming DoS attacks",
                    risk="Medium",
                    cvss_score=6.5,
                    solution="Implement proper rate limiting and resource management for streaming",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-770",
                    wasc_id="WASC-42",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Streaming DoS vulnerability detected"),
                    url=url,
                    parameter="streaming",
                    evidence="gRPC service vulnerable to streaming DoS",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing streaming DoS: {e}")
        
        return vulnerabilities
    
    def _test_streaming_resource_exhaustion(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for streaming resource exhaustion."""
        vulnerabilities = []
        
        try:
            # Test for resource exhaustion via streaming
            if self._test_resource_exhaustion(url, method, headers, body):
                vuln_id = f"grpc-resource-exhaustion-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Streaming Resource Exhaustion",
                    description="gRPC service is vulnerable to resource exhaustion via streaming",
                    risk="High",
                    cvss_score=7.5,
                    solution="Implement proper resource limits and connection management",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-770",
                    wasc_id="WASC-42",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Resource exhaustion vulnerability detected"),
                    url=url,
                    parameter="streaming",
                    evidence="gRPC service vulnerable to resource exhaustion",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing resource exhaustion: {e}")
        
        return vulnerabilities
    
    def _test_streaming_timeouts(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for streaming timeout vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test for timeout issues
            if self._test_timeout_vulnerability(url, method, headers, body):
                vuln_id = f"grpc-timeout-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Streaming Timeout Issues",
                    description="gRPC service has inadequate timeout handling for streaming",
                    risk="Low",
                    cvss_score=4.0,
                    solution="Implement proper timeout handling and connection cleanup",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-613",
                    wasc_id="WASC-37",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Timeout vulnerability detected"),
                    url=url,
                    parameter="timeout",
                    evidence="gRPC service has timeout handling issues",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing streaming timeouts: {e}")
        
        return vulnerabilities
    
    def _test_metadata_injection(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC metadata injection."""
        vulnerabilities = []
        
        try:
            # Test for metadata injection
            injection_metadata = [
                'grpc-internal-encoding-request: gzip',
                'grpc-accept-encoding: gzip,deflate',
                'grpc-message: test',
                'grpc-status: 0',
            ]
            
            for metadata in injection_metadata:
                if self._test_metadata_manipulation(url, method, headers, body, metadata):
                    vuln_id = f"grpc-metadata-injection-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="gRPC Metadata Injection",
                        description="gRPC service is vulnerable to metadata injection attacks",
                        risk="Medium",
                        cvss_score=6.0,
                        solution="Implement proper metadata validation and sanitization",
                        references=[
                            "https://grpc.io/docs/guides/auth/",
                            "https://owasp.org/www-project-api-security/"
                        ],
                        cwe_id="CWE-20",
                        wasc_id="WASC-20",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Metadata injection successful"),
                        url=url,
                        parameter="metadata",
                        evidence=f"gRPC metadata injection: {metadata}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing metadata injection: {e}")
        
        return vulnerabilities
    
    def _test_metadata_size_limits(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC metadata size limits."""
        vulnerabilities = []
        
        try:
            # Test for large metadata
            large_metadata = 'grpc-custom-header: ' + 'A' * 10000
            
            if self._test_metadata_manipulation(url, method, headers, body, large_metadata):
                vuln_id = f"grpc-metadata-size-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Metadata Size Limit Bypass",
                    description="gRPC service accepts oversized metadata",
                    risk="Low",
                    cvss_score=3.0,
                    solution="Implement proper metadata size limits",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-770",
                    wasc_id="WASC-42",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Oversized metadata accepted"),
                    url=url,
                    parameter="metadata",
                    evidence="gRPC service accepts oversized metadata",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing metadata size limits: {e}")
        
        return vulnerabilities
    
    def _test_metadata_exposure(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for sensitive metadata exposure."""
        vulnerabilities = []
        
        try:
            # Check for sensitive metadata in response
            response = self.make_request(url, method, headers, body)
            
            if response:
                # Check for sensitive headers
                sensitive_headers = ['grpc-status', 'grpc-message', 'grpc-encoding']
                for header in sensitive_headers:
                    if header in response.headers:
                        vuln_id = f"grpc-metadata-exposure-{uuid.uuid4().hex[:8]}"
                        vulnerabilities.append(Vulnerability(
                            id=vuln_id,
                            name="gRPC Sensitive Metadata Exposure",
                            description=f"Sensitive gRPC metadata '{header}' is exposed in response",
                            risk="Low",
                            cvss_score=3.0,
                            solution="Remove or sanitize sensitive metadata from responses",
                            references=[
                                "https://grpc.io/docs/guides/auth/",
                                "https://owasp.org/www-project-api-security/"
                            ],
                            cwe_id="CWE-200",
                            wasc_id="WASC-13",
                            request=format_http_request(method, url, headers, body),
                            response=format_http_response(200, {}, "Sensitive metadata exposed"),
                            url=url,
                            parameter="metadata",
                            evidence=f"Sensitive metadata exposed: {header}",
                            scan_id="",
                            timestamp=datetime.now()
                        ))
                        break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing metadata exposure: {e}")
        
        return vulnerabilities
    
    def _test_reflection_exposure(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for gRPC reflection service exposure."""
        vulnerabilities = []
        
        try:
            # Test for reflection service
            reflection_url = url.replace('/grpc/', '/grpc.reflection.v1alpha.ServerReflection/')
            if self._test_reflection_access(reflection_url, method, headers, body):
                vuln_id = f"grpc-reflection-exposure-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Reflection Service Exposure",
                    description="gRPC reflection service is enabled and accessible",
                    risk="Medium",
                    cvss_score=5.0,
                    solution="Disable gRPC reflection service in production environments",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-13",
                    request=format_http_request(method, reflection_url, headers, body),
                    response=format_http_response(200, {}, "Reflection service accessible"),
                    url=reflection_url,
                    parameter="reflection",
                    evidence="gRPC reflection service is accessible",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing reflection exposure: {e}")
        
        return vulnerabilities
    
    def _test_reflection_enumeration(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for service enumeration via reflection."""
        vulnerabilities = []
        
        try:
            # Test for service enumeration
            if self._test_service_enumeration(url, method, headers, body):
                vuln_id = f"grpc-service-enum-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="gRPC Service Enumeration via Reflection",
                    description="gRPC services can be enumerated via reflection",
                    risk="Low",
                    cvss_score=3.0,
                    solution="Disable reflection service or implement access controls",
                    references=[
                        "https://grpc.io/docs/guides/auth/",
                        "https://owasp.org/www-project-api-security/"
                    ],
                    cwe_id="CWE-200",
                    wasc_id="WASC-13",
                    request=format_http_request(method, url, headers, body),
                    response=format_http_response(200, {}, "Service enumeration possible"),
                    url=url,
                    parameter="reflection",
                    evidence="gRPC services can be enumerated via reflection",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing reflection enumeration: {e}")
        
        return vulnerabilities
    
    def _has_grpc_authentication(self, headers: Dict[str, str]) -> bool:
        """Check if gRPC request has authentication."""
        # Check for common gRPC authentication headers
        auth_headers = ['authorization', 'grpc-auth', 'x-api-key', 'x-auth-token']
        for header in auth_headers:
            if header in headers:
                return True
        return False
    
    def _test_grpc_method_access(self, url: str, method: str, headers: Dict[str, str], body: str, grpc_method: str) -> bool:
        """Test access to a specific gRPC method."""
        try:
            # Modify URL to test specific gRPC method
            test_url = f"{url}/{grpc_method}"
            response = self.make_request(test_url, method, headers, body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def _test_protobuf_payload(self, url: str, method: str, headers: Dict[str, str], body: str, payload: bytes) -> bool:
        """Test protobuf payload."""
        try:
            # Set protobuf content type
            modified_headers = headers.copy()
            modified_headers['content-type'] = 'application/grpc+proto'
            
            response = self.make_request(url, method, modified_headers, payload.decode('latin-1'))
            return bool(response and response.status_code in [200, 201, 202, 400, 500])
        except Exception:
            return False
    
    def _test_streaming_attack(self, url: str, method: str, headers: Dict[str, str], body: str) -> bool:
        """Test streaming DoS attack."""
        try:
            # Test streaming endpoint
            response = self.make_request(url, method, headers, body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def _test_resource_exhaustion(self, url: str, method: str, headers: Dict[str, str], body: str) -> bool:
        """Test resource exhaustion."""
        try:
            # Test with large payload
            large_body = 'A' * 1000000
            response = self.make_request(url, method, headers, large_body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def _test_timeout_vulnerability(self, url: str, method: str, headers: Dict[str, str], body: str) -> bool:
        """Test timeout vulnerability."""
        try:
            # Test with timeout header
            modified_headers = headers.copy()
            modified_headers['grpc-timeout'] = '1s'
            response = self.make_request(url, method, modified_headers, body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def _test_metadata_manipulation(self, url: str, method: str, headers: Dict[str, str], body: str, metadata: str) -> bool:
        """Test metadata manipulation."""
        try:
            # Add metadata to headers
            modified_headers = headers.copy()
            key, value = metadata.split(': ', 1)
            modified_headers[key] = value
            
            response = self.make_request(url, method, modified_headers, body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def _test_reflection_access(self, url: str, method: str, headers: Dict[str, str], body: str) -> bool:
        """Test reflection service access."""
        try:
            response = self.make_request(url, method, headers, body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def _test_service_enumeration(self, url: str, method: str, headers: Dict[str, str], body: str) -> bool:
        """Test service enumeration."""
        try:
            # Test service enumeration endpoint
            enum_url = f"{url}/ListServices"
            response = self.make_request(enum_url, method, headers, body)
            return bool(response and response.status_code in [200, 201, 202])
        except Exception:
            return False
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof of concept for gRPC vulnerability."""
        return None  # gRPC vulnerabilities don't typically have specific POCs
