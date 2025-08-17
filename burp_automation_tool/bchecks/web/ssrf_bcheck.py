#!/usr/bin/env python3
"""
Server-Side Request Forgery (SSRF) BCheck for Burp Suite
Detects SSRF vulnerabilities that allow attackers to make requests to internal services
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import time

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("SSRF BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(SSRFCheck(callbacks, self._helpers))

class SSRFCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Server-Side Request Forgery (SSRF)"
        
        # SSRF payloads for different detection methods
        self.ssrf_payloads = {
            'local_network': [
                "http://127.0.0.1",
                "http://localhost",
                "http://0.0.0.0",
                "http://10.0.0.1",
                "http://192.168.1.1",
                "http://172.16.0.1",
                "http://169.254.169.254",  # AWS metadata
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document"
            ],
            'cloud_metadata': [
                "http://169.254.169.254",  # AWS
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "http://metadata.google.internal",  # Google Cloud
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance",  # Azure
                "http://169.254.169.254/metadata/instance?api-version=2017-08-01"
            ],
            'internal_services': [
                "http://127.0.0.1:22",      # SSH
                "http://127.0.0.1:21",      # FTP
                "http://127.0.0.1:23",      # Telnet
                "http://127.0.0.1:25",      # SMTP
                "http://127.0.0.1:53",      # DNS
                "http://127.0.0.1:80",      # HTTP
                "http://127.0.0.1:443",     # HTTPS
                "http://127.0.0.1:3306",    # MySQL
                "http://127.0.0.1:5432",    # PostgreSQL
                "http://127.0.0.1:6379",    # Redis
                "http://127.0.0.1:27017",   # MongoDB
                "http://127.0.0.1:8080",    # Alternative HTTP
                "http://127.0.0.1:9000",    # Alternative HTTP
                "http://127.0.0.1:9200"     # Elasticsearch
            ],
            'bypass_techniques': [
                "http://127.1",              # Alternative localhost
                "http://0177.0000.0000.0001",  # Octal
                "http://0x7f.0x0.0x0.0x1",     # Hex
                "http://2130706433",         # Decimal
                "http://017700000001",       # Octal
                "http://0x7f000001",        # Hex
                "http://localhost:80@evil.com",  # URL parsing bypass
                "http://127.0.0.1#evil.com",     # Fragment bypass
                "http://127.0.0.1?evil.com",     # Query bypass
                "http://127.0.0.1.evil.com",     # Subdomain bypass
                "http://evil.com@127.0.0.1",     # Auth bypass
                "http://127.0.0.1:80%23evil.com" # URL encoding bypass
            ]
        }
        
        # SSRF detection patterns
        self.ssrf_patterns = [
            r"127\.0\.0\.1",
            r"localhost",
            r"0\.0\.0\.0",
            r"10\.\d+\.\d+\.\d+",
            r"192\.168\.\d+\.\d+",
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+",
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"internal",
            r"private",
            r"admin",
            r"management",
            r"console",
            r"dashboard"
        ]
        
        # Compile regex patterns
        self.ssrf_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.ssrf_patterns]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for SSRF indicators"""
        issues = []
        
        # Check request for SSRF patterns
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        for pattern in self.ssrf_regex:
            if pattern.search(request_str):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "Potential SSRF Detected",
                    f"SSRF pattern detected in request: {pattern.pattern}",
                    "Medium"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for SSRF vulnerabilities"""
        issues = []
        
        # Test different SSRF techniques
        for technique, payloads in self.ssrf_payloads.items():
            for payload in payloads:
                # Create test request
                checkRequest = self._create_test_request(baseRequestResponse, insertionPoint, payload)
                
                # Send request and get response
                checkResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest
                )
                
                if checkResponse is None:
                    continue
                
                # Analyze response for SSRF indicators
                if self._detect_ssrf(checkResponse, technique, payload):
                    issues.append(self._create_issue(
                        checkResponse,
                        f"SSRF Vulnerability - {technique.replace('_', ' ').title()}",
                        f"Server-side request forgery vulnerability detected using {technique} technique with payload: {payload}",
                        "High"
                    ))
                    break  # Found vulnerability, move to next technique
        
        return issues

    def _create_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Create a test request with the SSRF payload"""
        # Get the base request
        request = baseRequestResponse.getRequest()
        
        # Insert the payload
        checkRequest = insertionPoint.buildRequest(payload)
        
        return checkRequest

    def _detect_ssrf(self, response, technique, payload):
        """Detect SSRF based on response analysis"""
        if response is None:
            return False
        
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check for SSRF indicators in response
        if self._has_ssrf_indicators(response_str, payload):
            return True
        
        # Check for specific technique indicators
        if technique == 'cloud_metadata':
            return self._detect_cloud_metadata(response, payload)
        elif technique == 'internal_services':
            return self._detect_internal_service(response, payload)
        
        return False

    def _has_ssrf_indicators(self, response_str, payload):
        """Check for SSRF indicators in response"""
        # Look for internal network information
        internal_indicators = [
            'private ip',
            'internal server',
            'localhost',
            '127.0.0.1',
            'internal error',
            'connection refused',
            'connection timeout',
            'no route to host',
            'network unreachable',
            'host unreachable',
            'port unreachable'
        ]
        
        if any(indicator in response_str.lower() for indicator in internal_indicators):
            return True
        
        # Look for cloud metadata
        cloud_indicators = [
            'instance-id',
            'ami-id',
            'instance-type',
            'security-groups',
            'iam',
            'user-data',
            'hostname',
            'public-ip',
            'local-ipv4',
            'mac',
            'vpc-id',
            'subnet-id'
        ]
        
        if any(indicator in response_str.lower() for indicator in cloud_indicators):
            return True
        
        return False

    def _detect_cloud_metadata(self, response, payload):
        """Detect cloud metadata exposure"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check for AWS metadata
        if '169.254.169.254' in payload:
            aws_indicators = [
                'instance-id',
                'ami-id',
                'instance-type',
                'security-groups',
                'iam',
                'user-data'
            ]
            if any(indicator in response_str.lower() for indicator in aws_indicators):
                return True
        
        # Check for Google Cloud metadata
        if 'metadata.google.internal' in payload:
            gcp_indicators = [
                'computeMetadata',
                'instance',
                'project',
                'zone',
                'machine-type'
            ]
            if any(indicator in response_str.lower() for indicator in gcp_indicators):
                return True
        
        return False

    def _detect_internal_service(self, response, payload):
        """Detect internal service exposure"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check for service-specific indicators
        service_indicators = {
            '22': ['ssh', 'openssh', 'sshd'],
            '21': ['ftp', 'vsftpd', 'proftpd'],
            '23': ['telnet'],
            '25': ['smtp', 'postfix', 'sendmail'],
            '53': ['dns', 'bind', 'named'],
            '3306': ['mysql', 'mariadb'],
            '5432': ['postgresql', 'postgres'],
            '6379': ['redis'],
            '27017': ['mongodb'],
            '9200': ['elasticsearch']
        }
        
        # Extract port from payload
        for port, indicators in service_indicators.items():
            if f":{port}" in payload:
                if any(indicator in response_str.lower() for indicator in indicators):
                    return True
        
        return False

    def _create_issue(self, requestResponse, name, detail, severity):
        """Create a scan issue"""
        return CustomScanIssue(
            requestResponse.getHttpService(),
            self._helpers.analyzeRequest(requestResponse).getUrl(),
            [requestResponse],
            name,
            detail,
            severity
        )

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        if self._severity == "High":
            return "High"
        elif self._severity == "Medium":
            return "Medium"
        elif self._severity == "Low":
            return "Low"
        else:
            return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Server-side request forgery (SSRF) vulnerabilities allow attackers to make requests to internal services, potentially leading to unauthorized access to internal networks, cloud metadata, and sensitive information."

    def getRemediationBackground(self):
        return "Implement proper input validation, use allowlists for URLs, and implement network segmentation. Use security groups and firewalls to restrict outbound connections."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "1. Implement strict input validation for URLs\n2. Use allowlists for allowed domains and IP ranges\n3. Implement network segmentation and firewalls\n4. Use security groups to restrict outbound connections\n5. Monitor and log all outbound requests\n6. Implement proper authentication and authorization\n7. Use web application firewalls (WAFs)\n8. Regular security testing and code reviews"

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
