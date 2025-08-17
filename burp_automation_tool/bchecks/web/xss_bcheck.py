#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) BCheck for Burp Suite
Detects reflected, stored, and DOM-based XSS vulnerabilities
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re
import base64

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("XSS BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(XSSCheck(callbacks, self._helpers))

class XSSCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Cross-Site Scripting (XSS)"
        
        # XSS payloads for different detection methods
        self.xss_payloads = {
            'basic_reflected': [
                "<script>alert('XSS')</script>",
                "<script>alert(1)</script>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<object onload=alert('XSS')>",
                "<embed src=javascript:alert('XSS')>"
            ],
            'encoded_payloads': [
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;",
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "javascript:alert('XSS')",
                "vbscript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>"
            ],
            'bypass_payloads': [
                "<ScRiPt>alert('XSS')</ScRiPt>",
                "<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>",
                "<script>alert('XSS')</script>"
            ],
            'dom_based': [
                "javascript:alert(document.cookie)",
                "javascript:alert(location.href)",
                "javascript:alert(location.search)",
                "javascript:alert(location.hash)",
                "javascript:alert(document.referrer)",
                "javascript:alert(document.domain)"
            ]
        }
        
        # XSS detection patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<svg[^>]*>",
            r"<img[^>]*onerror[^>]*>",
            r"<body[^>]*onload[^>]*>",
            r"javascript:",
            r"vbscript:",
            r"data:text/html",
            r"on\w+\s*=",
            r"alert\s*\(",
            r"confirm\s*\(",
            r"prompt\s*\("
        ]
        
        # Compile regex patterns
        self.xss_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.xss_patterns]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for XSS indicators"""
        issues = []
        
        # Check response for XSS patterns
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        for pattern in self.xss_regex:
            if pattern.search(response_str):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "Potential XSS Detected",
                    f"XSS pattern detected in response: {pattern.pattern}",
                    "Medium"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for XSS vulnerabilities"""
        issues = []
        
        # Test different XSS techniques
        for technique, payloads in self.xss_payloads.items():
            for payload in payloads:
                # Create test request
                checkRequest = self._create_test_request(baseRequestResponse, insertionPoint, payload)
                
                # Send request and get response
                checkResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest
                )
                
                if checkResponse is None:
                    continue
                
                # Analyze response for XSS indicators
                if self._detect_xss(checkResponse, technique, payload):
                    issues.append(self._create_issue(
                        checkResponse,
                        f"XSS Vulnerability - {technique.replace('_', ' ').title()}",
                        f"Cross-site scripting vulnerability detected using {technique} technique with payload: {payload}",
                        "High"
                    ))
                    break  # Found vulnerability, move to next technique
        
        return issues

    def _create_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Create a test request with the XSS payload"""
        # Get the base request
        request = baseRequestResponse.getRequest()
        
        # Insert the payload
        checkRequest = insertionPoint.buildRequest(payload)
        
        return checkRequest

    def _detect_xss(self, response, technique, payload):
        """Detect XSS based on response analysis"""
        if response is None:
            return False
        
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check if payload is reflected in response
        if self._is_payload_reflected(response_str, payload):
            return True
        
        # Check for XSS patterns in response
        for pattern in self.xss_regex:
            if pattern.search(response_str):
                return True
        
        # Check for specific technique indicators
        if technique == 'dom_based':
            return self._detect_dom_xss(response, payload)
        
        return False

    def _is_payload_reflected(self, response_str, payload):
        """Check if the XSS payload is reflected in the response"""
        # Clean the payload for comparison
        clean_payload = payload.replace("'", "&#39;").replace('"', "&quot;")
        
        # Check if payload or cleaned version is in response
        if payload in response_str or clean_payload in response_str:
            return True
        
        # Check for encoded versions
        try:
            # URL encoded
            url_encoded = payload.replace('<', '%3C').replace('>', '%3E')
            if url_encoded in response_str:
                return True
            
            # HTML encoded
            html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if html_encoded in response_str:
                return True
        except:
            pass
        
        return False

    def _detect_dom_xss(self, response, payload):
        """Detect DOM-based XSS"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for DOM manipulation indicators
        dom_indicators = [
            'document.cookie',
            'location.href',
            'location.search',
            'location.hash',
            'document.referrer',
            'document.domain',
            'eval(',
            'innerHTML',
            'outerHTML'
        ]
        
        if any(indicator in response_str for indicator in dom_indicators):
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
        return "Cross-site scripting (XSS) vulnerabilities allow attackers to inject malicious scripts into web pages, potentially leading to session hijacking, data theft, and other security breaches."

    def getRemediationBackground(self):
        return "Implement proper input validation, output encoding, and Content Security Policy (CSP) headers. Use frameworks that automatically escape user input."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "1. Implement proper input validation and sanitization\n2. Use output encoding for all user-controlled data\n3. Implement Content Security Policy (CSP) headers\n4. Use modern frameworks with built-in XSS protection\n5. Regular security testing and code reviews\n6. Use HttpOnly flags for cookies\n7. Implement proper session management"

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
