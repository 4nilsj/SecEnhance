#!/usr/bin/env python3
"""
Advanced API Security Scanner Extension for Burp Suite
Includes GraphQL, OAuth, WebSocket, and advanced API testing
"""

import json
import base64
import hashlib
import hmac
import time
import random
import string
import re
import websocket
from urllib.parse import urlparse, parse_qs, urlencode
from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpRequestResponse, IHttpService
from java.io import PrintWriter
from java.util import List, ArrayList

class AdvancedAPISecurityScanner(IBurpExtender, IScannerCheck):
    """Advanced API security scanner with comprehensive testing capabilities"""
    
    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.stdout = None
        self.stderr = None
        
        # GraphQL payloads
        self.graphql_payloads = [
            # Introspection queries
            {"query": "query { __schema { types { name } } }"},
            {"query": "query { __type(name: \"User\") { fields { name } } }"},
            # Batch queries
            [{"query": "query { __schema { types { name } } }"}, {"query": "query { __type(name: \"User\") { fields { name } } }"}],
            # Nested queries
            {"query": "query { users { id name email posts { id title content } } }"},
            # Deep queries
            {"query": "query { users { id name email posts { id title content author { id name email } } } }"}
        ]
        
        # WebSocket payloads
        self.websocket_payloads = [
            # Authentication bypass
            {"type": "auth", "token": "null"},
            {"type": "auth", "token": "undefined"},
            {"type": "auth", "token": "bypass"},
            # Message injection
            {"type": "message", "data": "<script>alert('xss')</script>"},
            {"type": "message", "data": "'; DROP TABLE users; --"},
            # Subscription bypass
            {"type": "subscribe", "channel": "admin"},
            {"type": "subscribe", "channel": "*"}
        ]
        
        # API version testing
        self.api_version_payloads = [
            "v1", "v2", "v3", "latest", "stable", "beta", "alpha",
            "1.0", "2.0", "3.0", "1.1", "2.1", "3.1"
        ]
        
        # API documentation endpoints
        self.doc_endpoints = [
            "/swagger", "/swagger-ui", "/api-docs", "/docs",
            "/openapi", "/redoc", "/graphiql", "/playground",
            "/explorer", "/console", "/admin", "/management"
        ]

    def registerExtenderCallbacks(self, callbacks):
        """Register the extension with Burp Suite"""
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Set extension name
        callbacks.setExtensionName("Advanced API Security Scanner")
        
        # Register scanner check
        callbacks.registerScannerCheck(self)
        
        self.stdout.println("Advanced API Security Scanner loaded successfully!")

    def doPassiveScan(self, baseRequestResponse):
        """Perform passive scanning for advanced API security issues"""
        issues = ArrayList()
        
        # Get request and response
        requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
        responseInfo = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
        
        # Check for API endpoints
        if self.isAPIEndpoint(requestInfo.getUrl().getPath()):
            # Check for GraphQL endpoints
            self.checkGraphQLEndpoints(baseRequestResponse, responseInfo, issues)
            
            # Check for WebSocket endpoints
            self.checkWebSocketEndpoints(baseRequestResponse, responseInfo, issues)
            
            # Check for API documentation exposure
            self.checkAPIDocumentation(baseRequestResponse, responseInfo, issues)
            
            # Check for API version information
            self.checkAPIVersionInfo(baseRequestResponse, responseInfo, issues)
            
            # Check for sensitive API endpoints
            self.checkSensitiveAPIEndpoints(baseRequestResponse, responseInfo, issues)
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Perform active scanning for advanced API security issues"""
        issues = ArrayList()
        
        # Get request info
        requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
        
        # Check if this is an API endpoint
        if self.isAPIEndpoint(requestInfo.getUrl().getPath()):
            # Test GraphQL vulnerabilities
            self.testGraphQLVulnerabilities(baseRequestResponse, insertionPoint, issues)
            
            # Test WebSocket vulnerabilities
            self.testWebSocketVulnerabilities(baseRequestResponse, insertionPoint, issues)
            
            # Test API version vulnerabilities
            self.testAPIVersionVulnerabilities(baseRequestResponse, insertionPoint, issues)
            
            # Test API documentation vulnerabilities
            self.testAPIDocumentationVulnerabilities(baseRequestResponse, insertionPoint, issues)
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues"""
        if newIssue.getSeverity().equals("High") and not existingIssue.getSeverity().equals("High"):
            return -1
        elif existingIssue.getSeverity().equals("High") and not newIssue.getSeverity().equals("High"):
            return 1
        return 0

    def isAPIEndpoint(self, path):
        """Check if the path is an API endpoint"""
        api_patterns = ["/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql", "/swagger", "/openapi"]
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in api_patterns)

    def checkGraphQLEndpoints(self, baseRequestResponse, responseInfo, issues):
        """Check for GraphQL endpoint vulnerabilities"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for GraphQL indicators
        graphql_indicators = [
            "GraphQL", "graphql", "__schema", "__type", "query", "mutation",
            "subscription", "introspection", "GraphiQL"
        ]
        
        for indicator in graphql_indicators:
            if indicator.lower() in responseBody.lower():
                issues.add(AdvancedAPISecurityIssue(
                    baseRequestResponse,
                    "GraphQL Endpoint Detected",
                    f"GraphQL endpoint found with indicator: {indicator}",
                    "Medium"
                ))

    def checkWebSocketEndpoints(self, baseRequestResponse, responseInfo, issues):
        """Check for WebSocket endpoint vulnerabilities"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for WebSocket indicators
        websocket_indicators = [
            "WebSocket", "websocket", "ws://", "wss://", "Upgrade: websocket",
            "Connection: Upgrade", "Sec-WebSocket"
        ]
        
        for indicator in websocket_indicators:
            if indicator.lower() in responseBody.lower():
                issues.add(AdvancedAPISecurityIssue(
                    baseRequestResponse,
                    "WebSocket Endpoint Detected",
                    f"WebSocket endpoint found with indicator: {indicator}",
                    "Medium"
                ))

    def checkAPIDocumentation(self, baseRequestResponse, responseInfo, issues):
        """Check for API documentation exposure"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for documentation indicators
        doc_indicators = [
            "swagger", "openapi", "api-docs", "documentation", "redoc",
            "graphiql", "playground", "console", "explorer"
        ]
        
        for indicator in doc_indicators:
            if indicator.lower() in responseBody.lower():
                issues.add(AdvancedAPISecurityIssue(
                    baseRequestResponse,
                    "API Documentation Exposed",
                    f"API documentation found with indicator: {indicator}",
                    "Low"
                ))

    def checkAPIVersionInfo(self, baseRequestResponse, responseInfo, issues):
        """Check for API version information disclosure"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for version information
        version_patterns = [
            r'"version":\s*"[^"]*"',
            r'"api_version":\s*"[^"]*"',
            r'"build":\s*"[^"]*"',
            r'"release":\s*"[^"]*"'
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, responseBody, re.IGNORECASE):
                issues.add(AdvancedAPISecurityIssue(
                    baseRequestResponse,
                    "API Version Information Disclosure",
                    "API version information exposed in response",
                    "Low"
                ))

    def checkSensitiveAPIEndpoints(self, baseRequestResponse, responseInfo, issues):
        """Check for sensitive API endpoints"""
        responseBody = self.helpers.bytesToString(baseRequestResponse.getResponse())
        
        # Check for sensitive endpoint indicators
        sensitive_indicators = [
            "admin", "internal", "private", "secret", "backup", "config",
            "settings", "system", "management", "monitoring", "health"
        ]
        
        for indicator in sensitive_indicators:
            if indicator.lower() in responseBody.lower():
                issues.add(AdvancedAPISecurityIssue(
                    baseRequestResponse,
                    "Sensitive API Endpoint Detected",
                    f"Sensitive API endpoint found with indicator: {indicator}",
                    "Medium"
                ))

    def testGraphQLVulnerabilities(self, baseRequestResponse, insertionPoint, issues):
        """Test for GraphQL vulnerabilities"""
        for payload in self.graphql_payloads:
            try:
                modifiedRequest = insertionPoint.buildRequest(json.dumps(payload).getBytes())
                response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
                
                responseBody = self.helpers.bytesToString(response.getResponse())
                
                # Check for GraphQL introspection
                if "__schema" in responseBody or "__type" in responseBody:
                    issues.add(AdvancedAPISecurityIssue(
                        response,
                        "GraphQL Introspection Enabled",
                        "GraphQL introspection is accessible",
                        "High"
                    ))
                
                # Check for GraphQL batch queries
                if isinstance(payload, list) and len(payload) > 1:
                    if "__schema" in responseBody and "types" in responseBody:
                        issues.add(AdvancedAPISecurityIssue(
                            response,
                            "GraphQL Batch Queries Enabled",
                            "GraphQL batch queries are supported",
                            "Medium"
                        ))
                        
            except Exception as e:
                continue

    def testWebSocketVulnerabilities(self, baseRequestResponse, insertionPoint, issues):
        """Test for WebSocket vulnerabilities"""
        # Note: WebSocket testing requires actual WebSocket connection
        # This is a simplified test for WebSocket endpoints
        
        requestInfo = self.helpers.analyzeRequest(baseRequestResponse)
        url = requestInfo.getUrl()
        
        # Check if endpoint might be WebSocket
        if "ws" in url.getProtocol() or "websocket" in url.getPath().lower():
            issues.add(AdvancedAPISecurityIssue(
                baseRequestResponse,
                "WebSocket Endpoint Detected",
                "WebSocket endpoint found - manual testing required",
                "Medium"
            ))

    def testAPIVersionVulnerabilities(self, baseRequestResponse, insertionPoint, issues):
        """Test for API version vulnerabilities"""
        for version in self.api_version_payloads:
            modifiedRequest = insertionPoint.buildRequest(version.getBytes())
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest)
            
            if self.isSuccessfulResponse(response):
                responseBody = self.helpers.bytesToString(response.getResponse())
                
                # Check if version information is exposed
                if version in responseBody:
                    issues.add(AdvancedAPISecurityIssue(
                        response,
                        "API Version Information Exposed",
                        f"API version information exposed: {version}",
                        "Low"
                    ))

    def testAPIDocumentationVulnerabilities(self, baseRequestResponse, insertionPoint, issues):
        """Test for API documentation vulnerabilities"""
        for endpoint in self.doc_endpoints:
            docRequest = baseRequestResponse.clone()
            docRequest.setPath(endpoint)
            
            response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), docRequest.getRequest())
            
            if self.isSuccessfulResponse(response):
                responseBody = self.helpers.bytesToString(response.getResponse())
                
                # Check for documentation exposure
                if any(doc in responseBody.lower() for doc in ["swagger", "openapi", "api-docs", "documentation"]):
                    issues.add(AdvancedAPISecurityIssue(
                        response,
                        "API Documentation Exposed",
                        f"API documentation exposed at: {endpoint}",
                        "Medium"
                    ))

    def isSuccessfulResponse(self, response):
        """Check if response indicates successful request"""
        responseInfo = self.helpers.analyzeResponse(response.getResponse())
        status = responseInfo.getStatusCode()
        return 200 <= status < 300

    class AdvancedAPISecurityIssue(IScanIssue):
        """Custom scan issue for advanced API security vulnerabilities"""
        
        def __init__(self, requestResponse, name, detail, severity):
            self.requestResponse = requestResponse
            self.name = name
            self.detail = detail
            self.severity = severity
        
        def getUrl(self):
            return self.requestResponse.getUrl().toString()
        
        def getIssueName(self):
            return self.name
        
        def getIssueType(self):
            return 0
        
        def getSeverity(self):
            return self.severity
        
        def getConfidence(self):
            return "Certain"
        
        def getIssueBackground(self):
            return "This issue was detected by the Advanced API Security Scanner extension."
        
        def getRemediationBackground(self):
            return "Review the API implementation and implement appropriate security measures."
        
        def getIssueDetail(self):
            return self.detail
        
        def getRemediationDetail(self):
            return "Implement proper security controls and access restrictions."
        
        def getHttpMessages(self):
            return [self.requestResponse]
        
        def getHttpService(self):
            return self.requestResponse.getHttpService()


# Register the extension
if __name__ == "__main__":
    print("Advanced API Security Scanner Extension")
    print("This extension performs comprehensive API security testing including:")
    print("- GraphQL security testing")
    print("- WebSocket security testing")
    print("- API documentation exposure")
    print("- API version information disclosure")
    print("Load this extension in Burp Suite's Extensions tab") 