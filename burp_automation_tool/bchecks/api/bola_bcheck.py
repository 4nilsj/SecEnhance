#!/usr/bin/env python3
"""
Broken Object Level Authorization (BOLA) BCheck for Burp Suite
Detects IDOR vulnerabilities and unauthorized access to resources
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
        callbacks.setExtensionName("BOLA BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(BOLACheck(callbacks, self._helpers))

class BOLACheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "Broken Object Level Authorization (BOLA)"
        
        # BOLA test payloads for different resource types
        self.bola_payloads = {
            'user_ids': [
                "1", "2", "3", "10", "100", "999", "1000", "9999",
                "admin", "user", "test", "demo", "guest"
            ],
            'resource_ids': [
                "1", "2", "3", "10", "100", "999", "1000", "9999",
                "file1", "file2", "doc1", "doc2", "image1", "image2"
            ],
            'order_ids': [
                "1", "2", "3", "10", "100", "999", "1000", "9999",
                "order1", "order2", "transaction1", "transaction2"
            ],
            'document_ids': [
                "1", "2", "3", "10", "100", "999", "1000", "9999",
                "doc1", "doc2", "file1", "file2", "report1", "report2"
            ],
            'account_ids': [
                "1", "2", "3", "10", "100", "999", "1000", "9999",
                "acc1", "acc2", "account1", "account2"
            ]
        }
        
        # Parameter names commonly used for IDs
        self.id_parameters = [
            'id', 'user_id', 'userid', 'uid', 'resource_id', 'resourceid',
            'order_id', 'orderid', 'document_id', 'documentid', 'file_id',
            'fileid', 'account_id', 'accountid', 'transaction_id', 'transactionid',
            'product_id', 'productid', 'item_id', 'itemid', 'post_id', 'postid'
        ]
        
        # BOLA detection patterns
        self.bola_indicators = [
            r"HTTP/1\.1 200 OK",
            r"HTTP/1\.1 302 Found",
            r"HTTP/1\.1 403 Forbidden",
            r"HTTP/1\.1 404 Not Found",
            r"unauthorized",
            r"forbidden",
            r"access denied",
            r"not found",
            r"user.*not.*found",
            r"resource.*not.*found",
            r"invalid.*id",
            r"permission.*denied"
        ]
        
        # Compile regex patterns
        self.bola_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.bola_indicators]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for BOLA indicators"""
        issues = []
        
        # Check for ID parameters in URLs and requests
        request = baseRequestResponse.getRequest()
        request_str = self._helpers.bytesToString(request)
        
        # Look for ID parameters in the request
        for param in self.id_parameters:
            if param in request_str:
                issues.append(BOLAIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [baseRequestResponse],
                    "Potential BOLA - ID Parameter Detected",
                    f"Found ID parameter '{param}' which may be vulnerable to BOLA attacks",
                    "Medium",
                    "Low"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for BOLA vulnerabilities"""
        issues = []
        
        # Get the original request analysis
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()
        
        # Test different ID payloads
        for payload_type, payloads in self.bola_payloads.items():
            for payload in payloads:
                # Create modified request with the payload
                modified_request = self._helpers.buildHttpMessage(
                    headers,
                    payload.encode('utf-8')
                )
                
                check_request_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    modified_request
                )
                
                if check_request_response:
                    response = check_request_response.getResponse()
                    response_str = self._helpers.bytesToString(response)
                    
                    # Check for BOLA indicators
                    for pattern in self.bola_regex:
                        if pattern.search(response_str):
                            issues.append(BOLAIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [baseRequestResponse, check_request_response],
                                f"BOLA - {payload_type.replace('_', ' ').title()}",
                                f"BOLA vulnerability detected with {payload_type} payload: {payload}",
                                "High",
                                "Medium"
                            ))
                            break
        
        # Test parameter pollution for BOLA
        for param in self.id_parameters:
            for payload in self.bola_payloads['user_ids'][:5]:  # Use subset for performance
                # Create request with parameter pollution
                modified_headers = list(headers)
                modified_headers.append(f"{param}={payload}")
                
                modified_request = self._helpers.buildHttpMessage(
                    modified_headers,
                    baseRequestResponse.getRequest()[request_info.getBodyOffset():]
                )
                
                check_request_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(),
                    modified_request
                )
                
                if check_request_response:
                    response = check_request_response.getResponse()
                    response_str = self._helpers.bytesToString(response)
                    
                    # Check for BOLA indicators
                    for pattern in self.bola_regex:
                        if pattern.search(response_str):
                            issues.append(BOLAIssue(
                                baseRequestResponse.getHttpService(),
                                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                [baseRequestResponse, check_request_response],
                                f"BOLA - Parameter Pollution ({param})",
                                f"BOLA vulnerability detected via parameter pollution with {param}={payload}",
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

class BOLAIssue(IScanIssue):
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
        return "Broken Object Level Authorization (BOLA) occurs when an API endpoint fails to properly validate that the user has permission to access a specific resource, allowing unauthorized access to other users' data."

    def getRemediationBackground(self):
        return "To prevent BOLA, implement proper authorization checks for each resource access, validate user permissions, and use secure session management."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Implement proper authorization checks, validate user permissions for each resource, use secure session management, and consider using UUIDs instead of sequential IDs."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
