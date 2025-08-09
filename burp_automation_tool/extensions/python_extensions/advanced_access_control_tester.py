#!/usr/bin/env python3
"""
Advanced Access Control Tester (IDOR/BOLA)
Passive: collect candidate IDs from responses.
Active: mutate path/query IDs and drop/alter auth headers to detect access control flaws.
"""
import re
import json
from java.io import PrintWriter
from java.util import ArrayList
from burp import IBurpExtender, IScannerCheck

ID_PATTERN = re.compile(r"\b(\d{2,}|[a-f0-9]{8,})\b", re.I)

class AccessControlTester(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("Advanced Access Control Tester")
        callbacks.registerScannerCheck(self)
        self.stdout.println("Access Control Tester loaded")

    def doPassiveScan(self, baseRequestResponse):
        issues = ArrayList()
        resp = baseRequestResponse.getResponse()
        if not resp:
            return issues
        body = self.helpers.bytesToString(resp)
        if ID_PATTERN.search(body):
            issues.add(_Issue(baseRequestResponse, "Identifiers Found", "Potential candidate IDs in response.", "Information"))
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = ArrayList()
        req_info = self.helpers.analyzeRequest(baseRequestResponse)
        url = req_info.getUrl()
        path = url.getPath()
        # Extract numeric/hex IDs from path
        candidates = re.findall(r"/(\d{2,}|[a-f0-9]{8,})", path, re.I)
        tests = []
        for c in set(candidates):
            tests.append(path.replace("/"+c, "/"+self._alter_id(c)))
        # Also try removing Authorization header
        req_bytes = baseRequestResponse.getRequest()
        for new_path in tests:
            new_req = self._rebuild_request_with_path(req_bytes, new_path, drop_auth=False)
            rr = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
            if self._looks_like_success(rr):
                issues.add(_Issue(rr, "Possible IDOR/BOLA", "Modified ID in path resulted in success.", "High"))
        new_req = self._rebuild_request_with_path(req_bytes, path, drop_auth=True)
        rr2 = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
        if self._looks_like_success(rr2):
            issues.add(_Issue(rr2, "Possible Missing AuthZ", "Request without Authorization succeeded.", "High"))
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    def _alter_id(self, val: str) -> str:
        if val.isdigit():
            return str(int(val) + 1)
        return ("0" * max(0, len(val)-1)) + "1"

    def _rebuild_request_with_path(self, req_bytes, new_path: str, drop_auth: bool):
        req_info = self.helpers.analyzeRequest(req_bytes)
        headers = list(req_info.getHeaders())
        body = req_bytes[req_info.getBodyOffset():]
        new_headers = []
        for h in headers:
            if h.lower().startswith("get ") or h.lower().startswith("post ") or h.lower().startswith("put ") or h.lower().startswith("patch ") or h.lower().startswith("delete "):
                parts = h.split(" ")
                parts[1] = new_path
                new_headers.append(" ".join(parts))
            elif drop_auth and h.lower().startswith("authorization:"):
                continue
            else:
                new_headers.append(h)
        return self.helpers.buildHttpMessage(new_headers, body)

    def _looks_like_success(self, rr) -> bool:
        resp_info = self.helpers.analyzeResponse(rr.getResponse())
        code = resp_info.getStatusCode()
        return 200 <= code < 300 or code == 302

class _Issue:
    def __init__(self, rr, name, detail, severity):
        self._rr = rr; self._name = name; self._detail = detail; self._severity = severity
    def getUrl(self): return self._rr.getUrl()
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Tentative"
    def getIssueBackground(self): return "Access control weaknesses can allow unauthorized data access or actions."
    def getRemediationBackground(self): return "Enforce object- and function-level authorization using server-side checks."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._rr]
    def getHttpService(self): return self._rr.getHttpService()