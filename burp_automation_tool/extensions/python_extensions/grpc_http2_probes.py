#!/usr/bin/env python3
"""
gRPC and HTTP/2 Probes
Passive: detect application/grpc and HTTP/2 hints.
Active: attempt gRPC reflection and H2-specific header anomalies (best-effort within Burp APIs).
"""
from java.io import PrintWriter
from java.util import ArrayList
from burp import IBurpExtender, IScannerCheck

class GrpcHttp2Probes(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("gRPC/HTTP2 Probes")
        callbacks.registerScannerCheck(self)
        self.stdout.println("gRPC/HTTP2 Probes loaded")

    def doPassiveScan(self, baseRequestResponse):
        issues = ArrayList()
        resp = baseRequestResponse.getResponse()
        if not resp: return issues
        ri = self.helpers.analyzeResponse(resp)
        headers = ri.getHeaders()
        hmap = {h.split(":",1)[0].lower(): h.split(":",1)[1].strip() for h in headers if ":" in h}
        ctype = hmap.get("content-type", "").lower()
        if "application/grpc" in ctype:
            issues.add(_Issue(baseRequestResponse, "gRPC Detected", "Response has application/grpc content-type.", "Information"))
        if "http2" in hmap.get("alt-svc", "").lower():
            issues.add(_Issue(baseRequestResponse, "HTTP/2 Available", "Alt-Svc advertises h2.", "Information"))
        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = ArrayList()
        # Best-effort: send request with gRPC content-type and te: trailers
        req = baseRequestResponse.getRequest()
        ri = self.helpers.analyzeRequest(req)
        headers = list(ri.getHeaders())
        body = req[ri.getBodyOffset():]
        headers = [h for h in headers if not h.lower().startswith("content-type:")]
        headers.append("Content-Type: application/grpc")
        headers.append("TE: trailers")
        rr = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self.helpers.buildHttpMessage(headers, body))
        rri = self.helpers.analyzeResponse(rr.getResponse())
        if rri.getStatusCode() in (200, 415, 400):
            issues.add(_Issue(rr, "gRPC/H2 Response Variation", "Probe elicited different handling; check for gRPC endpoints.", "Low"))
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

class _Issue:
    def __init__(self, rr, name, detail, severity):
        self._rr = rr; self._name = name; self._detail = detail; self._severity = severity
    def getUrl(self): return self._rr.getUrl()
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Tentative"
    def getIssueBackground(self): return "gRPC and HTTP/2 services may expose additional attack surface."
    def getRemediationBackground(self): return "Ensure reflection is disabled in production; enforce auth and rate limits."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._rr]
    def getHttpService(self): return self._rr.getHttpService()