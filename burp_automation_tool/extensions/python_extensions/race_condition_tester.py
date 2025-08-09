#!/usr/bin/env python3
"""
Race Condition Tester
Sends parallel requests with varying Idempotency-Key and timing to detect double-processing.
"""
import threading
import time
from java.io import PrintWriter
from java.util import ArrayList
from burp import IBurpExtender, IScannerCheck

class RaceConditionTester(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("Race Condition Tester")
        callbacks.registerScannerCheck(self)
        self.stdout.println("Race Condition Tester loaded")

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = ArrayList()
        req_bytes = baseRequestResponse.getRequest()
        req_info = self.helpers.analyzeRequest(req_bytes)
        headers = list(req_info.getHeaders())
        body = req_bytes[req_info.getBodyOffset():]

        results = []
        def worker(i):
            h = list(headers)
            h = [x for x in h if not x.lower().startswith("idempotency-key:")]
            h.append("Idempotency-Key: test-%d-%d" % (int(time.time()*1000), i))
            rr = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self.helpers.buildHttpMessage(h, body))
            results.append(rr)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        # Simple heuristic: look for multiple success responses in tight window
        success = 0
        for rr in results:
            ri = self.helpers.analyzeResponse(rr.getResponse())
            if 200 <= ri.getStatusCode() < 300:
                success += 1
        if success >= 2:
            issues.add(_Issue(results[0], "Potential Race Condition", "Multiple parallel successes observed; check idempotency.", "Medium"))
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
    def getIssueBackground(self): return "Concurrent requests may cause double-spend or duplicate actions."
    def getRemediationBackground(self): return "Use server-side locks and idempotency keys for state-changing endpoints."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._rr]
    def getHttpService(self): return self._rr.getHttpService()