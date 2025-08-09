#!/usr/bin/env python
"""
Collaborator OAST Scanner (Python/Jython)

Performs out-of-band (OAST) probes using Burp Collaborator for:
- SSRF-like parameters (url, redirect, callback, endpoint, webhook)
- JWT JKU key fetch abuse (sets jku to Collaborator URL)

It injects a unique Collaborator payload and polls for DNS/HTTP interactions.
Results are raised as issues with concrete OAST evidence.
"""
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.util import ArrayList
from java.net import URL
import json

LIKELY_SSRF_KEYS = [
    "url", "uri", "link", "redirect", "return", "target", "callback",
    "endpoint", "webhook", "notify_url", "jku"
]

class CollaboratorOASTScanner(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("Collaborator OAST Scanner")

        # Create Collaborator context
        try:
            self.collab = callbacks.createBurpCollaboratorClientContext()
            self.stdout.println("Collaborator context created")
        except Exception as e:
            self.collab = None
            self.stderr.println("Failed to create Collaborator context: %s" % e)

        callbacks.registerScannerCheck(self)
        self.stdout.println("Collaborator OAST Scanner loaded")

    def doPassiveScan(self, baseRequestResponse):
        # No passive OAST
        return ArrayList()

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = ArrayList()
        if not self.collab:
            return issues

        req_info = self.helpers.analyzeRequest(baseRequestResponse)
        url = req_info.getUrl()
        path = url.getPath().lower()
        # Applicability: basic API path hints
        if not any(h in path for h in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql"]):
            return issues

        # Generate a unique Collaborator payload URL
        payload_host = self.collab.generatePayload(True)  # include DNS + HTTP
        payload_url = "http://%s" % payload_host

        # Attempt param-based injections via insertion points
        try:
            issue_from_params = self._probe_params(baseRequestResponse, insertionPoint, payload_url)
            if issue_from_params:
                issues.add(issue_from_params)
        except Exception as e:
            self.stderr.println("Param probe error: %s" % e)

        # Attempt JWT JKU header injection in Authorization Bearer JWT
        try:
            issue_from_jku = self._probe_jku(baseRequestResponse, payload_url)
            if issue_from_jku:
                issues.add(issue_from_jku)
        except Exception as e:
            self.stderr.println("JKU probe error: %s" % e)

        # Poll for interactions for this payload
        try:
            interactions = self.collab.fetchAllCollaboratorInteractions()
            matched = []
            for i in interactions:
                val = i.getProperty("interaction_id") or ""
                if payload_host in (i.getProperty("raw_query") or "") or payload_host in (i.getProperty("request") or "") or payload_host in (i.getProperty("client_ip") or ""):
                    matched.append(i)
            if matched:
                issues.add(self._build_issue(baseRequestResponse, url, "OAST interaction detected", "High", {
                    "payload": payload_url,
                    "count": len(matched),
                    "types": list({m.getProperty("type") for m in matched}),
                }))
        except Exception as e:
            self.stderr.println("Polling error: %s" % e)

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    def _probe_params(self, baseRequestResponse, insertionPoint, payload_url):
        # Use the provided insertion point to place payload_url, and also try common keys in URL query
        # Build a simple JSON body injection if content-type is JSON
        req = baseRequestResponse.getRequest()
        info = self.helpers.analyzeRequest(req)
        headers = list(info.getHeaders())
        body = req[info.getBodyOffset():]
        content_type = "".join([h for h in headers if h.lower().startswith("content-type:")]).lower()

        sent_any = False
        # 1) Use insertion point API where applicable
        try:
            req_with_ip = insertionPoint.buildRequest(self.helpers.stringToBytes(payload_url))
            rr = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req_with_ip)
            sent_any = True
        except Exception:
            pass

        # 2) JSON body key injection
        if "json" in content_type:
            try:
                body_str = self.helpers.bytesToString(body)
                obj = {}
                try:
                    obj = json.loads(body_str)
                except Exception:
                    obj = {}
                changed = False
                for k in LIKELY_SSRF_KEYS:
                    if k in obj:
                        obj[k] = payload_url
                        changed = True
                if not changed:
                    # add a key
                    obj["url"] = payload_url
                new_body = json.dumps(obj)
                new_msg = self.helpers.buildHttpMessage(headers, self.helpers.stringToBytes(new_body))
                rr2 = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_msg)
                sent_any = True
            except Exception:
                pass

        # 3) Query param injection by replacing path with appended query
        try:
            u = info.getUrl()
            base = str(u)
            sep = "&" if ("?" in base) else "?"
            for key in LIKELY_SSRF_KEYS:
                test_url = base + sep + ("%s=%s" % (key, payload_url))
                new_headers = []
                for h in headers:
                    if h.startswith("GET ") or h.startswith("POST ") or h.startswith("PUT ") or h.startswith("PATCH "):
                        parts = h.split(" ")
                        parts[1] = URL(test_url).getFile()
                        new_headers.append(" ".join(parts))
                    else:
                        new_headers.append(h)
                rr3 = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self.helpers.buildHttpMessage(new_headers, body))
                sent_any = True
                break
        except Exception:
            pass

        if sent_any:
            return self._build_issue(baseRequestResponse, info.getUrl(), "OAST probe sent (SSRF/webhook)", "Information", {"payload": payload_url})
        return None

    def _probe_jku(self, baseRequestResponse, payload_url):
        # If Authorization bearer JWT exists, replace header part with jku pointing to Collaborator
        req = baseRequestResponse.getRequest()
        info = self.helpers.analyzeRequest(req)
        headers = list(info.getHeaders())
        body = req[info.getBodyOffset():]
        new_headers = []
        auth_found = False
        for h in headers:
            if h.lower().startswith("authorization: bearer "):
                try:
                    token = h.split(" ", 2)[2].strip()
                    parts = token.split('.')
                    if len(parts) >= 2:
                        # naive base64 decode/encode via helpers
                        header_json = {"alg": "RS256", "jku": payload_url}
                        hdr = json.dumps(header_json)
                        hdr_b64 = self.helpers.base64Encode(hdr)
                        # base64Encode adds padding and '+/' not urlsafe; Scanner target generally parses fine
                        new_token = hdr_b64 + "." + parts[1] + ".signature"
                        new_headers.append("Authorization: Bearer " + new_token)
                        auth_found = True
                        continue
                except Exception:
                    pass
            new_headers.append(h)
        if not auth_found:
            return None
        rr = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self.helpers.buildHttpMessage(new_headers, body))
        return self._build_issue(baseRequestResponse, info.getUrl(), "OAST probe sent (JWT JKU)", "Information", {"payload": payload_url})

    def _build_issue(self, baseRequestResponse, url, name, severity, detail_dict):
        return _Issue(baseRequestResponse, str(url), name, severity, json.dumps(detail_dict))

class _Issue(IScanIssue):
    def __init__(self, rr, url, name, severity, detail):
        self._rr = rr
        self._url = url
        self._name = name
        self._sev = severity
        self._detail = detail
    def getUrl(self):
        try:
            return self._rr.getUrl()
        except Exception:
            return None
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._sev
    def getConfidence(self): return "Firm" if self._sev == "High" else "Tentative"
    def getIssueBackground(self):
        return "Out-of-band probes using Burp Collaborator detected potential SSRF/webhook/JKU key-fetch behavior."
    def getRemediationBackground(self):
        return "Validate and restrict outbound connections; disallow untrusted JKU; enforce allowlists for webhook/URL parameters."
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self._rr]
    def getHttpService(self): return self._rr.getHttpService()