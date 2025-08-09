#!/usr/bin/env python3
"""
OWASP/CWE Reporter
Maps detected issue categories to OWASP API Top 10 and CWE IDs and renders JSON/HTML summaries.
"""
from typing import List, Dict, Any
import json
from datetime import datetime

OWASP_API_TOP10 = {
    "auth_bypass": {"owasp": "API2: Broken Authentication", "cwe": [287, 798]},
    "idor": {"owasp": "API1: Broken Object Level Authorization", "cwe": [639, 862]},
    "bola": {"owasp": "API5: Broken Function Level Authorization", "cwe": [285, 284]},
    "ssrf": {"owasp": "API7: Server Side Request Forgery", "cwe": [918]},
    "sqli": {"owasp": "API8: Injection", "cwe": [89]},
    "nosqli": {"owasp": "API8: Injection", "cwe": [943]},
    "xss": {"owasp": "API8: Injection", "cwe": [79]},
    "cors": {"owasp": "API9: Improper Assets Management", "cwe": [942]},
    "info_disclosure": {"owasp": "API3: Excessive Data Exposure", "cwe": [200]},
    "rate_limit": {"owasp": "API4: Lack of Resources & Rate Limiting", "cwe": [770]},
    "proto_pollution": {"owasp": "API8: Injection", "cwe": [915]},
    "request_smuggling": {"owasp": "API10: Improper Inventory/Other", "cwe": [444]},
}

class Reporter:
    def __init__(self) -> None:
        pass

    def map_issue(self, issue_type: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        meta = OWASP_API_TOP10.get(issue_type, {"owasp": "Unmapped", "cwe": []})
        out = {
            "type": issue_type,
            "owasp": meta["owasp"],
            "cwe": meta["cwe"],
            "detail": detail,
        }
        return out

    def render_json(self, issues: List[Dict[str, Any]]) -> str:
        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "issues": issues,
            "summary": self._summarize(issues),
        }
        return json.dumps(report, indent=2)

    def render_html(self, issues: List[Dict[str, Any]]) -> str:
        summary = self._summarize(issues)
        rows = "".join(
            f"<tr><td>{i['type']}</td><td>{i['owasp']}</td><td>{','.join(map(str,i['cwe']))}</td><td>{i['detail'].get('url','')}</td></tr>"
            for i in issues
        )
        return f"""
<!doctype html>
<html><head><meta charset='utf-8'><title>API Security Report</title>
<style>table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px 8px}}</style>
</head><body>
<h1>API Security Report</h1>
<p>Generated: {datetime.utcnow().isoformat()}Z</p>
<h2>Summary</h2>
<pre>{json.dumps(summary, indent=2)}</pre>
<h2>Findings</h2>
<table><thead><tr><th>Type</th><th>OWASP</th><th>CWE</th><th>URL</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>
"""

    def _summarize(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for i in issues:
            by_type[i["type"]] = by_type.get(i["type"], 0) + 1
        return {"count": len(issues), "by_type": by_type}