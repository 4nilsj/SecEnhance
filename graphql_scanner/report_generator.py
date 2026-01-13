from typing import List, Dict, Any
import datetime


VULN_KB = {
    "Introspection": {
        "impact": "Attackers can map the entire API schema, finding hidden fields, arguments, and types.",
        "mitigation": "Disable introspection in production. Use a whitelist of allowed queries if possible."
    },
    "Complexity": {
        "impact": "Deeply nested queries can cause Denial of Service (DoS) by consuming excessive server resources.",
        "mitigation": "Implement Query Depth Limiting (e.g., max depth 10) and Query Complexity Analysis."
    },
    "Alias": {
        "impact": "Attackers can bypass rate limits or cause DoS by requesting the same field thousands of times in one query.",
        "mitigation": "Limit the maximum number of aliases allowed in a single query."
    },
    "Batch": {
        "impact": "Attackers can bypass rate limits or Brute Force credentials efficiently.",
        "mitigation": "Disable query batching (array of queries) if not needed."
    },
    "Field Duplication": {
        "impact": "Optimizers might be bypassed, leading to DoS via resource exhaustion.",
        "mitigation": "Reject queries with duplicate fields/arguments."
    },
    "Directive": {
        "impact": "Excessive directives can increase processing time significantly (DoS).",
        "mitigation": "Limit the number of directives allowed per field/query."
    },
    "Circular": {
        "impact": "Recursive fragments can crash the server or hang the thread (Stack Overflow / High CPU).",
        "mitigation": "Implement strict validation to detect and reject cycles in fragments."
    },
    "CSRF": {
        "impact": "Attackers can perform actions on behalf of authenticated users if they visit a malicious site.",
        "mitigation": "Disable state-changing operations via GET. Enforce `Content-Type: application/json` for POST."
    },
    "Injection": {
        "impact": "Critial: Attackers can extract data, modify database, or execute arbitrary code (RCE).",
        "mitigation": "Use Parameterized Queries / ORM. Validate and sanitize all input arguments."
    },
    "Stack Trace": {
        "impact": "Leaks internal file paths, library versions, and logic, aiding further attacks.",
        "mitigation": "Disable debug mode in production. Catch exceptions and return generic error messages."
    },
    "Large Payload": {
        "impact": "Can exhaust memory (RAM) or CPU parsing large strings (DoS).",
        "mitigation": "Limit the maximum size of request bodies and argument lengths."
    },
    "Hidden Directive": {
        "impact": "Might reveal internal logic or administrative features available via directives.",
        "mitigation": "Remove internal directives from the schema before exposing it."
    },
    "Interface": {
        "impact": "Might leak the existence of hidden/admin types if they implement public interfaces.",
        "mitigation": "Ensure internal types do not implement public interfaces or are completely hidden from the schema."
    },
    "IDOR": {
        "impact": "High: Users can access private data belonging to others.",
        "mitigation": "Implement robust Access Control checks in every resolver. verify requestor owns the resource."
    },
    "Input Validation": {
        "impact": "Can lead to Integer Overflows, Logic errors, or crashes.",
        "mitigation": "Strictly type and validate all scalar inputs. Enforce ranges for Integers."
    }
}

def get_kb_entry(vuln_name):
    # Fuzzy match
    for key, data in VULN_KB.items():
        if key.lower() in vuln_name.lower():
            return data
    return {"impact": "Unknown", "mitigation": "Review manually."}

def generate_html_report(results: List[Dict[str, Any]], target_url: str) -> str:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate Stats
    stats = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for res in results:
        sev = res.get("severity", "Info")
        # Normalize severity strings
        if "high" in sev.lower(): stats["High"] += 1
        elif "medium" in sev.lower(): stats["Medium"] += 1
        elif "low" in sev.lower(): stats["Low"] += 1
        else: stats["Info"] += 1
        
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GraphQL Security Scan Report</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary: #E10098; /* GraphQL Pink */
                --primary-dark: #9c006b;
                --secondary: #171E26; /* Dark background */
                --bg: #F4F6F8;
                --surface: #FFFFFF;
                --text: #333333;
                --text-secondary: #666666;
                --border: #E1E4E8;
                
                --high: #D32F2F;
                --medium: #F57C00;
                --low: #1976D2;
                --info: #0288D1;
                --safe: #388E3C;
            }}
            
            body {{ font-family: 'Inter', sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 0; line-height: 1.6; }}
            
            header {{ background-color: var(--secondary); color: white; padding: 2rem 0; margin-bottom: 2rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header-content {{ max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }}
            h1 {{ margin: 0; font-size: 1.8rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }}
            h1::before {{ content: ''; display: block; width: 30px; height: 30px; background: url('https://upload.wikimedia.org/wikipedia/commons/1/17/GraphQL_Logo.svg') no-repeat center/contain; }}
            .meta-info {{ font-size: 0.9rem; color: rgba(255,255,255,0.7); text-align: right; }}
            
            .container {{ max-width: 1200px; margin: 0 auto; padding: 0 20px 40px; }}
            
            /* Summary Cards */
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
            .card {{ background: var(--surface); padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); text-align: center; border-top: 4px solid transparent; transition: transform 0.2s; }}
            .card:hover {{ transform: translateY(-5px); }}
            .card h3 {{ margin: 0; font-size: 0.9rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }}
            .card .count {{ font-size: 2.5rem; font-weight: 700; margin: 10px 0 0; color: var(--text); }}
            
            .card.high {{ border-color: var(--high); }} .card.high .count {{ color: var(--high); }}
            .card.medium {{ border-color: var(--medium); }} .card.medium .count {{ color: var(--medium); }}
            .card.low {{ border-color: var(--low); }} .card.low .count {{ color: var(--low); }}
            .card.info {{ border-color: var(--info); }} .card.info .count {{ color: var(--info); }}
            
            /* Results Table */
            .results-section {{ background: var(--surface); border-radius: 12px; box-shadow: 0 2px 15px rgba(0,0,0,0.05); overflow: hidden; }}
            .results-header {{ padding: 20px 30px; border-bottom: 1px solid var(--border); background: #FAFBFD; }}
            .results-header h2 {{ margin: 0; font-size: 1.2rem; color: var(--secondary); }}
            
            .vulnerability-item {{ border-bottom: 1px solid var(--border); transition: background 0.15s; }}
            .vulnerability-item:last-child {{ border-bottom: none; }}
            .vulnerability-item:hover {{ background-color: #FAFAFA; }}
            
            .vulnerability-summary {{ padding: 15px 30px; display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 20px; align-items: center; cursor: pointer; }}
            .vulnerability-title {{ font-weight: 600; color: var(--secondary); }}
            
            .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }}
            .badge.vulnerable {{ background: #FDEDEC; color: var(--high); }}
            .badge.warning {{ background: #FEF5E7; color: var(--medium); }}
            .badge.safe {{ background: #E8F5E9; color: var(--safe); }}
            
            .severity-badge {{ font-weight: 700; font-size: 0.9rem; }}
            .severity-high {{ color: var(--high); }}
            .severity-medium {{ color: var(--medium); }}
            .severity-low {{ color: var(--low); }}
            
            /* Details Section */
            details {{ width: 100%; }}
            summary {{ list-style: none; outline: none; }}
            summary::-webkit-details-marker {{ display: none; }}
            
            .expanded-details {{ padding: 0 30px 20px 30px; margin-top: -10px; border-left: 4px solid transparent; animation: slideDown 0.3s ease-out; }}
            .status-vulnerable .expanded-details {{ border-color: var(--high); }}
            .status-warning .expanded-details {{ border-color: var(--medium); }}
            
            @keyframes slideDown {{ from {{ opacity: 0; transform: translateY(-10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
            
            .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 15px; }}
            .detail-box {{ background: #F8F9FA; padding: 15px; border-radius: 8px; border: 1px solid var(--border); }}
            .full-width {{ grid-column: 1 / -1; }}
            
            h4 {{ margin: 0 0 10px 0; font-size: 0.85rem; text-transform: uppercase; color: var(--text-secondary); display: flex; align-items: center; gap: 8px; }}
            
            .code-block {{ background: #2D3436; color: #DFE6E9; padding: 12px; border-radius: 6px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap; }}
            .description {{ color: var(--text); font-size: 0.95rem; }}
        </style>
    </head>
    <body>
        <header>
            <div class="header-content">
                <h1>GraphQL Security Report</h1>
                <div class="meta-info">
                    <div>Target: <strong>{target_url}</strong></div>
                    <div>Date: <strong>{timestamp}</strong></div>
                </div>
            </div>
        </header>
        
        <div class="container">
            <div class="summary">
                <div class="card high">
                    <h3>High Risk</h3>
                    <div class="count">{stats['High']}</div>
                </div>
                <div class="card medium">
                    <h3>Medium Risk</h3>
                    <div class="count">{stats['Medium']}</div>
                </div>
                <div class="card low">
                    <h3>Low Risk</h3>
                    <div class="count">{stats['Low']}</div>
                </div>
                <div class="card info">
                    <h3>Info / Safe</h3>
                    <div class="count">{stats['Info'] + stats.get('Safe', 0)}</div> 
                </div> 
            </div>
            
            <div class="results-section">
                <div class="results-header">
                    <h2>Scan Findings</h2>
                </div>
                
                <div class="vulnerability-list">
    """
    
    for res in results:
        status_slug = res['status'].lower()
        severity_slug = res.get('severity', 'info').lower()
        
        status_class = f"status-{status_slug}"
        badge_class = status_slug 
        
        kb = get_kb_entry(res.get('vulnerability', ''))
        
        impact_html = ""
        mitigation_html = ""
        poc_html = ""
        
        if res.get("status") != "SAFE":
            impact_html = f"<div class='detail-box'><div class='meta-title'>Impact</div><div class='meta-content'>{kb['impact']}</div></div>"
            mitigation_html = f"<div class='detail-box'><div class='meta-title'>Remediation</div><div class='meta-content'>{kb['mitigation']}</div></div>"
            
            if res.get("query"):
                 poc_html += f"<div class='detail-box full-width'><div class='meta-title'>Request Payload</div><div class='code-block'>{res['query']}</div></div>"
            if res.get("response"):
                 import json
                 resp_str = json.dumps(res['response'], indent=2) if isinstance(res['response'], dict) else str(res['response'])
                 poc_html += f"<div class='detail-box full-width'><div class='meta-title'>Server Response</div><div class='code-block'>{resp_str}</div></div>"

        # Safe items might just show description
        
        html += f"""
                <details class="vulnerability-item {status_class}">
                    <summary class="vulnerability-summary">
                        <div class="vulnerability-title">{res.get('vulnerability')}</div>
                        <div><span class="badge {badge_class}">{res.get('status')}</span></div>
                        <div class="severity-badge severity-{severity_slug}">{res.get('severity', '-')}</div>
                        <div style="text-align: right; color: #999;">▼</div>
                    </summary>
                    
                    <div class="expanded-details">
                        <p class="description"><strong>Description:</strong> {res.get('description')}</p>
                        {f"<div class='detail-box full-width'><div class='meta-title'>Details</div><pre>{res['details']}</pre></div>" if res.get('details') else ""}
                        
                        <div class="detail-grid">
                            {impact_html}
                            {mitigation_html}
                            {poc_html}
                        </div>
                    </div>
                </details>
        """
        
    html += """
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html
