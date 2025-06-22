import sys
sys.path.insert(0, 'src')

from core.api_security_scanner import APISecurityScanner

print("Testing SQL Injection vulnerabilities...")
scanner = APISecurityScanner()

# Test endpoints that are vulnerable to SQL injection
endpoints = [
    {'url': 'http://localhost:5001/api/search?q=test', 'method': 'GET'},
    {'url': 'http://localhost:5001/api/users/1', 'method': 'GET'},
    {'url': 'http://localhost:5001/api/users?id=1', 'method': 'GET'}
]

results = scanner.scan_api_endpoints(endpoints)

print(f"Total vulnerabilities found: {len(results.get('vulnerabilities_found', []))}")

# Check for vulnerabilities with request/response data
for vuln in results.get('vulnerabilities_found', []):
    print(f"\n- {vuln.get('type')} ({vuln.get('severity')})")
    print(f"  URL: {vuln.get('url')}")
    print(f"  Evidence: {vuln.get('evidence', 'N/A')}")
    
    if vuln.get('request_data'):
        print("  📤 Request data captured:")
        req_data = vuln.get('request_data')
        print(f"    Method: {req_data.get('method', 'N/A')}")
        print(f"    URL: {req_data.get('url', 'N/A')}")
        print(f"    Headers: {req_data.get('headers', 'N/A')}")
        print(f"    Parameters: {req_data.get('parameters', 'N/A')}")
        print(f"    Body: {req_data.get('body', 'N/A')}")
    
    if vuln.get('response_data'):
        print("  📥 Response data captured:")
        resp_data = vuln.get('response_data')
        print(f"    Status: {resp_data.get('status_code', 'N/A')}")
        print(f"    Headers: {resp_data.get('headers', 'N/A')}")
        print(f"    Content: {resp_data.get('content', 'N/A')[:200]}...")

# Generate enhanced reports
report_path = scanner.generate_api_security_report(results, 'json')
print(f"\nJSON report: {report_path}")

html_path = scanner.generate_owasp_report(results, 'html')
print(f"HTML report: {html_path}") 