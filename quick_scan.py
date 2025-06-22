import sys
sys.path.insert(0, 'src')

from core.api_security_scanner import APISecurityScanner

print("Starting comprehensive scan...")
scanner = APISecurityScanner()

endpoints = [
    {'url': 'http://localhost:5001/api/users', 'method': 'GET'},
    {'url': 'http://localhost:5001/api/users/1', 'method': 'GET'},
    {'url': 'http://localhost:5001/api/search', 'method': 'GET'},
    {'url': 'http://localhost:5001/api/admin', 'method': 'GET'}
]

results = scanner.scan_api_endpoints(endpoints)
print(f"Total vulnerabilities found: {len(results.get('vulnerabilities_found', []))}")

# Generate reports
report_path = scanner.generate_api_security_report(results, 'json')
print(f"JSON report: {report_path}")

html_path = scanner.generate_owasp_report(results, 'html')
print(f"HTML report: {html_path}")

# Show some vulnerability details
for vuln in results.get('vulnerabilities_found', [])[:3]:  # Show first 3
    print(f"- {vuln.get('type')} ({vuln.get('severity')}) at {vuln.get('url')}")
    if vuln.get('request_data'):
        print("  Request data captured")
    if vuln.get('response_data'):
        print("  Response data captured") 