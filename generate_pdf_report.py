import sys
import json
sys.path.insert(0, 'src')

from web.app import generate_pdf_from_json

# Load the latest scan results
with open('reports/api_security_scan_1750605290.json', 'r') as f:
    scan_data = json.load(f)

print("Generating PDF report...")
pdf_path, error = generate_pdf_from_json(scan_data, 'vulnerable_api_scan')

if pdf_path and not error:
    print(f"✅ PDF Report generated: {pdf_path}")
else:
    print(f"❌ PDF generation failed: {error}")

print(f"\nScan Summary:")
print(f"- Endpoints Scanned: {scan_data.get('endpoints_scanned', 0)}")
print(f"- Vulnerabilities Found: {len(scan_data.get('vulnerabilities_found', []))}")
print(f"- Scan Duration: {scan_data.get('scan_duration', 0):.2f} seconds")

# Show vulnerability types found
vuln_types = set()
for vuln in scan_data.get('vulnerabilities_found', []):
    vuln_types.add(vuln.get('type', 'Unknown'))

print(f"\nVulnerability Types Found:")
for vuln_type in vuln_types:
    count = len([v for v in scan_data.get('vulnerabilities_found', []) if v.get('type') == vuln_type])
    print(f"- {vuln_type}: {count}") 