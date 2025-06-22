#!/usr/bin/env python3
"""
Scan Vulnerable API and Generate Reports
This script scans the insecure API example and generates comprehensive security reports.
"""

import sys
import os
import time
import json
import requests
from datetime import datetime
import shutil
from pathlib import Path

# Add src directory to Python path (updated for examples/ directory location)
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

try:
    from src.core.api_security_scanner import APISecurityScanner
    print("✓ Successfully imported APISecurityScanner")
except ImportError as e:
    print(f"✗ Failed to import APISecurityScanner: {e}")
    sys.exit(1)

def test_insecure_api_endpoints():
    """Test the insecure API endpoints to verify they're working"""
    base_url = "http://localhost:5001"
    
    print("🔍 Testing Insecure API Endpoints")
    print("=" * 50)
    
    endpoints_to_test = [
        "/",
        "/api/users",
        "/api/users/1",
        "/api/posts",
        "/api/search?q=test",
        "/api/file?path=test.txt",
        "/api/admin"
    ]
    
    working_endpoints = []
    
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code in [200, 400, 404]:  # Accept various responses
                print(f"✓ {endpoint} - Status: {response.status_code}")
                working_endpoints.append(endpoint)
            else:
                print(f"⚠ {endpoint} - Status: {response.status_code}")
        except Exception as e:
            print(f"✗ {endpoint} - Error: {e}")
    
    return working_endpoints

def scan_vulnerable_api():
    """Perform comprehensive security scan of the vulnerable API"""
    
    print("\n🔒 Starting Security Scan of Vulnerable API")
    print("=" * 60)
    
    # Initialize scanner
    scanner = APISecurityScanner()
    
    # Define endpoints to scan
    endpoints = [
        {
            "url": "http://localhost:5001/api/users",
            "method": "GET",
            "description": "Get users - SQL injection vulnerable"
        },
        {
            "url": "http://localhost:5001/api/users/1",
            "method": "GET", 
            "description": "Get user by ID - SQL injection vulnerable"
        },
        {
            "url": "http://localhost:5001/api/users",
            "method": "POST",
            "description": "Create user - XSS vulnerable"
        },
        {
            "url": "http://localhost:5001/api/posts",
            "method": "GET",
            "description": "Get posts - SQL injection vulnerable"
        },
        {
            "url": "http://localhost:5001/api/posts",
            "method": "POST",
            "description": "Create post - XSS vulnerable"
        },
        {
            "url": "http://localhost:5001/api/search",
            "method": "GET",
            "description": "Search - Command injection vulnerable"
        },
        {
            "url": "http://localhost:5001/api/file",
            "method": "GET",
            "description": "File access - Path traversal vulnerable"
        },
        {
            "url": "http://localhost:5001/api/admin",
            "method": "GET",
            "description": "Admin endpoint - Missing authentication"
        }
    ]
    
    print(f"🎯 Scan Configuration:")
    print(f"   • Base URL: http://localhost:5001")
    print(f"   • Endpoints to scan: {len(endpoints)}")
    print(f"   • OWASP Top 10: Enabled")
    print(f"   • Custom Tests: Enabled")
    
    # Start scan
    print(f"\n🚀 Starting scan...")
    start_time = time.time()
    
    try:
        # Scan endpoints
        results = scanner.scan_api_endpoints(endpoints)
        
        scan_duration = time.time() - start_time
        
        print(f"✅ Scan completed successfully in {scan_duration:.2f} seconds")
        
        # Generate reports
        print(f"\n📊 Generating Reports...")
        
        # Generate standard report
        standard_report = scanner.generate_api_security_report(results)
        standard_report_file = f"vulnerable_api_scan_{int(time.time())}.json"
        with open(standard_report_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate OWASP report
        owasp_report = scanner.generate_owasp_report(results, format='html')
        owasp_report_file = f"vulnerable_api_owasp_{int(time.time())}.html"
        with open(owasp_report_file, 'w') as f:
            f.write(owasp_report)
        
        print(f"📄 Standard Report: {standard_report_file}")
        print(f"📄 OWASP Report: {owasp_report_file}")
        
        # Move reports to the correct location for web UI
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate scan ID for proper naming
        scan_id = str(int(time.time()))
        
        # Move and rename files to match web UI expectations
        web_ui_json_file = reports_dir / f"api_security_scan_{scan_id}.json"
        web_ui_html_file = reports_dir / f"owasp_api_scan_{scan_id}.html"
        
        # Copy the generated reports to the correct location
        shutil.copy2(standard_report_file, web_ui_json_file)
        shutil.copy2(owasp_report_file, web_ui_html_file)
        
        # Clean up temporary files
        os.remove(standard_report_file)
        os.remove(owasp_report_file)
        
        print(f"📄 Reports moved to web UI location:")
        print(f"   • JSON Report: {web_ui_json_file}")
        print(f"   • HTML Report: {web_ui_html_file}")
        
        print(f"✅ Reports saved in web UI format!")
        print(f"   • Scan ID: {scan_id}")
        print(f"   • Refresh the web UI to see the new scan in Reports tab")
        
        # Display summary
        print(f"\n📋 Scan Summary:")
        print(f"   • Endpoints Scanned: {len(results.get('endpoints_scanned', []))}")
        print(f"   • Vulnerabilities Found: {len(results.get('vulnerabilities', []))}")
        print(f"   • Scan Duration: {scan_duration:.2f} seconds")
        
        if results.get('vulnerabilities'):
            print(f"\n🚨 Vulnerabilities Detected:")
            for vuln in results['vulnerabilities']:
                print(f"   • {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
                print(f"     Endpoint: {vuln.get('endpoint', 'Unknown')}")
                print(f"     Severity: {vuln.get('severity', 'Unknown')}")
                print()
        
        return results, str(web_ui_json_file), str(web_ui_html_file)
        
    except Exception as e:
        print(f"❌ Scan error: {e}")
        return None, None, None

def main():
    """Main function to run the vulnerable API scan"""
    
    print("🔍 Vulnerable API Security Scanner")
    print("=" * 50)
    print("This script will scan the insecure API example and generate security reports.")
    print()
    
    # Test if insecure API is running
    print("1. Testing insecure API connectivity...")
    working_endpoints = test_insecure_api_endpoints()
    
    if not working_endpoints:
        print("❌ Insecure API is not accessible. Please start it first:")
        print("   python src/examples/insecure_api.py")
        return
    
    print(f"✅ Insecure API is running with {len(working_endpoints)} accessible endpoints")
    
    # Perform security scan
    print("\n2. Performing security scan...")
    results, standard_report, owasp_report = scan_vulnerable_api()
    
    if results:
        print(f"\n✅ Scan completed successfully!")
        print(f"📄 Reports generated:")
        print(f"   • Standard JSON Report: {standard_report}")
        print(f"   • OWASP HTML Report: {owasp_report}")
        
        print(f"\n🌐 You can also view the reports in the web UI:")
        print(f"   • Open: http://localhost:5000")
        print(f"   • Go to 'Reports' tab to see the scan results")
        
    else:
        print(f"\n❌ Scan failed. Check the error messages above.")

if __name__ == "__main__":
    main() 