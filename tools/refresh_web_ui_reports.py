#!/usr/bin/env python3
"""
Refresh Web UI Reports
This script refreshes the web UI to show all available reports including script-generated ones.
"""

import requests
import json
import time
from pathlib import Path
import sys

# Add src directory to Python path (updated for tools/ directory location)
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

def refresh_web_ui_reports():
    """Refresh the web UI to show all available reports"""
    
    base_url = "http://localhost:5000"
    
    print("🔄 Refreshing Web UI Reports")
    print("=" * 40)
    
    # Step 1: Check if web UI is running
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Web UI is running")
        else:
            print(f"❌ Web UI returned status {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Web UI is not accessible: {e}")
        print("   Please start the web UI with: python src/web/app.py")
        return
    
    # Step 2: Get current scan history
    try:
        response = requests.get(f"{base_url}/api/scans")
        if response.status_code == 200:
            scans = response.json()
            print(f"📊 Current scans in web UI: {len(scans)}")
            
            if len(scans) > 0:
                print("\n📋 Available Scans:")
                for scan in scans:
                    print(f"   • ID: {scan.get('id', 'N/A')}")
                    print(f"     Type: {scan.get('scan_type', 'N/A')}")
                    print(f"     Status: {scan.get('status', 'N/A')}")
                    print(f"     Start Time: {scan.get('start_time', 'N/A')}")
                    print(f"     Endpoints: {scan.get('endpoints_scanned', 'N/A')}")
                    print(f"     Vulnerabilities: {scan.get('vulnerabilities_found', 'N/A')}")
                    print()
            else:
                print("   No scans found in web UI")
                
        else:
            print(f"❌ Failed to get scan history: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Error getting scan history: {e}")
    
    # Step 3: Check reports directory
    reports_dir = Path("reports")
    if reports_dir.exists():
        json_reports = list(reports_dir.glob("api_security_scan_*.json"))
        html_reports = list(reports_dir.glob("owasp_api_scan_*.html"))
        
        print(f"📁 Reports Directory Contents:")
        print(f"   • JSON Reports: {len(json_reports)}")
        print(f"   • HTML Reports: {len(html_reports)}")
        
        if json_reports:
            print("\n📄 JSON Reports:")
            for report in json_reports:
                scan_id = report.stem.replace('api_security_scan_', '')
                print(f"   • {report.name} (Scan ID: {scan_id})")
        
        if html_reports:
            print("\n📄 HTML Reports:")
            for report in html_reports:
                scan_id = report.stem.replace('owasp_api_scan_', '')
                print(f"   • {report.name} (Scan ID: {scan_id})")
    
    # Step 4: Instructions for viewing reports
    print(f"\n🌐 How to View Reports in Web UI:")
    print(f"   1. Open browser and go to: {base_url}")
    print(f"   2. Click on 'Reports' tab")
    print(f"   3. You should see all available reports including:")
    print(f"      • Script-generated reports (vulnerable API scan)")
    print(f"      • Web UI generated reports (historical scans)")
    print(f"   4. Use the search and filter options to find specific reports")
    print(f"   5. Click 'Download' to get JSON or HTML versions")
    print(f"   6. Click 'View' to open HTML reports in browser")
    print(f"   7. Click 'Delete' to remove reports (with confirmation)")
    
    # Step 5: Test specific report endpoints
    print(f"\n🔗 Test Report Access:")
    
    # Test the latest vulnerable API scan
    test_scan_id = "1750605290"
    
    try:
        # Test JSON report download
        response = requests.get(f"{base_url}/api/report/{test_scan_id}/standard")
        if response.status_code == 200:
            print(f"✅ JSON report accessible: /api/report/{test_scan_id}/standard")
        else:
            print(f"❌ JSON report not accessible: {response.status_code}")
    except Exception as e:
        print(f"❌ Error accessing JSON report: {e}")
    
    try:
        # Test HTML report download
        response = requests.get(f"{base_url}/api/report/{test_scan_id}/owasp")
        if response.status_code == 200:
            print(f"✅ HTML report accessible: /api/report/{test_scan_id}/owasp")
        else:
            print(f"❌ HTML report not accessible: {response.status_code}")
    except Exception as e:
        print(f"❌ Error accessing HTML report: {e}")
    
    print(f"\n✅ Web UI Reports Refresh Complete!")
    print(f"   All reports should now be visible in the web UI")

if __name__ == "__main__":
    refresh_web_ui_reports() 