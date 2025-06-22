#!/usr/bin/env python3
"""
Test Web UI Access
Simple script to test if the web UI is accessible and reports are working
"""

import requests
import json

def test_web_ui():
    """Test web UI accessibility and report functionality"""
    
    base_url = "http://localhost:5000"
    
    print("🔍 Testing Web UI Access")
    print("=" * 30)
    
    # Test 1: Main page
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Main page accessible")
        else:
            print(f"❌ Main page returned {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Cannot access main page: {e}")
        return
    
    # Test 2: Get scan history
    try:
        response = requests.get(f"{base_url}/api/scans", timeout=5)
        if response.status_code == 200:
            scans = response.json()
            print(f"✅ Scan history accessible - {len(scans)} scans found")
            
            if len(scans) > 0:
                print("\n📋 Available Scans:")
                for scan in scans:
                    print(f"   • ID: {scan.get('id', 'N/A')}")
                    print(f"     Type: {scan.get('scan_type', 'N/A')}")
                    print(f"     Status: {scan.get('status', 'N/A')}")
                    print(f"     Endpoints: {scan.get('endpoints_scanned', 'N/A')}")
                    print()
        else:
            print(f"❌ Scan history returned {response.status_code}")
    except Exception as e:
        print(f"❌ Cannot access scan history: {e}")
    
    # Test 3: Test report download
    test_scan_id = "1750605290"
    
    try:
        response = requests.get(f"{base_url}/api/report/{test_scan_id}/standard", timeout=10)
        if response.status_code == 200:
            print(f"✅ JSON report download working for scan {test_scan_id}")
        else:
            print(f"❌ JSON report download failed: {response.status_code}")
    except Exception as e:
        print(f"❌ JSON report download error: {e}")
    
    try:
        response = requests.get(f"{base_url}/api/report/{test_scan_id}/owasp", timeout=10)
        if response.status_code == 200:
            print(f"✅ HTML report download working for scan {test_scan_id}")
        else:
            print(f"❌ HTML report download failed: {response.status_code}")
    except Exception as e:
        print(f"❌ HTML report download error: {e}")
    
    print(f"\n🌐 Web UI Access Instructions:")
    print(f"   1. Open browser and go to: {base_url}")
    print(f"   2. Click on 'Reports' tab")
    print(f"   3. You should see all available scans")
    print(f"   4. Click 'Download' or 'View' buttons to access reports")
    print(f"   5. If you still can't see reports, try refreshing the page")

if __name__ == "__main__":
    test_web_ui() 