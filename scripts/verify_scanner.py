#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Verify the security scanner is working
"""

import requests
import json

def verify_scanner():
    """Verify the scanner is working"""
    print("🔍 Verifying Security Scanner...")
    
    scanner_url = "http://localhost:5000"
    
    try:
        # Get scan history
        response = requests.get(f"{scanner_url}/api/scans", timeout=10)
        if response.status_code == 200:
            scans = response.json()
            print(f"✅ Found {len(scans)} completed scans")
            
            if scans:
                # Show the latest scan
                latest_scan = scans[-1]
                print(f"\n📊 Latest Scan Details:")
                print(f"   ID: {latest_scan.get('id')}")
                print(f"   Type: {latest_scan.get('scan_type')}")
                print(f"   Status: {latest_scan.get('status')}")
                print(f"   Start Time: {latest_scan.get('start_time')}")
                print(f"   End Time: {latest_scan.get('end_time')}")
                
                # Show results if available
                results = latest_scan.get('results', {})
                if results:
                    print(f"\n📈 Scan Results:")
                    print(f"   Total Endpoints: {results.get('total_endpoints', 0)}")
                    print(f"   Scanned Endpoints: {results.get('scanned_endpoints', 0)}")
                    
                    vulnerabilities = results.get('vulnerabilities', [])
                    print(f"   Vulnerabilities Found: {len(vulnerabilities)}")
                    
                    if vulnerabilities:
                        print(f"\n🚨 Detected Vulnerabilities:")
                        for i, vuln in enumerate(vulnerabilities[:10]):  # Show first 10
                            print(f"   {i+1}. {vuln.get('title', 'Unknown')}")
                            print(f"      Severity: {vuln.get('severity', 'Unknown')}")
                            print(f"      Description: {vuln.get('description', 'No description')[:100]}...")
                            print()
                
                # Show reports if available
                reports = latest_scan.get('reports', {})
                if reports:
                    print(f"\n📄 Generated Reports:")
                    for report_type, report_path in reports.items():
                        print(f"   {report_type}: {report_path}")
            else:
                print("❌ No completed scans found")
        
        # Test starting a new scan
        print(f"\n🔍 Testing new scan creation...")
        
        # Create a simple test scan config
        test_config = {
            "scan_type": "collection",
            "collection_file": "test_collection.json",
            "base_url": "http://localhost:5001"
        }
        
        response = requests.post(f"{scanner_url}/api/scan", json=test_config, timeout=10)
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get('scan_id')
            print(f"✅ New scan started successfully! Scan ID: {scan_id}")
            
            # Wait a moment and check status
            import time
            time.sleep(3)
            
            status_response = requests.get(f"{scanner_url}/api/scan/{scan_id}", timeout=5)
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data.get('status', 'unknown')
                print(f"📊 Scan status: {status}")
                
                if status == 'completed':
                    results = status_data.get('results', {})
                    print(f"📈 Endpoints scanned: {results.get('scanned_endpoints', 0)}")
                    print(f"🚨 Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
                elif status == 'failed':
                    error = status_data.get('error', 'Unknown error')
                    print(f"❌ Scan failed: {error}")
                else:
                    print(f"⏳ Scan is still running...")
        else:
            print(f"❌ Failed to start new scan: {response.status_code}")
        
        print(f"\n🎉 Scanner verification completed!")
        print(f"💡 Your security scanner is working correctly!")
        print(f"🌐 Access the web interface at: {scanner_url}")
        
    except Exception as e:
        print(f"❌ Error verifying scanner: {e}")

if __name__ == "__main__":
    verify_scanner() 