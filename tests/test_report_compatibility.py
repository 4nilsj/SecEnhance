#!/usr/bin/env python3
"""
Test script to verify report compatibility between script-generated reports and web UI
"""

import requests
import json
from pathlib import Path

def test_web_ui_reports():
    """Test if the web UI can properly load and access reports"""
    
    print("Testing Web UI Report Compatibility...")
    print("=" * 50)
    
    # Test 1: Check if scan history loads
    try:
        response = requests.get('http://localhost:5000/api/scans')
        if response.status_code == 200:
            scans = response.json()
            print(f"✓ Scan history loaded successfully: {len(scans)} scans found")
            
            # Show first few scans
            for i, scan in enumerate(scans[:3]):
                print(f"  Scan {i+1}: ID={scan.get('id')}, Type={scan.get('scan_type')}, Status={scan.get('status')}")
        else:
            print(f"✗ Failed to load scan history: {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Error connecting to web UI: {e}")
        return False
    
    # Test 2: Try to download a report
    if scans:
        first_scan = scans[0]
        scan_id = first_scan.get('id')
        
        print(f"\nTesting report download for scan ID: {scan_id}")
        
        # Test standard report download
        try:
            response = requests.get(f'http://localhost:5000/api/report/{scan_id}/standard')
            if response.status_code == 200:
                print(f"✓ Standard report download successful for scan {scan_id}")
            else:
                print(f"✗ Standard report download failed: {response.status_code}")
                if response.status_code == 404:
                    print(f"  Response: {response.json()}")
        except Exception as e:
            print(f"✗ Error downloading standard report: {e}")
        
        # Test OWASP report download
        try:
            response = requests.get(f'http://localhost:5000/api/report/{scan_id}/owasp')
            if response.status_code == 200:
                print(f"✓ OWASP report download successful for scan {scan_id}")
            else:
                print(f"✗ OWASP report download failed: {response.status_code}")
                if response.status_code == 404:
                    print(f"  Response: {response.json()}")
        except Exception as e:
            print(f"✗ Error downloading OWASP report: {e}")
    
    print("\n" + "=" * 50)
    print("Test completed!")
    
    return True

def check_report_files():
    """Check what report files exist and their naming patterns"""
    
    print("\nChecking Report Files...")
    print("=" * 50)
    
    reports_dir = Path('reports')
    
    # Check JSON reports
    json_files = list(reports_dir.glob('**/*.json'))
    print(f"Found {len(json_files)} JSON report files:")
    
    for json_file in json_files[:5]:  # Show first 5
        print(f"  {json_file}")
    
    # Check HTML reports
    html_files = list(reports_dir.glob('**/*.html'))
    print(f"\nFound {len(html_files)} HTML report files:")
    
    for html_file in html_files[:5]:  # Show first 5
        print(f"  {html_file}")
    
    # Check for double "scan" pattern
    double_scan_files = [f for f in json_files if 'scan_scan_' in f.name]
    print(f"\nFound {len(double_scan_files)} files with double 'scan' pattern:")
    
    for file in double_scan_files[:3]:  # Show first 3
        print(f"  {file.name}")

if __name__ == "__main__":
    check_report_files()
    test_web_ui_reports() 