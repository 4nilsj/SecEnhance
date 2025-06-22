#!/usr/bin/env python3
"""
Test script to verify scan ID consistency fix
"""

import requests
import json
import time

def test_scan_workflow():
    """Test the complete scan workflow"""
    base_url = "http://localhost:5000"
    
    print("🔍 Testing API Security Scanner Workflow")
    print("=" * 50)
    
    # Step 1: Check current scans
    print("1. Checking current scans...")
    try:
        response = requests.get(f"{base_url}/api/debug/scans")
        if response.status_code == 200:
            data = response.json()
            print(f"   Current scans: {data['scan_results_count']}")
            print(f"   Available scan IDs: {data['scan_results_keys'][:3]}...")
        else:
            print(f"   Error: {response.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Step 2: Start a new scan
    print("\n2. Starting a new scan...")
    scan_config = {
        "scan_type": "swagger_url",
        "swagger_url": "https://httpbin.org/json",
        "base_url": "https://httpbin.org"
    }
    
    try:
        response = requests.post(f"{base_url}/api/scan", json=scan_config)
        if response.status_code == 200:
            data = response.json()
            scan_id = data['scan_id']
            print(f"   Scan started with ID: {scan_id}")
            print(f"   Status: {data['status']}")
            
            # Step 3: Check scan status
            print(f"\n3. Checking scan status for ID: {scan_id}")
            
            # Wait a moment for scan to start
            time.sleep(2)
            
            response = requests.get(f"{base_url}/api/scan/{scan_id}")
            if response.status_code == 200:
                scan_data = response.json()
                print(f"   Scan found! Status: {scan_data.get('status', 'unknown')}")
                print(f"   Scan type: {scan_data.get('scan_type', 'unknown')}")
                print(f"   Endpoints scanned: {scan_data.get('endpoints_scanned', 0)}")
                print("   ✅ Scan ID consistency fix working!")
            else:
                print(f"   ❌ Scan not found: {response.status_code}")
                print(f"   Response: {response.text}")
                
        else:
            print(f"   ❌ Failed to start scan: {response.status_code}")
            print(f"   Response: {response.text}")
            
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Step 4: Test with non-existent scan ID
    print("\n4. Testing with non-existent scan ID...")
    try:
        response = requests.get(f"{base_url}/api/scan/nonexistent_scan_id")
        if response.status_code == 404:
            data = response.json()
            print(f"   ✅ Correctly returned 404 for non-existent scan")
            print(f"   Available scans: {data.get('available_scans', [])[:3]}...")
        else:
            print(f"   ❌ Unexpected response: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n🎉 Test completed!")

if __name__ == "__main__":
    test_scan_workflow() 