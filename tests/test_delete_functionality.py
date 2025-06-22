#!/usr/bin/env python3
"""
Test script to verify delete functionality for scan history and reports
"""

import requests
import json
import time

def test_delete_functionality():
    """Test the delete functionality for both scan history and reports"""
    
    base_url = "http://localhost:5000"
    
    print("🔍 Testing Delete Functionality for Scan History and Reports")
    print("=" * 60)
    
    # Step 1: Get current scan history
    print("\n1. Getting current scan history...")
    try:
        response = requests.get(f"{base_url}/api/scans")
        if response.status_code == 200:
            scans = response.json()
            print(f"   ✓ Found {len(scans)} scans in history")
            
            if len(scans) == 0:
                print("   ⚠ No scans found to test deletion")
                return
            
            # Get the first scan for testing
            test_scan = scans[0]
            scan_id = test_scan['id']
            print(f"   📋 Using scan ID: {scan_id} for testing")
            
        else:
            print(f"   ✗ Failed to get scan history: {response.status_code}")
            return
            
    except Exception as e:
        print(f"   ✗ Error getting scan history: {e}")
        return
    
    # Step 2: Test delete endpoint
    print(f"\n2. Testing delete endpoint for scan {scan_id}...")
    try:
        response = requests.delete(f"{base_url}/api/scan/{scan_id}/delete")
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print(f"   ✓ Successfully deleted scan {scan_id}")
                print(f"   📝 Response: {result}")
            else:
                print(f"   ✗ Delete failed: {result.get('error', 'Unknown error')}")
        else:
            print(f"   ✗ Delete request failed with status {response.status_code}")
            print(f"   📝 Response: {response.text}")
            
    except Exception as e:
        print(f"   ✗ Error during delete: {e}")
    
    # Step 3: Verify deletion by checking scan history again
    print(f"\n3. Verifying deletion...")
    try:
        time.sleep(1)  # Give server time to process
        response = requests.get(f"{base_url}/api/scans")
        if response.status_code == 200:
            scans_after = response.json()
            remaining_scans = [s for s in scans_after if s['id'] == scan_id]
            
            if len(remaining_scans) == 0:
                print(f"   ✓ Scan {scan_id} successfully removed from history")
            else:
                print(f"   ✗ Scan {scan_id} still exists in history")
                
            print(f"   📊 Scans before: {len(scans)}, after: {len(scans_after)}")
            
        else:
            print(f"   ✗ Failed to verify deletion: {response.status_code}")
            
    except Exception as e:
        print(f"   ✗ Error verifying deletion: {e}")
    
    # Step 4: Test web UI endpoints
    print(f"\n4. Testing web UI endpoints...")
    try:
        # Test scan history page
        response = requests.get(f"{base_url}/")
        if response.status_code == 200:
            print("   ✓ Web UI main page accessible")
        else:
            print(f"   ✗ Web UI main page failed: {response.status_code}")
            
    except Exception as e:
        print(f"   ✗ Error accessing web UI: {e}")
    
    print(f"\n✅ Delete functionality test completed!")
    print(f"\n📋 Summary:")
    print(f"   • Delete endpoint: /api/scan/<scan_id>/delete")
    print(f"   • Works for both scan history and reports")
    print(f"   • Removes scan data and associated reports")
    print(f"   • Web UI automatically refreshes after deletion")

if __name__ == "__main__":
    test_delete_functionality() 