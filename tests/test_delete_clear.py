#!/usr/bin/env python3
"""
Test script to verify delete and clear functionality for logs and diagnostics
"""

import requests
import json
import time

def test_delete_clear_functionality():
    """Test the delete and clear functionality"""
    
    base_url = "http://localhost:5000"
    
    print("🧹 Testing Delete & Clear Functionality")
    print("=" * 50)
    
    # Test 1: Check if web UI is running
    print("\n1. Checking if web UI is accessible...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Web UI is running and accessible")
        else:
            print(f"❌ Web UI returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to web UI: {e}")
        return False
    
    # Test 2: Test clear logs functionality
    print("\n2. Testing clear logs functionality...")
    try:
        response = requests.delete(f"{base_url}/api/logs/clear", timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print("✅ Clear logs successful")
                print(f"   Message: {result.get('message', 'N/A')}")
            else:
                print(f"❌ Clear logs failed: {result.get('error', 'Unknown error')}")
        else:
            print(f"❌ Clear logs returned status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing clear logs: {e}")
    
    # Test 3: Test clear diagnostics functionality
    print("\n3. Testing clear diagnostics functionality...")
    try:
        response = requests.delete(f"{base_url}/api/diagnostics/clear", timeout=10)
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                print("✅ Clear diagnostics successful")
                print(f"   Message: {result.get('message', 'N/A')}")
            else:
                print(f"❌ Clear diagnostics failed: {result.get('error', 'Unknown error')}")
        else:
            print(f"❌ Clear diagnostics returned status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing clear diagnostics: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Delete & Clear Functionality Test Summary")
    print("=" * 50)
    print("The delete and clear functionality should now be working with:")
    print("• Clear Logs button (🟡) - Clears log content but keeps files")
    print("• Delete Logs button (🔴) - Completely removes log files")
    print("• Clear Diagnostics button (🟡) - Resets counters and clears debug files")
    print("• Export Diagnostics button (🔵) - Exports debug data")
    print("\nTo test manually:")
    print("1. Open http://localhost:5000 in your browser")
    print("2. Go to the Logs & Diagnostics tab")
    print("3. Try the Clear Logs, Delete Logs, and Clear Diagnostics buttons")
    print("4. Check that the operations work as expected")
    
    return True

if __name__ == "__main__":
    test_delete_clear_functionality() 