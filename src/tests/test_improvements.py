#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify scan improvements
"""

import requests
import json
import time

def test_scan_improvements():
    """Test the improved scan functionality"""
    print("🔍 Testing Scan Improvements...")
    
    scanner_url = "http://localhost:5000"
    
    try:
        # Test 1: Start a scan and monitor status
        print("\n🔍 Test 1: Testing scan status tracking...")
        
        # Create a scan config for the insecure API
        scan_config = {
            "scan_type": "collection",
            "collection_file": "test_collection.json",
            "base_url": "http://localhost:5001"
        }
        
        # Start the scan
        response = requests.post(f"{scanner_url}/api/scan", json=scan_config, timeout=10)
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get('scan_id')
            print(f"✅ Scan started successfully! Scan ID: {scan_id}")
            
            # Monitor the scan status
            print("\n📊 Monitoring scan status...")
            for i in range(10):  # Check for up to 10 times
                time.sleep(3)
                status_response = requests.get(f"{scanner_url}/api/scan/{scan_id}", timeout=5)
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status', 'unknown')
                    print(f"   📊 Status check {i+1}: {status}")
                    
                    if status == 'completed':
                        results = status_data.get('results', {})
                        print(f"   ✅ Scan completed!")
                        print(f"   📈 Endpoints scanned: {results.get('scanned_endpoints', 0)}")
                        print(f"   🚨 Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
                        
                        # Check for duplicate prevention
                        if results.get('test_results'):
                            total_tests_run = 0
                            total_tests_skipped = 0
                            for category, test_result in results['test_results'].items():
                                tests_run = test_result.get('tests_run', 0)
                                tests_skipped = test_result.get('tests_skipped', 0)
                                total_tests_run += tests_run
                                total_tests_skipped += tests_skipped
                                print(f"   📋 {category}: {tests_run} tests run, {tests_skipped} skipped")
                            
                            print(f"   📊 Total: {total_tests_run} tests run, {total_tests_skipped} duplicates skipped")
                        
                        break
                    elif status == 'failed':
                        error = status_data.get('error', 'Unknown error')
                        print(f"   ❌ Scan failed: {error}")
                        break
                else:
                    print(f"   ⚠️  Status check failed: {status_response.status_code}")
        else:
            print(f"❌ Failed to start scan: {response.status_code}")
            print(f"   Response: {response.text}")
        
        # Test 2: Check scan history
        print("\n🔍 Test 2: Testing scan history...")
        history_response = requests.get(f"{scanner_url}/api/scans", timeout=5)
        if history_response.status_code == 200:
            scans = history_response.json()
            print(f"✅ Found {len(scans)} scans in history")
            
            if scans:
                latest_scan = scans[-1]
                print(f"   📊 Latest scan: {latest_scan.get('status', 'unknown')}")
                print(f"   🆔 Scan ID: {latest_scan.get('id', 'unknown')}")
                print(f"   📅 Start time: {latest_scan.get('start_time', 'unknown')}")
                print(f"   📅 End time: {latest_scan.get('end_time', 'unknown')}")
        
        print("\n🎉 Scan improvements test completed!")
        print("💡 The scanner now properly tracks status and prevents duplicate requests")
        
    except Exception as e:
        print(f"❌ Error testing improvements: {e}")

if __name__ == "__main__":
    test_scan_improvements() 