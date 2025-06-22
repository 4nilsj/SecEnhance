#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to scan the insecure API using the security scanner
"""

import requests
import json
import time

def test_scanner_with_api():
    """Test the security scanner with the insecure API"""
    print("🔍 Testing Security Scanner with Insecure API...")
    
    # Scanner base URL
    scanner_url = "http://localhost:5000"
    
    try:
        # Test 1: Scan with Swagger URL (the API doesn't have swagger, but let's test the endpoint)
        print("\n🔍 Test 1: Testing scanner connectivity...")
        response = requests.get(f"{scanner_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Security scanner is accessible")
        else:
            print(f"❌ Scanner returned status code: {response.status_code}")
            return
        
        # Test 2: Try to scan the API directly
        print("\n🔍 Test 2: Testing direct API scan...")
        
        # Create a scan config for the insecure API
        scan_config = {
            "scan_type": "swagger_url",
            "swagger_url": "http://localhost:5001/",
            "base_url": "http://localhost:5001"
        }
        
        # Start the scan
        response = requests.post(f"{scanner_url}/api/scan", json=scan_config, timeout=10)
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get('scan_id')
            print(f"✅ Scan started successfully! Scan ID: {scan_id}")
            
            # Monitor the scan
            print("\n🔍 Monitoring scan progress...")
            for i in range(10):  # Check for up to 10 times
                time.sleep(2)
                status_response = requests.get(f"{scanner_url}/api/scan/{scan_id}", timeout=5)
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status', 'unknown')
                    print(f"   📊 Scan status: {status}")
                    
                    if status == 'completed':
                        results = status_data.get('results', {})
                        print(f"   📈 Endpoints scanned: {results.get('scanned_endpoints', 0)}")
                        print(f"   🚨 Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
                        
                        # Show some vulnerabilities
                        vulnerabilities = results.get('vulnerabilities', [])
                        if vulnerabilities:
                            print("\n   🚨 Detected Vulnerabilities:")
                            for i, vuln in enumerate(vulnerabilities[:5]):  # Show first 5
                                print(f"      {i+1}. {vuln.get('title', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                        
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
        
        # Test 3: Test with a simple API collection
        print("\n🔍 Test 3: Testing with API collection...")
        
        # Create a simple API collection for the insecure API
        api_collection = {
            "info": {
                "name": "Insecure API Test Collection",
                "description": "Test collection for insecure API"
            },
            "item": [
                {
                    "name": "Get Users",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "http://localhost:5001/api/users",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5001",
                            "path": ["api", "users"]
                        }
                    }
                },
                {
                    "name": "Create User",
                    "request": {
                        "method": "POST",
                        "url": {
                            "raw": "http://localhost:5001/api/users",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5001",
                            "path": ["api", "users"]
                        },
                        "header": [
                            {
                                "key": "Content-Type",
                                "value": "application/json"
                            }
                        ],
                        "body": {
                            "mode": "raw",
                            "raw": '{"username": "test", "email": "test@test.com", "password": "test123"}'
                        }
                    }
                },
                {
                    "name": "Admin Panel",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "http://localhost:5001/api/admin",
                            "protocol": "http",
                            "host": ["localhost"],
                            "port": "5001",
                            "path": ["api", "admin"]
                        }
                    }
                }
            ]
        }
        
        # Save the collection to a file
        with open('test_collection.json', 'w') as f:
            json.dump(api_collection, f, indent=2)
        
        print("   📁 Created test collection file: test_collection.json")
        
        # Try to scan with the collection file
        scan_config_collection = {
            "scan_type": "collection",
            "collection_file": "test_collection.json",
            "base_url": "http://localhost:5001"
        }
        
        response = requests.post(f"{scanner_url}/api/scan", json=scan_config_collection, timeout=10)
        if response.status_code == 200:
            data = response.json()
            scan_id = data.get('scan_id')
            print(f"   ✅ Collection scan started! Scan ID: {scan_id}")
            
            # Monitor this scan too
            time.sleep(3)
            status_response = requests.get(f"{scanner_url}/api/scan/{scan_id}", timeout=5)
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data.get('status', 'unknown')
                print(f"   📊 Collection scan status: {status}")
                
                if status == 'completed':
                    results = status_data.get('results', {})
                    print(f"   📈 Endpoints scanned: {results.get('scanned_endpoints', 0)}")
                    print(f"   🚨 Vulnerabilities found: {len(results.get('vulnerabilities', []))}")
        
        print("\n🎉 Scanner testing completed!")
        print("💡 Check the scanner web interface for detailed results")
        
    except Exception as e:
        print(f"❌ Error testing scanner: {e}")

if __name__ == "__main__":
    test_scanner_with_api() 