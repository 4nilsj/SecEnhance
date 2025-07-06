#!/usr/bin/env python3
"""
Test script for Enhanced JWT Security Testing API with Scan ID Management
"""
import requests
import json
import time
import os

# Configuration
API_BASE_URL = "http://localhost:5000"
TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def test_enhanced_api():
    """Test the enhanced API with scan ID management."""
    print("🔍 Testing Enhanced JWT Security Testing API with Scan ID Management")
    print("=" * 70)
    
    # Test 1: Check API status
    print("\n1. Checking API status...")
    try:
        response = requests.get(f"{API_BASE_URL}/status")
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ API Status: {status_data['status']}")
            print(f"   Active scans: {status_data.get('active_scans', 0)}")
        else:
            print(f"❌ API Status check failed: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Cannot connect to API: {e}")
        print("   Make sure the enhanced API server is running:")
        print("   python src/jwt_api_enhanced.py")
        return
    
    # Test 2: Start a scan session
    print("\n2. Starting a scan session...")
    try:
        response = requests.post(f"{API_BASE_URL}/scan/start", json={
            "scan_type": "single",
            "description": "Testing enhanced API functionality"
        })
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data["scan_id"]
            print(f"✅ Scan session created: {scan_id}")
            print(f"   Status: {scan_data['status']}")
        else:
            print(f"❌ Failed to create scan session: {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Error creating scan session: {e}")
        return
    
    # Test 3: Check scan status
    print("\n3. Checking scan status...")
    try:
        response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/status")
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ Scan Status: {status_data['status']}")
            print(f"   Type: {status_data['scan_type']}")
            print(f"   Description: {status_data['description']}")
            print(f"   Has results: {status_data['has_results']}")
        else:
            print(f"❌ Failed to get scan status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting scan status: {e}")
    
    # Test 4: Analyze token with scan ID
    print("\n4. Analyzing JWT token...")
    try:
        response = requests.post(f"{API_BASE_URL}/scan/{scan_id}/analyze", json={
            "token": TEST_TOKEN,
            "secret": "test-secret"
        })
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Analysis completed: {results['status']}")
            print(f"   Scan ID: {results['scan_id']}")
            
            # Check if vulnerabilities were found
            if 'results' in results and 'vulnerabilities' in results['results']:
                vuln_count = len(results['results']['vulnerabilities'])
                print(f"   Vulnerabilities found: {vuln_count}")
        else:
            print(f"❌ Analysis failed: {response.status_code}")
            print(f"   Error: {response.text}")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
    
    # Test 5: Get scan results
    print("\n5. Retrieving scan results...")
    try:
        response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/results")
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Results retrieved successfully")
            print(f"   Scan ID: {results['scan_id']}")
            
            if 'results' in results:
                vuln_count = len(results['results'].get('vulnerabilities', []))
                rec_count = len(results['results'].get('recommendations', []))
                print(f"   Vulnerabilities: {vuln_count}")
                print(f"   Recommendations: {rec_count}")
        else:
            print(f"❌ Failed to get results: {response.status_code}")
    except Exception as e:
        print(f"❌ Error getting results: {e}")
    
    # Test 6: Generate HTML report
    print("\n6. Generating HTML report...")
    try:
        response = requests.get(f"{API_BASE_URL}/scan/{scan_id}/report?format=html")
        if response.status_code == 200:
            filename = f"jwt_scan_report_{scan_id}.html"
            with open(filename, "wb") as f:
                f.write(response.content)
            print(f"✅ HTML report saved: {filename}")
            print(f"   File size: {len(response.content)} bytes")
        else:
            print(f"❌ Failed to generate report: {response.status_code}")
    except Exception as e:
        print(f"❌ Error generating report: {e}")
    
    # Test 7: List all scans
    print("\n7. Listing all scans...")
    try:
        response = requests.get(f"{API_BASE_URL}/scans")
        if response.status_code == 200:
            scans_data = response.json()
            print(f"✅ Total scans: {scans_data['total_scans']}")
            for scan in scans_data['scans']:
                print(f"   - {scan['scan_id'][:8]}... ({scan['status']}) - {scan['scan_type']}")
        else:
            print(f"❌ Failed to list scans: {response.status_code}")
    except Exception as e:
        print(f"❌ Error listing scans: {e}")
    
    # Test 8: Batch analysis with scan ID
    print("\n8. Testing batch analysis...")
    try:
        # Start new scan for batch
        response = requests.post(f"{API_BASE_URL}/scan/start", json={
            "scan_type": "batch",
            "description": "Batch analysis test"
        })
        if response.status_code == 200:
            batch_scan_id = response.json()["scan_id"]
            print(f"✅ Batch scan session created: {batch_scan_id}")
            
            # Perform batch analysis
            response = requests.post(f"{API_BASE_URL}/scan/{batch_scan_id}/batch", json={
                "tokens": [TEST_TOKEN, TEST_TOKEN],  # Same token twice for testing
                "secret": "test-secret"
            })
            if response.status_code == 200:
                batch_results = response.json()
                print(f"✅ Batch analysis completed: {batch_results['status']}")
                print(f"   Tokens processed: {len(batch_results['results'])}")
            else:
                print(f"❌ Batch analysis failed: {response.status_code}")
        else:
            print(f"❌ Failed to create batch scan session: {response.status_code}")
    except Exception as e:
        print(f"❌ Error in batch analysis: {e}")
    
    print("\n" + "=" * 70)
    print("🎉 Enhanced API testing completed!")
    print("\n📋 Summary:")
    print("   - Scan ID management allows tracking multiple scans")
    print("   - Results can be retrieved later using scan ID")
    print("   - HTML reports are generated with scan ID in filename")
    print("   - All scans are listed and can be managed")
    print("\n💡 To start the enhanced API server:")
    print("   python src/jwt_api_enhanced.py")

if __name__ == "__main__":
    test_enhanced_api() 