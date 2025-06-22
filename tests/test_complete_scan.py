#!/usr/bin/env python3
"""
Complete API Security Scanner Test
Tests all major functionality of the API Security Scanner
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path (updated for tests/ directory location)
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from src.core.api_security_scanner import APISecurityScanner

def test_complete_scan():
    """Test the complete scanning process"""
    print("🧪 Testing complete scanning process...")
    
    # Create scanner
    scanner = APISecurityScanner()
    
    # Test endpoints
    test_endpoints = [
        {
            'url': 'https://httpbin.org/get',
            'method': 'GET',
            'name': 'Test GET endpoint',
            'description': 'Testing GET request'
        },
        {
            'url': 'https://httpbin.org/post',
            'method': 'POST',
            'name': 'Test POST endpoint',
            'description': 'Testing POST request'
        },
        {
            'url': 'https://httpbin.org/status/404',
            'method': 'GET',
            'name': 'Test 404 endpoint',
            'description': 'Testing 404 response'
        }
    ]
    
    print(f"📡 Testing {len(test_endpoints)} endpoints...")
    
    # Run scan
    results = scanner.scan_api_endpoints(test_endpoints)
    
    # Verify results structure
    required_fields = [
        'scan_id', 'scan_start_time', 'scan_end_time', 'scan_type',
        'endpoints_found', 'endpoints_scanned', 'vulnerabilities_found',
        'scan_duration', 'error_summary', 'endpoint_results', 'scan_status'
    ]
    
    print("\n📊 Scan Results:")
    print(f"  Scan ID: {results.get('scan_id', 'N/A')}")
    print(f"  Status: {results.get('scan_status', 'N/A')}")
    print(f"  Endpoints Found: {results.get('endpoints_found', 0)}")
    print(f"  Endpoints Scanned: {results.get('endpoints_scanned', 0)}")
    print(f"  Vulnerabilities Found: {len(results.get('vulnerabilities_found', []))}")
    print(f"  Scan Duration: {results.get('scan_duration', 0):.2f}s")
    print(f"  Errors: {len(results.get('error_summary', []))}")
    
    # Check for required fields
    missing_fields = [field for field in required_fields if field not in results]
    if missing_fields:
        print(f"❌ Missing required fields: {missing_fields}")
        return False
    
    # Generate reports
    print("\n📄 Generating reports...")
    try:
        json_report = scanner.generate_api_security_report(results)
        html_report = scanner.generate_owasp_report(results, 'html')
        
        print(f"✅ JSON Report: {json_report}")
        print(f"✅ HTML Report: {html_report}")
        
        # Check if reports exist
        if os.path.exists(json_report):
            print("✅ JSON report file created successfully")
        else:
            print("❌ JSON report file not found")
            return False
            
        if os.path.exists(html_report):
            print("✅ HTML report file created successfully")
        else:
            print("❌ HTML report file not found")
            return False
            
    except Exception as e:
        print(f"❌ Error generating reports: {e}")
        return False
    
    print("\n✅ Complete scanning process test passed!")
    return True

def test_collection_scan():
    """Test collection scanning"""
    print("\n🧪 Testing collection scanning...")
    
    # Check if we have a test collection
    test_collection = Path(__file__).parent.parent / 'data' / 'test_collection.json'
    
    if not test_collection.exists():
        print("⚠️  No test collection found, creating a simple one...")
        
        # Create a simple test collection
        test_data = {
            "info": {
                "name": "Test Collection",
                "description": "Test collection for scanning"
            },
            "item": [
                {
                    "name": "Test Request",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "https://httpbin.org/get"
                        }
                    }
                }
            ]
        }
        
        test_collection.parent.mkdir(exist_ok=True)
        import json
        with open(test_collection, 'w') as f:
            json.dump(test_data, f, indent=2)
    
    # Test collection scanning
    scanner = APISecurityScanner()
    
    try:
        results = scanner.upload_and_scan_collection(str(test_collection))
        
        print(f"📊 Collection Scan Results:")
        print(f"  Status: {results.get('status', 'N/A')}")
        print(f"  Endpoints Found: {results.get('endpoints_found', 0)}")
        
        if 'error' in results:
            print(f"❌ Collection scan failed: {results['error']}")
            return False
        else:
            print("✅ Collection scan completed successfully")
            return True
            
    except Exception as e:
        print(f"❌ Error in collection scan: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting API Security Scanner Complete Test")
    print("=" * 50)
    
    # Test 1: Complete scanning process
    test1_passed = test_complete_scan()
    
    # Test 2: Collection scanning
    test2_passed = test_collection_scan()
    
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    print(f"  Complete Scan Test: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"  Collection Scan Test: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 All tests passed! The scanning process is working correctly.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Please check the issues above.")
        sys.exit(1) 