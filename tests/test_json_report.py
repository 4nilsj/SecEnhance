#!/usr/bin/env python3
"""
Test script to verify JSON report generation with endpoints list
"""

from src.core.api_security_scanner import APISecurityScanner
import json

def test_json_report():
    print("🧪 Testing JSON report generation with endpoints list...")
    
    # Create scanner
    scanner = APISecurityScanner()
    
    # Test endpoints
    test_endpoints = [
        {
            'url': 'https://httpbin.org/get',
            'method': 'GET',
            'name': 'Test GET Endpoint'
        }
    ]
    
    print(f"📋 Scanning {len(test_endpoints)} endpoint...")
    
    # Run scan
    results = scanner.scan_api_endpoints(test_endpoints)
    
    print("✅ Scan completed!")
    print(f"📊 Endpoints scanned: {len(results.get('endpoint_results', []))}")
    
    # Check scan results structure
    print(f"\n🔍 Scan results structure:")
    print(f"   - Keys in results: {list(results.keys())}")
    print(f"   - endpoint_results present: {'endpoint_results' in results}")
    print(f"   - endpoint_results length: {len(results.get('endpoint_results', []))}")
    
    # Generate JSON report
    print("\n📄 Generating JSON report...")
    json_report_path = scanner.generate_api_security_report(results, 'json')
    print(f"📄 JSON report: {json_report_path}")
    
    # Read and check the JSON report
    try:
        with open(json_report_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        print(f"\n🔍 JSON report structure:")
        print(f"   - Keys in JSON: {list(json_data.keys())}")
        print(f"   - endpoint_results in JSON: {'endpoint_results' in json_data}")
        print(f"   - endpoint_results length in JSON: {len(json_data.get('endpoint_results', []))}")
        
        if 'endpoint_results' in json_data:
            print(f"\n📋 Endpoints in JSON report:")
            for i, endpoint_result in enumerate(json_data['endpoint_results'], 1):
                endpoint = endpoint_result.get('endpoint', {})
                url = endpoint.get('url', 'N/A')
                method = endpoint.get('method', 'GET')
                name = endpoint.get('name', 'N/A')
                scan_status = endpoint_result.get('scan_status', 'unknown')
                
                print(f"   {i}. {method} {url} ({name}) - Status: {scan_status}")
        else:
            print("❌ endpoint_results not found in JSON report!")
            
    except Exception as e:
        print(f"❌ Error reading JSON report: {e}")
    
    print("\n✅ JSON report test completed!")

if __name__ == "__main__":
    test_json_report() 