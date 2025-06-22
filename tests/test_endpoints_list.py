#!/usr/bin/env python3
"""
Test script to verify endpoints list functionality in reports
"""

from src.core.api_security_scanner import APISecurityScanner
import time
import json

def test_endpoints_list():
    print("🧪 Testing endpoints list functionality...")
    
    # Create scanner
    scanner = APISecurityScanner()
    
    # Test endpoints
    test_endpoints = [
        {
            'url': 'https://httpbin.org/get',
            'method': 'GET',
            'name': 'Test GET Endpoint'
        },
        {
            'url': 'https://httpbin.org/post',
            'method': 'POST',
            'name': 'Test POST Endpoint'
        },
        {
            'url': 'https://httpbin.org/put',
            'method': 'PUT',
            'name': 'Test PUT Endpoint'
        }
    ]
    
    print(f"📋 Scanning {len(test_endpoints)} endpoints...")
    
    # Run scan
    results = scanner.scan_api_endpoints(test_endpoints)
    
    print("✅ Scan completed!")
    print(f"📊 Endpoints scanned: {len(results.get('endpoint_results', []))}")
    
    # Check scan results structure
    print(f"\n🔍 Scan results structure:")
    print(f"   - Keys in results: {list(results.keys())}")
    print(f"   - endpoint_results present: {'endpoint_results' in results}")
    print(f"   - endpoint_results type: {type(results.get('endpoint_results', None))}")
    print(f"   - endpoint_results length: {len(results.get('endpoint_results', []))}")
    
    if 'endpoint_results' in results:
        print(f"\n📋 Endpoints list verification:")
        print(f"   - Total endpoints in results: {len(results['endpoint_results'])}")
        
        for i, endpoint_result in enumerate(results['endpoint_results'], 1):
            endpoint = endpoint_result.get('endpoint', {})
            url = endpoint.get('url', 'N/A')
            method = endpoint.get('method', 'GET')
            name = endpoint.get('name', 'N/A')
            scan_status = endpoint_result.get('scan_status', 'unknown')
            
            print(f"   {i}. {method} {url} ({name}) - Status: {scan_status}")
    
    # Generate reports
    print("\n📄 Generating reports with endpoints list...")
    
    # JSON report
    json_report = scanner.generate_api_security_report(results, 'json')
    print(f"📄 JSON report: {json_report}")
    
    # Check if endpoint_results is in the JSON report
    try:
        with open(json_report, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        print(f"   - endpoint_results in JSON: {'endpoint_results' in json_data}")
        print(f"   - endpoint_results length in JSON: {len(json_data.get('endpoint_results', []))}")
    except Exception as e:
        print(f"   - Error reading JSON report: {e}")
    
    # HTML report
    html_report = scanner.generate_owasp_report(results, 'html')
    print(f"📄 HTML report: {html_report}")
    
    # Check if endpoints list is in HTML report
    try:
        with open(html_report, 'r', encoding='utf-8') as f:
            html_content = f.read()
        print(f"   - 'Endpoints Scanned' in HTML: {'Endpoints Scanned' in html_content}")
        print(f"   - 'endpoints-table' in HTML: {'endpoints-table' in html_content}")
    except Exception as e:
        print(f"   - Error reading HTML report: {e}")
    
    print("\n✅ Endpoints list functionality test completed!")
    print("📖 Check the generated reports to see the endpoints list section.")

if __name__ == "__main__":
    test_endpoints_list() 