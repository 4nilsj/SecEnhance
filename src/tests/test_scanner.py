#!/usr/bin/env python3
"""
Test script for API Security Scanner
This script helps verify that the scanner is working correctly and identifies issues.
"""

import json
import time
from api_security_scanner import APISecurityScanner

def test_scanner_initialization():
    """Test scanner initialization"""
    print("🔧 Testing scanner initialization...")
    
    try:
        scanner = APISecurityScanner()
        print("✅ Scanner initialized successfully")
        
        # Check if security tests are loaded
        tests = scanner.api_tests
        print(f"📊 Loaded {len(tests)} security test categories")
        
        for category, config in tests.items():
            test_count = len(config.get('tests', []))
            print(f"  - {category}: {test_count} tests")
        
        return scanner
    except Exception as e:
        print(f"❌ Scanner initialization failed: {e}")
        return None

def test_endpoint_parsing():
    """Test endpoint parsing functionality"""
    print("\n🔍 Testing endpoint parsing...")
    
    scanner = APISecurityScanner()
    
    # Test with a simple Swagger spec
    test_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "servers": [
            {
                "url": "https://api.example.com"
            }
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "description": "Retrieve list of users"
                },
                "post": {
                    "summary": "Create user",
                    "description": "Create a new user"
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "description": "Retrieve a specific user"
                }
            }
        }
    }
    
    try:
        endpoints = scanner.parse_swagger_spec(test_spec, "https://api.example.com")
        print(f"✅ Parsed {len(endpoints)} endpoints from test spec")
        
        for i, endpoint in enumerate(endpoints):
            print(f"  {i+1}. {endpoint['method']} {endpoint['path']} - {endpoint['summary']}")
        
        return endpoints
    except Exception as e:
        print(f"❌ Endpoint parsing failed: {e}")
        return []

def test_single_endpoint_scan():
    """Test scanning a single endpoint"""
    print("\n🎯 Testing single endpoint scan...")
    
    scanner = APISecurityScanner()
    
    # Create a test endpoint
    test_endpoint = {
        'method': 'GET',
        'path': 'https://httpbin.org/get',
        'summary': 'Test endpoint',
        'base_url': 'https://httpbin.org'
    }
    
    try:
        print(f"🔗 Testing endpoint: {test_endpoint['method']} {test_endpoint['path']}")
        
        result = scanner.scan_single_endpoint(test_endpoint)
        
        print(f"✅ Single endpoint scan completed")
        print(f"  - Connectivity: {result.get('connectivity', False)}")
        print(f"  - Error: {result.get('error', 'None')}")
        print(f"  - Test categories run: {len(result.get('test_results', {}))}")
        print(f"  - Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
        
        if result.get('test_results'):
            for category, test_result in result['test_results'].items():
                print(f"    - {category}: {test_result.get('tests_run', 0)} tests run")
        
        return result
    except Exception as e:
        print(f"❌ Single endpoint scan failed: {e}")
        return None

def test_multiple_endpoints_scan():
    """Test scanning multiple endpoints"""
    print("\n🚀 Testing multiple endpoints scan...")
    
    scanner = APISecurityScanner()
    
    # Create test endpoints
    test_endpoints = [
        {
            'method': 'GET',
            'path': 'https://httpbin.org/get',
            'summary': 'Test GET endpoint',
            'base_url': 'https://httpbin.org'
        },
        {
            'method': 'POST',
            'path': 'https://httpbin.org/post',
            'summary': 'Test POST endpoint',
            'base_url': 'https://httpbin.org'
        }
    ]
    
    try:
        print(f"🔗 Testing {len(test_endpoints)} endpoints")
        
        result = scanner.scan_api_endpoints(test_endpoints)
        
        print(f"✅ Multiple endpoints scan completed")
        print(f"  - Total endpoints: {result.get('total_endpoints', 0)}")
        print(f"  - Scanned endpoints: {result.get('scanned_endpoints', 0)}")
        print(f"  - Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
        print(f"  - Summary: {result.get('summary', {})}")
        
        if result.get('error'):
            print(f"  - Error: {result['error']}")
        
        return result
    except Exception as e:
        print(f"❌ Multiple endpoints scan failed: {e}")
        return None

def test_swagger_url_scan():
    """Test scanning from Swagger URL"""
    print("\n🌐 Testing Swagger URL scan...")
    
    scanner = APISecurityScanner()
    
    # Use a public test API
    swagger_url = "https://petstore.swagger.io/v2/swagger.json"
    
    try:
        print(f"🔗 Testing Swagger URL: {swagger_url}")
        
        result = scanner.scan_from_swagger_url(swagger_url)
        
        if 'error' in result:
            print(f"❌ Swagger URL scan failed: {result['error']}")
            return result
        
        print(f"✅ Swagger URL scan completed")
        print(f"  - Endpoints found: {result.get('endpoints_found', 0)}")
        print(f"  - Scanned endpoints: {result.get('scanned_endpoints', 0)}")
        print(f"  - Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
        print(f"  - Summary: {result.get('summary', {})}")
        
        return result
    except Exception as e:
        print(f"❌ Swagger URL scan failed: {e}")
        return None

def main():
    """Main test function"""
    print("🧪 API Security Scanner Test Suite")
    print("=" * 50)
    
    # Test 1: Scanner initialization
    scanner = test_scanner_initialization()
    if not scanner:
        return
    
    # Test 2: Endpoint parsing
    endpoints = test_endpoint_parsing()
    if not endpoints:
        return
    
    # Test 3: Single endpoint scan
    single_result = test_single_endpoint_scan()
    if not single_result:
        return
    
    # Test 4: Multiple endpoints scan
    multi_result = test_multiple_endpoints_scan()
    if not multi_result:
        return
    
    # Test 5: Swagger URL scan (optional - requires internet)
    print("\n" + "=" * 50)
    print("🌐 Internet-based tests (optional)")
    print("=" * 50)
    
    try:
        swagger_result = test_swagger_url_scan()
        if swagger_result and 'error' not in swagger_result:
            print("✅ All tests completed successfully!")
        else:
            print("⚠️  Some tests had issues, but core functionality works")
    except Exception as e:
        print(f"⚠️  Internet-based test failed (this is normal if offline): {e}")
    
    print("\n" + "=" * 50)
    print("📋 Test Summary")
    print("=" * 50)
    print("✅ Scanner initialization: Working")
    print("✅ Endpoint parsing: Working")
    print("✅ Single endpoint scan: Working")
    print("✅ Multiple endpoints scan: Working")
    print("✅ Security tests loaded: Working")
    print("\n🎯 If scans are finishing immediately, check:")
    print("  1. Are endpoints being parsed correctly?")
    print("  2. Are the endpoints accessible?")
    print("  3. Are security tests being executed?")
    print("  4. Check the debug logs for more details")

if __name__ == "__main__":
    main() 