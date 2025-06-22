#!/usr/bin/env python3
"""
Simple test script to identify scanner issues
"""

import sys
import traceback
import json
import os
from src.core.api_security_scanner import APISecurityScanner
from pathlib import Path

def test_imports():
    """Test all imports"""
    print("Testing imports...")
    
    try:
        import requests
        print("✅ requests imported")
    except Exception as e:
        print(f"❌ requests import failed: {e}")
        return False
    
    try:
        import yaml
        print("✅ yaml imported")
    except Exception as e:
        print(f"❌ yaml import failed: {e}")
        return False
    
    try:
        from debug_config import debug_logger
        print("✅ debug_config imported")
    except Exception as e:
        print(f"❌ debug_config import failed: {e}")
        return False
    
    try:
        from api_security_scanner import APISecurityScanner
        print("✅ APISecurityScanner imported")
    except Exception as e:
        print(f"❌ APISecurityScanner import failed: {e}")
        traceback.print_exc()
        return False
    
    return True

def test_scanner_init():
    """Test scanner initialization"""
    print("\nTesting scanner initialization...")
    
    try:
        from api_security_scanner import APISecurityScanner
        scanner = APISecurityScanner()
        print("✅ Scanner initialized")
        
        # Check if tests are loaded
        tests = scanner.api_tests
        print(f"✅ Loaded {len(tests)} test categories")
        
        return scanner
    except Exception as e:
        print(f"❌ Scanner initialization failed: {e}")
        traceback.print_exc()
        return None

def test_endpoint_scan():
    """Test endpoint scanning"""
    print("\nTesting endpoint scanning...")
    
    scanner = test_scanner_init()
    if not scanner:
        return False
    
    # Create a simple test endpoint
    test_endpoint = {
        'method': 'GET',
        'path': '/test',
        'summary': 'Test endpoint',
        'base_url': 'https://httpbin.org'
    }
    
    try:
        print(f"Testing endpoint: {test_endpoint['method']} {test_endpoint['base_url']}{test_endpoint['path']}")
        result = scanner.scan_single_endpoint(test_endpoint)
        
        print(f"✅ Scan completed")
        print(f"  - Connectivity: {result.get('connectivity', False)}")
        print(f"  - Error: {result.get('error', 'None')}")
        print(f"  - Test categories: {len(result.get('test_results', {}))}")
        print(f"  - Vulnerabilities: {len(result.get('vulnerabilities', []))}")
        
        return True
    except Exception as e:
        print(f"❌ Endpoint scan failed: {e}")
        traceback.print_exc()
        return False

def test_endpoint_extraction():
    print("🔍 Testing Endpoint Extraction")
    print("=" * 30)
    
    # Find a test file
    uploads_dir = "uploads"
    if not os.path.exists(uploads_dir):
        print("❌ Uploads directory not found")
        return
    
    collection_files = [f for f in os.listdir(uploads_dir) if f.endswith('.json')]
    if not collection_files:
        print("❌ No Postman collection files found")
        return
    
    test_file = os.path.join(uploads_dir, collection_files[0])
    print(f"📁 Testing with file: {test_file}")
    
    try:
        # Create scanner
        scanner = APISecurityScanner()
        
        # Read collection file
        with open(test_file, 'r', encoding='utf-8') as f:
            collection_data = json.load(f)
        
        # Extract endpoints
        endpoints = scanner._extract_endpoints_from_postman_collection(collection_data)
        
        print(f"✅ Endpoints extracted: {len(endpoints)}")
        
        if endpoints:
            print("\n📋 Sample endpoints:")
            for i, endpoint in enumerate(endpoints[:5]):
                print(f"  {i+1}. {endpoint.get('method', 'GET')} {endpoint.get('full_url', 'N/A')}")
                print(f"     Description: {endpoint.get('description', 'N/A')}")
                print(f"     Folder: {endpoint.get('folder', 'N/A')}")
                print()
        else:
            print("❌ No endpoints extracted!")
    
    except Exception as e:
        print(f"❌ Test error: {e}")
        traceback.print_exc()

def test_with_uploaded_file():
    """Test scanner with an uploaded file"""
    # Get project root directory (3 levels up from src/examples/)
    project_root = Path(__file__).parent.parent.parent
    uploads_dir = project_root / "uploads"
    
    if not uploads_dir.exists():
        print(f"❌ Uploads directory not found: {uploads_dir}")
        return False
    
    # Find JSON files in uploads directory
    collection_files = [f for f in uploads_dir.iterdir() if f.suffix == '.json']
    
    if not collection_files:
        print("❌ No JSON files found in uploads directory")
        return False
    
    print(f"📁 Found {len(collection_files)} JSON files in uploads directory")
    
    # Test with the first file
    test_file = collection_files[0]
    print(f"🔍 Testing with file: {test_file.name}")

def main():
    """Main test function"""
    print("🧪 Simple API Security Scanner Test")
    print("=" * 40)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed")
        return
    
    # Test scanner initialization
    if not test_scanner_init():
        print("\n❌ Scanner initialization failed")
        return
    
    # Test endpoint scanning
    if not test_endpoint_scan():
        print("\n❌ Endpoint scanning failed")
        return
    
    # Test endpoint extraction
    test_endpoint_extraction()
    
    print("\n✅ All tests passed!")

if __name__ == "__main__":
    main() 