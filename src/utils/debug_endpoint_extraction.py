#!/usr/bin/env python3
"""
Debug Endpoint Extraction
Test and debug endpoint extraction from Postman collections
"""

import json
import os
from api_security_scanner_updated import APISecurityScanner

def debug_endpoint_extraction():
    """Debug endpoint extraction from Postman collections"""
    print("🔍 Debugging Endpoint Extraction")
    print("=" * 50)
    
    # Check for uploaded files
    uploads_dir = "uploads"
    if not os.path.exists(uploads_dir):
        print("❌ Uploads directory not found")
        return
    
    # List all uploaded files
    uploaded_files = [f for f in os.listdir(uploads_dir) if f.endswith('.json')]
    print(f"📁 Found {len(uploaded_files)} uploaded files:")
    
    for file in uploaded_files:
        print(f"   - {file}")
    
    if not uploaded_files:
        print("❌ No uploaded files found")
        return
    
    # Test with the first uploaded file
    test_file = os.path.join(uploads_dir, uploaded_files[0])
    print(f"\n🔍 Testing with file: {test_file}")
    
    try:
        # Read the collection file
        with open(test_file, 'r', encoding='utf-8') as f:
            collection_data = json.load(f)
        
        print(f"✅ File loaded successfully")
        print(f"📊 File size: {os.path.getsize(test_file)} bytes")
        
        # Check collection structure
        print(f"\n📋 Collection Structure:")
        print(f"   - Has 'info': {'info' in collection_data}")
        print(f"   - Has 'item': {'item' in collection_data}")
        print(f"   - Has 'variable': {'variable' in collection_data}")
        
        if 'info' in collection_data:
            info = collection_data['info']
            print(f"   - Collection name: {info.get('name', 'Unknown')}")
            print(f"   - Collection description: {info.get('description', 'None')}")
        
        if 'variable' in collection_data:
            variables = collection_data['variable']
            print(f"   - Variables count: {len(variables)}")
            for var in variables[:5]:  # Show first 5 variables
                print(f"     - {var.get('key', 'Unknown')}: {var.get('value', 'None')}")
        
        if 'item' in collection_data:
            items = collection_data['item']
            print(f"   - Root items count: {len(items)}")
            
            # Count total requests and folders
            total_requests = 0
            total_folders = 0
            
            def count_items(items_list, level=0):
                nonlocal total_requests, total_folders
                for item in items_list:
                    if 'request' in item:
                        total_requests += 1
                        if level == 0:
                            print(f"     - Request: {item.get('name', 'Unknown')}")
                    elif 'item' in item:
                        total_folders += 1
                        folder_name = item.get('name', 'Unknown Folder')
                        print(f"     - Folder: {folder_name} (level {level})")
                        count_items(item['item'], level + 1)
            
            count_items(items)
            print(f"   - Total requests found: {total_requests}")
            print(f"   - Total folders found: {total_folders}")
        
        # Test endpoint extraction
        print(f"\n🔍 Testing Endpoint Extraction:")
        scanner = APISecurityScanner(enable_optimization=False)
        
        # Test the extraction method directly
        endpoints = scanner._extract_endpoints_from_postman_collection(collection_data)
        
        print(f"✅ Endpoints extracted: {len(endpoints)}")
        
        if endpoints:
            print(f"\n📋 Sample Endpoints:")
            for i, endpoint in enumerate(endpoints[:10]):  # Show first 10
                print(f"   {i+1}. {endpoint.get('method', 'GET')} {endpoint.get('path', 'N/A')}")
                print(f"      Base URL: {endpoint.get('base_url', 'N/A')}")
                print(f"      Description: {endpoint.get('description', 'N/A')}")
                print(f"      Folder: {endpoint.get('folder', 'N/A')}")
                print()
        else:
            print("❌ No endpoints extracted!")
            
            # Debug why no endpoints were found
            print(f"\n🔍 Debugging why no endpoints were found:")
            
            def debug_items(items_list, level=0):
                for i, item in enumerate(items_list):
                    print(f"   {'  ' * level}Item {i}: {item.get('name', 'Unknown')}")
                    
                    if 'request' in item:
                        request = item['request']
                        print(f"   {'  ' * level}  - Has request")
                        print(f"   {'  ' * level}  - Method: {request.get('method', 'N/A')}")
                        
                        url = request.get('url', {})
                        if isinstance(url, str):
                            print(f"   {'  ' * level}  - URL (string): {url}")
                        elif isinstance(url, dict):
                            print(f"   {'  ' * level}  - URL (dict): {url}")
                            print(f"   {'  ' * level}  - Path: {url.get('path', 'N/A')}")
                            print(f"   {'  ' * level}  - Raw: {url.get('raw', 'N/A')}")
                        else:
                            print(f"   {'  ' * level}  - URL (other): {type(url)}")
                    
                    elif 'item' in item:
                        print(f"   {'  ' * level}  - Has sub-items: {len(item['item'])}")
                        debug_items(item['item'], level + 1)
                    else:
                        print(f"   {'  ' * level}  - Unknown item type")
            
            if 'item' in collection_data:
                debug_items(collection_data['item'])
        
        # Test the full scan method
        print(f"\n🔍 Testing Full Scan Method:")
        try:
            result = scanner.upload_and_scan_collection(test_file)
            
            if 'error' in result:
                print(f"❌ Scan failed: {result['error']}")
            else:
                print(f"✅ Scan completed successfully")
                print(f"   - Endpoints scanned: {result.get('scanned_endpoints', 0)}")
                print(f"   - Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
                print(f"   - Scan duration: {result.get('scan_info', {}).get('duration', 0):.2f}s")
        except Exception as e:
            print(f"❌ Scan error: {e}")
            import traceback
            traceback.print_exc()
        
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        import traceback
        traceback.print_exc()

def test_simple_endpoints():
    """Test with simple endpoints to verify scanner works"""
    print(f"\n🔍 Testing Simple Endpoints:")
    print("=" * 30)
    
    scanner = APISecurityScanner(enable_optimization=False)
    
    simple_endpoints = [
        {
            'path': '/api/users',
            'method': 'GET',
            'base_url': 'http://localhost:5001',
            'description': 'Test endpoint'
        }
    ]
    
    try:
        result = scanner.scan_api_endpoints_optimized(simple_endpoints)
        print(f"✅ Simple scan completed")
        print(f"   - Endpoints scanned: {result.get('scanned_endpoints', 0)}")
        print(f"   - Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
    except Exception as e:
        print(f"❌ Simple scan failed: {e}")

if __name__ == "__main__":
    debug_endpoint_extraction()
    test_simple_endpoints() 