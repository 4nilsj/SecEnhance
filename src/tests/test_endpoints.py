#!/usr/bin/env python3
import json
import os
from api_security_scanner_updated import APISecurityScanner

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
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_endpoint_extraction() 