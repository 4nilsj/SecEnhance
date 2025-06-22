#!/usr/bin/env python3
import json
import os
from src.core.api_security_scanner import APISecurityScanner
from pathlib import Path

def test_endpoint_extraction():
    """Test endpoint extraction from uploaded files"""
    # Get project root directory (3 levels up from src/tests/)
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