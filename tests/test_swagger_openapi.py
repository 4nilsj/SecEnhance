#!/usr/bin/env python3
"""
Test script for Swagger/OpenAPI integration
Tests the scanner's ability to parse and scan APIs from Swagger/OpenAPI specifications
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path (updated for tests/ directory location)
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from src.core.api_security_scanner import APISecurityScanner
import json

def test_swagger_support():
    """Test Swagger/OpenAPI scanning capabilities"""
    print("🔍 Testing Swagger and OpenAPI Support")
    print("=" * 50)
    
    # Initialize scanner
    scanner = APISecurityScanner()
    print("✅ Scanner initialized")
    
    # Test 1: Swagger 2.0 URL
    print("\n1. Testing Swagger 2.0 URL...")
    swagger_urls = [
        "https://petstore.swagger.io/v2/swagger.json",  # Petstore Swagger 2.0
        "https://httpbin.org/json",  # Simple JSON API
    ]
    
    for url in swagger_urls:
        print(f"   Testing: {url}")
        try:
            results = scanner.scan_from_swagger_url(url, base_url="https://petstore.swagger.io")
            print(f"   Status: {results.get('status', 'unknown')}")
            print(f"   Endpoints found: {results.get('endpoints_found', 0)}")
            if 'error' in results:
                print(f"   Error: {results['error']}")
            else:
                print(f"   ✅ Successfully parsed Swagger specification")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Test 2: Create a sample OpenAPI 3.0 specification
    print("\n2. Testing OpenAPI 3.0 specification...")
    sample_openapi = {
        "openapi": "3.0.0",
        "info": {
            "title": "Sample API",
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
                    "operationId": "getUsers",
                    "responses": {
                        "200": {
                            "description": "Success"
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "operationId": "createUser",
                    "responses": {
                        "201": {
                            "description": "Created"
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "operationId": "getUserById",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {
                                "type": "integer"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success"
                        }
                    }
                }
            }
        }
    }
    
    # Save sample OpenAPI spec to file
    sample_file = "sample_openapi.json"
    with open(sample_file, 'w') as f:
        json.dump(sample_openapi, f, indent=2)
    
    print(f"   Created sample OpenAPI spec: {sample_file}")
    
    try:
        # Test parsing the OpenAPI spec
        endpoints = scanner.parse_swagger_spec(sample_openapi, base_url="https://api.example.com")
        print(f"   Parsed {len(endpoints)} endpoints from OpenAPI spec")
        
        for endpoint in endpoints:
            print(f"     - {endpoint['method']} {endpoint['url']}")
        
        # Test scanning the endpoints
        print("\n3. Testing endpoint scanning...")
        scan_results = scanner.scan_api_endpoints(endpoints)
        print(f"   Scan completed: {scan_results.get('scan_status', 'unknown')}")
        print(f"   Endpoints scanned: {scan_results.get('endpoints_scanned', 0)}")
        print(f"   Vulnerabilities found: {len(scan_results.get('vulnerabilities_found', []))}")
        
        # Generate report
        print("\n4. Generating report...")
        report_path = scanner.generate_api_security_report(scan_results, 'json')
        print(f"   Report saved to: {report_path}")
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Clean up
    if os.path.exists(sample_file):
        os.remove(sample_file)
    
    print("\n🎉 Swagger/OpenAPI testing completed!")

def show_supported_formats():
    """Show supported API specification formats"""
    print("\n📋 Supported API Specification Formats:")
    print("=" * 40)
    
    formats = [
        {
            "format": "Swagger 2.0",
            "description": "OpenAPI 2.0 specification",
            "file_extension": ".json, .yaml",
            "url_example": "https://api.example.com/swagger.json",
            "supported": "✅ Yes"
        },
        {
            "format": "OpenAPI 3.0",
            "description": "OpenAPI 3.0 specification",
            "file_extension": ".json, .yaml",
            "url_example": "https://api.example.com/openapi.json",
            "supported": "✅ Yes"
        },
        {
            "format": "OpenAPI 3.1",
            "description": "OpenAPI 3.1 specification",
            "file_extension": ".json, .yaml",
            "url_example": "https://api.example.com/openapi.json",
            "supported": "✅ Yes"
        },
        {
            "format": "Postman Collection",
            "description": "Postman collection export",
            "file_extension": ".json",
            "url_example": "N/A (file upload only)",
            "supported": "✅ Yes"
        },
        {
            "format": "Insomnia Collection",
            "description": "Insomnia collection export",
            "file_extension": ".json",
            "url_example": "N/A (file upload only)",
            "supported": "✅ Yes"
        }
    ]
    
    for fmt in formats:
        print(f"\n🔹 {fmt['format']}")
        print(f"   Description: {fmt['description']}")
        print(f"   File Extensions: {fmt['file_extension']}")
        print(f"   URL Example: {fmt['url_example']}")
        print(f"   Supported: {fmt['supported']}")

def main():
    """Main function"""
    print("🚀 API Security Scanner - Swagger/OpenAPI Support")
    print("=" * 60)
    
    show_supported_formats()
    test_swagger_support()
    
    print("\n💡 Usage Examples:")
    print("   Web UI: python main.py web")
    print("   Then use the 'Swagger URL' option in the web interface")
    print("   Or upload OpenAPI JSON/YAML files directly")

if __name__ == "__main__":
    main() 