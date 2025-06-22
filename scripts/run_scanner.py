#!/usr/bin/env python3
"""
API Security Scanner - Run Script
Simple script to demonstrate how to use the API Security Scanner
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from src.core.api_security_scanner import APISecurityScanner

def main():
    print("🔍 API Security Scanner - Run Script")
    print("=" * 50)
    
    # Initialize scanner
    scanner = APISecurityScanner()
    
    # Example 1: Public API scan (no authentication needed)
    print("\n📋 Example 1: Scanning Public API")
    print("-" * 30)
    
    try:
        results = scanner.scan_from_swagger_url(
            "https://petstore.swagger.io/v2/swagger.json",
            "https://petstore.swagger.io/v2"
        )
        
        if 'error' not in results:
            # Generate reports
            report_file = scanner.generate_api_security_report(results)
            owasp_report = scanner.generate_owasp_report(results, 'html')
            
            print(f"✅ Public scan completed successfully!")
            print(f"📊 Endpoints found: {results['endpoints_found']}")
            print(f"📄 Standard report: {report_file}")
            print(f"📄 OWASP report: {owasp_report}")
        else:
            print(f"❌ Public scan failed: {results['error']}")
            
    except Exception as e:
        print(f"❌ Error during public scan: {e}")
    
    # Example 2: Authenticated API scan
    print("\n🔐 Example 2: Authenticated API Scan")
    print("-" * 30)
    
    # Check if authentication credentials are provided
    api_token = os.getenv('API_TOKEN')
    api_key = os.getenv('API_KEY')
    
    if api_token or api_key:
        print("🔐 Using provided authentication credentials...")
        
        # Set up authentication
        auth_config = {}
        if api_token:
            auth_config['type'] = 'bearer'
            auth_config['token'] = api_token
        if api_key:
            auth_config['headers'] = {'X-API-Key': api_key}
        
        scanner.set_auth_config(auth_config)
        
        # Replace with your actual API URL
        api_url = os.getenv('API_URL', 'https://api.example.com')
        swagger_url = os.getenv('SWAGGER_URL', f'{api_url}/swagger.json')
        
        try:
            results = scanner.scan_from_swagger_url(swagger_url, api_url)
            
            if 'error' not in results:
                report_file = scanner.generate_api_security_report(results)
                owasp_report = scanner.generate_owasp_report(results, 'html')
                
                print(f"✅ Authenticated scan completed successfully!")
                print(f"📊 Endpoints found: {results['endpoints_found']}")
                print(f"🔐 Auth type: {results.get('auth_config', {}).get('type', 'none')}")
                print(f"📄 Standard report: {report_file}")
                print(f"📄 OWASP report: {owasp_report}")
            else:
                print(f"❌ Authenticated scan failed: {results['error']}")
                
        except Exception as e:
            print(f"❌ Error during authenticated scan: {e}")
    else:
        print("⚠️ No authentication credentials provided.")
        print("   Set API_TOKEN and/or API_KEY environment variables for authenticated scanning.")
        print("   Example: API_TOKEN=your_token API_KEY=your_key python run_scanner.py")
    
    # Example 3: Collection upload (if file exists)
    print("\n📁 Example 3: Collection Upload")
    print("-" * 30)
    
    # Check for common collection files
    collection_files = [
        "postman_collection.json",
        "insomnia_collection.json", 
        "api_collection.json",
        "network_traffic.har",
        "curl_commands.txt"
    ]
    
    found_collection = None
    for file in collection_files:
        if os.path.exists(file):
            found_collection = file
            break
    
    if found_collection:
        print(f"📂 Found collection file: {found_collection}")
        
        try:
            results = scanner.upload_and_scan_collection(found_collection)
            
            if 'error' not in results:
                print(f"✅ Collection scan completed successfully!")
                print(f"📊 Format: {results['collection_format']}")
                print(f"📊 Endpoints found: {results['endpoints_found']}")
                print(f"📄 Reports: {results['reports']['standard_report']}, {results['reports']['owasp_report']}")
            else:
                print(f"❌ Collection scan failed: {results['error']}")
                
        except Exception as e:
            print(f"❌ Error during collection scan: {e}")
    else:
        print("⚠️ No collection files found.")
        print("   Supported formats: .json (Postman/Insomnia), .har, .txt (curl)")
        print("   Place collection files in the same directory as this script.")
    
    # Example 4: Authentication management
    print("\n🔧 Example 4: Authentication Management")
    print("-" * 30)
    
    # Show current authentication status
    auth_info = scanner.get_auth_info()
    print(f"🔐 Current auth type: {auth_info['type']}")
    
    # Demonstrate different auth methods
    print("\n🔧 Available authentication methods:")
    print("   • scanner.set_bearer_token('your_token')")
    print("   • scanner.set_api_key('X-API-Key', 'your_key')")
    print("   • scanner.set_basic_auth('username', 'password')")
    print("   • scanner.set_oauth2_token('your_oauth2_token')")
    print("   • scanner.add_auth_header('X-Custom', 'value')")
    print("   • scanner.clear_auth()")
    
    print("\n🎉 Scanner demonstration completed!")
    print("\n📚 Next steps:")
    print("   1. Review generated reports")
    print("   2. Check OWASP API Top 10 compliance")
    print("   3. Address identified vulnerabilities")
    print("   4. Integrate with your CI/CD pipeline")

if __name__ == "__main__":
    main() 