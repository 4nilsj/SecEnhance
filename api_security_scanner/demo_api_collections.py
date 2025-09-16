#!/usr/bin/env python3
"""
Simple demonstration script for testing API Security Scanner with API collections.
Shows how to scan Postman collections, OpenAPI specs, and curl commands.
"""

import os
import sys
import subprocess
from pathlib import Path

def run_scanner_demo():
    """Run demonstration of the API Security Scanner with different collection types."""
    
    print("🔍 API Security Scanner - Collection Demo")
    print("=" * 60)
    print("This demo shows how to scan different types of API collections:")
    print("• Postman Collections")
    print("• OpenAPI/Swagger Specifications") 
    print("• Curl Commands")
    print("=" * 60)
    
    # Get the project directory
    project_dir = Path(__file__).parent
    examples_dir = project_dir / "examples"
    reports_dir = project_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    # Demo 1: Scan Postman Collection
    print("\n📋 Demo 1: Scanning Postman Collection")
    print("-" * 40)
    postman_file = examples_dir / "sample_postman_collection.json"
    if postman_file.exists():
        print(f"Scanning: {postman_file.name}")
        cmd = [
            sys.executable, "-m", "api_security_scanner.cli.main", "scan",
            "--file", str(postman_file),
            "--no-zap",  # Skip ZAP for faster demo
            "--no-progress"
        ]
        print(f"Command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=120)
            if result.returncode == 0:
                print("✅ Postman collection scan completed successfully!")
            else:
                print(f"❌ Postman collection scan failed (exit code: {result.returncode})")
        except subprocess.TimeoutExpired:
            print("⏰ Postman collection scan timed out")
        except Exception as e:
            print(f"❌ Error: {e}")
    else:
        print("⚠️  Postman collection file not found")
    
    # Demo 2: Scan OpenAPI Specification
    print("\n📋 Demo 2: Scanning OpenAPI Specification")
    print("-" * 40)
    openapi_file = examples_dir / "sample_openapi.yaml"
    if openapi_file.exists():
        print(f"Scanning: {openapi_file.name}")
        cmd = [
            sys.executable, "-m", "api_security_scanner.cli.main", "scan",
            "--file", str(openapi_file),
            "--no-zap",  # Skip ZAP for faster demo
            "--no-progress"
        ]
        print(f"Command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=120)
            if result.returncode == 0:
                print("✅ OpenAPI specification scan completed successfully!")
            else:
                print(f"❌ OpenAPI specification scan failed (exit code: {result.returncode})")
        except subprocess.TimeoutExpired:
            print("⏰ OpenAPI specification scan timed out")
        except Exception as e:
            print(f"❌ Error: {e}")
    else:
        print("⚠️  OpenAPI specification file not found")
    
    # Demo 3: Scan Curl Command
    print("\n📋 Demo 3: Scanning Curl Command")
    print("-" * 40)
    curl_command = 'curl -X GET "https://httpbin.org/get" -H "Accept: application/json"'
    print(f"Scanning curl command: {curl_command}")
    cmd = [
        sys.executable, "-m", "api_security_scanner.cli.main", "scan",
        "--curl", curl_command,
        "--no-zap",  # Skip ZAP for faster demo
        "--no-progress"
    ]
    print(f"Command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=120)
        if result.returncode == 0:
            print("✅ Curl command scan completed successfully!")
        else:
            print(f"❌ Curl command scan failed (exit code: {result.returncode})")
    except subprocess.TimeoutExpired:
        print("⏰ Curl command scan timed out")
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Demo 4: Scan with Authentication
    print("\n📋 Demo 4: Scanning with Authentication")
    print("-" * 40)
    if postman_file.exists():
        print(f"Scanning with auth: {postman_file.name}")
        cmd = [
            sys.executable, "-m", "api_security_scanner.cli.main", "scan",
            "--file", str(postman_file),
            "--auth-type", "header",
            "--auth-name", "Authorization", 
            "--auth-value", "Bearer demo-token-123",
            "--no-zap",
            "--no-progress"
        ]
        print(f"Command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, timeout=120)
            if result.returncode == 0:
                print("✅ Authenticated scan completed successfully!")
            else:
                print(f"❌ Authenticated scan failed (exit code: {result.returncode})")
        except subprocess.TimeoutExpired:
            print("⏰ Authenticated scan timed out")
        except Exception as e:
            print(f"❌ Error: {e}")
    else:
        print("⚠️  Postman collection file not found for auth demo")
    
    print("\n🎉 Demo completed!")
    print(f"📁 Check the 'reports' directory for generated HTML and JSON reports")
    print(f"📁 Check the 'logs' directory for detailed scan logs")

def show_usage_examples():
    """Show usage examples for different collection types."""
    print("\n📚 Usage Examples")
    print("=" * 60)
    
    print("\n1. Scan Postman Collection:")
    print("   python -m api_security_scanner.cli.main scan --file examples/sample_postman_collection.json")
    
    print("\n2. Scan OpenAPI Specification:")
    print("   python -m api_security_scanner.cli.main scan --file examples/sample_openapi.yaml")
    
    print("\n3. Scan Curl Command:")
    print('   python -m api_security_scanner.cli.main scan --curl "curl -X GET https://api.example.com/users"')
    
    print("\n4. Scan with Authentication:")
    print("   python -m api_security_scanner.cli.main scan --file collection.json --auth-type header --auth-name Authorization --auth-value Bearer token123")
    
    print("\n5. Scan with Custom Report Location:")
    print("   python -m api_security_scanner.cli.main scan --file collection.json --export custom_report.html --export-json custom_report.json")
    
    print("\n6. Scan with ZAP Only (no custom plugins):")
    print("   python -m api_security_scanner.cli.main scan --file collection.json --no-plugins")
    
    print("\n7. Scan with Custom Plugins Only (no ZAP):")
    print("   python -m api_security_scanner.cli.main scan --file collection.json --no-zap")
    
    print("\n8. Scan with Performance Statistics:")
    print("   python -m api_security_scanner.cli.main scan --file collection.json --performance-stats")
    
    print("\n9. List Available Plugins:")
    print("   python -m api_security_scanner.cli.main plugins")
    
    print("\n10. List Recent Scans:")
    print("    python -m api_security_scanner.cli.main list-scans")

def main():
    """Main function."""
    if len(sys.argv) > 1 and sys.argv[1] == "--examples":
        show_usage_examples()
    else:
        run_scanner_demo()

if __name__ == "__main__":
    main()
