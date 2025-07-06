#!/usr/bin/env python3
"""
Quick Start Guide for JWT Security Testing Tool
This file demonstrates basic usage scenarios for the JWT tool.
"""

import sys
import os

# Add the src directory to the path so we can import the tester
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from jwt_security_tester import JWTSecurityTester

def main():
    """Quick start examples for JWT Security Testing Tool."""
    
    print("🔒 JWT Security Testing Tool - Quick Start Examples")
    print("=" * 60)
    
    # Initialize the tester
    tester = JWTSecurityTester(debug=False)
    tester.print_version()
    
    # Example 1: Test a sample JWT token
    print("\n📋 Example 1: Testing a sample JWT token")
    print("-" * 40)
    
    # This is a sample JWT token (you can replace with your own)
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    print(f"Testing token: {sample_token[:50]}...")
    
    # Run comprehensive test
    results = tester.comprehensive_test(sample_token)
    
    # Print summary
    tester.print_summary(results)
    tester.print_vulnerabilities(results)
    
    # Example 2: Test with a weak secret
    print("\n📋 Example 2: Testing with weak secret")
    print("-" * 40)
    
    # Create a token with a weak secret
    weak_secret = "secret"
    weak_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2MzQ1Njc4OTB9.example_signature"
    
    print(f"Testing token with weak secret: {weak_token[:50]}...")
    
    # Test signature verification
    sig_results = tester.test_signature_verification(weak_token, weak_secret)
    print("Signature verification results:")
    for test in sig_results.get("tests", []):
        if test.get("vulnerable"):
            print(f"  ❌ {test.get('test')}: {test.get('description')}")
        else:
            print(f"  ✅ {test.get('test')}: Secure")
    
    # Example 3: Test algorithm confusion
    print("\n📋 Example 3: Testing algorithm confusion")
    print("-" * 40)
    
    # Test algorithm confusion
    alg_results = tester.test_algorithm_confusion(sample_token)
    print("Algorithm confusion results:")
    for test in alg_results.get("tests", []):
        if test.get("vulnerable"):
            print(f"  ❌ {test.get('test')}: {test.get('description')}")
        else:
            print(f"  ✅ {test.get('test')}: Secure")
    
    # Example 4: Generate a report
    print("\n📋 Example 4: Generating HTML report")
    print("-" * 40)
    
    # Generate HTML report
    report_file = tester.generate_html_report(results, "quick_start_report.html")
    print(f"✅ Report generated: {report_file}")
    
    print("\n🎉 Quick start examples completed!")
    print("\nNext steps:")
    print("1. Try testing your own JWT tokens")
    print("2. Use --help to see all available options")
    print("3. Check the generated HTML report for detailed results")
    print("4. Explore other example files for advanced usage")

if __name__ == "__main__":
    main() 