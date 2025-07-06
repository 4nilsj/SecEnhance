#!/usr/bin/env python3
"""
Batch Testing Example for JWT Security Testing Tool
This file demonstrates how to test multiple JWT tokens from a file.
"""

import sys
import os
import tempfile

# Add the src directory to the path so we can import the tester
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from jwt_security_tester import JWTSecurityTester

def create_sample_tokens_file():
    """Create a temporary file with sample JWT tokens for testing."""
    sample_tokens = [
        # Sample token 1 - Standard JWT
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        
        # Sample token 2 - Token with role claim
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2MzQ1Njc4OTB9.example_signature",
        
        # Sample token 3 - Token with admin role
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbjEyMyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYzNDU2Nzg5MH0.example_signature",
        
        # Sample token 4 - Token with expiration
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyNDU2IiwiZXhwIjoxNzM0NTY3ODkwLCJpYXQiOjE2MzQ1Njc4OTB9.example_signature",
        
        # Sample token 5 - Token with no expiration (vulnerable)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyNzg5IiwiaWF0IjoxNjM0NTY3ODkwfQ.example_signature"
    ]
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    for token in sample_tokens:
        temp_file.write(token + '\n')
    temp_file.close()
    
    return temp_file.name

def main():
    """Batch testing example for JWT Security Testing Tool."""
    
    print("🔒 JWT Security Testing Tool - Batch Testing Example")
    print("=" * 60)
    
    # Initialize the tester
    tester = JWTSecurityTester(debug=False)
    tester.print_version()
    
    # Create sample tokens file
    print("\n📋 Creating sample tokens file...")
    tokens_file = create_sample_tokens_file()
    print(f"✅ Created sample tokens file: {tokens_file}")
    
    try:
        # Read tokens from file
        print(f"\n📁 Reading tokens from file: {tokens_file}")
        with open(tokens_file, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
        
        print(f"📊 Found {len(tokens)} tokens to test")
        
        # Validate tokens first
        print("\n🔍 Validating tokens...")
        valid_tokens = []
        invalid_tokens = []
        
        for i, token in enumerate(tokens, 1):
            if tester.validate_jwt_token(token):
                valid_tokens.append(token)
                print(f"  ✅ Token {i}: Valid")
            else:
                invalid_tokens.append((i, token))
                print(f"  ❌ Token {i}: Invalid")
        
        if invalid_tokens:
            print(f"\n⚠️ Found {len(invalid_tokens)} invalid tokens")
        
        if not valid_tokens:
            print("❌ No valid tokens found for testing")
            return
        
        print(f"\n🚀 Starting batch testing with {len(valid_tokens)} valid tokens...")
        
        # Test each token
        all_results = []
        for i, token in enumerate(valid_tokens, 1):
            print(f"\n🔍 Testing token {i}/{len(valid_tokens)}")
            print(f"   Token: {token[:50]}...")
            
            try:
                results = tester.comprehensive_test(token)
                all_results.append(results)
                print(f"   ✅ Completed testing token {i}")
            except Exception as e:
                print(f"   ❌ Error testing token {i}: {str(e)}")
                all_results.append({"error": str(e), "token_preview": token[:50]})
        
        # Generate batch report
        print("\n📊 Generating batch report...")
        combined_report = {
            "batch_report": {
                "title": "JWT Security Batch Analysis - Example",
                "generated_date": "2024-01-01T00:00:00",
                "tokens_tested": len(valid_tokens),
                "invalid_tokens": len(invalid_tokens),
                "results": all_results
            }
        }
        
        # Generate HTML report
        report_file = tester.generate_html_report(combined_report, "batch_testing_report.html")
        print(f"✅ Batch report generated: {report_file}")
        
        # Print summary statistics
        print("\n📈 Batch Testing Summary:")
        print(f"   Total tokens processed: {len(tokens)}")
        print(f"   Valid tokens tested: {len(valid_tokens)}")
        print(f"   Invalid tokens found: {len(invalid_tokens)}")
        
        # Count total vulnerabilities
        total_vulns = 0
        for result in all_results:
            if "summary" in result:
                total_vulns += result["summary"].get("total_vulnerabilities", 0)
        
        print(f"   Total vulnerabilities found: {total_vulns}")
        
        print("\n🎉 Batch testing example completed!")
        print(f"\n📄 Check the generated report: {report_file}")
        
    finally:
        # Clean up temporary file
        try:
            os.unlink(tokens_file)
            print(f"\n🧹 Cleaned up temporary file: {tokens_file}")
        except:
            pass

if __name__ == "__main__":
    main() 