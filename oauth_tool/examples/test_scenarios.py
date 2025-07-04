#!/usr/bin/env python3
"""
OAuth/OIDC Security Testing Scenarios
Demonstrates various testing scenarios for the OAuth/OIDC security testing tool.
"""

import sys
import os
import json
from datetime import datetime

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from oauth_oidc_tester import (
    discover_metadata, simulate_authorization_flow, handle_tokens,
    check_vulnerabilities, fuzz_and_manipulate, generate_report
)

def test_google_oauth():
    """Test Google OAuth 2.0/OIDC implementation."""
    print("🔍 Testing Google OAuth 2.0/OIDC")
    print("=" * 50)
    
    # Google OAuth configuration
    config = {
        "issuer": "https://accounts.google.com",
        "client_id": "your_google_client_id",  # Replace with actual client ID
        "client_secret": "your_google_client_secret",  # Replace with actual secret
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email"
    }
    
    print(f"Testing issuer: {config['issuer']}")
    
    # 1. Discovery
    metadata = discover_metadata(config["issuer"])
    if "error" in metadata:
        print(f"❌ Discovery failed: {metadata['error']}")
        return
    
    print("✅ Discovery successful")
    
    # 2. Vulnerability checks
    print("\n🔍 Running vulnerability checks...")
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    # 3. Fuzzing
    print("\n🎯 Running fuzzing tests...")
    fuzz_results = fuzz_and_manipulate(type('Args', (), config)())
    
    # Generate report
    results = {
        "metadata": metadata,
        "vulnerabilities": vuln_results,
        "fuzzing": fuzz_results
    }
    
    report_file = generate_report(results, "google_oauth_test_report.json")
    print(f"\n📄 Report saved: {report_file}")

def test_azure_ad():
    """Test Microsoft Azure AD OAuth 2.0/OIDC implementation."""
    print("\n🔍 Testing Microsoft Azure AD OAuth 2.0/OIDC")
    print("=" * 50)
    
    # Azure AD configuration
    config = {
        "issuer": "https://login.microsoftonline.com/your_tenant_id/v2.0",
        "client_id": "your_azure_client_id",  # Replace with actual client ID
        "client_secret": "your_azure_client_secret",  # Replace with actual secret
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email"
    }
    
    print(f"Testing issuer: {config['issuer']}")
    
    # 1. Discovery
    metadata = discover_metadata(config["issuer"])
    if "error" in metadata:
        print(f"❌ Discovery failed: {metadata['error']}")
        return
    
    print("✅ Discovery successful")
    
    # 2. Vulnerability checks
    print("\n🔍 Running vulnerability checks...")
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    # 3. Fuzzing
    print("\n🎯 Running fuzzing tests...")
    fuzz_results = fuzz_and_manipulate(type('Args', (), config)())
    
    # Generate report
    results = {
        "metadata": metadata,
        "vulnerabilities": vuln_results,
        "fuzzing": fuzz_results
    }
    
    report_file = generate_report(results, "azure_ad_test_report.json")
    print(f"\n📄 Report saved: {report_file}")

def test_okta():
    """Test Okta OAuth 2.0/OIDC implementation."""
    print("\n🔍 Testing Okta OAuth 2.0/OIDC")
    print("=" * 50)
    
    # Okta configuration
    config = {
        "issuer": "https://your-domain.okta.com",
        "client_id": "your_okta_client_id",  # Replace with actual client ID
        "client_secret": "your_okta_client_secret",  # Replace with actual secret
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email"
    }
    
    print(f"Testing issuer: {config['issuer']}")
    
    # 1. Discovery
    metadata = discover_metadata(config["issuer"])
    if "error" in metadata:
        print(f"❌ Discovery failed: {metadata['error']}")
        return
    
    print("✅ Discovery successful")
    
    # 2. Vulnerability checks
    print("\n🔍 Running vulnerability checks...")
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    # 3. Fuzzing
    print("\n🎯 Running fuzzing tests...")
    fuzz_results = fuzz_and_manipulate(type('Args', (), config)())
    
    # Generate report
    results = {
        "metadata": metadata,
        "vulnerabilities": vuln_results,
        "fuzzing": fuzz_results
    }
    
    report_file = generate_report(results, "okta_test_report.json")
    print(f"\n📄 Report saved: {report_file}")

def test_open_redirect_scenario():
    """Test specific open redirect vulnerability scenario."""
    print("\n🎯 Testing Open Redirect Vulnerability Scenario")
    print("=" * 50)
    
    config = {
        "issuer": "https://vulnerable-oauth.example.com",
        "client_id": "test_client",
        "redirect_uri": "https://attacker.com/callback",
        "scope": "openid profile email"
    }
    
    print("Testing for open redirect vulnerabilities...")
    
    # Test various malicious redirect URIs
    malicious_redirects = [
        "https://attacker.com/steal",
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>",
        "https://evil.com/callback?token=stolen"
    ]
    
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    print("✅ Open redirect scenario test completed")
    return vuln_results

def test_csrf_scenario():
    """Test CSRF vulnerability scenario."""
    print("\n🎯 Testing CSRF Vulnerability Scenario")
    print("=" * 50)
    
    config = {
        "issuer": "https://vulnerable-oauth.example.com",
        "client_id": "test_client",
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email"
    }
    
    print("Testing for CSRF vulnerabilities (missing state parameter)...")
    
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    print("✅ CSRF scenario test completed")
    return vuln_results

def test_scope_escalation_scenario():
    """Test scope escalation vulnerability scenario."""
    print("\n🎯 Testing Scope Escalation Scenario")
    print("=" * 50)
    
    config = {
        "issuer": "https://vulnerable-oauth.example.com",
        "client_id": "test_client",
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "admin root superuser"  # Attempt escalated scopes
    }
    
    print("Testing for scope escalation vulnerabilities...")
    
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    print("✅ Scope escalation scenario test completed")
    return vuln_results

def test_pkce_scenario():
    """Test PKCE (Proof Key for Code Exchange) scenario."""
    print("\n🎯 Testing PKCE Scenario")
    print("=" * 50)
    
    config = {
        "issuer": "https://vulnerable-oauth.example.com",
        "client_id": "public_client",
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email",
        "pkce": True  # Enable PKCE
    }
    
    print("Testing PKCE implementation...")
    
    # Test PKCE downgrade
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    print("✅ PKCE scenario test completed")
    return vuln_results

def test_comprehensive_security_audit():
    """Run a comprehensive security audit on an OAuth/OIDC implementation."""
    print("\n🔒 Comprehensive OAuth/OIDC Security Audit")
    print("=" * 60)
    
    # Configuration for comprehensive testing
    config = {
        "issuer": "https://your-oauth-provider.com",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret",
        "redirect_uri": "http://localhost:8080/callback",
        "scope": "openid profile email",
        "pkce": True
    }
    
    print("🚀 Starting comprehensive security audit...")
    print(f"Target: {config['issuer']}")
    print(f"Client ID: {config['client_id']}")
    
    # 1. Discovery and Metadata Analysis
    print("\n1️⃣ Discovery and Metadata Analysis")
    metadata = discover_metadata(config["issuer"])
    
    # 2. Authorization Flow Testing
    print("\n2️⃣ Authorization Flow Testing")
    flow_results = simulate_authorization_flow(type('Args', (), config)())
    
    # 3. Token Handling
    print("\n3️⃣ Token Handling and Validation")
    token_results = handle_tokens(type('Args', (), config)())
    
    # 4. Vulnerability Assessment
    print("\n4️⃣ Vulnerability Assessment")
    vuln_results = check_vulnerabilities(type('Args', (), config)())
    
    # 5. Fuzzing and Manipulation
    print("\n5️⃣ Fuzzing and Parameter Manipulation")
    fuzz_results = fuzz_and_manipulate(type('Args', (), config)())
    
    # 6. Generate Comprehensive Report
    print("\n6️⃣ Generating Comprehensive Report")
    results = {
        "metadata": metadata,
        "flow": flow_results,
        "tokens": token_results,
        "vulnerabilities": vuln_results,
        "fuzzing": fuzz_results
    }
    
    report_file = generate_report(results, "comprehensive_oauth_audit.json")
    
    print(f"\n🎉 Comprehensive security audit completed!")
    print(f"📄 Detailed report saved: {report_file}")
    
    return results

def main():
    """Run all test scenarios."""
    print("🔒 OAuth/OIDC Security Testing Scenarios")
    print("=" * 60)
    print("This script demonstrates various OAuth/OIDC security testing scenarios.")
    print("⚠️  IMPORTANT: Only test systems you own or have permission to test!")
    print()
    
    # Run specific scenarios
    scenarios = [
        ("Google OAuth", test_google_oauth),
        ("Azure AD", test_azure_ad),
        ("Okta", test_okta),
        ("Open Redirect", test_open_redirect_scenario),
        ("CSRF", test_csrf_scenario),
        ("Scope Escalation", test_scope_escalation_scenario),
        ("PKCE", test_pkce_scenario),
        ("Comprehensive Audit", test_comprehensive_security_audit)
    ]
    
    print("Available test scenarios:")
    for i, (name, _) in enumerate(scenarios, 1):
        print(f"  {i}. {name}")
    
    print("\nTo run a specific scenario, modify the main() function or call the function directly.")
    print("Example: test_comprehensive_security_audit()")
    
    # Uncomment the scenario you want to run:
    # test_comprehensive_security_audit()
    # test_google_oauth()
    # test_azure_ad()
    # test_okta()

if __name__ == "__main__":
    main() 