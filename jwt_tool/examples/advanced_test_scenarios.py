#!/usr/bin/env python3
"""
Advanced JWT Security Testing Scenarios
Demonstrates all the new features and capabilities of the enhanced JWT security testing tool.
"""

import json
import sys
import os

# Add the src directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from jwt_security_tester import JWTSecurityTester

def main():
    """Demonstrate advanced JWT security testing scenarios."""
    print("🔒 Advanced JWT Security Testing Scenarios")
    print("=" * 60)
    
    tester = JWTSecurityTester()
    
    # Example JWT tokens for testing
    example_tokens = {
        "hs256_weak": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoidXNlciIsImV4cCI6MTczNTY4MzAwMH0.Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8",
        "rs256_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoidXNlciIsImV4cCI6MTczNTY4MzAwMH0.Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8",
        "es256_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJyb2xlIjoidXNlciIsImV4cCI6MTczNTY4MzAwMH0.Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8Ej8"
    }
    
    print("\n1. 🚨 CVE-Specific Testing")
    print("-" * 30)
    
    for token_name, token in example_tokens.items():
        print(f"\nTesting {token_name}:")
        
        # CVE-2015-2951: alg=none bypass
        cve_result = tester.test_cve_2015_2951_alg_none(token)
        if cve_result.get("vulnerable"):
            print(f"  ⚠️ CVE-2015-2951: Vulnerable to alg=none bypass")
        
        # CVE-2019-20933: blank password
        blank_result = tester.test_cve_2019_20933_blank_password(token)
        if blank_result.get("vulnerable"):
            print(f"  ⚠️ CVE-2019-20933: Vulnerable to blank password")
        
        # CVE-2020-28042: null signature
        null_result = tester.test_cve_2020_28042_null_signature(token)
        if null_result.get("vulnerable"):
            print(f"  ⚠️ CVE-2020-28042: Vulnerable to null signature")
    
    print("\n2. 🎯 Claim Fuzzing")
    print("-" * 30)
    
    token = example_tokens["hs256_weak"]
    fuzzing_result = tester.test_claim_fuzzing(token)
    print(f"Generated {len(fuzzing_result.get('fuzzing_tests', []))} fuzzed tokens")
    
    # Show some examples
    for i, test in enumerate(fuzzing_result.get('fuzzing_tests', [])[:3]):
        print(f"  Fuzzed {test['claim']}: '{test['original_value']}' -> '{test['fuzzed_value']}'")
    
    print("\n3. ⏰ Timestamp Tampering")
    print("-" * 30)
    
    timestamp_result = tester.test_timestamp_tampering(token)
    print(f"Generated {len(timestamp_result.get('timestamp_tests', []))} timestamp manipulations")
    
    # Show some examples
    for i, test in enumerate(timestamp_result.get('timestamp_tests', [])[:3]):
        print(f"  {test['claim']} manipulation: {test['manipulation']}")
    
    print("\n4. 🔍 Dictionary Attack")
    print("-" * 30)
    
    # Create a simple wordlist for demonstration
    wordlist_content = "secret\npassword\n123456\nadmin\nroot\njwt\ntoken\nkey\nprivate\n"
    with open("demo_wordlist.txt", "w") as f:
        f.write(wordlist_content)
    
    dict_result = tester.test_dictionary_attack(token, "demo_wordlist.txt", 10)
    print(f"Dictionary attack completed: {dict_result['attempts_made']} attempts")
    if dict_result.get("attack_successful"):
        print(f"  ✅ Secret found: '{dict_result['cracked_secret']}'")
    else:
        print("  ❌ No secret found")
    
    # Clean up
    os.remove("demo_wordlist.txt")
    
    print("\n5. 🔑 Key Generation")
    print("-" * 30)
    
    # Generate RSA keys
    rsa_keys = tester.generate_rsa_key_pair(2048)
    if "error" not in rsa_keys:
        print("  ✅ RSA 2048-bit key pair generated")
        print(f"  Private key length: {len(rsa_keys['private_key'])} characters")
        print(f"  Public key length: {len(rsa_keys['public_key'])} characters")
    
    # Generate ECDSA keys
    ecdsa_keys = tester.generate_ecdsa_key_pair("P-256")
    if "error" not in ecdsa_keys:
        print("  ✅ ECDSA P-256 key pair generated")
        print(f"  Private key length: {len(ecdsa_keys['private_key'])} characters")
        print(f"  Public key length: {len(ecdsa_keys['public_key'])} characters")
    
    print("\n6. 🔨 Token Forging")
    print("-" * 30)
    
    # Forge a new token
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "role": "admin",
        "iat": 1516239022,
        "exp": 1735683000
    }
    
    forged_result = tester.forge_token(payload, "HS256", "new_secret")
    if "error" not in forged_result:
        print("  ✅ Token forged successfully")
        print(f"  Algorithm: {forged_result['algorithm']}")
        print(f"  Token preview: {forged_result['forged_token'][:50]}...")
    
    print("\n7. 📊 Comprehensive Testing")
    print("-" * 30)
    
    # Run comprehensive test
    print("Running comprehensive security test...")
    comprehensive_result = tester.comprehensive_test(token)
    
    summary = comprehensive_result.get("summary", {})
    print(f"  Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"  Critical: {summary.get('critical', 0)}")
    print(f"  High: {summary.get('high', 0)}")
    print(f"  Medium: {summary.get('medium', 0)}")
    print(f"  Low: {summary.get('low', 0)}")
    print(f"  Overall risk: {summary.get('overall_risk', 'Unknown')}")
    
    print("\n8. 📄 Report Generation")
    print("-" * 30)
    
    # Generate report
    report_file = tester.generate_report(comprehensive_result, "advanced_test_report.json")
    print(f"  ✅ Report saved: {report_file}")
    
    print("\n" + "=" * 60)
    print("🎉 Advanced JWT Security Testing Scenarios Completed!")
    print("Check the generated report for detailed results.")

if __name__ == "__main__":
    main() 