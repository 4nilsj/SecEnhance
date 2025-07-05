#!/usr/bin/env python3
"""
JWKS Spoofing Test Examples
Demonstrate JWKS spoofing attack testing with the JWT Security Testing Tool.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from jwt_security_tester import JWTSecurityTester
import jwt
from datetime import datetime, timedelta

def create_test_tokens():
    """Create test JWT tokens for JWKS spoofing testing."""
    print("🔑 Creating Test JWT Tokens for JWKS Spoofing Testing")
    print("=" * 60)
    
    tokens = {}
    
    # 1. RSA-signed token (for JWKS testing)
    print("\n1. 🔐 RSA-Signed Token (for JWKS testing)")
    rsa_payload = {
        "sub": "user123",
        "name": "John Doe",
        "role": "user",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iss": "https://example.com",
        "aud": "https://api.example.com",
        "kid": "example-key-1"
    }
    
    # Create a simple RSA key for testing
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Create token with custom header including kid
    rsa_token = jwt.encode(
        rsa_payload, 
        private_pem, 
        algorithm='RS256',
        headers={'kid': 'example-key-1', 'typ': 'JWT'}
    )
    
    tokens["rsa_token"] = rsa_token
    print(f"Token: {rsa_token}")
    print("✅ RSA token created with kid header")
    
    # Save keys for reference
    with open("test_private_key.pem", "w") as f:
        f.write(private_pem.decode('utf-8'))
    with open("test_public_key.pem", "w") as f:
        f.write(public_pem.decode('utf-8'))
    print("✅ Keys saved to test_private_key.pem and test_public_key.pem")
    
    # 2. Token with malicious kid
    print("\n2. 🎭 Token with Malicious KID")
    malicious_header = {'kid': 'attacker-key-1', 'typ': 'JWT', 'alg': 'RS256'}
    malicious_token = (
        jwt.encode(rsa_payload, private_pem, algorithm='RS256', headers=malicious_header)
    )
    tokens["malicious_kid_token"] = malicious_token
    print(f"Token: {malicious_token}")
    print("❌ Token with malicious kid created")
    
    # 3. Token without kid (vulnerable)
    print("\n3. ⚠️ Token without KID (vulnerable)")
    no_kid_token = jwt.encode(rsa_payload, private_pem, algorithm='RS256')
    tokens["no_kid_token"] = no_kid_token
    print(f"Token: {no_kid_token}")
    print("❌ Token without kid created")
    
    return tokens, private_pem.decode('utf-8'), public_pem.decode('utf-8')

def test_jwks_spoofing():
    """Test JWKS spoofing functionality."""
    print("\n🎭 Testing JWKS Spoofing Attacks")
    print("=" * 50)
    
    # Create test tokens
    tokens, private_key, public_key = create_test_tokens()
    
    # Initialize tester
    tester = JWTSecurityTester(debug=True)
    
    # Test 1: JWKS Validation
    print("\n🔑 Test 1: JWKS Validation")
    print("-" * 30)
    jwks_result = tester.test_jwks_validation(tokens["rsa_token"])
    print(f"JWKS Validation Results: {len(jwks_result.get('jwks_tests', []))} tests")
    
    # Test 2: JWKS Spoofing
    print("\n🎭 Test 2: JWKS Spoofing")
    print("-" * 30)
    spoofing_result = tester.test_jwks_spoofing(tokens["rsa_token"])
    
    if "error" not in spoofing_result:
        tests = spoofing_result.get("jwks_spoofing_tests", [])
        vulnerabilities = spoofing_result.get("vulnerabilities", [])
        
        print(f"✅ JWKS Spoofing tests completed")
        print(f"📊 Total tests: {len(tests)}")
        print(f"🚨 Vulnerabilities found: {len(vulnerabilities)}")
        
        # Show test details
        for i, test in enumerate(tests, 1):
            print(f"\n{i}. {test['test']}")
            print(f"   Risk Level: {test['risk_level']}")
            print(f"   Description: {test['description']}")
            print(f"   Mitigation: {test['mitigation']}")
            
            if test.get('malicious_token'):
                print(f"   Malicious Token: {test['malicious_token'][:50]}...")
            if test.get('malicious_url'):
                print(f"   Malicious URL: {test['malicious_url']}")
    else:
        print(f"❌ JWKS Spoofing test failed: {spoofing_result['error']}")
    
    # Test 3: Token with malicious kid
    print("\n🎭 Test 3: Token with Malicious KID")
    print("-" * 30)
    malicious_result = tester.test_jwks_spoofing(tokens["malicious_kid_token"])
    print(f"Malicious KID test completed: {len(malicious_result.get('jwks_spoofing_tests', []))} tests")
    
    # Test 4: Token without kid
    print("\n🎭 Test 4: Token without KID")
    print("-" * 30)
    no_kid_result = tester.test_jwks_spoofing(tokens["no_kid_token"])
    print(f"No KID test completed: {len(no_kid_result.get('jwks_spoofing_tests', []))} tests")
    
    return {
        "tokens": tokens,
        "jwks_validation": jwks_result,
        "jwks_spoofing": spoofing_result,
        "malicious_kid_test": malicious_result,
        "no_kid_test": no_kid_result
    }

def demonstrate_attack_scenarios():
    """Demonstrate real-world JWKS spoofing attack scenarios."""
    print("\n🌐 Real-World JWKS Spoofing Attack Scenarios")
    print("=" * 60)
    
    scenarios = [
        {
            "name": "DNS Spoofing Attack",
            "description": "Attacker redirects JWKS requests to malicious server",
            "attack_vector": "DNS cache poisoning or DNS hijacking",
            "impact": "All JWT validations use attacker's keys",
            "mitigation": "Use DNS over HTTPS (DoH) or certificate pinning"
        },
        {
            "name": "Man-in-the-Middle Attack",
            "description": "Attacker intercepts and modifies JWKS responses",
            "attack_vector": "Network interception or proxy manipulation",
            "impact": "JWKS responses contain attacker's public keys",
            "mitigation": "Use HTTPS with certificate validation"
        },
        {
            "name": "Cache Poisoning Attack",
            "description": "Attacker poisons JWKS cache with malicious keys",
            "attack_vector": "Exploit cache validation weaknesses",
            "impact": "Cached malicious keys used for validation",
            "mitigation": "Implement proper cache validation and TTL"
        },
        {
            "name": "Key ID Manipulation",
            "description": "Attacker uses malicious kid to reference wrong keys",
            "attack_vector": "Modify JWT header kid claim",
            "impact": "Token validated against attacker's keys",
            "mitigation": "Validate kid against trusted key registry"
        },
        {
            "name": "JWKS URL Manipulation",
            "description": "Attacker redirects to malicious JWKS endpoint",
            "attack_vector": "Modify JWKS URL in configuration",
            "impact": "Server fetches keys from attacker's endpoint",
            "mitigation": "Validate JWKS URL against allowlist"
        }
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print(f"   Description: {scenario['description']}")
        print(f"   Attack Vector: {scenario['attack_vector']}")
        print(f"   Impact: {scenario['impact']}")
        print(f"   Mitigation: {scenario['mitigation']}")

def main():
    """Main function to run JWKS spoofing tests."""
    print("🎭 JWKS Spoofing Test Suite")
    print("=" * 50)
    print("This script demonstrates JWKS spoofing attack testing")
    print("using the JWT Security Testing Tool.")
    
    try:
        # Run JWKS spoofing tests
        results = test_jwks_spoofing()
        
        # Demonstrate attack scenarios
        demonstrate_attack_scenarios()
        
        # Summary
        print("\n📊 Test Summary")
        print("=" * 30)
        print("✅ JWKS spoofing tests completed successfully")
        print("✅ Attack scenarios demonstrated")
        print("✅ Test tokens and keys generated")
        print("\n📁 Generated files:")
        print("   - test_private_key.pem")
        print("   - test_public_key.pem")
        print("   - Various test JWT tokens")
        
        print("\n🔧 Usage Examples:")
        print("   python ../src/jwt_security_tester.py --token <token> --test jwks-spoofing")
        print("   python ../src/jwt_security_tester.py --token <token> --test jwks")
        print("   python ../src/jwt_security_tester.py --token <token> --test all")
        
    except Exception as e:
        print(f"❌ Error during testing: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 