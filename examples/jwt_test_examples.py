#!/usr/bin/env python3
"""
JWT Test Examples
Generate example JWT tokens for testing the JWT Security Testing Tool.
"""

import jwt
import json
from datetime import datetime, timedelta
import base64

def create_example_tokens():
    """Create various example JWT tokens for testing."""
    
    print("🔑 Creating Example JWT Tokens for Testing")
    print("=" * 50)
    
    tokens = {}
    
    # 1. Secure JWT Token (Good example)
    print("\n1. 🔒 Secure JWT Token (Good Example)")
    secure_payload = {
        "sub": "user123",
        "name": "John Doe",
        "email": "john.doe@example.com",
        "role": "user",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iss": "https://example.com",
        "aud": "https://api.example.com",
        "jti": "unique-jwt-id-12345"
    }
    
    secure_token = jwt.encode(secure_payload, "your-256-bit-secret", algorithm="HS256")
    tokens["secure"] = secure_token
    print(f"Token: {secure_token}")
    print("✅ This token follows security best practices")
    
    # 2. Weak Secret Token
    print("\n2. ⚠️ Weak Secret Token")
    weak_payload = {
        "sub": "user456",
        "role": "admin",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    
    weak_token = jwt.encode(weak_payload, "secret", algorithm="HS256")
    tokens["weak_secret"] = weak_token
    print(f"Token: {weak_token}")
    print("❌ This token uses a weak secret")
    
    # 3. No Expiration Token
    print("\n3. ⏰ No Expiration Token")
    no_exp_payload = {
        "sub": "user789",
        "role": "user",
        "iat": datetime.utcnow()
    }
    
    no_exp_token = jwt.encode(no_exp_payload, "your-secret", algorithm="HS256")
    tokens["no_expiration"] = no_exp_token
    print(f"Token: {no_exp_token}")
    print("❌ This token has no expiration time")
    
    # 4. Expired Token
    print("\n4. 🕐 Expired Token")
    expired_payload = {
        "sub": "user101",
        "role": "user",
        "iat": datetime.utcnow() - timedelta(hours=2),
        "exp": datetime.utcnow() - timedelta(hours=1)
    }
    
    expired_token = jwt.encode(expired_payload, "your-secret", algorithm="HS256")
    tokens["expired"] = expired_token
    print(f"Token: {expired_token}")
    print("❌ This token is expired")
    
    # 5. Algorithm None Token (Vulnerable)
    print("\n5. 🚨 Algorithm None Token (Vulnerable)")
    none_header = {"alg": "none", "typ": "JWT"}
    none_payload = {
        "sub": "admin",
        "role": "superadmin",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    
    none_token = (
        base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b'=').decode() + '.' +
        base64.urlsafe_b64encode(json.dumps(none_payload).encode()).rstrip(b'=').decode() + '.' +
        ''  # Empty signature
    )
    tokens["algorithm_none"] = none_token
    print(f"Token: {none_token}")
    print("🚨 CRITICAL: This token uses 'none' algorithm")
    
    # 6. Sensitive Data Token
    print("\n6. 🔓 Sensitive Data Token")
    sensitive_payload = {
        "sub": "user202",
        "password": "mypassword123",
        "secret_key": "super-secret-key",
        "credit_card": "1234-5678-9012-3456",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    
    sensitive_token = jwt.encode(sensitive_payload, "your-secret", algorithm="HS256")
    tokens["sensitive_data"] = sensitive_token
    print(f"Token: {sensitive_token}")
    print("❌ This token contains sensitive data")
    
    # 7. Missing Claims Token
    print("\n7. 📋 Missing Claims Token")
    missing_claims_payload = {
        "sub": "user303",
        "role": "user"
        # Missing: iat, exp, iss, aud, jti
    }
    
    missing_claims_token = jwt.encode(missing_claims_payload, "your-secret", algorithm="HS256")
    tokens["missing_claims"] = missing_claims_token
    print(f"Token: {missing_claims_token}")
    print("❌ This token is missing important claims")
    
    # 8. Future IAT Token
    print("\n8. ⏭️ Future IAT Token")
    future_iat_payload = {
        "sub": "user404",
        "role": "user",
        "iat": datetime.utcnow() + timedelta(hours=1),  # Future IAT
        "exp": datetime.utcnow() + timedelta(hours=2)
    }
    
    future_iat_token = jwt.encode(future_iat_payload, "your-secret", algorithm="HS256")
    tokens["future_iat"] = future_iat_token
    print(f"Token: {future_iat_token}")
    print("❌ This token has IAT in the future")
    
    # Save tokens to file
    output_file = "example_jwt_tokens.txt"
    with open(output_file, 'w') as f:
        f.write("# Example JWT Tokens for Security Testing\n")
        f.write("# Generated on: " + datetime.now().isoformat() + "\n\n")
        
        for token_name, token_value in tokens.items():
            f.write(f"# {token_name.upper().replace('_', ' ')}\n")
            f.write(f"{token_value}\n\n")
    
    print(f"\n✅ Example tokens saved to: {output_file}")
    print("\n📝 Usage Examples:")
    print("  python jwt_security_tester.py --token <token>")
    print("  python jwt_security_tester.py --file example_jwt_tokens.txt")
    
    return tokens

def create_test_scenarios():
    """Create test scenarios for different JWT vulnerabilities."""
    
    print("\n🧪 JWT Security Test Scenarios")
    print("=" * 40)
    
    scenarios = [
        {
            "name": "Algorithm Confusion Attack",
            "description": "Test changing algorithm from RS256 to HS256",
            "steps": [
                "1. Obtain a JWT token signed with RS256",
                "2. Change the 'alg' header to 'HS256'",
                "3. Try to verify with the public key as HMAC secret",
                "4. If successful, the signature verification will be bypassed"
            ],
            "risk": "Critical"
        },
        {
            "name": "None Algorithm Attack",
            "description": "Test using 'none' algorithm to bypass signature verification",
            "steps": [
                "1. Change the 'alg' header to 'none'",
                "2. Remove the signature (set to empty string)",
                "3. Some libraries may accept this as valid"
            ],
            "risk": "Critical"
        },
        {
            "name": "Weak Secret Brute Force",
            "description": "Test common weak secrets",
            "steps": [
                "1. Try common secrets: 'secret', 'password', 'admin'",
                "2. Use wordlists for more comprehensive testing",
                "3. Check if token can be verified with weak secrets"
            ],
            "risk": "High"
        },
        {
            "name": "Token Tampering",
            "description": "Modify claims to escalate privileges",
            "steps": [
                "1. Decode the JWT token",
                "2. Modify user ID, role, or permissions",
                "3. Re-encode without re-signing",
                "4. Test if the application accepts the modified token"
            ],
            "risk": "Critical"
        },
        {
            "name": "Replay Attack",
            "description": "Reuse expired or valid tokens",
            "steps": [
                "1. Capture a valid JWT token",
                "2. Reuse it multiple times",
                "3. Check if the application prevents replay attacks"
            ],
            "risk": "Medium"
        }
    ]
    
    for scenario in scenarios:
        print(f"\n🔍 {scenario['name']}")
        print(f"Risk Level: {scenario['risk']}")
        print(f"Description: {scenario['description']}")
        print("Steps:")
        for step in scenario['steps']:
            print(f"  {step}")
    
    # Save scenarios to file
    scenarios_file = "jwt_test_scenarios.md"
    with open(scenarios_file, 'w') as f:
        f.write("# JWT Security Test Scenarios\n\n")
        for scenario in scenarios:
            f.write(f"## {scenario['name']}\n")
            f.write(f"**Risk Level:** {scenario['risk']}\n\n")
            f.write(f"**Description:** {scenario['description']}\n\n")
            f.write("**Steps:**\n")
            for step in scenario['steps']:
                f.write(f"{step}\n")
            f.write("\n---\n\n")
    
    print(f"\n✅ Test scenarios saved to: {scenarios_file}")

def main():
    """Main function to create example tokens and scenarios."""
    print("🔑 JWT Security Testing Examples Generator")
    print("=" * 50)
    
    # Create example tokens
    tokens = create_example_tokens()
    
    # Create test scenarios
    create_test_scenarios()
    
    print("\n🎉 Example generation complete!")
    print("\n📚 Next Steps:")
    print("1. Use the generated tokens to test the JWT Security Tester")
    print("2. Follow the test scenarios to understand different vulnerabilities")
    print("3. Practice with real JWT tokens from your applications")
    print("4. Integrate the tool into your security testing workflow")

if __name__ == "__main__":
    main() 