#!/usr/bin/env python3
"""
JWT Security Testing Tool
A comprehensive CLI tool for analyzing and testing JWT token security.
"""

import json
import base64
import hashlib
import hmac
import argparse
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import jwt
from jwt.exceptions import InvalidTokenError, DecodeError
import requests
import time

class JWTSecurityTester:
    def __init__(self):
        self.test_results = []
        self.vulnerabilities = []
        self.secrets_to_try = []
        
    def load_common_secrets(self):
        """Load common JWT secrets for testing."""
        self.secrets_to_try = [
            "",  # Empty secret
            "secret",
            "SECRET",
            "Secret",
            "password",
            "123456",
            "admin",
            "root",
            "jwt",
            "token",
            "key",
            "private",
            "secretkey",
            "jwtsecret",
            "mysecret",
            "supersecret",
            "verysecret",
            "extremelysecret",
            "ultrasecret",
            "megaultrasecret"
        ]
    
    def decode_token_without_verification(self, token: str) -> Tuple[Dict, Dict, str]:
        """Decode JWT token without signature verification."""
        try:
            # Split the token
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '==').decode('utf-8'))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '==').decode('utf-8'))
            
            return header, payload, signature_b64
            
        except Exception as e:
            raise ValueError(f"Error decoding token: {str(e)}")
    
    def analyze_token_structure(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token structure and basic information."""
        print("🔍 Analyzing JWT token structure...")
        
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            
            analysis = {
                "token_length": len(token),
                "header": header,
                "payload": payload,
                "signature_length": len(signature),
                "algorithm": header.get('alg', 'unknown'),
                "token_type": header.get('typ', 'JWT'),
                "claims_count": len(payload),
                "timestamp_claims": {}
            }
            
            # Analyze timestamp claims
            timestamp_fields = ['exp', 'iat', 'nbf']
            for field in timestamp_fields:
                if field in payload:
                    timestamp = payload[field]
                    if isinstance(timestamp, (int, float)):
                        dt = datetime.fromtimestamp(timestamp)
                        analysis["timestamp_claims"][field] = {
                            "timestamp": timestamp,
                            "datetime": dt.isoformat(),
                            "is_expired": field == 'exp' and datetime.now() > dt,
                            "is_future": field == 'nbf' and datetime.now() < dt
                        }
            
            return analysis
            
        except Exception as e:
            return {"error": str(e)}
    
    def test_algorithm_confusion(self, token: str) -> Dict[str, Any]:
        """Test for algorithm confusion vulnerabilities."""
        print("🔄 Testing algorithm confusion attacks...")
        
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            original_alg = header.get('alg', 'unknown')
            
            results = {
                "original_algorithm": original_alg,
                "tests": []
            }
            
            # Test 1: Change algorithm to 'none'
            if original_alg != 'none':
                none_header = header.copy()
                none_header['alg'] = 'none'
                
                # Create token with 'none' algorithm
                none_token = (
                    base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b'=').decode() + '.' +
                    base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.' +
                    ''  # Empty signature for 'none' algorithm
                )
                
                results["tests"].append({
                    "test": "Algorithm None Attack",
                    "vulnerable": True,
                    "description": "Token with 'none' algorithm created",
                    "token": none_token,
                    "risk_level": "Critical"
                })
            
            # Test 2: Test weak algorithms
            weak_algorithms = ['HS256', 'HS384', 'HS512']
            if original_alg in weak_algorithms:
                results["tests"].append({
                    "test": "Weak Algorithm",
                    "vulnerable": True,
                    "description": f"Using weak algorithm: {original_alg}",
                    "recommendation": "Use RS256, RS384, RS512, ES256, ES384, or ES512",
                    "risk_level": "High"
                })
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def test_signature_verification(self, token: str, secret: str = None) -> Dict[str, Any]:
        """Test signature verification with various secrets."""
        print("🔐 Testing signature verification...")
        
        self.load_common_secrets()
        
        if secret:
            self.secrets_to_try.insert(0, secret)
        
        results = {
            "verified_secrets": [],
            "failed_attempts": len(self.secrets_to_try),
            "tests": []
        }
        
        for test_secret in self.secrets_to_try:
            try:
                # Try to decode with current secret
                decoded = jwt.decode(token, test_secret, algorithms=['HS256', 'HS384', 'HS512'])
                results["verified_secrets"].append({
                    "secret": test_secret,
                    "algorithm": "HS256/HS384/HS512"
                })
                
                results["tests"].append({
                    "test": "Weak Secret Found",
                    "vulnerable": True,
                    "description": f"Token verified with weak secret: '{test_secret}'",
                    "secret": test_secret,
                    "risk_level": "Critical"
                })
                
            except jwt.InvalidSignatureError:
                continue
            except Exception as e:
                continue
        
        # Test with no secret (for RS256 tokens)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            results["tests"].append({
                "test": "No Signature Verification",
                "vulnerable": True,
                "description": "Token can be decoded without signature verification",
                "recommendation": "Always verify signatures",
                "risk_level": "High"
            })
        except Exception:
            pass
        
        return results
    
    def test_claim_validation(self, token: str) -> Dict[str, Any]:
        """Test JWT claims for security issues."""
        print("📋 Testing claim validation...")
        
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            
            results = {
                "missing_claims": [],
                "insecure_claims": [],
                "tests": []
            }
            
            # Check for required claims
            required_claims = ['exp', 'iat', 'iss', 'aud']
            for claim in required_claims:
                if claim not in payload:
                    results["missing_claims"].append(claim)
                    results["tests"].append({
                        "test": f"Missing {claim} Claim",
                        "vulnerable": True,
                        "description": f"Required claim '{claim}' is missing",
                        "recommendation": f"Always include '{claim}' claim",
                        "risk_level": "Medium"
                    })
            
            # Check expiration
            if 'exp' in payload:
                exp_timestamp = payload['exp']
                if isinstance(exp_timestamp, (int, float)):
                    exp_time = datetime.fromtimestamp(exp_timestamp)
                    if datetime.now() > exp_time:
                        results["tests"].append({
                            "test": "Expired Token",
                            "vulnerable": True,
                            "description": f"Token expired at {exp_time}",
                            "recommendation": "Use valid, non-expired tokens",
                            "risk_level": "Medium"
                        })
            
            # Check issued at time
            if 'iat' in payload:
                iat_timestamp = payload['iat']
                if isinstance(iat_timestamp, (int, float)):
                    iat_time = datetime.fromtimestamp(iat_timestamp)
                    future_time = datetime.now() + timedelta(hours=1)
                    if iat_time > future_time:
                        results["tests"].append({
                            "test": "Future IAT",
                            "vulnerable": True,
                            "description": f"IAT is in the future: {iat_time}",
                            "recommendation": "IAT should not be in the future",
                            "risk_level": "Low"
                        })
            
            # Check for sensitive data in payload
            sensitive_fields = ['password', 'secret', 'key', 'token', 'credential']
            for field in sensitive_fields:
                if field in payload:
                    results["tests"].append({
                        "test": "Sensitive Data in Payload",
                        "vulnerable": True,
                        "description": f"Sensitive field '{field}' found in payload",
                        "recommendation": "Never include sensitive data in JWT payload",
                        "risk_level": "High"
                    })
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def test_token_tampering(self, token: str) -> Dict[str, Any]:
        """Test various token tampering techniques."""
        print("🔧 Testing token tampering...")
        
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            
            results = {
                "tampered_tokens": [],
                "tests": []
            }
            
            # Test 1: Modify user ID
            if 'user_id' in payload or 'sub' in payload or 'user' in payload:
                user_field = 'user_id' if 'user_id' in payload else ('sub' if 'sub' in payload else 'user')
                original_value = payload[user_field]
                
                # Create tampered payload
                tampered_payload = payload.copy()
                tampered_payload[user_field] = "admin" if original_value != "admin" else "superadmin"
                
                # Create tampered token
                tampered_token = (
                    base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' +
                    base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).rstrip(b'=').decode() + '.' +
                    signature
                )
                
                results["tampered_tokens"].append({
                    "type": "User ID Tampering",
                    "original_value": original_value,
                    "tampered_value": tampered_payload[user_field],
                    "token": tampered_token
                })
                
                results["tests"].append({
                    "test": "User ID Tampering",
                    "vulnerable": True,
                    "description": f"User ID can be modified from '{original_value}' to '{tampered_payload[user_field]}'",
                    "recommendation": "Validate user permissions server-side",
                    "risk_level": "Critical"
                })
            
            # Test 2: Modify roles/permissions
            role_fields = ['role', 'roles', 'permissions', 'scope', 'authorities']
            for role_field in role_fields:
                if role_field in payload:
                    original_roles = payload[role_field]
                    tampered_payload = payload.copy()
                    tampered_payload[role_field] = "admin" if original_roles != "admin" else "superadmin"
                    
                    tampered_token = (
                        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' +
                        base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).rstrip(b'=').decode() + '.' +
                        signature
                    )
                    
                    results["tampered_tokens"].append({
                        "type": "Role Tampering",
                        "original_value": original_roles,
                        "tampered_value": tampered_payload[role_field],
                        "token": tampered_token
                    })
                    
                    results["tests"].append({
                        "test": "Role Tampering",
                        "vulnerable": True,
                        "description": f"Role can be modified from '{original_roles}' to '{tampered_payload[role_field]}'",
                        "recommendation": "Validate roles server-side",
                        "risk_level": "Critical"
                    })
                    break
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def test_replay_attack(self, token: str) -> Dict[str, Any]:
        """Test for replay attack vulnerabilities."""
        print("🔄 Testing replay attack scenarios...")
        
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            
            results = {
                "replay_vulnerable": False,
                "tests": []
            }
            
            # Check for jti (JWT ID) claim
            if 'jti' not in payload:
                results["replay_vulnerable"] = True
                results["tests"].append({
                    "test": "Missing JTI Claim",
                    "vulnerable": True,
                    "description": "No JWT ID (jti) claim found",
                    "recommendation": "Include unique jti claim to prevent replay attacks",
                    "risk_level": "Medium"
                })
            
            # Check for nonce claim
            if 'nonce' not in payload:
                results["tests"].append({
                    "test": "Missing Nonce",
                    "vulnerable": True,
                    "description": "No nonce claim found",
                    "recommendation": "Include nonce claim for additional replay protection",
                    "risk_level": "Low"
                })
            
            # Check expiration time
            if 'exp' not in payload:
                results["replay_vulnerable"] = True
                results["tests"].append({
                    "test": "No Expiration",
                    "vulnerable": True,
                    "description": "Token has no expiration time",
                    "recommendation": "Always set expiration time",
                    "risk_level": "High"
                })
            
            return results
            
        except Exception as e:
            return {"error": str(e)}
    
    def comprehensive_test(self, token: str, secret: str = None) -> Dict[str, Any]:
        """Run comprehensive JWT security tests."""
        print("🚀 Running comprehensive JWT security tests...")
        print("=" * 60)
        
        results = {
            "test_timestamp": datetime.now().isoformat(),
            "token_preview": token[:50] + "..." if len(token) > 50 else token,
            "tests": {}
        }
        
        # Run all tests
        results["tests"]["structure_analysis"] = self.analyze_token_structure(token)
        results["tests"]["algorithm_confusion"] = self.test_algorithm_confusion(token)
        results["tests"]["signature_verification"] = self.test_signature_verification(token, secret)
        results["tests"]["claim_validation"] = self.test_claim_validation(token)
        results["tests"]["token_tampering"] = self.test_token_tampering(token)
        results["tests"]["replay_attack"] = self.test_replay_attack(token)
        
        # Calculate summary
        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        for test_name, test_result in results["tests"].items():
            if "tests" in test_result:
                for test in test_result["tests"]:
                    total_vulnerabilities += 1
                    risk_level = test.get("risk_level", "Unknown")
                    if risk_level == "Critical":
                        critical_vulns += 1
                    elif risk_level == "High":
                        high_vulns += 1
                    elif risk_level == "Medium":
                        medium_vulns += 1
                    elif risk_level == "Low":
                        low_vulns += 1
        
        results["summary"] = {
            "total_vulnerabilities": total_vulnerabilities,
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns,
            "low": low_vulns,
            "overall_risk": "Critical" if critical_vulns > 0 else ("High" if high_vulns > 0 else ("Medium" if medium_vulns > 0 else "Low"))
        }
        
        return results
    
    def generate_report(self, results: Dict[str, Any], output_file: str = None) -> str:
        """Generate a comprehensive security report."""
        print("\n📊 Generating JWT Security Report...")
        
        report = {
            "jwt_security_report": {
                "title": "JWT Security Analysis Report",
                "generated_date": datetime.now().isoformat(),
                "summary": results["summary"],
                "detailed_results": results["tests"]
            }
        }
        
        # Generate recommendations
        recommendations = []
        summary = results["summary"]
        
        if summary["critical"] > 0:
            recommendations.append("🚨 CRITICAL: Immediate action required for critical vulnerabilities")
        if summary["high"] > 0:
            recommendations.append("⚠️ HIGH: Address high-risk vulnerabilities within 30 days")
        if summary["medium"] > 0:
            recommendations.append("🔶 MEDIUM: Plan remediation for medium-risk vulnerabilities")
        
        recommendations.extend([
            "🔐 Always verify JWT signatures",
            "⏰ Set appropriate expiration times",
            "🆔 Include unique JWT ID (jti) claims",
            "👤 Validate user permissions server-side",
            "🔒 Use strong algorithms (RS256, ES256)",
            "📋 Include all required claims (exp, iat, iss, aud)"
        ])
        
        report["recommendations"] = recommendations
        
        # Save report
        if output_file is None:
            output_file = f"jwt_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Report saved: {output_file}")
        return output_file
    
    def print_summary(self, results: Dict[str, Any]):
        """Print a summary of test results."""
        print("\n" + "=" * 60)
        print("📋 JWT Security Test Summary")
        print("=" * 60)
        
        summary = results["summary"]
        print(f"🔍 Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"🚨 Critical: {summary['critical']}")
        print(f"⚠️ High: {summary['high']}")
        print(f"🔶 Medium: {summary['medium']}")
        print(f"🔵 Low: {summary['low']}")
        print(f"🎯 Overall Risk: {summary['overall_risk']}")
        
        if summary['total_vulnerabilities'] == 0:
            print("\n✅ No vulnerabilities found! JWT appears secure.")
        else:
            print(f"\n❌ {summary['total_vulnerabilities']} vulnerabilities found. Review detailed results.")

def main():
    """Main function for JWT Security Tester."""
    parser = argparse.ArgumentParser(description="JWT Security Testing Tool")
    parser.add_argument("--token", help="JWT token to test")
    parser.add_argument("--secret", help="Secret key for signature verification")
    parser.add_argument("--file", help="File containing JWT tokens (one per line)")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--test", choices=["structure", "algorithm", "signature", "claims", "tampering", "replay", "all"], 
                       default="all", help="Specific test to run")
    
    args = parser.parse_args()
    
    tester = JWTSecurityTester()
    
    if args.token:
        # Test single token
        print("🔒 JWT Security Testing Tool")
        print("=" * 40)
        
        if args.test == "all":
            results = tester.comprehensive_test(args.token, args.secret)
        else:
            # Run specific test
            if args.test == "structure":
                results = {"tests": {"structure_analysis": tester.analyze_token_structure(args.token)}}
            elif args.test == "algorithm":
                results = {"tests": {"algorithm_confusion": tester.test_algorithm_confusion(args.token)}}
            elif args.test == "signature":
                results = {"tests": {"signature_verification": tester.test_signature_verification(args.token, args.secret)}}
            elif args.test == "claims":
                results = {"tests": {"claim_validation": tester.test_claim_validation(args.token)}}
            elif args.test == "tampering":
                results = {"tests": {"token_tampering": tester.test_token_tampering(args.token)}}
            elif args.test == "replay":
                results = {"tests": {"replay_attack": tester.test_replay_attack(args.token)}}
        
        tester.print_summary(results)
        
        if args.output:
            tester.generate_report(results, args.output)
    
    elif args.file:
        # Test multiple tokens from file
        print("🔒 JWT Security Testing Tool - Batch Mode")
        print("=" * 50)
        
        try:
            with open(args.file, 'r') as f:
                tokens = [line.strip() for line in f if line.strip()]
            
            print(f"📁 Testing {len(tokens)} tokens from {args.file}")
            
            all_results = []
            for i, token in enumerate(tokens, 1):
                print(f"\n🔍 Testing token {i}/{len(tokens)}")
                results = tester.comprehensive_test(token, args.secret)
                all_results.append(results)
            
            # Generate combined report
            combined_report = {
                "batch_report": {
                    "title": "JWT Security Batch Analysis",
                    "generated_date": datetime.now().isoformat(),
                    "tokens_tested": len(tokens),
                    "results": all_results
                }
            }
            
            output_file = args.output or f"jwt_batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(combined_report, f, indent=2)
            
            print(f"\n✅ Batch report saved: {output_file}")
            
        except FileNotFoundError:
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
    
    else:
        # Interactive mode
        print("🔒 JWT Security Testing Tool - Interactive Mode")
        print("=" * 50)
        
        while True:
            token = input("\nEnter JWT token (or 'quit' to exit): ").strip()
            if token.lower() == 'quit':
                break
            
            if not token:
                print("❌ Please enter a valid JWT token")
                continue
            
            try:
                results = tester.comprehensive_test(token)
                tester.print_summary(results)
                
                save_choice = input("\nSave report? (y/n): ").lower().strip()
                if save_choice == 'y':
                    output_file = input("Enter output filename (or press Enter for default): ").strip()
                    if not output_file:
                        output_file = None
                    tester.generate_report(results, output_file)
                
            except Exception as e:
                print(f"❌ Error testing token: {str(e)}")
        
        print("\n👋 Thank you for using JWT Security Testing Tool!")

if __name__ == "__main__":
    main() 