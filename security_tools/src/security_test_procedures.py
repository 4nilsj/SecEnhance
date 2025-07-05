#!/usr/bin/env python3
"""
Security Test Procedures
Detailed testing methodologies and procedures for security controls.
"""

import json
import subprocess
import requests
import base64
import hashlib
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

class SecurityTestProcedures:
    def __init__(self):
        self.test_results = {}
        self.vulnerabilities = []
        
    def test_authentication_bypass(self, target_url: str) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities."""
        print("🔐 Testing Authentication Bypass...")
        
        test_cases = [
            {
                "name": "Missing Authentication",
                "description": "Test endpoints without authentication",
                "method": "GET",
                "endpoints": ["/admin", "/api/admin", "/dashboard", "/user/profile"],
                "expected": "401 Unauthorized or 403 Forbidden"
            },
            {
                "name": "Weak Session Management",
                "description": "Test session fixation and hijacking",
                "method": "POST",
                "endpoints": ["/login", "/auth"],
                "expected": "New session ID after login"
            }
        ]
        
        results = []
        for test_case in test_cases:
            for endpoint in test_case["endpoints"]:
                try:
                    url = f"{target_url}{endpoint}"
                    response = requests.get(url, timeout=10)
                    
                    result = {
                        "test": test_case["name"],
                        "endpoint": endpoint,
                        "status_code": response.status_code,
                        "vulnerable": response.status_code not in [401, 403],
                        "details": f"Status: {response.status_code}"
                    }
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        "test": test_case["name"],
                        "endpoint": endpoint,
                        "status_code": None,
                        "vulnerable": False,
                        "details": f"Error: {str(e)}"
                    })
        
        return {
            "test_type": "Authentication Bypass",
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "total_tests": len(results),
                "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
                "risk_level": "Critical" if any(r["vulnerable"] for r in results) else "Low"
            }
        }
    
    def test_sql_injection(self, target_url: str, test_endpoints: List[str]) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities."""
        print("💉 Testing SQL Injection...")
        
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2"
        ]
        
        results = []
        for endpoint in test_endpoints:
            for payload in payloads:
                try:
                    # Test in different parameters
                    test_data = {
                        "username": payload,
                        "password": payload,
                        "id": payload,
                        "search": payload
                    }
                    
                    response = requests.post(f"{target_url}{endpoint}", data=test_data, timeout=10)
                    
                    # Check for SQL error indicators
                    sql_errors = [
                        "sql syntax", "mysql_fetch", "oracle error", "sql server",
                        "postgresql", "sqlite", "database error", "syntax error"
                    ]
                    
                    is_vulnerable = any(error in response.text.lower() for error in sql_errors)
                    
                    result = {
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": response.status_code,
                        "vulnerable": is_vulnerable,
                        "response_length": len(response.text),
                        "details": "SQL error detected" if is_vulnerable else "No SQL error"
                    }
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": None,
                        "vulnerable": False,
                        "details": f"Error: {str(e)}"
                    })
        
        return {
            "test_type": "SQL Injection",
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "total_tests": len(results),
                "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
                "risk_level": "Critical" if any(r["vulnerable"] for r in results) else "Low"
            }
        }
    
    def test_xss(self, target_url: str, test_endpoints: List[str]) -> Dict[str, Any]:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        print("🎯 Testing Cross-Site Scripting...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        results = []
        for endpoint in test_endpoints:
            for payload in xss_payloads:
                try:
                    test_data = {
                        "comment": payload,
                        "message": payload,
                        "search": payload,
                        "input": payload
                    }
                    
                    response = requests.post(f"{target_url}{endpoint}", data=test_data, timeout=10)
                    
                    # Check if payload is reflected in response
                    is_reflected = payload in response.text
                    
                    result = {
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": response.status_code,
                        "reflected": is_reflected,
                        "vulnerable": is_reflected,
                        "details": "Payload reflected in response" if is_reflected else "Payload not reflected"
                    }
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": None,
                        "reflected": False,
                        "vulnerable": False,
                        "details": f"Error: {str(e)}"
                    })
        
        return {
            "test_type": "Cross-Site Scripting",
            "target": target_url,
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "total_tests": len(results),
                "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
                "risk_level": "High" if any(r["vulnerable"] for r in results) else "Low"
            }
        }
    
    def test_jwt_vulnerabilities(self, jwt_token: str) -> Dict[str, Any]:
        """Test JWT token for common vulnerabilities."""
        print("🔑 Testing JWT Token Security...")
        
        import jwt
        
        results = []
        
        try:
            # Decode token without verification
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            
            # Test 1: Check algorithm
            header = jwt.get_unverified_header(jwt_token)
            algorithm = header.get('alg', 'unknown')
            
            results.append({
                "test": "Algorithm Check",
                "algorithm": algorithm,
                "vulnerable": algorithm == 'none' or algorithm == 'HS256',
                "details": f"Algorithm: {algorithm}",
                "recommendation": "Use RS256 or ES256 for better security"
            })
            
            # Test 2: Check expiration
            exp = decoded.get('exp')
            if exp:
                exp_date = datetime.fromtimestamp(exp)
                is_expired = datetime.now() > exp_date
                
                results.append({
                    "test": "Token Expiration",
                    "expiration": exp_date.isoformat(),
                    "vulnerable": is_expired,
                    "details": f"Token expires: {exp_date}",
                    "recommendation": "Token is expired" if is_expired else "Token is valid"
                })
            
            # Test 3: Check issuer
            iss = decoded.get('iss')
            results.append({
                "test": "Token Issuer",
                "issuer": iss,
                "vulnerable": not iss,
                "details": f"Issuer: {iss or 'Not specified'}",
                "recommendation": "Always specify issuer"
            })
            
            # Test 4: Check audience
            aud = decoded.get('aud')
            results.append({
                "test": "Token Audience",
                "audience": aud,
                "vulnerable": not aud,
                "details": f"Audience: {aud or 'Not specified'}",
                "recommendation": "Always specify audience"
            })
            
        except Exception as e:
            results.append({
                "test": "Token Decoding",
                "vulnerable": True,
                "details": f"Error decoding token: {str(e)}",
                "recommendation": "Invalid token format"
            })
        
        return {
            "test_type": "JWT Security",
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": {
                "total_tests": len(results),
                "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
                "risk_level": "High" if any(r["vulnerable"] for r in results) else "Low"
            }
        }
    
    def test_ssl_tls_configuration(self, target_host: str, port: int = 443) -> Dict[str, Any]:
        """Test SSL/TLS configuration."""
        print("🔒 Testing SSL/TLS Configuration...")
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((target_host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            results = []
            
            # Test 1: TLS Version
            results.append({
                "test": "TLS Version",
                "version": version,
                "vulnerable": version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
                "details": f"TLS Version: {version}",
                "recommendation": "Use TLS 1.2 or higher"
            })
            
            # Test 2: Certificate Validity
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            now = datetime.now()
            
            is_valid = not_before <= now <= not_after
            
            results.append({
                "test": "Certificate Validity",
                "valid": is_valid,
                "vulnerable": not is_valid,
                "details": f"Valid from {not_before} to {not_after}",
                "recommendation": "Certificate is expired" if not is_valid else "Certificate is valid"
            })
            
            # Test 3: Cipher Suite
            cipher_name = cipher[0]
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
            is_weak = any(weak in cipher_name for weak in weak_ciphers)
            
            results.append({
                "test": "Cipher Suite",
                "cipher": cipher_name,
                "vulnerable": is_weak,
                "details": f"Cipher: {cipher_name}",
                "recommendation": "Use strong cipher suites"
            })
            
            return {
                "test_type": "SSL/TLS Configuration",
                "target": f"{target_host}:{port}",
                "timestamp": datetime.now().isoformat(),
                "results": results,
                "summary": {
                    "total_tests": len(results),
                    "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
                    "risk_level": "High" if any(r["vulnerable"] for r in results) else "Low"
                }
            }
            
        except Exception as e:
            return {
                "test_type": "SSL/TLS Configuration",
                "target": f"{target_host}:{port}",
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "results": [],
                "summary": {
                    "total_tests": 0,
                    "vulnerabilities_found": 0,
                    "risk_level": "Unknown"
                }
            }
    
    def generate_test_report(self, test_results: List[Dict[str, Any]], output_file: str = None) -> str:
        """Generate a comprehensive test report."""
        print("📊 Generating Test Report...")
        
        report = {
            "report_title": "Security Test Report",
            "generated_date": datetime.now().isoformat(),
            "summary": {
                "total_tests": 0,
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0
            },
            "test_results": test_results,
            "recommendations": []
        }
        
        # Calculate summary
        for result in test_results:
            report["summary"]["total_tests"] += result["summary"]["total_tests"]
            report["summary"]["total_vulnerabilities"] += result["summary"]["vulnerabilities_found"]
            
            if result["summary"]["risk_level"] == "Critical":
                report["summary"]["critical_vulnerabilities"] += result["summary"]["vulnerabilities_found"]
            elif result["summary"]["risk_level"] == "High":
                report["summary"]["high_vulnerabilities"] += result["summary"]["vulnerabilities_found"]
            elif result["summary"]["risk_level"] == "Medium":
                report["summary"]["medium_vulnerabilities"] += result["summary"]["vulnerabilities_found"]
            else:
                report["summary"]["low_vulnerabilities"] += result["summary"]["vulnerabilities_found"]
        
        # Generate recommendations
        if report["summary"]["critical_vulnerabilities"] > 0:
            report["recommendations"].append("Immediate action required for critical vulnerabilities")
        if report["summary"]["high_vulnerabilities"] > 0:
            report["recommendations"].append("Address high-risk vulnerabilities within 30 days")
        if report["summary"]["medium_vulnerabilities"] > 0:
            report["recommendations"].append("Plan remediation for medium-risk vulnerabilities")
        
        # Save report
        if output_file is None:
            output_file = f"security_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Test report saved: {output_file}")
        return output_file

def main():
    """Example usage of SecurityTestProcedures."""
    tester = SecurityTestProcedures()
    
    # Example tests
    target_url = "https://example.com"
    
    print("🔒 Security Test Procedures Demo")
    print("=" * 40)
    
    # Test authentication bypass
    auth_results = tester.test_authentication_bypass(target_url)
    
    # Test SQL injection
    sql_results = tester.test_sql_injection(target_url, ["/login", "/search", "/api/users"])
    
    # Test XSS
    xss_results = tester.test_xss(target_url, ["/comment", "/message", "/search"])
    
    # Generate report
    all_results = [auth_results, sql_results, xss_results]
    report_file = tester.generate_test_report(all_results)
    
    print(f"\n📋 Report Summary:")
    print(f"Total tests: {sum(r['summary']['total_tests'] for r in all_results)}")
    print(f"Vulnerabilities found: {sum(r['summary']['vulnerabilities_found'] for r in all_results)}")
    print(f"Report saved: {report_file}")

if __name__ == "__main__":
    main() 