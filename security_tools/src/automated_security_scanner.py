#!/usr/bin/env python3
"""
Automated Security Scanner
Integrates with Security Checklist Generator to perform automated security testing.
"""

import json
import requests
import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
from datetime import datetime
import argparse
import sys
import os

class AutomatedSecurityScanner:
    def __init__(self):
        self.scan_results = {}
        self.vulnerabilities = []
        self.scan_config = {}
        
    def load_scan_config(self, config_file: str = None):
        """Load scan configuration."""
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.scan_config = json.load(f)
        else:
            # Default configuration
            self.scan_config = {
                "targets": [],
                "scan_types": ["auth_bypass", "sql_injection", "xss", "ssl_tls"],
                "threads": 5,
                "timeout": 30,
                "user_agent": "SecurityScanner/1.0",
                "exclude_paths": ["/logout", "/admin/logout"],
                "custom_headers": {},
                "rate_limit": 1  # requests per second
            }
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive security scan on a target."""
        print(f"🔍 Scanning target: {target}")
        
        scan_result = {
            "target": target,
            "scan_start": datetime.now().isoformat(),
            "tests": {},
            "summary": {
                "total_vulnerabilities": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        # Test 1: Authentication Bypass
        if "auth_bypass" in self.scan_config["scan_types"]:
            print(f"  🔐 Testing authentication bypass...")
            auth_result = self.test_auth_bypass(target)
            scan_result["tests"]["authentication_bypass"] = auth_result
            scan_result["summary"]["total_vulnerabilities"] += auth_result["vulnerabilities_found"]
        
        # Test 2: SQL Injection
        if "sql_injection" in self.scan_config["scan_types"]:
            print(f"  💉 Testing SQL injection...")
            sql_result = self.test_sql_injection(target)
            scan_result["tests"]["sql_injection"] = sql_result
            scan_result["summary"]["total_vulnerabilities"] += sql_result["vulnerabilities_found"]
        
        # Test 3: XSS
        if "xss" in self.scan_config["scan_types"]:
            print(f"  🎯 Testing XSS...")
            xss_result = self.test_xss(target)
            scan_result["tests"]["xss"] = xss_result
            scan_result["summary"]["total_vulnerabilities"] += xss_result["vulnerabilities_found"]
        
        # Test 4: SSL/TLS
        if "ssl_tls" in self.scan_config["scan_types"]:
            print(f"  🔒 Testing SSL/TLS...")
            ssl_result = self.test_ssl_tls(target)
            scan_result["tests"]["ssl_tls"] = ssl_result
            scan_result["summary"]["total_vulnerabilities"] += ssl_result["vulnerabilities_found"]
        
        scan_result["scan_end"] = datetime.now().isoformat()
        return scan_result
    
    def test_auth_bypass(self, target: str) -> Dict[str, Any]:
        """Test for authentication bypass vulnerabilities."""
        test_endpoints = [
            "/admin", "/admin/", "/admin/dashboard",
            "/api/admin", "/api/users", "/api/admin/users",
            "/dashboard", "/user/profile", "/settings",
            "/config", "/backup", "/logs"
        ]
        
        results = []
        for endpoint in test_endpoints:
            try:
                url = f"{target}{endpoint}"
                headers = {
                    "User-Agent": self.scan_config.get("user_agent", "SecurityScanner/1.0")
                }
                headers.update(self.scan_config.get("custom_headers", {}))
                
                response = requests.get(url, headers=headers, timeout=self.scan_config["timeout"])
                
                # Check if endpoint is accessible without authentication
                is_vulnerable = response.status_code not in [401, 403, 404]
                
                results.append({
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "vulnerable": is_vulnerable,
                    "details": f"Status: {response.status_code}"
                })
                
                time.sleep(self.scan_config["rate_limit"])  # Rate limiting
                
            except Exception as e:
                results.append({
                    "endpoint": endpoint,
                    "status_code": None,
                    "vulnerable": False,
                    "details": f"Error: {str(e)}"
                })
        
        return {
            "test_type": "Authentication Bypass",
            "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
            "results": results,
            "risk_level": "Critical" if any(r["vulnerable"] for r in results) else "Low"
        }
    
    def test_sql_injection(self, target: str) -> Dict[str, Any]:
        """Test for SQL injection vulnerabilities."""
        test_endpoints = ["/login", "/search", "/api/users", "/api/products"]
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "admin'--",
            "1' AND '1'='1"
        ]
        
        results = []
        for endpoint in test_endpoints:
            for payload in payloads:
                try:
                    url = f"{target}{endpoint}"
                    test_data = {
                        "username": payload,
                        "password": payload,
                        "search": payload,
                        "id": payload
                    }
                    
                    headers = {
                        "User-Agent": self.scan_config.get("user_agent", "SecurityScanner/1.0")
                    }
                    headers.update(self.scan_config.get("custom_headers", {}))
                    
                    response = requests.post(url, data=test_data, headers=headers, 
                                          timeout=self.scan_config["timeout"])
                    
                    # Check for SQL error indicators
                    sql_errors = [
                        "sql syntax", "mysql_fetch", "oracle error", "sql server",
                        "postgresql", "sqlite", "database error", "syntax error"
                    ]
                    
                    is_vulnerable = any(error in response.text.lower() for error in sql_errors)
                    
                    results.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": response.status_code,
                        "vulnerable": is_vulnerable,
                        "details": "SQL error detected" if is_vulnerable else "No SQL error"
                    })
                    
                    time.sleep(self.scan_config["rate_limit"])
                    
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
            "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
            "results": results,
            "risk_level": "Critical" if any(r["vulnerable"] for r in results) else "Low"
        }
    
    def test_xss(self, target: str) -> Dict[str, Any]:
        """Test for XSS vulnerabilities."""
        test_endpoints = ["/comment", "/message", "/search", "/contact"]
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        results = []
        for endpoint in test_endpoints:
            for payload in xss_payloads:
                try:
                    url = f"{target}{endpoint}"
                    test_data = {
                        "comment": payload,
                        "message": payload,
                        "search": payload,
                        "input": payload
                    }
                    
                    headers = {
                        "User-Agent": self.scan_config.get("user_agent", "SecurityScanner/1.0")
                    }
                    headers.update(self.scan_config.get("custom_headers", {}))
                    
                    response = requests.post(url, data=test_data, headers=headers,
                                          timeout=self.scan_config["timeout"])
                    
                    # Check if payload is reflected
                    is_reflected = payload in response.text
                    
                    results.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": response.status_code,
                        "vulnerable": is_reflected,
                        "details": "Payload reflected" if is_reflected else "Payload not reflected"
                    })
                    
                    time.sleep(self.scan_config["rate_limit"])
                    
                except Exception as e:
                    results.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "status_code": None,
                        "vulnerable": False,
                        "details": f"Error: {str(e)}"
                    })
        
        return {
            "test_type": "Cross-Site Scripting",
            "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
            "results": results,
            "risk_level": "High" if any(r["vulnerable"] for r in results) else "Low"
        }
    
    def test_ssl_tls(self, target: str) -> Dict[str, Any]:
        """Test SSL/TLS configuration."""
        try:
            import ssl
            import socket
            
            # Extract hostname from URL
            if target.startswith("http://"):
                hostname = target[7:]
            elif target.startswith("https://"):
                hostname = target[8:]
            else:
                hostname = target
            
            # Remove path and port
            hostname = hostname.split('/')[0].split(':')[0]
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            
            results = []
            
            # Test TLS version
            weak_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
            is_weak_version = version in weak_versions
            
            results.append({
                "test": "TLS Version",
                "version": version,
                "vulnerable": is_weak_version,
                "details": f"TLS Version: {version}",
                "recommendation": "Use TLS 1.2 or higher"
            })
            
            # Test certificate validity
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            is_expired = datetime.now() > not_after
            
            results.append({
                "test": "Certificate Validity",
                "expires": not_after.isoformat(),
                "vulnerable": is_expired,
                "details": f"Certificate expires: {not_after}",
                "recommendation": "Certificate is expired" if is_expired else "Certificate is valid"
            })
            
            # Test cipher suite
            cipher_name = cipher[0]
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
            is_weak_cipher = any(weak in cipher_name for weak in weak_ciphers)
            
            results.append({
                "test": "Cipher Suite",
                "cipher": cipher_name,
                "vulnerable": is_weak_cipher,
                "details": f"Cipher: {cipher_name}",
                "recommendation": "Use strong cipher suites"
            })
            
            return {
                "test_type": "SSL/TLS Configuration",
                "vulnerabilities_found": len([r for r in results if r["vulnerable"]]),
                "results": results,
                "risk_level": "High" if any(r["vulnerable"] for r in results) else "Low"
            }
            
        except Exception as e:
            return {
                "test_type": "SSL/TLS Configuration",
                "vulnerabilities_found": 0,
                "results": [{
                    "test": "SSL/TLS Test",
                    "vulnerable": False,
                    "details": f"Error: {str(e)}",
                    "recommendation": "Unable to test SSL/TLS configuration"
                }],
                "risk_level": "Unknown"
            }
    
    def run_scan(self, targets: List[str], output_file: str = None) -> str:
        """Run security scan on multiple targets."""
        print(f"🚀 Starting automated security scan for {len(targets)} targets")
        print("=" * 60)
        
        scan_results = []
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.scan_config["threads"]) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    scan_results.append(result)
                    print(f"✅ Completed scan for: {target}")
                except Exception as e:
                    print(f"❌ Error scanning {target}: {str(e)}")
                    scan_results.append({
                        "target": target,
                        "error": str(e),
                        "scan_start": datetime.now().isoformat(),
                        "scan_end": datetime.now().isoformat()
                    })
        
        # Generate summary report
        total_vulnerabilities = sum(r.get("summary", {}).get("total_vulnerabilities", 0) for r in scan_results)
        
        report = {
            "scan_report": {
                "title": "Automated Security Scan Report",
                "generated_date": datetime.now().isoformat(),
                "targets_scanned": len(targets),
                "total_vulnerabilities": total_vulnerabilities,
                "scan_config": self.scan_config
            },
            "scan_results": scan_results,
            "recommendations": self.generate_recommendations(scan_results)
        }
        
        # Save report
        if output_file is None:
            output_file = f"security_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📊 Scan Summary:")
        print(f"  Targets scanned: {len(targets)}")
        print(f"  Total vulnerabilities: {total_vulnerabilities}")
        print(f"  Report saved: {output_file}")
        
        return output_file
    
    def generate_recommendations(self, scan_results: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on scan results."""
        recommendations = []
        
        critical_vulns = 0
        high_vulns = 0
        
        for result in scan_results:
            for test_name, test_result in result.get("tests", {}).items():
                if test_result["risk_level"] == "Critical":
                    critical_vulns += test_result["vulnerabilities_found"]
                elif test_result["risk_level"] == "High":
                    high_vulns += test_result["vulnerabilities_found"]
        
        if critical_vulns > 0:
            recommendations.append(f"🚨 CRITICAL: {critical_vulns} critical vulnerabilities found. Immediate remediation required.")
        
        if high_vulns > 0:
            recommendations.append(f"⚠️ HIGH: {high_vulns} high-risk vulnerabilities found. Remediate within 30 days.")
        
        if critical_vulns == 0 and high_vulns == 0:
            recommendations.append("✅ No critical or high-risk vulnerabilities found.")
        
        recommendations.append("🔍 Consider implementing automated security testing in CI/CD pipeline.")
        recommendations.append("📚 Regular security training for development teams recommended.")
        
        return recommendations

def main():
    """Main function for automated security scanner."""
    parser = argparse.ArgumentParser(description="Automated Security Scanner")
    parser.add_argument("--targets", nargs="+", help="Target URLs to scan")
    parser.add_argument("--config", help="Configuration file")
    parser.add_argument("--output", help="Output file for scan results")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    
    args = parser.parse_args()
    
    scanner = AutomatedSecurityScanner()
    scanner.load_scan_config(args.config)
    
    if args.threads:
        scanner.scan_config["threads"] = args.threads
    
    if args.targets:
        targets = args.targets
    else:
        # Interactive mode
        print("🔒 Automated Security Scanner")
        print("=" * 40)
        targets = []
        while True:
            target = input("Enter target URL (or 'done' to finish): ").strip()
            if target.lower() == 'done':
                break
            if target:
                targets.append(target)
    
    if not targets:
        print("❌ No targets specified. Exiting.")
        return
    
    # Run scan
    output_file = scanner.run_scan(targets, args.output)
    
    print(f"\n🎉 Scan completed! Results saved to: {output_file}")

if __name__ == "__main__":
    main() 