#!/usr/bin/env python3
"""
Network Analyzer for Mobile Security Testing
Analyzes network security, SSL/TLS configuration, and traffic patterns.
"""

import os
import subprocess
import json
import logging
import re
import zipfile
import tempfile
import shutil
from typing import Dict, List, Any, Optional
from pathlib import Path
import xml.etree.ElementTree as ET

class NetworkAnalyzer:
    """Network analysis of mobile applications."""
    
    def __init__(self, debug: bool = False):
        """Initialize network analyzer."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        
        # Network security patterns
        self.ssl_tls_patterns = [
            r'SSLContext',
            r'TLSv1\.2',
            r'TLSv1\.3',
            r'SSLSocket',
            r'HttpsURLConnection',
            r'OkHttpClient',
            r'Retrofit',
            r'Volley'
        ]
        
        self.certificate_pinning_patterns = [
            r'CertificatePinner',
            r'X509TrustManager',
            r'TrustManager',
            r'HostnameVerifier',
            r'SSLContext\.getInstance',
            r'KeyStore',
            r'CertificateFactory'
        ]
        
        self.insecure_network_patterns = [
            r'http://',
            r'HttpURLConnection',
            r'cleartextTraffic',
            r'usesCleartextTraffic',
            r'ALLOW_ALL_HOSTNAME_VERIFIER',
            r'TrustAllCerts',
            r'TrustAllHostnameVerifier'
        ]
        
        self.network_security_config_patterns = [
            r'networkSecurityConfig',
            r'network-security-config',
            r'domain-config',
            r'base-config',
            r'debug-overrides'
        ]
        
        self.api_endpoint_patterns = [
            r'https?://[^\s\'"]+',
            r'api\.',
            r'\.com/api',
            r'\.org/api',
            r'\.net/api',
            r'endpoint',
            r'baseUrl',
            r'BASE_URL'
        ]
        
        self.weak_crypto_patterns = [
            r'MD5',
            r'SHA1',
            r'DES',
            r'RC4',
            r'Blowfish',
            r'3DES'
        ]
        
    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """Analyze network security from APK."""
        self.logger.info(f"Starting network analysis of APK: {apk_path}")
        
        results = {
            "network_config": {},
            "ssl_tls_analysis": {},
            "certificate_pinning": {},
            "network_security_config": {},
            "api_endpoints": [],
            "traffic_analysis": {},
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Extract network configuration
            results["network_config"] = self._extract_network_config(apk_path)
            
            # Analyze SSL/TLS implementation
            results["ssl_tls_analysis"] = self._analyze_ssl_tls(apk_path)
            
            # Analyze certificate pinning
            results["certificate_pinning"] = self._analyze_certificate_pinning(apk_path)
            
            # Analyze network security configuration
            results["network_security_config"] = self._analyze_network_security_config(apk_path)
            
            # Analyze API endpoints
            results["api_endpoints"] = self._analyze_api_endpoints(apk_path)
            
            # Analyze network traffic patterns
            results["traffic_analysis"] = self._analyze_network_traffic(apk_path)
            
        except Exception as e:
            self.logger.error(f"Error during network analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_network_vulnerabilities(results)
        results["security_issues"] = self._identify_network_security_issues(results)
        results["recommendations"] = self._generate_network_recommendations(results)
        
        return results
    
    def analyze_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze network security from IPA."""
        self.logger.info(f"Starting network analysis of IPA: {ipa_path}")
        
        results = {
            "network_config": {},
            "ssl_tls_analysis": {},
            "certificate_pinning": {},
            "app_transport_security": {},
            "api_endpoints": [],
            "traffic_analysis": {},
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Extract iOS network configuration
            results["network_config"] = self._extract_ios_network_config(ipa_path)
            
            # Analyze SSL/TLS implementation
            results["ssl_tls_analysis"] = self._analyze_ios_ssl_tls(ipa_path)
            
            # Analyze certificate pinning
            results["certificate_pinning"] = self._analyze_ios_certificate_pinning(ipa_path)
            
            # Analyze App Transport Security
            results["app_transport_security"] = self._analyze_app_transport_security(ipa_path)
            
            # Analyze API endpoints
            results["api_endpoints"] = self._analyze_ios_api_endpoints(ipa_path)
            
            # Analyze network traffic patterns
            results["traffic_analysis"] = self._analyze_ios_network_traffic(ipa_path)
            
        except Exception as e:
            self.logger.error(f"Error during iOS network analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_ios_network_vulnerabilities(results)
        results["security_issues"] = self._identify_ios_network_security_issues(results)
        results["recommendations"] = self._generate_ios_network_recommendations(results)
        
        return results
    
    def _extract_network_config(self, apk_path: str) -> Dict[str, Any]:
        """Extract network configuration from APK."""
        network_config = {
            "cleartext_traffic": False,
            "network_security_config": None,
            "internet_permission": False,
            "network_permissions": [],
            "security_issues": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check AndroidManifest.xml for network configuration
                if "AndroidManifest.xml" in apk_zip.namelist():
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    root = ET.fromstring(manifest_data)
                    
                    # Check for cleartext traffic
                    application = root.find(".//application")
                    if application is not None:
                        cleartext = application.get("android:usesCleartextTraffic")
                        if cleartext == "true":
                            network_config["cleartext_traffic"] = True
                            network_config["security_issues"].append({
                                "type": "cleartext_traffic_enabled",
                                "severity": "high",
                                "description": "Cleartext traffic is enabled",
                                "risk": "Network traffic is not encrypted"
                            })
                    
                    # Check for network security config
                    if application is not None:
                        nsc = application.get("android:networkSecurityConfig")
                        if nsc:
                            network_config["network_security_config"] = nsc
                    
                    # Check for network permissions
                    network_permissions = [
                        "android.permission.INTERNET",
                        "android.permission.ACCESS_NETWORK_STATE",
                        "android.permission.ACCESS_WIFI_STATE",
                        "android.permission.CHANGE_WIFI_STATE"
                    ]
                    
                    for permission in root.findall(".//uses-permission"):
                        perm_name = permission.get("android:name")
                        if perm_name in network_permissions:
                            network_config["network_permissions"].append(perm_name)
                            if perm_name == "android.permission.INTERNET":
                                network_config["internet_permission"] = True
                
                # Check for network security config file
                for filename in apk_zip.namelist():
                    if "network_security_config" in filename or filename.endswith("network_security_config.xml"):
                        network_config["network_security_config"] = filename
        
        except Exception as e:
            self.logger.error(f"Error extracting network config: {str(e)}")
            network_config["error"] = str(e)
        
        return network_config
    
    def _extract_ios_network_config(self, ipa_path: str) -> Dict[str, Any]:
        """Extract iOS network configuration."""
        network_config = {
            "app_transport_security": True,
            "allows_arbitrary_loads": False,
            "network_permissions": [],
            "security_issues": []
        }
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                # Look for Info.plist
                for filename in ipa_zip.namelist():
                    if filename.endswith("Info.plist"):
                        try:
                            plist_data = ipa_zip.read(filename)
                            # Basic check for App Transport Security settings
                            plist_text = plist_data.decode('utf-8', errors='ignore')
                            
                            if "NSAppTransportSecurity" in plist_text:
                                if "NSAllowsArbitraryLoads" in plist_text:
                                    network_config["allows_arbitrary_loads"] = True
                                    network_config["security_issues"].append({
                                        "type": "allows_arbitrary_loads",
                                        "severity": "high",
                                        "description": "App Transport Security allows arbitrary loads",
                                        "risk": "Network traffic may not be encrypted"
                                    })
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error extracting iOS network config: {str(e)}")
            network_config["error"] = str(e)
        
        return network_config
    
    def _analyze_ssl_tls(self, apk_path: str) -> Dict[str, Any]:
        """Analyze SSL/TLS implementation."""
        ssl_tls_analysis = {
            "ssl_tls_used": False,
            "ssl_tls_patterns": [],
            "protocol_versions": [],
            "cipher_suites": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt', '.xml')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for SSL/TLS patterns
                            for pattern in self.ssl_tls_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    ssl_tls_analysis["ssl_tls_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "SSL/TLS implementation detected"
                                    })
                                    ssl_tls_analysis["ssl_tls_used"] = True
                            
                            # Check for protocol versions
                            protocol_patterns = [
                                r'TLSv1\.2',
                                r'TLSv1\.3',
                                r'TLSv1\.1',
                                r'TLSv1\.0',
                                r'SSLv3',
                                r'SSLv2'
                            ]
                            
                            for protocol in protocol_patterns:
                                if re.search(protocol, content, re.IGNORECASE):
                                    ssl_tls_analysis["protocol_versions"].append({
                                        "file": filename,
                                        "protocol": protocol,
                                        "secure": protocol in ["TLSv1.2", "TLSv1.3"]
                                    })
                            
                            # Check for weak crypto
                            for weak_pattern in self.weak_crypto_patterns:
                                if re.search(weak_pattern, content, re.IGNORECASE):
                                    ssl_tls_analysis["security_issues"].append({
                                        "type": "weak_crypto",
                                        "severity": "medium",
                                        "description": f"Weak cryptographic algorithm: {weak_pattern}",
                                        "file": filename,
                                        "risk": "Weak crypto may be compromised"
                                    })
                            
                        except Exception as e:
                            continue
                
                # Generate recommendations
                if not ssl_tls_analysis["ssl_tls_used"]:
                    ssl_tls_analysis["security_issues"].append({
                        "type": "no_ssl_tls",
                        "severity": "high",
                        "description": "No SSL/TLS implementation detected",
                        "risk": "Network traffic may not be encrypted"
                    })
                    ssl_tls_analysis["recommendations"].append(
                        "Implement SSL/TLS for all network communications"
                    )
                
                # Check for weak protocols
                weak_protocols = [p for p in ssl_tls_analysis["protocol_versions"] if not p["secure"]]
                if weak_protocols:
                    ssl_tls_analysis["security_issues"].append({
                        "type": "weak_protocols",
                        "severity": "medium",
                        "description": f"Found {len(weak_protocols)} weak SSL/TLS protocols",
                        "risk": "Weak protocols may be vulnerable to attacks"
                    })
                    ssl_tls_analysis["recommendations"].append(
                        "Use only TLS 1.2 and TLS 1.3 protocols"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in SSL/TLS analysis: {str(e)}")
            ssl_tls_analysis["error"] = str(e)
        
        return ssl_tls_analysis
    
    def _analyze_ios_ssl_tls(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS SSL/TLS implementation."""
        ssl_tls_analysis = {
            "ssl_tls_used": False,
            "ssl_tls_patterns": [],
            "protocol_versions": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                for filename in ipa_zip.namelist():
                    if filename.endswith(('.swift', '.m', '.h', '.plist')):
                        try:
                            content = ipa_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for iOS SSL/TLS patterns
                            ios_ssl_patterns = [
                                r'NSURLSession',
                                r'URLSession',
                                r'NSURLConnection',
                                r'CFNetwork',
                                r'kSecTrustResult',
                                r'SecTrustEvaluate'
                            ]
                            
                            for pattern in ios_ssl_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    ssl_tls_analysis["ssl_tls_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "iOS SSL/TLS implementation detected"
                                    })
                                    ssl_tls_analysis["ssl_tls_used"] = True
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error in iOS SSL/TLS analysis: {str(e)}")
            ssl_tls_analysis["error"] = str(e)
        
        return ssl_tls_analysis
    
    def _analyze_certificate_pinning(self, apk_path: str) -> Dict[str, Any]:
        """Analyze certificate pinning implementation."""
        cert_pinning_analysis = {
            "certificate_pinning_used": False,
            "pinning_patterns": [],
            "trust_managers": [],
            "hostname_verifiers": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for certificate pinning patterns
                            for pattern in self.certificate_pinning_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    cert_pinning_analysis["pinning_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "Certificate pinning implementation detected"
                                    })
                                    cert_pinning_analysis["certificate_pinning_used"] = True
                            
                            # Check for trust all certificates
                            trust_all_patterns = [
                                r'TrustAllCerts',
                                r'TrustAllHostnameVerifier',
                                r'ALLOW_ALL_HOSTNAME_VERIFIER',
                                r'X509TrustManager.*return.*true',
                                r'HostnameVerifier.*return.*true'
                            ]
                            
                            for pattern in trust_all_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    cert_pinning_analysis["security_issues"].append({
                                        "type": "trust_all_certificates",
                                        "severity": "high",
                                        "description": "Trust all certificates implementation detected",
                                        "file": filename,
                                        "risk": "Vulnerable to man-in-the-middle attacks"
                                    })
                            
                        except Exception as e:
                            continue
                
                # Generate recommendations
                if not cert_pinning_analysis["certificate_pinning_used"]:
                    cert_pinning_analysis["security_issues"].append({
                        "type": "no_certificate_pinning",
                        "severity": "medium",
                        "description": "No certificate pinning detected",
                        "risk": "Vulnerable to certificate-based attacks"
                    })
                    cert_pinning_analysis["recommendations"].append(
                        "Implement certificate pinning to prevent MITM attacks"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in certificate pinning analysis: {str(e)}")
            cert_pinning_analysis["error"] = str(e)
        
        return cert_pinning_analysis
    
    def _analyze_ios_certificate_pinning(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS certificate pinning implementation."""
        cert_pinning_analysis = {
            "certificate_pinning_used": False,
            "pinning_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                for filename in ipa_zip.namelist():
                    if filename.endswith(('.swift', '.m', '.h')):
                        try:
                            content = ipa_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for iOS certificate pinning patterns
                            ios_pinning_patterns = [
                                r'SSLPinningMode',
                                r'AFSecurityPolicy',
                                r'certificatePinning',
                                r'pinnedCertificates',
                                r'SSLPinningModePublicKey',
                                r'SSLPinningModeCertificate'
                            ]
                            
                            for pattern in ios_pinning_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    cert_pinning_analysis["pinning_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "iOS certificate pinning implementation detected"
                                    })
                                    cert_pinning_analysis["certificate_pinning_used"] = True
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error in iOS certificate pinning analysis: {str(e)}")
            cert_pinning_analysis["error"] = str(e)
        
        return cert_pinning_analysis
    
    def _analyze_network_security_config(self, apk_path: str) -> Dict[str, Any]:
        """Analyze network security configuration."""
        nsc_analysis = {
            "network_security_config_present": False,
            "config_file": None,
            "domain_configs": [],
            "base_config": {},
            "debug_overrides": {},
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for network security config file
                for filename in apk_zip.namelist():
                    if "network_security_config" in filename or filename.endswith("network_security_config.xml"):
                        nsc_analysis["network_security_config_present"] = True
                        nsc_analysis["config_file"] = filename
                        
                        try:
                            config_data = apk_zip.read(filename)
                            config_content = config_data.decode('utf-8', errors='ignore')
                            
                            # Basic analysis of network security config
                            if "cleartextTrafficPermitted" in config_content:
                                nsc_analysis["security_issues"].append({
                                    "type": "cleartext_traffic_permitted",
                                    "severity": "high",
                                    "description": "Cleartext traffic permitted in network security config",
                                    "risk": "Network traffic may not be encrypted"
                                })
                            
                            if "trust-anchors" in config_content:
                                nsc_analysis["base_config"]["trust_anchors"] = "configured"
                            
                        except Exception as e:
                            continue
                
                if not nsc_analysis["network_security_config_present"]:
                    nsc_analysis["security_issues"].append({
                        "type": "no_network_security_config",
                        "severity": "medium",
                        "description": "No network security configuration found",
                        "risk": "Using default network security settings"
                    })
                    nsc_analysis["recommendations"].append(
                        "Implement network security configuration for better security control"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in network security config analysis: {str(e)}")
            nsc_analysis["error"] = str(e)
        
        return nsc_analysis
    
    def _analyze_app_transport_security(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS App Transport Security."""
        ats_analysis = {
            "app_transport_security_enabled": True,
            "allows_arbitrary_loads": False,
            "allows_local_networking": False,
            "exception_domains": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                for filename in ipa_zip.namelist():
                    if filename.endswith("Info.plist"):
                        try:
                            plist_data = ipa_zip.read(filename)
                            plist_content = plist_data.decode('utf-8', errors='ignore')
                            
                            if "NSAllowsArbitraryLoads" in plist_content:
                                ats_analysis["allows_arbitrary_loads"] = True
                                ats_analysis["security_issues"].append({
                                    "type": "allows_arbitrary_loads",
                                    "severity": "high",
                                    "description": "App Transport Security allows arbitrary loads",
                                    "risk": "Network traffic may not be encrypted"
                                })
                            
                            if "NSAllowsLocalNetworking" in plist_content:
                                ats_analysis["allows_local_networking"] = True
                                ats_analysis["security_issues"].append({
                                    "type": "allows_local_networking",
                                    "severity": "medium",
                                    "description": "App Transport Security allows local networking",
                                    "risk": "May allow insecure local connections"
                                })
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error in App Transport Security analysis: {str(e)}")
            ats_analysis["error"] = str(e)
        
        return ats_analysis
    
    def _analyze_api_endpoints(self, apk_path: str) -> List[Dict[str, Any]]:
        """Analyze API endpoints and their security."""
        api_endpoints = []
        
        # Filter out non-API patterns
        exclude_patterns = [
            r'http://schemas\.android\.com',
            r'http://www\.w3\.org',
            r'http://xmlns\.com',
            r'android\.app\.',
            r'android\.content\.',
            r'android\.view\.',
            r'android\.widget\.',
            r'android\.support\.',
            r'androidx\.',
            r'res/',
            r'assets/',
            r'META-INF/',
            r'AndroidManifest\.xml',
            r'\.xml$',
            r'\.properties$'
        ]
        
        try:
            # Use APKTool to decompile the APK first
            import tempfile
            import subprocess
            import os
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Decompile APK using APKTool
                try:
                    # Check if apktool is available
                    apktool_cmd = "apktool"
                    try:
                        subprocess.run([apktool_cmd, "--version"], capture_output=True, check=True)
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        # Try with java -jar
                        apktool_cmd = "java -jar C:\\Users\\DELL\\apktool\\apktool.jar"
                    
                    # Decompile APK
                    if apktool_cmd.startswith("java -jar"):
                        cmd = apktool_cmd.split() + ["d", apk_path, "-o", temp_dir, "-f"]
                    else:
                        cmd = [apktool_cmd, "d", apk_path, "-o", temp_dir, "-f"]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0:
                        self.logger.info(f"APK decompiled successfully to {temp_dir}")
                        
                        # Now analyze the decompiled files
                        for root, dirs, files in os.walk(temp_dir):
                            for file in files:
                                if file.endswith(('.java', '.kt', '.xml')):
                                    file_path = os.path.join(root, file)
                                    try:
                                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                            content = f.read()
                                            
                                            # Find API endpoints with improved patterns
                                            api_patterns = [
                                                r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\'"]*)?',
                                                r'api\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s\'"]*)?',
                                                r'[a-zA-Z0-9.-]+\.com/api(?:/[^\s\'"]*)?',
                                                r'[a-zA-Z0-9.-]+\.org/api(?:/[^\s\'"]*)?',
                                                r'[a-zA-Z0-9.-]+\.net/api(?:/[^\s\'"]*)?',
                                                r'baseUrl\s*[=:]\s*["\']([^"\']+)["\']',
                                                r'BASE_URL\s*[=:]\s*["\']([^"\']+)["\']',
                                                r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
                                                r'url\s*[=:]\s*["\']([^"\']+)["\']',
                                                r'URL\s*[=:]\s*["\']([^"\']+)["\']',
                                                r'loadUrl\s*\(\s*["\']([^"\']+)["\']',
                                                r'HttpURLConnection\s*\(\s*["\']([^"\']+)["\']',
                                                r'OkHttpClient.*["\']([^"\']+)["\']',
                                                r'Retrofit.*["\']([^"\']+)["\']'
                                            ]
                                            
                                            for pattern in api_patterns:
                                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                                for match in matches:
                                                    endpoint = match.group(1) if len(match.groups()) > 0 else match.group()
                                                    
                                                    # Skip if matches exclude patterns
                                                    should_exclude = False
                                                    for exclude_pattern in exclude_patterns:
                                                        if re.search(exclude_pattern, endpoint, re.IGNORECASE):
                                                            should_exclude = True
                                                            break
                                                    
                                                    if should_exclude:
                                                        continue
                                                    
                                                    # Clean up endpoint
                                                    endpoint = endpoint.strip('"\'')
                                                    if not endpoint.startswith(('http://', 'https://')):
                                                        continue
                                                    
                                                    # Analyze endpoint security
                                                    is_secure = endpoint.startswith('https://')
                                                    is_api = 'api' in endpoint.lower() or '/api/' in endpoint.lower()
                                                    
                                                    # Extract domain for grouping
                                                    domain = re.search(r'https?://([^/]+)', endpoint)
                                                    domain = domain.group(1) if domain else 'unknown'
                                                    
                                                    api_endpoints.append({
                                                        "endpoint": endpoint,
                                                        "file": os.path.relpath(file_path, temp_dir),
                                                        "domain": domain,
                                                        "secure": is_secure,
                                                        "is_api": is_api,
                                                        "category": "API" if is_api else "External",
                                                        "risk": "Insecure endpoint" if not is_secure else "Secure endpoint"
                                                    })
                                            
                                    except Exception as e:
                                        continue
                    else:
                        self.logger.error(f"APKTool decompilation failed: {result.stderr}")
                        
                except Exception as e:
                    self.logger.error(f"Error during APK decompilation: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Error in API endpoint analysis: {str(e)}")
        
        # Remove duplicates and sort
        unique_endpoints = []
        seen_endpoints = set()
        for ep in api_endpoints:
            if ep["endpoint"] not in seen_endpoints:
                unique_endpoints.append(ep)
                seen_endpoints.add(ep["endpoint"])
        
        return sorted(unique_endpoints, key=lambda x: x["domain"])
    
    def _analyze_ios_api_endpoints(self, ipa_path: str) -> List[Dict[str, Any]]:
        """Analyze iOS API endpoints."""
        api_endpoints = []
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                for filename in ipa_zip.namelist():
                    if filename.endswith(('.swift', '.m', '.h', '.plist')):
                        try:
                            content = ipa_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Find API endpoints
                            for pattern in self.api_endpoint_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    endpoint = match.group()
                                    
                                    is_secure = endpoint.startswith('https://')
                                    is_api = 'api' in endpoint.lower()
                                    
                                    api_endpoints.append({
                                        "endpoint": endpoint,
                                        "file": filename,
                                        "secure": is_secure,
                                        "is_api": is_api,
                                        "risk": "Insecure endpoint" if not is_secure else "Secure endpoint"
                                    })
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error in iOS API endpoint analysis: {str(e)}")
        
        return api_endpoints
    
    def _analyze_network_traffic(self, apk_path: str) -> Dict[str, Any]:
        """Analyze network traffic patterns."""
        traffic_analysis = {
            "http_traffic": False,
            "https_traffic": False,
            "insecure_patterns": [],
            "secure_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt', '.xml')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for insecure patterns
                            for pattern in self.insecure_network_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    traffic_analysis["insecure_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "risk": "Insecure network pattern detected"
                                    })
                                    traffic_analysis["http_traffic"] = True
                            
                            # Check for secure patterns
                            secure_patterns = [
                                r'https://',
                                r'HttpsURLConnection',
                                r'SSLSocket',
                                r'SSLContext'
                            ]
                            
                            for pattern in secure_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    traffic_analysis["secure_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "Secure network pattern detected"
                                    })
                                    traffic_analysis["https_traffic"] = True
                            
                        except Exception as e:
                            continue
                
                # Generate security issues
                if traffic_analysis["http_traffic"]:
                    traffic_analysis["security_issues"].append({
                        "type": "insecure_traffic",
                        "severity": "high",
                        "description": "Insecure HTTP traffic detected",
                        "risk": "Network traffic is not encrypted"
                    })
                    traffic_analysis["recommendations"].append(
                        "Use HTTPS for all network communications"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in network traffic analysis: {str(e)}")
            traffic_analysis["error"] = str(e)
        
        return traffic_analysis
    
    def _analyze_ios_network_traffic(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS network traffic patterns."""
        traffic_analysis = {
            "http_traffic": False,
            "https_traffic": False,
            "insecure_patterns": [],
            "secure_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                for filename in ipa_zip.namelist():
                    if filename.endswith(('.swift', '.m', '.h', '.plist')):
                        try:
                            content = ipa_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for insecure patterns
                            if re.search(r'http://', content, re.IGNORECASE):
                                traffic_analysis["insecure_patterns"].append({
                                    "file": filename,
                                    "pattern": "http://",
                                    "risk": "Insecure HTTP traffic detected"
                                })
                                traffic_analysis["http_traffic"] = True
                            
                            # Check for secure patterns
                            if re.search(r'https://', content, re.IGNORECASE):
                                traffic_analysis["secure_patterns"].append({
                                    "file": filename,
                                    "pattern": "https://",
                                    "usage": "Secure HTTPS traffic detected"
                                })
                                traffic_analysis["https_traffic"] = True
                            
                        except Exception as e:
                            continue
                
                # Generate security issues
                if traffic_analysis["http_traffic"]:
                    traffic_analysis["security_issues"].append({
                        "type": "insecure_traffic",
                        "severity": "high",
                        "description": "Insecure HTTP traffic detected",
                        "risk": "Network traffic is not encrypted"
                    })
                    traffic_analysis["recommendations"].append(
                        "Use HTTPS for all network communications"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in iOS network traffic analysis: {str(e)}")
            traffic_analysis["error"] = str(e)
        
        return traffic_analysis
    
    def _identify_network_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify network vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for cleartext traffic
            network_config = results.get("network_config", {})
            if network_config.get("cleartext_traffic"):
                vulnerabilities.append({
                    "type": "cleartext_traffic",
                    "severity": "high",
                    "description": "Cleartext traffic is enabled",
                    "recommendation": "Disable cleartext traffic and use HTTPS only"
                })
            
            # Check for SSL/TLS issues
            ssl_tls = results.get("ssl_tls_analysis", {})
            for issue in ssl_tls.get("security_issues", []):
                vulnerabilities.append(issue)
            
            # Check for certificate pinning issues
            cert_pinning = results.get("certificate_pinning", {})
            for issue in cert_pinning.get("security_issues", []):
                vulnerabilities.append(issue)
            
            # Check for network security config issues
            nsc = results.get("network_security_config", {})
            for issue in nsc.get("security_issues", []):
                vulnerabilities.append(issue)
            
            # Check for insecure API endpoints
            api_endpoints = results.get("api_endpoints", [])
            insecure_endpoints = [ep for ep in api_endpoints if not ep.get("secure", True)]
            if insecure_endpoints:
                vulnerabilities.append({
                    "type": "insecure_api_endpoints",
                    "severity": "high",
                    "description": f"Found {len(insecure_endpoints)} insecure API endpoints",
                    "recommendation": "Use HTTPS for all API endpoints"
                })
            
            # Check for traffic analysis issues
            traffic = results.get("traffic_analysis", {})
            for issue in traffic.get("security_issues", []):
                vulnerabilities.append(issue)
        
        except Exception as e:
            self.logger.error(f"Error identifying network vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _identify_ios_network_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS network vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for App Transport Security issues
            ats = results.get("app_transport_security", {})
            for issue in ats.get("security_issues", []):
                vulnerabilities.append(issue)
            
            # Check for SSL/TLS issues
            ssl_tls = results.get("ssl_tls_analysis", {})
            for issue in ssl_tls.get("security_issues", []):
                vulnerabilities.append(issue)
            
            # Check for certificate pinning issues
            cert_pinning = results.get("certificate_pinning", {})
            for issue in cert_pinning.get("security_issues", []):
                vulnerabilities.append(issue)
            
            # Check for insecure API endpoints
            api_endpoints = results.get("api_endpoints", [])
            insecure_endpoints = [ep for ep in api_endpoints if not ep.get("secure", True)]
            if insecure_endpoints:
                vulnerabilities.append({
                    "type": "insecure_api_endpoints",
                    "severity": "high",
                    "description": f"Found {len(insecure_endpoints)} insecure API endpoints",
                    "recommendation": "Use HTTPS for all API endpoints"
                })
            
            # Check for traffic analysis issues
            traffic = results.get("traffic_analysis", {})
            for issue in traffic.get("security_issues", []):
                vulnerabilities.append(issue)
        
        except Exception as e:
            self.logger.error(f"Error identifying iOS network vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _identify_network_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify general network security issues."""
        issues = []
        
        # Add any additional network security issues here
        return issues
    
    def _identify_ios_network_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS-specific network security issues."""
        issues = []
        
        # Add any additional iOS network security issues here
        return issues
    
    def _generate_network_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate network security recommendations."""
        recommendations = [
            "Use HTTPS for all network communications",
            "Implement certificate pinning to prevent MITM attacks",
            "Use only TLS 1.2 and TLS 1.3 protocols",
            "Implement network security configuration",
            "Disable cleartext traffic",
            "Use strong cipher suites",
            "Implement proper error handling for network failures",
            "Regular security audits of network communications",
            "Monitor network traffic for anomalies",
            "Use secure network libraries and frameworks"
        ]
        
        return recommendations
    
    def _generate_ios_network_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate iOS-specific network recommendations."""
        recommendations = [
            "Enable App Transport Security",
            "Use HTTPS for all network communications",
            "Implement certificate pinning",
            "Avoid NSAllowsArbitraryLoads",
            "Use secure network libraries",
            "Implement proper error handling",
            "Regular security audits of network communications",
            "Monitor network traffic for anomalies"
        ]
        
        return recommendations 