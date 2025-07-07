#!/usr/bin/env python3
"""
Code Analyzer for Mobile Security Testing
Analyzes source code for security vulnerabilities.
"""

import os
import subprocess
import json
import logging
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
import tempfile
import shutil
import zipfile

class CodeAnalyzer:
    """Code analysis of mobile applications."""
    
    def __init__(self, debug: bool = False, config: Dict[str, Any] = None):
        """Initialize code analyzer."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        # Get apktool path from config
        self.apktool_path = self.config.get("tools", {}).get("apktool_path", "apktool")
        
    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """Analyze source code security from APK."""
        self.logger.info(f"Starting code analysis of APK: {apk_path}")
        
        results = {
            "code_quality": {},
            "security_patterns": [],
            "vulnerabilities": [],
            "hardcoded_secrets": [],
            "injection_vulnerabilities": [],
            "authentication_issues": [],
            "authorization_issues": [],
            "cryptography_issues": [],
            "recommendations": [],
            "summary": {}
        }
        
        # Check if apktool is available
        self.logger.info(f"Checking APKTool availability at: {self.apktool_path}")
        try:
            # Handle both direct path and java -jar command
            if self.apktool_path.startswith("java -jar"):
                cmd = self.apktool_path.split() + ["--version"]
            else:
                cmd = [self.apktool_path, "--version"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info(f"APKTool version: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self.logger.error(f"APKTool check failed: {str(e)}")
            results["error"] = f"apktool not found at {self.apktool_path}. Please install apktool for code analysis."
            results["code_quality"] = {
                "total_files": 0,
                "java_files": 0,
                "kotlin_files": 0,
                "xml_files": 0,
                "issues": [],
                "metrics": {},
                "note": "Code analysis requires apktool to be installed"
            }
            results["summary"] = {
                "total_files": 0,
                "java_files": 0,
                "kotlin_files": 0,
                "xml_files": 0,
                "issues": 0,
                "metrics": {},
                "note": "apktool not available"
            }
            return results
        
        try:
            # Decompile APK
            self.logger.info(f"Starting APK decompilation with APKTool...")
            self.logger.info(f"APK file: {apk_path}")
            self.logger.info(f"APKTool command: {self.apktool_path} d {apk_path} -o <temp_dir> -f")
            
            with tempfile.TemporaryDirectory() as temp_dir:
                self.logger.info(f"Created temporary directory: {temp_dir}")
                self.logger.info("Running APKTool decompilation (this may take several minutes for large APKs)...")
                
                # Handle both direct path and java -jar command
                if self.apktool_path.startswith("java -jar"):
                    cmd = self.apktool_path.split() + ["d", apk_path, "-o", temp_dir, "-f"]
                else:
                    cmd = [self.apktool_path, "d", apk_path, "-o", temp_dir, "-f"]
                
                self.logger.info(f"Executing command: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # Increased timeout to 10 minutes
                )
                
                if result.returncode == 0:
                    self.logger.info("APKTool decompilation completed successfully!")
                    self.logger.info(f"Decompiled files saved to: {temp_dir}")
                    
                    # Analyze code quality
                    self.logger.info("Starting code quality analysis...")
                    results["code_quality"] = self._analyze_code_quality(temp_dir)
                    # Find security patterns
                    self.logger.info("Analyzing security patterns...")
                    results["security_patterns"] = self._find_security_patterns(temp_dir)
                    
                    # Find hardcoded secrets
                    self.logger.info("Searching for hardcoded secrets...")
                    results["hardcoded_secrets"] = self._find_hardcoded_secrets(temp_dir)
                    
                    # Find injection vulnerabilities
                    self.logger.info("Checking for injection vulnerabilities...")
                    results["injection_vulnerabilities"] = self._find_injection_vulnerabilities(temp_dir)
                    
                    # Find authentication issues
                    self.logger.info("Analyzing authentication mechanisms...")
                    results["authentication_issues"] = self._find_authentication_issues(temp_dir)
                    
                    # Find authorization issues
                    self.logger.info("Checking authorization controls...")
                    results["authorization_issues"] = self._find_authorization_issues(temp_dir)
                    
                    # Find cryptography issues
                    self.logger.info("Analyzing cryptography implementation...")
                    results["cryptography_issues"] = self._find_cryptography_issues(temp_dir)
                    
                    # Find biometric flaws
                    self.logger.info("Checking biometric security...")
                    results["biometric_flaws"] = self._find_biometric_flaws(temp_dir)
                    
                    # Find insecure deserialization
                    self.logger.info("Checking for insecure deserialization...")
                    results["insecure_deserialization"] = self._find_insecure_deserialization(temp_dir)
                    
                    # Find path traversal
                    self.logger.info("Checking for path traversal vulnerabilities...")
                    results["path_traversal"] = self._find_path_traversal(temp_dir)
                    
                    # Find clipboard exposure
                    self.logger.info("Checking for clipboard exposure...")
                    results["clipboard_exposure"] = self._find_clipboard_exposure(temp_dir)
                    
                    # Find keyboard caching
                    self.logger.info("Checking for keyboard caching issues...")
                    results["keyboard_caching"] = self._find_keyboard_caching(temp_dir)
                    
                    # Find background screenshot
                    self.logger.info("Checking for background screenshot vulnerabilities...")
                    results["background_screenshot"] = self._find_background_screenshot(temp_dir)
                    
                    # Find SSRF
                    self.logger.info("Checking for SSRF vulnerabilities...")
                    results["ssrf"] = self._find_ssrf(temp_dir)
                    
                    # Find PII in logs
                    self.logger.info("Checking for PII exposure in logs...")
                    results["pii_in_logs"] = self._find_pii_in_logs(temp_dir)
                    
                    # Find custom crypto
                    self.logger.info("Checking for custom cryptography...")
                    results["custom_crypto"] = self._find_custom_crypto(temp_dir)
                    
                    # Find insecure key management
                    self.logger.info("Checking for insecure key management...")
                    results["insecure_key_management"] = self._find_insecure_key_management(temp_dir)
                    
                    # Find jailbreak/root bypass
                    self.logger.info("Checking for jailbreak/root bypass...")
                    results["jailbreak_root_bypass"] = self._find_jailbreak_root_bypass(temp_dir)
                    
                    # Find step-up authentication
                    self.logger.info("Checking for step-up authentication...")
                    results["step_up_auth"] = self._find_step_up_auth(temp_dir)
                    
                    # Find WebView security issues
                    self.logger.info("Checking for WebView security issues...")
                    results["webview_security"] = self._find_webview_security(temp_dir)
                    
                    # Find intent injection issues
                    self.logger.info("Checking for intent injection issues...")
                    results["intent_injection"] = self._find_intent_injection(temp_dir)
                    
                    # Find certificate bypass issues
                    self.logger.info("Checking for certificate bypass issues...")
                    results["certificate_bypass"] = self._find_certificate_bypass(temp_dir)
                    
                    # Find sensitive data handling issues
                    self.logger.info("Checking for sensitive data handling issues...")
                    results["sensitive_data_handling"] = self._find_sensitive_data_handling(temp_dir)
                else:
                    self.logger.error(f"APKTool decompilation failed with return code: {result.returncode}")
                    self.logger.error(f"APKTool stderr: {result.stderr}")
                    self.logger.error(f"APKTool stdout: {result.stdout}")
                    results["error"] = f"apktool failed: {result.stderr}"
                    results["code_quality"] = {
                        "total_files": 0,
                        "java_files": 0,
                        "kotlin_files": 0,
                        "xml_files": 0,
                        "issues": [],
                        "metrics": {},
                        "note": f"apktool decompilation failed: {result.stderr}"
                    }
        except Exception as e:
            self.logger.error(f"Error during code analysis: {str(e)}")
            results["error"] = str(e)
            results["code_quality"] = {
                "total_files": 0,
                "java_files": 0,
                "kotlin_files": 0,
                "xml_files": 0,
                "issues": [],
                "metrics": {},
                "note": f"Analysis error: {str(e)}"
            }
        
        # Generate vulnerability findings
        self.logger.info("Generating vulnerability findings...")
        results["vulnerabilities"] = self._identify_code_vulnerabilities(results)
        results["recommendations"] = self._generate_code_recommendations(results)
        
        self.logger.info("Code analysis completed successfully!")
        
        # Add summary stats
        cq = results.get("code_quality", {})
        results["summary"] = {
            "total_files": cq.get("total_files", 0),
            "java_files": cq.get("java_files", 0),
            "kotlin_files": cq.get("kotlin_files", 0),
            "xml_files": cq.get("xml_files", 0),
            "issues": len(cq.get("issues", [])),
            "metrics": cq.get("metrics", {}),
            "note": cq.get("note", "")
        }
        
        return results
    
    def analyze_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze source code security from IPA."""
        self.logger.info(f"Starting code analysis of IPA: {ipa_path}")
        
        results = {
            "code_quality": {},
            "security_patterns": [],
            "vulnerabilities": [],
            "hardcoded_secrets": [],
            "injection_vulnerabilities": [],
            "authentication_issues": [],
            "authorization_issues": [],
            "cryptography_issues": [],
            "recommendations": []
        }
        
        try:
            # Extract IPA
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Extract binary files for analysis
                    for filename in ipa_zip.namelist():
                        if filename.endswith((".dylib", ".framework")):
                            ipa_zip.extract(filename, temp_dir)
                    
                    # Analyze binary code (simplified)
                    results["code_quality"] = self._analyze_ios_code_quality(temp_dir)
                    results["security_patterns"] = self._find_ios_security_patterns(temp_dir)
                    results["hardcoded_secrets"] = self._find_ios_hardcoded_secrets(temp_dir)
        
        except Exception as e:
            self.logger.error(f"Error during iOS code analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_ios_code_vulnerabilities(results)
        results["recommendations"] = self._generate_ios_code_recommendations(results)
        
        return results
    
    def _analyze_code_quality(self, temp_dir: str) -> Dict[str, Any]:
        """Analyze code quality and best practices."""
        quality = {
            "total_files": 0,
            "java_files": 0,
            "kotlin_files": 0,
            "xml_files": 0,
            "issues": [],
            "metrics": {}
        }
        
        try:
            # Count files
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    quality["total_files"] += 1
                    
                    if file.endswith(".java"):
                        quality["java_files"] += 1
                    elif file.endswith(".kt"):
                        quality["kotlin_files"] += 1
                    elif file.endswith(".xml"):
                        quality["xml_files"] += 1
            
            # Analyze code patterns
            quality["issues"] = self._find_code_quality_issues(temp_dir)
            quality["metrics"] = self._calculate_code_metrics(temp_dir)
        
        except Exception as e:
            self.logger.error(f"Error analyzing code quality: {str(e)}")
            quality["error"] = str(e)
        
        return quality
    
    def _analyze_ios_code_quality(self, temp_dir: str) -> Dict[str, Any]:
        """Analyze iOS code quality."""
        quality = {
            "total_files": 0,
            "binary_files": 0,
            "issues": [],
            "metrics": {}
        }
        
        try:
            # Count files
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    quality["total_files"] += 1
                    
                    if file.endswith((".dylib", ".framework")):
                        quality["binary_files"] += 1
            
            # iOS binary analysis is limited without source code
            quality["note"] = "iOS binary analysis limited without source code"
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS code quality: {str(e)}")
            quality["error"] = str(e)
        
        return quality
    
    def _find_security_patterns(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find security-related patterns in code."""
        patterns = []
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        patterns.extend(self._analyze_file_security_patterns(file_path))
        
        except Exception as e:
            self.logger.error(f"Error finding security patterns: {str(e)}")
        
        return patterns
    
    def _find_ios_security_patterns(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find iOS security patterns."""
        patterns = []
        
        try:
            # iOS binary analysis is limited
            patterns.append({
                "type": "Binary Analysis",
                "description": "iOS binary analysis requires additional tools",
                "severity": "info"
            })
        
        except Exception as e:
            self.logger.error(f"Error finding iOS security patterns: {str(e)}")
        
        return patterns
    
    def _find_hardcoded_secrets(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find hardcoded secrets in code."""
        secrets = []
        
        try:
            # Patterns for hardcoded secrets
            secret_patterns = [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'key\s*=\s*["\'][^"\']+["\']',
                r'private_key\s*=\s*["\'][^"\']+["\']',
                r'client_secret\s*=\s*["\'][^"\']+["\']',
                r'access_token\s*=\s*["\'][^"\']+["\']'
            ]
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt", ".xml")):
                        file_path = os.path.join(root, file)
                        secrets.extend(self._find_secrets_in_file(file_path, secret_patterns))
        
        except Exception as e:
            self.logger.error(f"Error finding hardcoded secrets: {str(e)}")
        
        return secrets
    
    def _find_ios_hardcoded_secrets(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find hardcoded secrets in iOS binaries."""
        secrets = []
        
        try:
            # iOS binary analysis for secrets is limited
            secrets.append({
                "type": "Binary Analysis",
                "description": "iOS binary secret analysis requires additional tools",
                "severity": "info"
            })
        
        except Exception as e:
            self.logger.error(f"Error finding iOS hardcoded secrets: {str(e)}")
        
        return secrets
    
    def _find_injection_vulnerabilities(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find injection vulnerabilities."""
        injections = []
        
        try:
            # SQL Injection patterns
            sql_patterns = [
                r'rawQuery\s*\(\s*["\'][^"\']*["\']\s*\+',
                r'execSQL\s*\(\s*["\'][^"\']*["\']\s*\+',
                r'query\s*\(\s*["\'][^"\']*["\']\s*\+'
            ]
            
            # Command Injection patterns
            cmd_patterns = [
                r'Runtime\.getRuntime\(\)\.exec\s*\(',
                r'ProcessBuilder\s*\(',
                r'exec\s*\(\s*["\'][^"\']*["\']\s*\+'
            ]
            
            # XSS patterns
            xss_patterns = [
                r'loadUrl\s*\(\s*["\'][^"\']*["\']\s*\+',
                r'evaluateJavascript\s*\(\s*["\'][^"\']*["\']\s*\+',
                r'loadData\s*\(\s*["\'][^"\']*["\']\s*\+'
            ]
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        
                        # Check for SQL injection
                        injections.extend(self._find_patterns_in_file(file_path, sql_patterns, "SQL Injection"))
                        
                        # Check for command injection
                        injections.extend(self._find_patterns_in_file(file_path, cmd_patterns, "Command Injection"))
                        
                        # Check for XSS
                        injections.extend(self._find_patterns_in_file(file_path, xss_patterns, "XSS"))
        
        except Exception as e:
            self.logger.error(f"Error finding injection vulnerabilities: {str(e)}")
        
        return injections
    
    def _find_authentication_issues(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find authentication-related issues."""
        auth_issues = []
        
        try:
            # Weak authentication patterns
            auth_patterns = [
                r'if\s*\(\s*password\s*==\s*["\'][^"\']+["\']\s*\)',
                r'if\s*\(\s*username\s*==\s*["\'][^"\']+["\']\s*\)',
                r'if\s*\(\s*input\s*\.equals\s*\(\s*["\'][^"\']+["\']\s*\)\s*\)',
                r'password\s*\.equals\s*\(\s*["\'][^"\']+["\']\s*\)',
                r'username\s*\.equals\s*\(\s*["\'][^"\']+["\']\s*\)'
            ]
            
            # Missing authentication patterns
            missing_auth_patterns = [
                r'@Override\s+protected\s+void\s+onCreate\s*\(',
                r'public\s+class\s+\w+\s+extends\s+Activity',
                r'public\s+class\s+\w+\s+extends\s+Fragment'
            ]
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        
                        # Check for weak authentication
                        auth_issues.extend(self._find_patterns_in_file(file_path, auth_patterns, "Weak Authentication"))
                        
                        # Check for missing authentication
                        auth_issues.extend(self._find_patterns_in_file(file_path, missing_auth_patterns, "Missing Authentication"))
        
        except Exception as e:
            self.logger.error(f"Error finding authentication issues: {str(e)}")
        
        return auth_issues
    
    def _find_authorization_issues(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find authorization-related issues."""
        auth_issues = []
        
        try:
            # Missing authorization patterns
            auth_patterns = [
                r'checkSelfPermission\s*\(',
                r'requestPermissions\s*\(',
                r'ContextCompat\.checkSelfPermission',
                r'ActivityCompat\.requestPermissions'
            ]
            
            # Privilege escalation patterns
            priv_patterns = [
                r'Runtime\.getRuntime\(\)\.exec\s*\(',
                r'ProcessBuilder\s*\(',
                r'su\s*\(',
                r'root\s*\('
            ]
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        
                        # Check for missing authorization
                        auth_issues.extend(self._find_patterns_in_file(file_path, auth_patterns, "Missing Authorization"))
                        
                        # Check for privilege escalation
                        auth_issues.extend(self._find_patterns_in_file(file_path, priv_patterns, "Privilege Escalation"))
        
        except Exception as e:
            self.logger.error(f"Error finding authorization issues: {str(e)}")
        
        return auth_issues
    
    def _find_cryptography_issues(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find cryptography-related issues."""
        crypto_issues = []
        
        try:
            # Weak cryptography patterns
            weak_crypto_patterns = [
                r'MD5\s*\(',
                r'SHA1\s*\(',
                r'DES\s*\(',
                r'RC4\s*\(',
                r'MD5\s*\.getInstance',
                r'SHA1\s*\.getInstance',
                r'DES\s*\.getInstance',
                r'RC4\s*\.getInstance'
            ]
            
            # Hardcoded keys patterns
            key_patterns = [
                r'SecretKeySpec\s*\(\s*["\'][^"\']+["\']',
                r'KeyGenerator\s*\.getInstance\s*\(\s*["\'][^"\']+["\']',
                r'Cipher\s*\.getInstance\s*\(\s*["\'][^"\']+["\']'
            ]
            
            # Missing encryption patterns
            missing_encryption_patterns = [
                r'SharedPreferences\s*\.edit\s*\(',
                r'FileOutputStream\s*\(',
                r'FileWriter\s*\(',
                r'PrintWriter\s*\('
            ]
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        
                        # Check for weak cryptography
                        crypto_issues.extend(self._find_patterns_in_file(file_path, weak_crypto_patterns, "Weak Cryptography"))
                        
                        # Check for hardcoded keys
                        crypto_issues.extend(self._find_patterns_in_file(file_path, key_patterns, "Hardcoded Keys"))
                        
                        # Check for missing encryption
                        crypto_issues.extend(self._find_patterns_in_file(file_path, missing_encryption_patterns, "Missing Encryption"))
        
        except Exception as e:
            self.logger.error(f"Error finding cryptography issues: {str(e)}")
        
        return crypto_issues
    
    def _find_biometric_flaws(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect biometric authentication implementation flaws."""
        flaws = []
        biometric_patterns = [
            r'FingerprintManager', r'BiometricPrompt', r'FaceManager', r'TouchID', r'FaceID'
        ]
        fallback_patterns = [r'if\s*\(\s*biometricResult\s*==\s*false', r'if\s*\(\s*biometricError']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in biometric_patterns:
                            if re.search(pattern, content):
                                for fallback in fallback_patterns:
                                    if re.search(fallback, content):
                                        flaws.append({
                                            "type": "Biometric Auth Flaw",
                                            "file": file,
                                            "description": "Biometric fallback may be insecure.",
                                            "severity": "high"
                                        })
        return flaws

    def _find_insecure_deserialization(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect insecure deserialization usage."""
        issues = []
        patterns = [r'ObjectInputStream', r'ObjectOutputStream', r'NSKeyedUnarchiver', r'NSKeyedArchiver']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                issues.append({
                                    "type": "Insecure Deserialization",
                                    "file": file,
                                    "description": "Potential insecure deserialization detected.",
                                    "severity": "high"
                                })
        return issues

    def _find_path_traversal(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect path traversal vulnerabilities."""
        issues = []
        patterns = [r'\.\./', r'File\s*\(', r'open\s*\(', r'new File\s*\(']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                if re.search(r'input|user|param|request', content, re.IGNORECASE):
                                    issues.append({
                                        "type": "Path Traversal",
                                        "file": file,
                                        "description": "Potential path traversal with user input.",
                                        "severity": "high"
                                    })
        return issues

    def _find_clipboard_exposure(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect clipboard exposure of sensitive data."""
        issues = []
        patterns = [r'ClipboardManager', r'UIPasteboard']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                if re.search(r'password|token|secret|key|credit|ssn', content, re.IGNORECASE):
                                    issues.append({
                                        "type": "Clipboard Exposure",
                                        "file": file,
                                        "description": "Sensitive data may be copied to clipboard.",
                                        "severity": "high"
                                    })
        return issues

    def _find_keyboard_caching(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect keyboard caching for password fields."""
        issues = []
        patterns = [r'inputType\s*=\s*InputType.TYPE_TEXT_VARIATION_PASSWORD', r'setTextIsSelectable\s*\(true\)']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".xml")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                issues.append({
                                    "type": "Keyboard Caching",
                                    "file": file,
                                    "description": "Password field may be cached by keyboard.",
                                    "severity": "medium"
                                })
        return issues

    def _find_background_screenshot(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect lack of FLAG_SECURE for sensitive screens."""
        issues = []
        patterns = [r'WindowManager.LayoutParams.FLAG_SECURE', r'setFlags\s*\(.*FLAG_SECURE']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".xml")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if not any(re.search(pattern, content) for pattern in patterns):
                            if re.search(r'password|token|secret|credit|ssn', content, re.IGNORECASE):
                                issues.append({
                                    "type": "Background Screenshot",
                                    "file": file,
                                    "description": "Sensitive screen may be captured in screenshots.",
                                    "severity": "medium"
                                })
        return issues

    def _find_ssrf(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect SSRF patterns in network requests."""
        issues = []
        patterns = [r'HttpURLConnection', r'OkHttpClient', r'URL\s*\(', r'NSURLSession']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if re.search(r'input|user|param|request', content, re.IGNORECASE):
                            for pattern in patterns:
                                if re.search(pattern, content):
                                    issues.append({
                                        "type": "SSRF",
                                        "file": file,
                                        "description": "Potential SSRF with user input in network request.",
                                        "severity": "high"
                                    })
        return issues

    def _find_pii_in_logs(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect PII leakage in logs."""
        issues = []
        log_patterns = [r'Log\.d\s*\(', r'Log\.i\s*\(', r'print\s*\(', r'NSLog']
        pii_patterns = [r'password', r'token', r'secret', r'key', r'credit', r'ssn', r'email', r'phone']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for log_pattern in log_patterns:
                            if re.search(log_pattern, content):
                                for pii in pii_patterns:
                                    if re.search(pii, content, re.IGNORECASE):
                                        issues.append({
                                            "type": "PII in Logs",
                                            "file": file,
                                            "description": f"PII ({pii}) may be leaked in logs.",
                                            "severity": "high"
                                        })
        return issues

    def _find_custom_crypto(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect custom encryption implementations."""
        issues = []
        patterns = [r'CustomCrypto', r'CustomEncrypt', r'CustomDecrypt', r'Cipher\s*\(', r'new Cipher']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                if not re.search(r'AES|RSA|DES|Blowfish|PBKDF2', content):
                                    issues.append({
                                        "type": "Custom Crypto",
                                        "file": file,
                                        "description": "Custom encryption implementation detected.",
                                        "severity": "high"
                                    })
        return issues

    def _find_insecure_key_management(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect insecure key management practices."""
        issues = []
        patterns = [r'key\s*=\s*.*', r'KeyStore', r'NSUserDefaults', r'SharedPreferences']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                if re.search(r'key\s*=\s*"[^"]+"', content):
                                    issues.append({
                                        "type": "Insecure Key Management",
                                        "file": file,
                                        "description": "Key may be hardcoded or stored insecurely.",
                                        "severity": "high"
                                    })
        return issues

    def _find_jailbreak_root_bypass(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect jailbreak/root detection bypass logic."""
        issues = []
        patterns = [r'rooted\s*=\s*false', r'jailbreak\s*=\s*false', r'if\s*\(\s*!isRooted', r'if\s*\(\s*!isJailbroken']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for pattern in patterns:
                            if re.search(pattern, content):
                                issues.append({
                                    "type": "Jailbreak/Root Detection Bypass",
                                    "file": file,
                                    "description": "Potential bypass of root/jailbreak detection.",
                                    "severity": "high"
                                })
        return issues

    def _find_step_up_auth(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Detect missing step-up authentication for sensitive operations."""
        issues = []
        sensitive_ops = [r'transfer', r'payment', r'changePassword', r'updateEmail', r'deleteAccount']
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith((".java", ".kt", ".swift", ".m")):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for op in sensitive_ops:
                            if re.search(op, content, re.IGNORECASE):
                                if not re.search(r'biometric|otp|2fa|stepup|reauth', content, re.IGNORECASE):
                                    issues.append({
                                        "type": "Missing Step-Up Authentication",
                                        "file": file,
                                        "description": f"Sensitive operation '{op}' may lack step-up authentication.",
                                        "severity": "high"
                                    })
        return issues
    
    def _find_code_quality_issues(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find code quality issues."""
        issues = []
        
        try:
            # Code quality patterns
            quality_patterns = [
                (r'System\.out\.println', "Debug Code"),
                (r'Log\.d\s*\(', "Debug Logging"),
                (r'Log\.v\s*\(', "Verbose Logging"),
                (r'Toast\.makeText\s*\([^)]*["\'][^"\']*["\']', "Hardcoded Strings"),
                (r'new\s+Exception\s*\(\s*["\'][^"\']*["\']', "Generic Exceptions"),
                (r'catch\s*\(\s*Exception\s+e\s*\)', "Generic Exception Handling")
            ]
            
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        
                        for pattern, issue_type in quality_patterns:
                            matches = re.findall(pattern, open(file_path, 'r', encoding='utf-8', errors='ignore').read())
                            if matches:
                                issues.append({
                                    "type": issue_type,
                                    "file": file,
                                    "count": len(matches),
                                    "severity": "low"
                                })
        
        except Exception as e:
            self.logger.error(f"Error finding code quality issues: {str(e)}")
        
        return issues
    
    def _calculate_code_metrics(self, temp_dir: str) -> Dict[str, Any]:
        """Calculate code metrics."""
        metrics = {
            "total_lines": 0,
            "java_lines": 0,
            "kotlin_lines": 0,
            "xml_lines": 0,
            "complexity": "low"
        }
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt", ".xml")):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = len(f.readlines())
                                metrics["total_lines"] += lines
                                
                                if file.endswith(".java"):
                                    metrics["java_lines"] += lines
                                elif file.endswith(".kt"):
                                    metrics["kotlin_lines"] += lines
                                elif file.endswith(".xml"):
                                    metrics["xml_lines"] += lines
                        except Exception:
                            continue
            
            # Determine complexity
            if metrics["total_lines"] > 10000:
                metrics["complexity"] = "high"
            elif metrics["total_lines"] > 5000:
                metrics["complexity"] = "medium"
            else:
                metrics["complexity"] = "low"
        
        except Exception as e:
            self.logger.error(f"Error calculating code metrics: {str(e)}")
        
        return metrics
    
    def _analyze_file_security_patterns(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze security patterns in a single file."""
        patterns = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Security patterns to look for
                security_patterns = [
                    (r'WebView\s*\w*\s*=\s*new\s+WebView', "WebView Usage"),
                    (r'loadUrl\s*\(\s*["\'][^"\']*["\']', "URL Loading"),
                    (r'JavascriptInterface', "JavaScript Interface"),
                    (r'addJavascriptInterface', "JavaScript Interface Addition"),
                    (r'FileProvider', "File Provider"),
                    (r'ContentProvider', "Content Provider"),
                    (r'BroadcastReceiver', "Broadcast Receiver"),
                    (r'IntentFilter', "Intent Filter"),
                    (r'PendingIntent', "Pending Intent"),
                    (r'startActivityForResult', "Activity Result"),
                    (r'requestPermissions', "Permission Request"),
                    (r'checkSelfPermission', "Permission Check")
                ]
                
                for pattern, pattern_type in security_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        patterns.append({
                            "type": pattern_type,
                            "file": os.path.basename(file_path),
                            "count": len(matches),
                            "severity": "info"
                        })
        
        except Exception as e:
            self.logger.error(f"Error analyzing file security patterns: {str(e)}")
        
        return patterns
    
    def _find_secrets_in_file(self, file_path: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Find secrets in a single file."""
        secrets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        secrets.append({
                            "type": "Hardcoded Secret",
                            "file": os.path.basename(file_path),
                            "pattern": pattern,
                            "count": len(matches),
                            "severity": "high"
                        })
        
        except Exception as e:
            self.logger.error(f"Error finding secrets in file: {str(e)}")
        
        return secrets
    
    def _find_patterns_in_file(self, file_path: str, patterns: List[str], issue_type: str) -> List[Dict[str, Any]]:
        """Find patterns in a single file."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        issues.append({
                            "type": issue_type,
                            "file": os.path.basename(file_path),
                            "pattern": pattern,
                            "count": len(matches),
                            "severity": "medium"
                        })
        
        except Exception as e:
            self.logger.error(f"Error finding patterns in file: {str(e)}")
        
        return issues
    
    def _identify_code_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify code vulnerabilities."""
        vulnerabilities = []
        
        # Add hardcoded secrets
        for secret in results.get("hardcoded_secrets", []):
            vulnerabilities.append({
                "type": "Hardcoded Secret",
                "severity": secret.get("severity", "high"),
                "description": f"Hardcoded secret found in {secret.get('file', 'unknown')}",
                "recommendation": "Move secrets to secure storage or use obfuscation"
            })
        
        # Add injection vulnerabilities
        for injection in results.get("injection_vulnerabilities", []):
            vulnerabilities.append({
                "type": injection.get("type", "Injection"),
                "severity": injection.get("severity", "high"),
                "description": f"Injection vulnerability found in {injection.get('file', 'unknown')}",
                "recommendation": "Use parameterized queries and input validation"
            })
        
        # Add authentication issues
        for auth in results.get("authentication_issues", []):
            vulnerabilities.append({
                "type": auth.get("type", "Authentication Issue"),
                "severity": auth.get("severity", "medium"),
                "description": f"Authentication issue found in {auth.get('file', 'unknown')}",
                "recommendation": "Implement proper authentication mechanisms"
            })
        
        # Add authorization issues
        for auth in results.get("authorization_issues", []):
            vulnerabilities.append({
                "type": auth.get("type", "Authorization Issue"),
                "severity": auth.get("severity", "medium"),
                "description": f"Authorization issue found in {auth.get('file', 'unknown')}",
                "recommendation": "Implement proper authorization checks"
            })
        
        # Add cryptography issues
        for crypto in results.get("cryptography_issues", []):
            vulnerabilities.append({
                "type": crypto.get("type", "Cryptography Issue"),
                "severity": crypto.get("severity", "medium"),
                "description": f"Cryptography issue found in {crypto.get('file', 'unknown')}",
                "recommendation": "Use strong cryptographic algorithms and proper key management"
            })
        
        # Add new checks
        for key in [
            "biometric_flaws", "insecure_deserialization", "path_traversal", "clipboard_exposure",
            "keyboard_caching", "background_screenshot", "ssrf", "pii_in_logs", "custom_crypto",
            "insecure_key_management", "jailbreak_root_bypass", "step_up_auth"
        ]:
            for issue in results.get(key, []):
                vulnerabilities.append(issue)
        
        return vulnerabilities
    
    def _identify_ios_code_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS-specific code vulnerabilities."""
        vulnerabilities = []
        
        # iOS binary analysis is limited
        vulnerabilities.append({
            "type": "Binary Analysis Limitation",
            "severity": "info",
            "description": "iOS binary analysis is limited without source code",
            "recommendation": "Perform source code analysis when available"
        })
        
        return vulnerabilities
    
    def _generate_code_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate code security recommendations."""
        recommendations = [
            "Remove all hardcoded secrets and credentials",
            "Implement proper input validation and sanitization",
            "Use parameterized queries to prevent SQL injection",
            "Implement proper authentication and authorization",
            "Use strong cryptographic algorithms (AES, RSA)",
            "Implement proper key management",
            "Remove debug code and logging from production",
            "Use secure coding practices",
            "Implement proper error handling",
            "Regular code security reviews",
            "Use static analysis tools",
            "Implement proper session management"
        ]
        
        return recommendations
    
    def _generate_ios_code_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate iOS-specific code recommendations."""
        recommendations = [
            "Perform source code analysis when available",
            "Use secure coding practices for iOS",
            "Implement proper authentication and authorization",
            "Use strong cryptographic algorithms",
            "Implement proper key management",
            "Use keychain for sensitive data",
            "Implement proper error handling",
            "Regular code security reviews"
        ]
        
        return recommendations 

    def _find_webview_security(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find WebView security issues."""
        issues = []
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(('.smali', '.java', '.kt', '.xml')):
                        file_path = os.path.join(root, file)
                        patterns = [
                            r'addJavascriptInterface',
                            r'@JavascriptInterface',
                            r'javascriptEnabled\s*\(\s*true\s*\)',
                            r'setJavaScriptEnabled\s*\(\s*true\s*\)',
                            r'allowFileAccess\s*\(\s*true\s*\)',
                            r'setAllowFileAccess\s*\(\s*true\s*\)',
                            r'allowContentAccess\s*\(\s*true\s*\)',
                            r'setAllowContentAccess\s*\(\s*true\s*\)',
                            r'allowFileAccessFromFileURLs\s*\(\s*true\s*\)',
                            r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
                            r'allowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
                            r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
                            r'domStorageEnabled\s*\(\s*true\s*\)',
                            r'setDomStorageEnabled\s*\(\s*true\s*\)',
                            r'databaseEnabled\s*\(\s*true\s*\)',
                            r'setDatabaseEnabled\s*\(\s*true\s*\)',
                            r'loadUrl\s*\(\s*["\']file://',
                            r'loadUrl\s*\(\s*["\']content://',
                            r'loadUrl\s*\(\s*["\']data:',
                            r'setWebViewClient\s*\(\s*null\s*\)',
                            r'WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)'
                        ]
                        issues.extend(self._find_patterns_in_file(file_path, patterns, "WebView Security Issue"))
        except Exception as e:
            self.logger.error(f"Error finding WebView security issues: {str(e)}")
        return issues

    def _find_intent_injection(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find intent injection issues."""
        issues = []
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(('.smali', '.java', '.kt', '.xml')):
                        file_path = os.path.join(root, file)
                        patterns = [
                            r'getStringExtra',
                            r'getIntExtra',
                            r'getBooleanExtra',
                            r'getParcelableExtra',
                            r'getBundleExtra',
                            r'getSerializableExtra',
                            r'new Intent\s*\(',
                            r'Intent\.parseUri',
                            r'Intent\.getIntent',
                            r'getData\s*\(\s*\)',
                            r'getDataString\s*\(\s*\)',
                            r'getScheme\s*\(\s*\)',
                            r'getHost\s*\(\s*\)',
                            r'getPath\s*\(\s*\)',
                            r'getQuery\s*\(\s*\)',
                            r'resolveActivity\s*\(\s*\)',
                            r'resolveActivityInfo\s*\(\s*\)',
                            r'startActivity\s*\(',
                            r'startActivityForResult\s*\(',
                            r'startService\s*\(',
                            r'sendBroadcast\s*\(',
                            r'putExtra\s*\(',
                            r'setData\s*\(',
                            r'setDataAndType\s*\(',
                            r'setAction\s*\(',
                            r'setPackage\s*\(',
                            r'setClassName\s*\('
                        ]
                        issues.extend(self._find_patterns_in_file(file_path, patterns, "Intent Injection Issue"))
        except Exception as e:
            self.logger.error(f"Error finding intent injection issues: {str(e)}")
        return issues

    def _find_certificate_bypass(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find certificate bypass issues."""
        issues = []
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(('.smali', '.java', '.kt', '.xml')):
                        file_path = os.path.join(root, file)
                        patterns = [
                            r'X509TrustManager',
                            r'TrustManager',
                            r'checkServerTrusted\s*\(\s*[^)]*null[^)]*\)',
                            r'checkClientTrusted\s*\(\s*[^)]*null[^)]*\)',
                            r'getAcceptedIssuers\s*\(\s*\)\s*{\s*return\s*null',
                            r'HostnameVerifier',
                            r'verify\s*\(\s*[^)]*true[^)]*\)',
                            r'verify\s*\(\s*[^)]*null[^)]*\)',
                            r'AllHostnameVerifier',
                            r'SSLContext\.getInstance\s*\(',
                            r'init\s*\(\s*[^)]*null[^)]*[^)]*null[^)]*\)',
                            r'TrustManagerFactory',
                            r'KeyManagerFactory',
                            r'CertificateFactory',
                            r'generateCertificate',
                            r'X509Certificate',
                            r'checkValidity\s*\(',
                            r'getSubjectDN\s*\(',
                            r'getIssuerDN\s*\(',
                            r'CertificatePinner',
                            r'check\s*\(\s*[^)]*null[^)]*\)',
                            r'add\s*\(\s*[^)]*null[^)]*\)',
                            r'KeyStore',
                            r'load\s*\(\s*null\s*\)',
                            r'getCertificate\s*\(\s*[^)]*null[^)]*\)',
                            r'getKey\s*\(\s*[^)]*null[^)]*\)'
                        ]
                        issues.extend(self._find_patterns_in_file(file_path, patterns, "Certificate Bypass Issue"))
        except Exception as e:
            self.logger.error(f"Error finding certificate bypass issues: {str(e)}")
        return issues

    def _find_sensitive_data_handling(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find sensitive data handling issues."""
        issues = []
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith(('.smali', '.java', '.kt', '.xml')):
                        file_path = os.path.join(root, file)
                        patterns = [
                            r'getDeviceId\s*\(',
                            r'getSubscriberId\s*\(',
                            r'getLine1Number\s*\(',
                            r'getSimSerialNumber\s*\(',
                            r'getImei\s*\(',
                            r'getMacAddress\s*\(',
                            r'getAndroidId\s*\(',
                            r'getString\s*\(\s*[^)]*android_id[^)]*\)',
                            r'getLastKnownLocation\s*\(',
                            r'requestLocationUpdates\s*\(',
                            r'LocationManager',
                            r'GPS_PROVIDER',
                            r'NETWORK_PROVIDER',
                            r'ContactsContract',
                            r'getContentResolver\s*\(\s*\)\.query',
                            r'Phone\.DISPLAY_NAME',
                            r'Phone\.NUMBER',
                            r'Phone\.EMAIL',
                            r'CalendarContract',
                            r'Events\.TITLE',
                            r'Events\.DESCRIPTION',
                            r'Events\.DTSTART',
                            r'Events\.DTEND',
                            r'Telephony\.Sms',
                            r'Telephony\.Mms',
                            r'getAllMessagesFromProvider',
                            r'getSmsMessagesForPhone',
                            r'CallLog\.Calls',
                            r'getCallLog\s*\(',
                            r'getLastCallLogEntry\s*\(',
                            r'Browser\.BOOKMARKS_URI',
                            r'Browser\.SEARCHES_URI',
                            r'Browser\.HISTORY_PROJECTION'
                        ]
                        issues.extend(self._find_patterns_in_file(file_path, patterns, "Sensitive Data Handling Issue"))
        except Exception as e:
            self.logger.error(f"Error finding sensitive data handling issues: {str(e)}")
        return issues 