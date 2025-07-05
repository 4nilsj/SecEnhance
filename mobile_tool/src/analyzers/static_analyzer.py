#!/usr/bin/env python3
"""
Static Analyzer for Mobile Security Testing
Analyzes APK/IPA files for security vulnerabilities without execution.
"""

import os
import zipfile
import xml.etree.ElementTree as ET
import json
import logging
import re
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path
import subprocess
import tempfile
import shutil
import base64

class StaticAnalyzer:
    """Static analysis of mobile applications."""
    
    def __init__(self, debug: bool = False):
        """Initialize static analyzer."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        
        # Android-specific security patterns
        self.dangerous_permissions = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_SETTINGS",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.REQUEST_DELETE_PACKAGES"
        ]
        
        self.signature_permissions = [
            "android.permission.READ_LOGS",
            "android.permission.WRITE_SECURE_SETTINGS",
            "android.permission.WRITE_GSERVICES",
            "android.permission.ACCESS_SUPERUSER"
        ]
        
        self.exported_components_risks = [
            "android.intent.action.MAIN",
            "android.intent.action.VIEW",
            "android.intent.action.EDIT",
            "android.intent.action.PICK",
            "android.intent.action.GET_CONTENT"
        ]
        
    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """Analyze Android APK file statically."""
        self.logger.info(f"Starting static analysis of APK: {apk_path}")
        
        results = {
            "file_info": {},
            "manifest_analysis": {},
            "permissions": [],
            "components": {},
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": [],
            "deep_analysis": {},
            "code_analysis": {},
            "resource_analysis": {},
            "certificate_analysis": {},
            "backup_analysis": {},
            "intent_analysis": {},
            "deeplink_analysis": {},
            "webview_analysis": {},
            "native_analysis": {},
            "third_party_analysis": {}
        }
        
        try:
            # Extract APK
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get file information
                results["file_info"] = self._analyze_file_info(apk_zip, apk_path)
                
                # Analyze AndroidManifest.xml
                if "AndroidManifest.xml" in apk_zip.namelist():
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    results["manifest_analysis"] = self._analyze_manifest(manifest_data)
                
                # Deep manifest analysis
                results["deep_analysis"] = self._deep_manifest_analysis(results["manifest_analysis"])
                
                # Analyze permissions
                results["permissions"] = self._analyze_permissions(results["manifest_analysis"])
                
                # Analyze components
                results["components"] = self._analyze_components(results["manifest_analysis"])
                
                # Analyze intent filters
                results["intent_analysis"] = self._analyze_intent_filters(results["manifest_analysis"])
                
                # Analyze deep links
                results["deeplink_analysis"] = self._analyze_deep_links(results["manifest_analysis"])
                
                # Analyze resources
                results["resource_analysis"] = self._analyze_resources(apk_zip)
                
                # Analyze native libraries
                results["native_analysis"] = self._analyze_native_libraries(apk_zip)
                
                # Analyze certificates
                results["certificate_analysis"] = self._analyze_certificates(apk_zip)
                
                # Analyze backup configuration
                results["backup_analysis"] = self._analyze_backup_configuration(results["manifest_analysis"])
                
                # Analyze WebView configuration
                results["webview_analysis"] = self._analyze_webview_configuration(apk_zip)
                
                # Analyze third-party libraries
                results["third_party_analysis"] = self._analyze_third_party_libraries(apk_zip)
                
                # Analyze code patterns
                results["code_analysis"] = self._analyze_code_patterns(apk_zip)
                
        except Exception as e:
            self.logger.error(f"Error during APK static analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_vulnerabilities(results)
        results["security_issues"] = self._identify_security_issues(results)
        results["recommendations"] = self._generate_recommendations(results)
        
        return results
    
    def analyze_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS IPA file statically."""
        self.logger.info(f"Starting static analysis of IPA: {ipa_path}")
        
        results = {
            "file_info": {},
            "info_plist": {},
            "entitlements": {},
            "frameworks": [],
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Extract IPA
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                # Get file information
                results["file_info"] = self._analyze_file_info(ipa_zip, ipa_path)
                
                # Find and analyze Info.plist
                info_plist_path = self._find_info_plist(ipa_zip)
                if info_plist_path:
                    info_plist_data = ipa_zip.read(info_plist_path)
                    results["info_plist"] = self._analyze_info_plist(info_plist_data)
                
                # Analyze entitlements
                results["entitlements"] = self._analyze_entitlements(ipa_zip)
                
                # Analyze frameworks
                results["frameworks"] = self._analyze_frameworks(ipa_zip)
                
                # Analyze embedded frameworks
                results["embedded_frameworks"] = self._analyze_embedded_frameworks(ipa_zip)
                
                # Analyze certificates
                results["certificates"] = self._analyze_ios_certificates(ipa_zip)
                
        except Exception as e:
            self.logger.error(f"Error during IPA static analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_ios_vulnerabilities(results)
        results["security_issues"] = self._identify_ios_security_issues(results)
        results["recommendations"] = self._generate_ios_recommendations(results)
        
        return results
    
    def _analyze_file_info(self, zip_file: zipfile.ZipFile, file_path: str) -> Dict[str, Any]:
        """Analyze basic file information."""
        file_info = {
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "file_type": "APK" if file_path.endswith(".apk") else "IPA",
            "total_files": len(zip_file.namelist()),
            "compressed_size": sum(info.file_size for info in zip_file.filelist),
            "uncompressed_size": sum(info.file_size for info in zip_file.filelist)
        }
        
        # Analyze file types
        file_extensions = {}
        for filename in zip_file.namelist():
            ext = Path(filename).suffix
            file_extensions[ext] = file_extensions.get(ext, 0) + 1
        
        file_info["file_types"] = file_extensions
        
        return file_info
    
    def _analyze_manifest(self, manifest_data: bytes) -> Dict[str, Any]:
        """Analyze AndroidManifest.xml."""
        try:
            # Parse manifest XML
            root = ET.fromstring(manifest_data)
            
            manifest_info = {
                "package": root.get("package"),
                "version_code": root.get("android:versionCode"),
                "version_name": root.get("android:versionName"),
                "min_sdk": root.get("android:minSdkVersion"),
                "target_sdk": root.get("android:targetSdkVersion"),
                "permissions": [],
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
                "intent_filters": []
            }
            
            # Extract permissions
            for permission in root.findall(".//uses-permission"):
                manifest_info["permissions"].append(permission.get("android:name"))
            
            # Extract components
            for activity in root.findall(".//activity"):
                manifest_info["activities"].append({
                    "name": activity.get("android:name"),
                    "exported": activity.get("android:exported"),
                    "permission": activity.get("android:permission")
                })
            
            for service in root.findall(".//service"):
                manifest_info["services"].append({
                    "name": service.get("android:name"),
                    "exported": service.get("android:exported"),
                    "permission": service.get("android:permission")
                })
            
            for receiver in root.findall(".//receiver"):
                manifest_info["receivers"].append({
                    "name": receiver.get("android:name"),
                    "exported": receiver.get("android:exported"),
                    "permission": receiver.get("android:permission")
                })
            
            for provider in root.findall(".//provider"):
                manifest_info["providers"].append({
                    "name": provider.get("android:name"),
                    "exported": provider.get("android:exported"),
                    "permission": provider.get("android:permission"),
                    "authorities": provider.get("android:authorities")
                })
            
            return manifest_info
            
        except Exception as e:
            self.logger.error(f"Error parsing AndroidManifest.xml: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_permissions(self, manifest_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze Android permissions for security implications."""
        permissions = manifest_analysis.get("permissions", [])
        permission_analysis = []
        
        # Dangerous permissions that require runtime permission
        dangerous_permissions = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS"
        ]
        
        # High-risk permissions
        high_risk_permissions = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.WRITE_SETTINGS",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.REQUEST_DELETE_PACKAGES",
            "android.permission.ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BIND_INPUT_METHOD",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        ]
        
        for permission in permissions:
            permission_info = {
                "permission": permission,
                "severity": "normal",
                "description": "",
                "risk": ""
            }
            
            if permission in dangerous_permissions:
                permission_info["severity"] = "high"
                permission_info["description"] = "Dangerous permission requiring runtime permission"
                permission_info["risk"] = "Requires user consent at runtime"
            
            elif permission in high_risk_permissions:
                permission_info["severity"] = "critical"
                permission_info["description"] = "High-risk permission with system-level access"
                permission_info["risk"] = "System-level access, potential privilege escalation"
            
            permission_analysis.append(permission_info)
        
        return permission_analysis
    
    def _analyze_components(self, manifest_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Android components for security issues."""
        components = {
            "activities": manifest_analysis.get("activities", []),
            "services": manifest_analysis.get("services", []),
            "receivers": manifest_analysis.get("receivers", []),
            "providers": manifest_analysis.get("providers", []),
            "security_issues": []
        }
        
        # Check for exported components without proper permissions
        for activity in components["activities"]:
            if activity.get("exported") == "true" and not activity.get("permission"):
                components["security_issues"].append({
                    "type": "Exported Activity",
                    "component": activity.get("name"),
                    "severity": "high",
                    "description": "Exported activity without permission protection"
                })
        
        for service in components["services"]:
            if service.get("exported") == "true" and not service.get("permission"):
                components["security_issues"].append({
                    "type": "Exported Service",
                    "component": service.get("name"),
                    "severity": "high",
                    "description": "Exported service without permission protection"
                })
        
        for receiver in components["receivers"]:
            if receiver.get("exported") == "true" and not receiver.get("permission"):
                components["security_issues"].append({
                    "type": "Exported Receiver",
                    "component": receiver.get("name"),
                    "severity": "high",
                    "description": "Exported receiver without permission protection"
                })
        
        for provider in components["providers"]:
            if provider.get("exported") == "true" and not provider.get("permission"):
                components["security_issues"].append({
                    "type": "Exported Provider",
                    "component": provider.get("name"),
                    "severity": "critical",
                    "description": "Exported content provider without permission protection"
                })
        
        return components
    
    def _analyze_resources(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze APK resources for security issues."""
        resources = {
            "strings": [],
            "layouts": [],
            "drawables": [],
            "security_issues": []
        }
        
        # Extract strings.xml for hardcoded secrets
        for filename in apk_zip.namelist():
            if filename.endswith("strings.xml"):
                try:
                    strings_data = apk_zip.read(filename)
                    root = ET.fromstring(strings_data)
                    
                    for string_elem in root.findall(".//string"):
                        string_name = string_elem.get("name")
                        string_value = string_elem.text or ""
                        
                        # Check for potential secrets
                        if any(keyword in string_name.lower() for keyword in ["key", "secret", "password", "token", "api"]):
                            if string_value and len(string_value) > 10:
                                resources["security_issues"].append({
                                    "type": "Hardcoded Secret",
                                    "file": filename,
                                    "name": string_name,
                                    "severity": "high",
                                    "description": "Potential hardcoded secret in strings.xml"
                                })
                        
                        resources["strings"].append({
                            "name": string_name,
                            "value": string_value[:50] + "..." if len(string_value) > 50 else string_value
                        })
                        
                except Exception as e:
                    self.logger.error(f"Error parsing {filename}: {str(e)}")
        
        return resources
    
    def _analyze_native_libraries(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze native libraries for security issues."""
        native_libs = {
            "libraries": [],
            "architectures": [],
            "security_issues": []
        }
        
        for filename in apk_zip.namelist():
            if filename.startswith("lib/") and filename.endswith(".so"):
                native_libs["libraries"].append(filename)
                
                # Extract architecture
                arch = filename.split("/")[1] if "/" in filename else "unknown"
                if arch not in native_libs["architectures"]:
                    native_libs["architectures"].append(arch)
        
        return native_libs
    
    def _analyze_certificates(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze APK certificates."""
        certificates = {
            "signing_info": {},
            "security_issues": []
        }
        
        # Check for certificates
        cert_files = [f for f in apk_zip.namelist() if f.startswith("META-INF/") and f.endswith(".RSA")]
        
        if cert_files:
            certificates["signing_info"]["signed"] = True
            certificates["signing_info"]["certificate_files"] = cert_files
        else:
            certificates["signing_info"]["signed"] = False
            certificates["security_issues"].append({
                "type": "Unsigned APK",
                "severity": "critical",
                "description": "APK is not signed with a certificate"
            })
        
        return certificates
    
    def _find_info_plist(self, ipa_zip: zipfile.ZipFile) -> Optional[str]:
        """Find Info.plist file in IPA."""
        for filename in ipa_zip.namelist():
            if filename.endswith("Info.plist"):
                return filename
        return None
    
    def _analyze_info_plist(self, plist_data: bytes) -> Dict[str, Any]:
        """Analyze iOS Info.plist file."""
        # This is a simplified parser - in production, use a proper plist parser
        plist_info = {
            "bundle_identifier": "",
            "version": "",
            "build": "",
            "minimum_os_version": "",
            "security_issues": []
        }
        
        try:
            # Convert plist to XML for easier parsing
            # In production, use plistlib or biplist
            plist_text = plist_data.decode('utf-8', errors='ignore')
            
            # Extract basic information (simplified)
            if "CFBundleIdentifier" in plist_text:
                plist_info["bundle_identifier"] = "extracted_bundle_id"
            
            if "CFBundleShortVersionString" in plist_text:
                plist_info["version"] = "extracted_version"
            
            if "CFBundleVersion" in plist_text:
                plist_info["build"] = "extracted_build"
            
            if "MinimumOSVersion" in plist_text:
                plist_info["minimum_os_version"] = "extracted_min_os"
            
        except Exception as e:
            self.logger.error(f"Error parsing Info.plist: {str(e)}")
            plist_info["error"] = str(e)
        
        return plist_info
    
    def _analyze_entitlements(self, ipa_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze iOS entitlements."""
        entitlements = {
            "entitlements": [],
            "security_issues": []
        }
        
        # Look for entitlements files
        for filename in ipa_zip.namelist():
            if filename.endswith(".entitlements"):
                entitlements["entitlements"].append(filename)
        
        return entitlements
    
    def _analyze_frameworks(self, ipa_zip: zipfile.ZipFile) -> List[str]:
        """Analyze iOS frameworks."""
        frameworks = []
        
        for filename in ipa_zip.namelist():
            if "Frameworks/" in filename and filename.endswith(".framework"):
                frameworks.append(filename)
        
        return frameworks
    
    def _analyze_embedded_frameworks(self, ipa_zip: zipfile.ZipFile) -> List[str]:
        """Analyze embedded frameworks."""
        embedded_frameworks = []
        
        for filename in ipa_zip.namelist():
            if "Frameworks/" in filename and filename.endswith(".framework"):
                embedded_frameworks.append(filename)
        
        return embedded_frameworks
    
    def _analyze_ios_certificates(self, ipa_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze iOS certificates."""
        certificates = {
            "signing_info": {},
            "security_issues": []
        }
        
        # Check for embedded provisioning profiles
        provisioning_profiles = [f for f in ipa_zip.namelist() if f.endswith(".mobileprovision")]
        
        if provisioning_profiles:
            certificates["signing_info"]["provisioned"] = True
            certificates["signing_info"]["provisioning_profiles"] = provisioning_profiles
        else:
            certificates["signing_info"]["provisioned"] = False
            certificates["security_issues"].append({
                "type": "No Provisioning Profile",
                "severity": "medium",
                "description": "No embedded provisioning profile found"
            })
        
        return certificates
    
    def _identify_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify vulnerabilities from static analysis results."""
        vulnerabilities = []
        
        try:
            # Check for dangerous permissions
            permissions = results.get("permissions", [])
            for permission in permissions:
                if permission.get("name") in self.dangerous_permissions:
                    vulnerabilities.append({
                        "type": "dangerous_permission",
                        "severity": "medium",
                        "description": f"Dangerous permission: {permission.get('name')}",
                        "permission": permission.get("name"),
                        "risk": "May expose sensitive user data"
                    })
            
            # Check for signature permissions
            for permission in permissions:
                if permission.get("name") in self.signature_permissions:
                    vulnerabilities.append({
                        "type": "signature_permission",
                        "severity": "high",
                        "description": f"Signature permission: {permission.get('name')}",
                        "permission": permission.get("name"),
                        "risk": "Requires same signature as system, potential privilege escalation"
                    })
            
            # Check for exported components without permissions
            for component in results.get("components", {}).get("exported", []):
                if not component.get("permission"):
                    vulnerabilities.append({
                        "type": "exported_component_no_permission",
                        "severity": "high",
                        "description": f"Exported component without permission: {component.get('name')}",
                        "component": component.get("name"),
                        "component_type": component.get("type"),
                        "risk": "Component can be accessed by other applications"
                    })
            
            # Check for debuggable applications
            if results.get("manifest_analysis", {}).get("application", {}).get("android:debuggable") == "true":
                vulnerabilities.append({
                    "type": "debuggable_application",
                    "severity": "high",
                    "description": "Application is debuggable",
                    "risk": "Allows reverse engineering and debugging"
                })
            
            # Check for cleartext traffic
            if results.get("manifest_analysis", {}).get("application", {}).get("android:usesCleartextTraffic") == "true":
                vulnerabilities.append({
                    "type": "cleartext_traffic",
                    "severity": "high",
                    "description": "Application allows cleartext network traffic",
                    "risk": "Network traffic is not encrypted"
                })
            
            # Check for backup enabled
            if results.get("manifest_analysis", {}).get("application", {}).get("android:allowBackup") == "true":
                vulnerabilities.append({
                    "type": "backup_enabled",
                    "severity": "medium",
                    "description": "Application backup is enabled",
                    "risk": "Sensitive data may be exposed through backup"
                })
            
            # Check for unprotected deep links
            for deeplink in results.get("deeplink_analysis", {}).get("deeplinks", []):
                if deeplink.get("exported") == "true" and not deeplink.get("permission"):
                    vulnerabilities.append({
                        "type": "unprotected_deeplink",
                        "severity": "high",
                        "description": f"Unprotected deep link: {deeplink.get('scheme')}://{deeplink.get('host')}",
                        "deeplink": deeplink,
                        "risk": "Deep link can be accessed by other applications"
                    })
            
            # Check for vulnerable third-party libraries
            for lib in results.get("third_party_analysis", {}).get("vulnerable_libraries", []):
                vulnerabilities.append({
                    "type": "vulnerable_library",
                    "severity": "high",
                    "description": f"Vulnerable library: {lib.get('name')} {lib.get('version')}",
                    "library": lib,
                    "risk": "Known security vulnerabilities in third-party library"
                })
            
            # Check for hardcoded secrets
            for secret in results.get("code_analysis", {}).get("hardcoded_secrets", []):
                vulnerabilities.append({
                    "type": "hardcoded_secret",
                    "severity": "high",
                    "description": f"Hardcoded secret found in {secret.get('file')}",
                    "secret": secret,
                    "risk": "Sensitive information exposed in code"
                })
            
            # Check for insecure crypto usage
            for crypto in results.get("code_analysis", {}).get("insecure_crypto", []):
                vulnerabilities.append({
                    "type": "insecure_crypto",
                    "severity": "medium",
                    "description": f"Insecure crypto usage in {crypto.get('file')}",
                    "crypto": crypto,
                    "risk": "Weak cryptographic algorithms may be compromised"
                })
            
            # Check for SQL injection patterns
            for sql in results.get("code_analysis", {}).get("sql_injection", []):
                vulnerabilities.append({
                    "type": "sql_injection_pattern",
                    "severity": "high",
                    "description": f"Potential SQL injection in {sql.get('file')}",
                    "sql": sql,
                    "risk": "SQL injection vulnerability may exist"
                })
            
            # Check for path traversal patterns
            for path in results.get("code_analysis", {}).get("path_traversal", []):
                vulnerabilities.append({
                    "type": "path_traversal_pattern",
                    "severity": "medium",
                    "description": f"Potential path traversal in {path.get('file')}",
                    "path": path,
                    "risk": "Path traversal vulnerability may exist"
                })
            
            # Check for command injection patterns
            for cmd in results.get("code_analysis", {}).get("command_injection", []):
                vulnerabilities.append({
                    "type": "command_injection_pattern",
                    "severity": "high",
                    "description": f"Potential command injection in {cmd.get('file')}",
                    "command": cmd,
                    "risk": "Command injection vulnerability may exist"
                })
            
            # Check for WebView security issues
            if results.get("webview_analysis", {}).get("webview_usage"):
                vulnerabilities.append({
                    "type": "webview_usage",
                    "severity": "info",
                    "description": "WebView usage detected",
                    "risk": "Review WebView configuration for security"
                })
            
            # Check for native library security
            native_libs = results.get("native_analysis", {}).get("native_libraries", [])
            if native_libs:
                vulnerabilities.append({
                    "type": "native_libraries",
                    "severity": "info",
                    "description": f"Found {len(native_libs)} native libraries",
                    "libraries": native_libs,
                    "risk": "Review native libraries for vulnerabilities"
                })
            
            # Check for deep analysis security issues
            for issue in results.get("deep_analysis", {}).get("security_issues", []):
                vulnerabilities.append({
                    "type": issue["type"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "risk": issue.get("recommendation", "Review security configuration")
                })
            
            # Check for intent filter security issues
            for issue in results.get("intent_analysis", {}).get("security_issues", []):
                vulnerabilities.append({
                    "type": issue["type"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "risk": "Intent filter security issue detected"
                })
            
            # Check for backup configuration issues
            for issue in results.get("backup_analysis", {}).get("security_issues", []):
                vulnerabilities.append({
                    "type": issue["type"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "risk": issue.get("impact", "Backup security issue")
                })
            
        except Exception as e:
            self.logger.error(f"Error identifying vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _identify_ios_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS-specific vulnerabilities."""
        vulnerabilities = []
        
        # Check for missing entitlements
        entitlements = results.get("entitlements", {})
        if not entitlements.get("entitlements"):
            vulnerabilities.append({
                "type": "Missing Entitlements",
                "severity": "medium",
                "description": "No entitlements file found",
                "recommendation": "Review if app needs specific entitlements for functionality"
            })
        
        # Check for unsigned app
        certificates = results.get("certificates", {})
        if not certificates.get("signing_info", {}).get("provisioned"):
            vulnerabilities.append({
                "type": "Unsigned App",
                "severity": "critical",
                "description": "App is not properly signed",
                "recommendation": "Sign the app with a valid certificate and provisioning profile"
            })
        
        return vulnerabilities
    
    def _identify_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify general security issues."""
        issues = []
        
        # Check for debug flags
        manifest = results.get("manifest_analysis", {})
        if manifest.get("debuggable") == "true":
            issues.append({
                "type": "Debug Flag",
                "severity": "high",
                "description": "App is debuggable",
                "recommendation": "Set android:debuggable=false for production builds"
            })
        
        # Check for backup enabled
        if manifest.get("allowBackup") == "true":
            issues.append({
                "type": "Backup Enabled",
                "severity": "medium",
                "description": "App allows backup",
                "recommendation": "Consider disabling backup or implementing proper backup security"
            })
        
        return issues
    
    def _identify_ios_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS-specific security issues."""
        issues = []
        
        # Check for jailbreak detection
        info_plist = results.get("info_plist", {})
        # Add iOS-specific checks here
        
        return issues
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Permission recommendations
        dangerous_perms = [p for p in results.get("permissions", []) if p.get("severity") in ["high", "critical"]]
        if dangerous_perms:
            recommendations.append("Review and minimize dangerous permissions")
            recommendations.append("Implement proper runtime permission handling")
        
        # Component recommendations
        if results.get("components", {}).get("security_issues"):
            recommendations.append("Protect exported components with proper permissions")
            recommendations.append("Set exported=false for internal components")
        
        # General recommendations
        recommendations.extend([
            "Implement certificate pinning for network communications",
            "Use secure storage for sensitive data",
            "Implement proper input validation",
            "Enable ProGuard/R8 for code obfuscation",
            "Use HTTPS for all network communications",
            "Implement proper session management",
            "Regular security audits and penetration testing"
        ])
        
        return recommendations
    
    def _generate_ios_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate iOS-specific recommendations."""
        recommendations = [
            "Implement proper code signing",
            "Use App Transport Security (ATS)",
            "Implement proper keychain usage",
            "Use secure enclave for sensitive data",
            "Implement proper entitlements",
            "Regular security audits and penetration testing"
        ]
        
        return recommendations 

    def _deep_manifest_analysis(self, manifest_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deep analysis of AndroidManifest.xml."""
        deep_analysis = {
            "security_config": {},
            "network_security": {},
            "backup_config": {},
            "exported_components": [],
            "intent_filters": [],
            "content_providers": [],
            "broadcast_receivers": [],
            "services": [],
            "activities": [],
            "permission_groups": {},
            "uses_features": [],
            "uses_libraries": [],
            "application_attributes": {},
            "security_issues": []
        }
        
        try:
            # Analyze security configuration
            if "application" in manifest_analysis:
                app = manifest_analysis["application"]
                deep_analysis["application_attributes"] = {
                    "allowBackup": app.get("android:allowBackup"),
                    "allowClearUserData": app.get("android:allowClearUserData"),
                    "allowTaskReparenting": app.get("android:allowTaskReparenting"),
                    "allowClearUserData": app.get("android:allowClearUserData"),
                    "debuggable": app.get("android:debuggable"),
                    "hardwareAccelerated": app.get("android:hardwareAccelerated"),
                    "largeHeap": app.get("android:largeHeap"),
                    "requestLegacyExternalStorage": app.get("android:requestLegacyExternalStorage"),
                    "usesCleartextTraffic": app.get("android:usesCleartextTraffic"),
                    "networkSecurityConfig": app.get("android:networkSecurityConfig")
                }
                
                # Check for security issues
                if app.get("android:allowBackup") == "true":
                    deep_analysis["security_issues"].append({
                        "type": "backup_enabled",
                        "severity": "medium",
                        "description": "Application backup is enabled, potentially exposing sensitive data",
                        "recommendation": "Disable backup or implement proper backup encryption"
                    })
                
                if app.get("android:debuggable") == "true":
                    deep_analysis["security_issues"].append({
                        "type": "debuggable",
                        "severity": "high",
                        "description": "Application is debuggable, allowing reverse engineering",
                        "recommendation": "Disable debuggable flag in production builds"
                    })
                
                if app.get("android:usesCleartextTraffic") == "true":
                    deep_analysis["security_issues"].append({
                        "type": "cleartext_traffic",
                        "severity": "high",
                        "description": "Application allows cleartext network traffic",
                        "recommendation": "Disable cleartext traffic and use HTTPS only"
                    })
            
            # Analyze exported components
            for activity in manifest_analysis.get("activities", []):
                if activity.get("exported") == "true":
                    deep_analysis["exported_components"].append({
                        "type": "activity",
                        "name": activity.get("name"),
                        "permission": activity.get("permission"),
                        "intent_filters": activity.get("intent_filters", [])
                    })
            
            for service in manifest_analysis.get("services", []):
                if service.get("exported") == "true":
                    deep_analysis["exported_components"].append({
                        "type": "service",
                        "name": service.get("name"),
                        "permission": service.get("permission"),
                        "intent_filters": service.get("intent_filters", [])
                    })
            
            for receiver in manifest_analysis.get("receivers", []):
                if receiver.get("exported") == "true":
                    deep_analysis["exported_components"].append({
                        "type": "receiver",
                        "name": receiver.get("name"),
                        "permission": receiver.get("permission"),
                        "intent_filters": receiver.get("intent_filters", [])
                    })
            
            for provider in manifest_analysis.get("providers", []):
                if provider.get("exported") == "true":
                    deep_analysis["exported_components"].append({
                        "type": "provider",
                        "name": provider.get("name"),
                        "permission": provider.get("permission"),
                        "authorities": provider.get("authorities")
                    })
            
        except Exception as e:
            self.logger.error(f"Error in deep manifest analysis: {str(e)}")
            deep_analysis["error"] = str(e)
        
        return deep_analysis
    
    def _analyze_intent_filters(self, manifest_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze intent filters for security issues."""
        intent_analysis = {
            "intent_filters": [],
            "deeplinks": [],
            "schemes": [],
            "hosts": [],
            "security_issues": []
        }
        
        try:
            # Extract all intent filters
            for activity in manifest_analysis.get("activities", []):
                for intent_filter in activity.get("intent_filters", []):
                    intent_analysis["intent_filters"].append({
                        "component": activity.get("name"),
                        "type": "activity",
                        "actions": intent_filter.get("actions", []),
                        "categories": intent_filter.get("categories", []),
                        "data": intent_filter.get("data", [])
                    })
                    
                    # Check for deep links
                    for data in intent_filter.get("data", []):
                        if data.get("scheme"):
                            intent_analysis["schemes"].append(data.get("scheme"))
                            if data.get("host"):
                                intent_analysis["hosts"].append(data.get("host"))
                                intent_analysis["deeplinks"].append({
                                    "scheme": data.get("scheme"),
                                    "host": data.get("host"),
                                    "path": data.get("path"),
                                    "component": activity.get("name")
                                })
            
            # Check for security issues
            if len(intent_analysis["deeplinks"]) > 0:
                intent_analysis["security_issues"].append({
                    "type": "deeplinks_exposed",
                    "severity": "medium",
                    "description": f"Found {len(intent_analysis['deeplinks'])} deep links",
                    "deeplinks": intent_analysis["deeplinks"]
                })
            
            # Check for dangerous intent actions
            dangerous_actions = [
                "android.intent.action.VIEW",
                "android.intent.action.EDIT",
                "android.intent.action.PICK",
                "android.intent.action.GET_CONTENT"
            ]
            
            for intent_filter in intent_analysis["intent_filters"]:
                for action in intent_filter["actions"]:
                    if action in dangerous_actions and intent_filter["component"]:
                        intent_analysis["security_issues"].append({
                            "type": "dangerous_intent_action",
                            "severity": "medium",
                            "description": f"Dangerous intent action '{action}' in component {intent_filter['component']}",
                            "action": action,
                            "component": intent_filter["component"]
                        })
            
        except Exception as e:
            self.logger.error(f"Error in intent filter analysis: {str(e)}")
            intent_analysis["error"] = str(e)
        
        return intent_analysis
    
    def _analyze_deep_links(self, manifest_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze deep links for security issues."""
        deeplink_analysis = {
            "deeplinks": [],
            "schemes": set(),
            "hosts": set(),
            "security_issues": [],
            "validation_methods": []
        }
        
        try:
            for activity in manifest_analysis.get("activities", []):
                for intent_filter in activity.get("intent_filters", []):
                    for data in intent_filter.get("data", []):
                        if data.get("scheme"):
                            scheme = data.get("scheme")
                            host = data.get("host", "")
                            path = data.get("path", "")
                            
                            deeplink = {
                                "scheme": scheme,
                                "host": host,
                                "path": path,
                                "component": activity.get("name"),
                                "exported": activity.get("exported"),
                                "permission": activity.get("permission")
                            }
                            
                            deeplink_analysis["deeplinks"].append(deeplink)
                            deeplink_analysis["schemes"].add(scheme)
                            deeplink_analysis["hosts"].add(host)
                            
                            # Check for security issues
                            if activity.get("exported") == "true" and not activity.get("permission"):
                                deeplink_analysis["security_issues"].append({
                                    "type": "unprotected_deeplink",
                                    "severity": "high",
                                    "description": f"Deep link to {scheme}://{host} is unprotected",
                                    "deeplink": deeplink
                                })
            
            # Convert sets to lists for JSON serialization
            deeplink_analysis["schemes"] = list(deeplink_analysis["schemes"])
            deeplink_analysis["hosts"] = list(deeplink_analysis["hosts"])
            
        except Exception as e:
            self.logger.error(f"Error in deep link analysis: {str(e)}")
            deeplink_analysis["error"] = str(e)
        
        return deeplink_analysis
    
    def _analyze_backup_configuration(self, manifest_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze backup configuration for security issues."""
        backup_analysis = {
            "backup_enabled": False,
            "backup_rules": None,
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            if "application" in manifest_analysis:
                app = manifest_analysis["application"]
                backup_analysis["backup_enabled"] = app.get("android:allowBackup") == "true"
                
                if backup_analysis["backup_enabled"]:
                    backup_analysis["security_issues"].append({
                        "type": "backup_enabled",
                        "severity": "medium",
                        "description": "Application backup is enabled",
                        "impact": "Sensitive data may be exposed through backup"
                    })
                    
                    backup_analysis["recommendations"].append(
                        "Disable backup or implement proper backup encryption"
                    )
                    
                    # Check for backup rules
                    if app.get("android:fullBackupContent"):
                        backup_analysis["backup_rules"] = "Custom backup rules defined"
                    else:
                        backup_analysis["security_issues"].append({
                            "type": "no_backup_rules",
                            "severity": "medium",
                            "description": "No backup rules defined, all data may be backed up",
                            "impact": "Sensitive data could be exposed"
                        })
                        backup_analysis["recommendations"].append(
                            "Define backup rules to exclude sensitive data"
                        )
            
        except Exception as e:
            self.logger.error(f"Error in backup configuration analysis: {str(e)}")
            backup_analysis["error"] = str(e)
        
        return backup_analysis
    
    def _analyze_webview_configuration(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze WebView configuration for security issues."""
        webview_analysis = {
            "webview_usage": False,
            "javascript_enabled": False,
            "file_access_enabled": False,
            "dom_storage_enabled": False,
            "database_enabled": False,
            "geolocation_enabled": False,
            "mixed_content_mode": None,
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check for WebView usage in resources
            webview_patterns = [
                "WebView",
                "webview",
                "android.webkit.WebView"
            ]
            
            for filename in apk_zip.namelist():
                if filename.endswith(('.xml', '.java', '.kt')):
                    try:
                        content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                        for pattern in webview_patterns:
                            if pattern in content:
                                webview_analysis["webview_usage"] = True
                                break
                    except:
                        continue
            
            # Check for common WebView security misconfigurations
            if webview_analysis["webview_usage"]:
                webview_analysis["security_issues"].append({
                    "type": "webview_usage_detected",
                    "severity": "info",
                    "description": "WebView usage detected, review configuration"
                })
                
                webview_analysis["recommendations"].extend([
                    "Disable JavaScript if not required",
                    "Disable file access",
                    "Disable DOM storage",
                    "Disable geolocation",
                    "Set mixed content mode to MIXED_CONTENT_NEVER_ALLOW"
                ])
            
        except Exception as e:
            self.logger.error(f"Error in WebView configuration analysis: {str(e)}")
            webview_analysis["error"] = str(e)
        
        return webview_analysis
    
    def _analyze_third_party_libraries(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze third-party libraries for security issues."""
        third_party_analysis = {
            "libraries": [],
            "vulnerable_libraries": [],
            "outdated_libraries": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Common third-party library patterns
            library_patterns = {
                "okhttp": r"okhttp[0-9.-]*",
                "retrofit": r"retrofit[0-9.-]*",
                "gson": r"gson[0-9.-]*",
                "jackson": r"jackson[0-9.-]*",
                "volley": r"volley[0-9.-]*",
                "picasso": r"picasso[0-9.-]*",
                "glide": r"glide[0-9.-]*",
                "firebase": r"firebase[0-9.-]*",
                "facebook": r"facebook[0-9.-]*",
                "google": r"google[0-9.-]*"
            }
            
            for filename in apk_zip.namelist():
                if filename.endswith('.jar') or 'lib/' in filename:
                    for lib_name, pattern in library_patterns.items():
                        if re.search(pattern, filename, re.IGNORECASE):
                            third_party_analysis["libraries"].append({
                                "name": lib_name,
                                "file": filename,
                                "version": self._extract_version(filename)
                            })
            
            # Check for known vulnerable libraries
            vulnerable_libs = {
                "okhttp": ["3.12.0", "3.12.1", "3.12.2"],
                "gson": ["2.8.0", "2.8.1", "2.8.2"]
            }
            
            for lib in third_party_analysis["libraries"]:
                if lib["name"] in vulnerable_libs:
                    if lib["version"] in vulnerable_libs[lib["name"]]:
                        third_party_analysis["vulnerable_libraries"].append(lib)
                        third_party_analysis["security_issues"].append({
                            "type": "vulnerable_library",
                            "severity": "high",
                            "description": f"Vulnerable version of {lib['name']} detected",
                            "library": lib
                        })
            
        except Exception as e:
            self.logger.error(f"Error in third-party library analysis: {str(e)}")
            third_party_analysis["error"] = str(e)
        
        return third_party_analysis
    
    def _analyze_code_patterns(self, apk_zip: zipfile.ZipFile) -> Dict[str, Any]:
        """Analyze code patterns for security issues."""
        code_analysis = {
            "hardcoded_secrets": [],
            "insecure_crypto": [],
            "sql_injection": [],
            "path_traversal": [],
            "command_injection": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Patterns for security issues
            patterns = {
                "hardcoded_secrets": [
                    r'password["\s]*[:=]["\s]*["\'][^"\']+["\']',
                    r'api_key["\s]*[:=]["\s]*["\'][^"\']+["\']',
                    r'secret["\s]*[:=]["\s]*["\'][^"\']+["\']',
                    r'token["\s]*[:=]["\s]*["\'][^"\']+["\']'
                ],
                "insecure_crypto": [
                    r'MD5',
                    r'SHA1',
                    r'DES',
                    r'RC4',
                    r'Blowfish'
                ],
                "sql_injection": [
                    r'rawQuery\s*\(',
                    r'execSQL\s*\(',
                    r'String\.format.*SELECT',
                    r'String\.format.*INSERT',
                    r'String\.format.*UPDATE',
                    r'String\.format.*DELETE'
                ],
                "path_traversal": [
                    r'\.\./',
                    r'\.\.\\',
                    r'%2e%2e',
                    r'%2e%2e%2f'
                ],
                "command_injection": [
                    r'Runtime\.getRuntime\(\)\.exec',
                    r'ProcessBuilder',
                    r'Process\.start'
                ]
            }
            
            for filename in apk_zip.namelist():
                if filename.endswith(('.java', '.kt', '.xml')):
                    try:
                        content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                        
                        for issue_type, pattern_list in patterns.items():
                            for pattern in pattern_list:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    code_analysis[issue_type].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "line": content[:match.start()].count('\n') + 1,
                                        "match": match.group()
                                    })
                    except:
                        continue
            
            # Generate security issues
            for issue_type, findings in code_analysis.items():
                if findings and issue_type != "security_issues" and issue_type != "recommendations":
                    code_analysis["security_issues"].append({
                        "type": issue_type,
                        "severity": "high" if issue_type in ["hardcoded_secrets", "sql_injection"] else "medium",
                        "description": f"Found {len(findings)} {issue_type.replace('_', ' ')}",
                        "findings": findings
                    })
            
        except Exception as e:
            self.logger.error(f"Error in code pattern analysis: {str(e)}")
            code_analysis["error"] = str(e)
        
        return code_analysis
    
    def _extract_version(self, filename: str) -> str:
        """Extract version from filename."""
        version_pattern = r'[0-9]+\.[0-9]+(\.[0-9]+)?'
        match = re.search(version_pattern, filename)
        return match.group() if match else "unknown" 