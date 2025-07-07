#!/usr/bin/env python3
"""
Storage Analyzer for Mobile Security Testing
Analyzes data storage and encryption implementations.
"""

import os
import subprocess
import json
import logging
import sqlite3
import tempfile
import shutil
import re
import zipfile
from typing import Dict, List, Any, Optional
from pathlib import Path
import xml.etree.ElementTree as ET

class StorageAnalyzer:
    """Storage analysis of mobile applications."""
    
    def __init__(self, debug: bool = False):
        """Initialize storage analyzer."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        
        # Android-specific storage security patterns
        self.secure_storage_patterns = [
            r'android\.security\.keystore\.KeyStore',
            r'android\.security\.keystore\.KeyGenParameterSpec',
            r'android\.security\.keystore\.KeyProperties',
            r'javax\.crypto\.Cipher',
            r'javax\.crypto\.KeyGenerator',
            r'javax\.crypto\.SecretKey',
            r'android\.security\.keystore\.KeyStore\.Entry'
        ]
        
        self.insecure_storage_patterns = [
            r'SharedPreferences\.edit\(\)',
            r'getSharedPreferences',
            r'openFileOutput',
            r'openFileInput',
            r'FileOutputStream',
            r'FileInputStream',
            r'SQLiteDatabase\.openOrCreateDatabase',
            r'SQLiteDatabase\.openDatabase'
        ]
        
        self.data_leakage_patterns = [
            r'Log\.d\s*\([^)]*password[^)]*\)',
            r'Log\.v\s*\([^)]*token[^)]*\)',
            r'Log\.i\s*\([^)]*api_key[^)]*\)',
            r'Log\.w\s*\([^)]*secret[^)]*\)',
            r'System\.out\.println\s*\([^)]*password[^)]*\)',
            r'System\.err\.println\s*\([^)]*token[^)]*\)'
        ]
        
        self.encryption_patterns = {
            "secure": [
                r'AES/GCM/NoPadding',
                r'AES/CBC/PKCS5Padding',
                r'RSA/ECB/PKCS1Padding',
                r'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'
            ],
            "insecure": [
                r'DES',
                r'3DES',
                r'RC4',
                r'MD5',
                r'SHA1',
                r'Blowfish'
            ]
        }
        
    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """Analyze storage security from APK."""
        self.logger.info(f"Starting storage analysis of APK: {apk_path}")
        
        results = {
            "storage_config": {},
            "databases": [],
            "shared_preferences": [],
            "file_storage": [],
            "encryption_analysis": {},
            "backup_analysis": {},
            "secure_storage_analysis": {},
            "data_leakage_analysis": {},
            "external_storage_analysis": {},
            "cache_analysis": {},
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Extract storage configuration
            results["storage_config"] = self._extract_storage_config(apk_path)
            
            # Analyze database configurations
            results["databases"] = self._analyze_database_configs(apk_path)
            
            # Analyze shared preferences
            results["shared_preferences"] = self._analyze_shared_preferences(apk_path)
            
            # Analyze file storage
            results["file_storage"] = self._analyze_file_storage(apk_path)
            
            # Analyze encryption implementation
            results["encryption_analysis"] = self._analyze_encryption(apk_path)
            
            # Analyze backup configuration
            results["backup_analysis"] = self._analyze_backup_config(apk_path)
            
            # Analyze secure storage implementation
            results["secure_storage_analysis"] = self._analyze_secure_storage(apk_path)
            
            # Analyze data leakage patterns
            results["data_leakage_analysis"] = self._analyze_data_leakage(apk_path)
            
            # Analyze external storage usage
            results["external_storage_analysis"] = self._analyze_external_storage(apk_path)
            
            # Analyze cache storage
            results["cache_analysis"] = self._analyze_cache_storage(apk_path)
            
        except Exception as e:
            self.logger.error(f"Error during storage analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_storage_vulnerabilities(results)
        results["security_issues"] = self._identify_storage_security_issues(results)
        results["recommendations"] = self._generate_storage_recommendations(results)
        
        return results
    
    def analyze_ipa(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze storage security from IPA."""
        self.logger.info(f"Starting storage analysis of IPA: {ipa_path}")
        
        results = {
            "storage_config": {},
            "databases": [],
            "keychain_analysis": {},
            "file_storage": [],
            "encryption_analysis": {},
            "backup_analysis": {},
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Extract storage configuration
            results["storage_config"] = self._extract_ios_storage_config(ipa_path)
            
            # Analyze database configurations
            results["databases"] = self._analyze_ios_database_configs(ipa_path)
            
            # Analyze keychain usage
            results["keychain_analysis"] = self._analyze_keychain_usage(ipa_path)
            
            # Analyze file storage
            results["file_storage"] = self._analyze_ios_file_storage(ipa_path)
            
            # Analyze encryption implementation
            results["encryption_analysis"] = self._analyze_ios_encryption(ipa_path)
            
            # Analyze backup configuration
            results["backup_analysis"] = self._analyze_ios_backup_config(ipa_path)
            
        except Exception as e:
            self.logger.error(f"Error during iOS storage analysis: {str(e)}")
            results["error"] = str(e)
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_ios_storage_vulnerabilities(results)
        results["security_issues"] = self._identify_ios_storage_security_issues(results)
        results["recommendations"] = self._generate_ios_storage_recommendations(results)
        
        return results
    
    def analyze_device(self, device_type: str, package_name: str = None) -> Dict[str, Any]:
        """Analyze storage on device."""
        self.logger.info(f"Starting device storage analysis: {device_type}")
        
        results = {
            "app_data": {},
            "databases": [],
            "shared_preferences": [],
            "cache_files": [],
            "external_storage": [],
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            if device_type.lower() == "android":
                if package_name:
                    results["app_data"] = self._analyze_android_app_data(package_name)
                    results["databases"] = self._analyze_android_databases(package_name)
                    results["shared_preferences"] = self._analyze_android_shared_preferences(package_name)
                    results["cache_files"] = self._analyze_android_cache(package_name)
                    results["external_storage"] = self._analyze_android_external_storage(package_name)
                else:
                    results["error"] = "Package name required for Android device analysis"
            
            elif device_type.lower() == "ios":
                if package_name:
                    results["app_data"] = self._analyze_ios_app_data(package_name)
                    results["databases"] = self._analyze_ios_databases(package_name)
                    results["keychain"] = self._analyze_ios_keychain(package_name)
                else:
                    results["error"] = "Package name required for iOS device analysis"
        
        except Exception as e:
            self.logger.error(f"Error during device storage analysis: {str(e)}")
            results["error"] = str(e)
        
        return results
    
    def _extract_storage_config(self, apk_path: str) -> Dict[str, Any]:
        """Extract storage configuration from APK."""
        config = {
            "backup_enabled": False,
            "allow_backup": True,
            "full_backup_content": False,
            "external_storage": False,
            "security_issues": []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    # Check AndroidManifest.xml for backup settings
                    manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
                    if os.path.exists(manifest_path):
                        config.update(self._parse_backup_config(manifest_path))
                    
                    # Check for external storage usage
                    config["external_storage"] = self._check_external_storage_usage(temp_dir)
        
        except Exception as e:
            self.logger.error(f"Error extracting storage config: {str(e)}")
            config["error"] = str(e)
        
        return config
    
    def _extract_ios_storage_config(self, ipa_path: str) -> Dict[str, Any]:
        """Extract iOS storage configuration."""
        config = {
            "backup_enabled": True,
            "keychain_access": False,
            "file_protection": "complete",
            "security_issues": []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Find Info.plist
                    for filename in ipa_zip.namelist():
                        if filename.endswith("Info.plist"):
                            plist_data = ipa_zip.read(filename)
                            config.update(self._parse_ios_storage_config(plist_data))
                            break
        
        except Exception as e:
            self.logger.error(f"Error extracting iOS storage config: {str(e)}")
            config["error"] = str(e)
        
        return config
    
    def _analyze_database_configs(self, apk_path: str) -> List[Dict[str, Any]]:
        """Analyze database configurations in APK."""
        databases = []
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    # Look for database-related code
                    databases = self._find_database_usage(temp_dir)
        
        except Exception as e:
            self.logger.error(f"Error analyzing database configs: {str(e)}")
        
        return databases
    
    def _analyze_ios_database_configs(self, ipa_path: str) -> List[Dict[str, Any]]:
        """Analyze iOS database configurations."""
        databases = []
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Look for database files and configurations
                    for filename in ipa_zip.namelist():
                        if filename.endswith((".db", ".sqlite", ".sqlite3")):
                            databases.append({
                                "type": "embedded_database",
                                "file": filename,
                                "encrypted": False  # Would need to check encryption
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS database configs: {str(e)}")
        
        return databases
    
    def _analyze_shared_preferences(self, apk_path: str) -> List[Dict[str, Any]]:
        """Analyze shared preferences usage."""
        preferences = []
        
        try:
            # First try with apktool if available
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    result = subprocess.run(
                        ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        # Look for SharedPreferences usage in code
                        preferences = self._find_shared_preferences_usage(temp_dir)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Fallback: analyze APK directly without apktool
                preferences = self._analyze_shared_preferences_direct(apk_path)
        
        except Exception as e:
            self.logger.error(f"Error analyzing shared preferences: {str(e)}")
            # Return basic analysis
            preferences = [
                {
                    "type": "SharedPreferences",
                    "usage": "Detected",
                    "security_level": "medium",
                    "description": "Standard Android preferences storage"
                }
            ]
        
        return preferences
    
    def _analyze_shared_preferences_direct(self, apk_path: str) -> List[Dict[str, Any]]:
        """Analyze shared preferences directly from APK without external tools."""
        preferences = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for SharedPreferences patterns in files
                for filename in apk_zip.namelist():
                    if filename.endswith('.smali') or filename.endswith('.java'):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            if 'SharedPreferences' in content:
                                preferences.append({
                                    "type": "SharedPreferences",
                                    "file": filename,
                                    "usage": "Detected",
                                    "security_level": "medium",
                                    "description": "SharedPreferences usage found in code"
                                })
                        except:
                            continue
        except Exception as e:
            self.logger.warning(f"Error in direct shared preferences analysis: {str(e)}")
        
        return preferences
    
    def _analyze_keychain_usage(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS keychain usage."""
        keychain = {
            "keychain_access": False,
            "entitlements": [],
            "security_issues": []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Look for keychain entitlements
                    for filename in ipa_zip.namelist():
                        if filename.endswith(".entitlements"):
                            keychain["entitlements"].append(filename)
                            keychain["keychain_access"] = True
        
        except Exception as e:
            self.logger.error(f"Error analyzing keychain usage: {str(e)}")
        
        return keychain
    
    def _analyze_file_storage(self, apk_path: str) -> List[Dict[str, Any]]:
        """Analyze file storage patterns."""
        file_storage = []
        
        try:
            # First try with apktool if available
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    result = subprocess.run(
                        ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        # Look for file storage patterns in code
                        file_storage = self._find_file_storage_patterns(temp_dir)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Fallback: analyze APK directly without apktool
                file_storage = self._analyze_file_storage_direct(apk_path)
        
        except Exception as e:
            self.logger.error(f"Error analyzing file storage: {str(e)}")
            # Return basic analysis
            file_storage = [
                {
                    "type": "FileStorage",
                    "usage": "Detected",
                    "security_level": "medium",
                    "description": "Standard Android file storage"
                }
            ]
        
        return file_storage
    
    def _analyze_file_storage_direct(self, apk_path: str) -> List[Dict[str, Any]]:
        """Analyze file storage directly from APK without external tools."""
        file_storage = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for file storage patterns in files
                for filename in apk_zip.namelist():
                    if filename.endswith('.smali') or filename.endswith('.java'):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            if any(pattern in content for pattern in ['FileOutputStream', 'FileInputStream', 'openFileOutput', 'openFileInput']):
                                file_storage.append({
                                    "type": "FileStorage",
                                    "file": filename,
                                    "usage": "Detected",
                                    "security_level": "medium",
                                    "description": "File storage usage found in code"
                                })
                        except:
                            continue
        except Exception as e:
            self.logger.warning(f"Error in direct file storage analysis: {str(e)}")
        
        return file_storage
    
    def _analyze_ios_file_storage(self, ipa_path: str) -> List[Dict[str, Any]]:
        """Analyze iOS file storage patterns."""
        file_storage = []
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Look for file storage patterns
                    for filename in ipa_zip.namelist():
                        if any(pattern in filename for pattern in ["Documents/", "Library/", "tmp/"]):
                            file_storage.append({
                                "type": "app_storage",
                                "path": filename,
                                "encrypted": False  # Would need to check encryption
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS file storage: {str(e)}")
        
        return file_storage
    
    def _analyze_encryption(self, apk_path: str) -> Dict[str, Any]:
        """Analyze encryption implementation."""
        encryption = {
            "encryption_used": False,
            "encryption_methods": [],
            "key_management": {},
            "security_issues": []
        }
        
        try:
            # First try with apktool if available
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    result = subprocess.run(
                        ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    if result.returncode == 0:
                        encryption.update(self._find_encryption_implementation(temp_dir))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # Fallback: analyze APK directly without apktool
                encryption.update(self._analyze_encryption_direct(apk_path))
        
        except Exception as e:
            self.logger.error(f"Error analyzing encryption: {str(e)}")
            encryption["error"] = str(e)
            # Return basic analysis
            encryption.update({
                "encryption_used": False,
                "encryption_methods": [],
                "key_management": {"type": "unknown"},
                "security_issues": []
            })
        
        return encryption
    
    def _analyze_encryption_direct(self, apk_path: str) -> Dict[str, Any]:
        """Analyze encryption directly from APK without external tools."""
        encryption = {
            "encryption_used": False,
            "encryption_methods": [],
            "key_management": {},
            "security_issues": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for encryption patterns in files
                for filename in apk_zip.namelist():
                    if filename.endswith('.smali') or filename.endswith('.java'):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            if any(pattern in content for pattern in ['Cipher', 'KeyGenerator', 'SecretKey', 'KeyStore']):
                                encryption["encryption_used"] = True
                                encryption["encryption_methods"].append("Java Cryptography")
                                encryption["key_management"]["type"] = "Java KeyStore"
                        except:
                            continue
        except Exception as e:
            self.logger.warning(f"Error in direct encryption analysis: {str(e)}")
        
        return encryption
    
    def _analyze_ios_encryption(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS encryption implementation."""
        encryption = {
            "encryption_used": False,
            "encryption_methods": [],
            "keychain_encryption": False,
            "security_issues": []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Look for encryption patterns in binary
                    for filename in ipa_zip.namelist():
                        if filename.endswith((".dylib", ".framework")):
                            encryption["encryption_used"] = True
                            encryption["encryption_methods"].append("native_encryption")
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS encryption: {str(e)}")
            encryption["error"] = str(e)
        
        return encryption
    
    def _analyze_backup_config(self, apk_path: str) -> Dict[str, Any]:
        """Analyze backup configuration."""
        backup = {
            "backup_enabled": True,
            "full_backup_content": False,
            "include_external": False,
            "security_issues": []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                result = subprocess.run(
                    ["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    # Check AndroidManifest.xml for backup settings
                    manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
                    if os.path.exists(manifest_path):
                        backup.update(self._parse_backup_config(manifest_path))
        
        except Exception as e:
            self.logger.error(f"Error analyzing backup config: {str(e)}")
            backup["error"] = str(e)
        
        return backup
    
    def _analyze_ios_backup_config(self, ipa_path: str) -> Dict[str, Any]:
        """Analyze iOS backup configuration."""
        backup = {
            "backup_enabled": True,
            "excluded_files": [],
            "security_issues": []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                    # Look for backup exclusion patterns
                    for filename in ipa_zip.namelist():
                        if "backup" in filename.lower():
                            backup["excluded_files"].append(filename)
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS backup config: {str(e)}")
            backup["error"] = str(e)
        
        return backup
    
    def _analyze_android_app_data(self, package_name: str) -> Dict[str, Any]:
        """Analyze Android app data on device."""
        app_data = {
            "data_directory": f"/data/data/{package_name}",
            "files": [],
            "permissions": [],
            "security_issues": []
        }
        
        try:
            # List app data files
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/data/data/{package_name}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                app_data["files"] = result.stdout.strip().split('\n')
            
            # Check file permissions
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/data/data/{package_name}/databases"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                app_data["permissions"] = result.stdout.strip().split('\n')
        
        except Exception as e:
            self.logger.error(f"Error analyzing Android app data: {str(e)}")
            app_data["error"] = str(e)
        
        return app_data
    
    def _analyze_android_databases(self, package_name: str) -> List[Dict[str, Any]]:
        """Analyze Android databases on device."""
        databases = []
        
        try:
            # List database files
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/data/data/{package_name}/databases"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('total'):
                        parts = line.split()
                        if len(parts) >= 9:
                            databases.append({
                                "name": parts[8],
                                "size": parts[4],
                                "permissions": parts[0]
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing Android databases: {str(e)}")
        
        return databases
    
    def _analyze_android_shared_preferences(self, package_name: str) -> List[Dict[str, Any]]:
        """Analyze Android shared preferences on device."""
        preferences = []
        
        try:
            # List shared preferences files
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/data/data/{package_name}/shared_prefs"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('total'):
                        parts = line.split()
                        if len(parts) >= 9:
                            preferences.append({
                                "name": parts[8],
                                "size": parts[4],
                                "permissions": parts[0]
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing Android shared preferences: {str(e)}")
        
        return preferences
    
    def _analyze_android_cache(self, package_name: str) -> List[Dict[str, Any]]:
        """Analyze Android cache files."""
        cache_files = []
        
        try:
            # List cache files
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/data/data/{package_name}/cache"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('total'):
                        parts = line.split()
                        if len(parts) >= 9:
                            cache_files.append({
                                "name": parts[8],
                                "size": parts[4],
                                "permissions": parts[0]
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing Android cache: {str(e)}")
        
        return cache_files
    
    def _analyze_android_external_storage(self, package_name: str) -> List[Dict[str, Any]]:
        """Analyze Android external storage."""
        external_files = []
        
        try:
            # List external storage files
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", f"/sdcard/Android/data/{package_name}"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('total'):
                        parts = line.split()
                        if len(parts) >= 9:
                            external_files.append({
                                "name": parts[8],
                                "size": parts[4],
                                "permissions": parts[0]
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing Android external storage: {str(e)}")
        
        return external_files
    
    def _analyze_ios_app_data(self, package_name: str) -> Dict[str, Any]:
        """Analyze iOS app data on device."""
        app_data = {
            "data_directory": f"/var/mobile/Containers/Data/Application/{package_name}",
            "files": [],
            "security_issues": []
        }
        
        try:
            # iOS device analysis requires additional tools
            app_data["note"] = "iOS device analysis requires libimobiledevice tools"
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS app data: {str(e)}")
            app_data["error"] = str(e)
        
        return app_data
    
    def _analyze_ios_databases(self, package_name: str) -> List[Dict[str, Any]]:
        """Analyze iOS databases on device."""
        databases = []
        
        try:
            # iOS device analysis requires additional tools
            databases.append({
                "note": "iOS database analysis requires libimobiledevice tools"
            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS databases: {str(e)}")
        
        return databases
    
    def _analyze_ios_keychain(self, package_name: str) -> Dict[str, Any]:
        """Analyze iOS keychain on device."""
        keychain = {
            "keychain_items": [],
            "security_issues": []
        }
        
        try:
            # iOS device analysis requires additional tools
            keychain["note"] = "iOS keychain analysis requires libimobiledevice tools"
        
        except Exception as e:
            self.logger.error(f"Error analyzing iOS keychain: {str(e)}")
            keychain["error"] = str(e)
        
        return keychain
    
    def _parse_backup_config(self, manifest_path: str) -> Dict[str, Any]:
        """Parse backup configuration from AndroidManifest.xml."""
        backup_config = {
            "backup_enabled": True,
            "full_backup_content": False,
            "include_external": False
        }
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Check application tag for backup settings
            application = root.find(".//application")
            if application is not None:
                allow_backup = application.get("android:allowBackup")
                if allow_backup == "false":
                    backup_config["backup_enabled"] = False
                
                full_backup_content = application.get("android:fullBackupContent")
                if full_backup_content:
                    backup_config["full_backup_content"] = True
            
        except Exception as e:
            self.logger.error(f"Error parsing backup config: {str(e)}")
        
        return backup_config
    
    def _parse_ios_storage_config(self, plist_data: bytes) -> Dict[str, Any]:
        """Parse iOS storage configuration."""
        storage_config = {
            "backup_enabled": True,
            "keychain_access": False,
            "file_protection": "complete"
        }
        
        try:
            # This is a simplified parser
            # In production, use a proper plist parser
            plist_text = plist_data.decode('utf-8', errors='ignore')
            
            if "NSFileProtectionComplete" in plist_text:
                storage_config["file_protection"] = "complete"
            elif "NSFileProtectionCompleteUnlessOpen" in plist_text:
                storage_config["file_protection"] = "complete_unless_open"
            elif "NSFileProtectionCompleteUntilFirstUserAuthentication" in plist_text:
                storage_config["file_protection"] = "complete_until_first_auth"
        
        except Exception as e:
            self.logger.error(f"Error parsing iOS storage config: {str(e)}")
        
        return storage_config
    
    def _check_external_storage_usage(self, temp_dir: str) -> bool:
        """Check for external storage usage."""
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if any(keyword in content for keyword in [
                                "getExternalStorageDirectory", "getExternalFilesDir",
                                "Environment.getExternalStorageState"
                            ]):
                                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking external storage usage: {str(e)}")
            return False
    
    def _find_database_usage(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find database usage in code."""
        databases = []
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            if "SQLiteDatabase" in content:
                                databases.append({
                                    "type": "SQLite",
                                    "file": file,
                                    "encrypted": "SQLCipher" in content
                                })
                            
                            if "Room" in content:
                                databases.append({
                                    "type": "Room",
                                    "file": file,
                                    "encrypted": False
                                })
        
        except Exception as e:
            self.logger.error(f"Error finding database usage: {str(e)}")
        
        return databases
    
    def _find_shared_preferences_usage(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find shared preferences usage in code."""
        preferences = []
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            if "SharedPreferences" in content:
                                preferences.append({
                                    "type": "SharedPreferences",
                                    "file": file,
                                    "encrypted": "EncryptedSharedPreferences" in content
                                })
        
        except Exception as e:
            self.logger.error(f"Error finding shared preferences usage: {str(e)}")
        
        return preferences
    
    def _find_file_storage_patterns(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Find file storage patterns in code."""
        patterns = []
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            if "FileOutputStream" in content or "FileInputStream" in content:
                                patterns.append({
                                    "type": "File I/O",
                                    "file": file,
                                    "encrypted": "Cipher" in content
                                })
        
        except Exception as e:
            self.logger.error(f"Error finding file storage patterns: {str(e)}")
        
        return patterns
    
    def _find_encryption_implementation(self, temp_dir: str) -> Dict[str, Any]:
        """Find encryption implementation in code."""
        encryption = {
            "encryption_used": False,
            "encryption_methods": [],
            "key_management": {},
            "security_issues": []
        }
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith((".java", ".kt")):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Check for encryption usage
                            if any(keyword in content for keyword in [
                                "Cipher", "SecretKey", "KeyGenerator", "AES", "RSA"
                            ]):
                                encryption["encryption_used"] = True
                                encryption["encryption_methods"].append("standard_crypto")
                            
                            # Check for hardcoded keys
                            if any(keyword in content for keyword in [
                                "secret", "key", "password", "token"
                            ]):
                                encryption["security_issues"].append({
                                    "type": "Potential Hardcoded Key",
                                    "file": file,
                                    "severity": "high"
                                })
        
        except Exception as e:
            self.logger.error(f"Error finding encryption implementation: {str(e)}")
        
        return encryption
    
    def _identify_storage_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify storage vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for insecure backup
            backup_config = results.get("backup_analysis", {})
            if backup_config.get("backup_enabled"):
                vulnerabilities.append({
                    "type": "Insecure Backup",
                    "severity": "medium",
                    "description": "App allows backup which may expose sensitive data",
                    "recommendation": "Disable backup or implement secure backup encryption"
                })
            
            # Check for missing encryption
            encryption = results.get("encryption_analysis", {})
            if not encryption.get("encryption_used"):
                vulnerabilities.append({
                    "type": "No Encryption",
                    "severity": "high",
                    "description": "App does not use encryption for sensitive data",
                    "recommendation": "Implement encryption for sensitive data storage"
                })
            
            # Check for external storage usage
            if results.get("storage_config", {}).get("external_storage"):
                vulnerabilities.append({
                    "type": "External Storage",
                    "severity": "medium",
                    "description": "App uses external storage which is less secure",
                    "recommendation": "Use internal storage for sensitive data"
                })
            
            # Check for secure storage issues
            secure_storage = results.get("secure_storage_analysis", {})
            if not secure_storage.get("keystore_usage"):
                vulnerabilities.append({
                    "type": "No Secure Storage",
                    "severity": "high",
                    "description": "No Android Keystore usage detected",
                    "recommendation": "Implement Android Keystore for secure key storage"
                })
            
            if secure_storage.get("insecure_storage_patterns"):
                vulnerabilities.append({
                    "type": "Insecure Storage Patterns",
                    "severity": "medium",
                    "description": f"Found {len(secure_storage['insecure_storage_patterns'])} insecure storage patterns",
                    "recommendation": "Review and secure all data storage implementations"
                })
            
            # Check for data leakage issues
            data_leakage = results.get("data_leakage_analysis", {})
            if data_leakage.get("leakage_patterns"):
                vulnerabilities.append({
                    "type": "Data Leakage Patterns",
                    "severity": "high",
                    "description": f"Found {len(data_leakage['leakage_patterns'])} data leakage patterns",
                    "recommendation": "Remove or secure all sensitive data logging"
                })
            
            if data_leakage.get("sensitive_data_logging"):
                vulnerabilities.append({
                    "type": "Sensitive Data Logging",
                    "severity": "medium",
                    "description": f"Found {len(data_leakage['sensitive_data_logging'])} instances of sensitive data logging",
                    "recommendation": "Implement secure logging practices for sensitive data"
                })
            
            # Check for external storage security issues
            external_storage = results.get("external_storage_analysis", {})
            if external_storage.get("external_storage_usage"):
                vulnerabilities.append({
                    "type": "External Storage Usage",
                    "severity": "medium",
                    "description": "External storage usage detected",
                    "recommendation": "Use internal storage for sensitive data or implement proper encryption"
                })
            
            if external_storage.get("storage_permissions"):
                vulnerabilities.append({
                    "type": "External Storage Permissions",
                    "severity": "medium",
                    "description": f"External storage permissions: {len(external_storage['storage_permissions'])}",
                    "recommendation": "Review and minimize external storage permissions"
                })
            
            # Check for cache storage issues
            cache_analysis = results.get("cache_analysis", {})
            if cache_analysis.get("sensitive_data_in_cache"):
                vulnerabilities.append({
                    "type": "Sensitive Data in Cache",
                    "severity": "high",
                    "description": f"Found {len(cache_analysis['sensitive_data_in_cache'])} instances of sensitive data in cache",
                    "recommendation": "Avoid storing sensitive data in cache directories"
                })
            
            # Check for database security issues
            databases = results.get("databases", [])
            for db in databases:
                if not db.get("encrypted", False):
                    vulnerabilities.append({
                        "type": "Unencrypted Database",
                        "severity": "medium",
                        "description": f"Database {db.get('name', 'unknown')} is not encrypted",
                        "recommendation": "Implement database encryption for sensitive data"
                    })
            
            # Check for shared preferences security issues
            shared_prefs = results.get("shared_preferences", [])
            for pref in shared_prefs:
                if not pref.get("encrypted", False):
                    vulnerabilities.append({
                        "type": "Unencrypted SharedPreferences",
                        "severity": "medium",
                        "description": f"SharedPreferences {pref.get('name', 'unknown')} is not encrypted",
                        "recommendation": "Use encrypted SharedPreferences for sensitive data"
                    })
            
            # Check for file storage security issues
            file_storage = results.get("file_storage", [])
            for file in file_storage:
                if not file.get("encrypted", False):
                    vulnerabilities.append({
                        "type": "Unencrypted File Storage",
                        "severity": "medium",
                        "description": f"File storage {file.get('name', 'unknown')} is not encrypted",
                        "recommendation": "Implement file encryption for sensitive data"
                    })
        
        except Exception as e:
            self.logger.error(f"Error identifying storage vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _identify_ios_storage_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS-specific storage vulnerabilities."""
        vulnerabilities = []
        
        # Check for missing keychain usage
        keychain = results.get("keychain_analysis", {})
        if not keychain.get("keychain_access"):
            vulnerabilities.append({
                "type": "No Keychain Usage",
                "severity": "medium",
                "description": "App does not use keychain for sensitive data",
                "recommendation": "Use keychain for storing sensitive data"
            })
        
        # Check for weak file protection
        storage_config = results.get("storage_config", {})
        if storage_config.get("file_protection") != "complete":
            vulnerabilities.append({
                "type": "Weak File Protection",
                "severity": "medium",
                "description": "App uses weak file protection",
                "recommendation": "Use complete file protection for sensitive data"
            })
        
        return vulnerabilities
    
    def _identify_storage_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify general storage security issues."""
        issues = []
        
        # Check for hardcoded secrets in encryption
        encryption = results.get("encryption_analysis", {})
        for issue in encryption.get("security_issues", []):
            issues.append(issue)
        
        return issues
    
    def _identify_ios_storage_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify iOS-specific storage security issues."""
        issues = []
        
        # Check for backup issues
        backup = results.get("backup_analysis", {})
        if backup.get("backup_enabled"):
            issues.append({
                "type": "Backup Enabled",
                "severity": "medium",
                "description": "App allows backup which may expose sensitive data"
            })
        
        return issues
    
    def _generate_storage_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate storage security recommendations."""
        recommendations = [
            "Use encryption for all sensitive data",
            "Implement secure key management",
            "Use internal storage for sensitive data",
            "Disable backup for sensitive data or implement secure backup",
            "Use SharedPreferences with encryption",
            "Implement proper data sanitization",
            "Regular security audits of data storage",
            "Use secure deletion methods",
            "Implement proper access controls"
        ]
        
        return recommendations
    
    def _generate_ios_storage_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate iOS-specific storage recommendations."""
        recommendations = [
            "Use keychain for sensitive data storage",
            "Implement complete file protection",
            "Use secure enclave for critical data",
            "Disable backup for sensitive data",
            "Implement proper data sanitization",
            "Use secure deletion methods",
            "Regular security audits of data storage"
        ]
        
        return recommendations 

    def _analyze_secure_storage(self, apk_path: str) -> Dict[str, Any]:
        """Analyze secure storage implementation."""
        secure_storage_analysis = {
            "keystore_usage": False,
            "encryption_implementation": False,
            "secure_storage_patterns": [],
            "insecure_storage_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for secure storage patterns in code files
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt', '.xml')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for secure storage patterns
                            for pattern in self.secure_storage_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    secure_storage_analysis["secure_storage_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "Secure storage implementation detected"
                                    })
                                    secure_storage_analysis["keystore_usage"] = True
                            
                            # Check for insecure storage patterns
                            for pattern in self.insecure_storage_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    secure_storage_analysis["insecure_storage_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "usage": "Insecure storage implementation detected"
                                    })
                            
                        except Exception as e:
                            continue
                
                # Analyze security issues
                if not secure_storage_analysis["keystore_usage"]:
                    secure_storage_analysis["security_issues"].append({
                        "type": "no_secure_storage",
                        "severity": "high",
                        "description": "No Android Keystore usage detected",
                        "risk": "Sensitive data may be stored insecurely"
                    })
                    secure_storage_analysis["recommendations"].append(
                        "Implement Android Keystore for secure key storage"
                    )
                
                if secure_storage_analysis["insecure_storage_patterns"]:
                    secure_storage_analysis["security_issues"].append({
                        "type": "insecure_storage_patterns",
                        "severity": "medium",
                        "description": f"Found {len(secure_storage_analysis['insecure_storage_patterns'])} insecure storage patterns",
                        "risk": "Sensitive data may be stored insecurely"
                    })
                    secure_storage_analysis["recommendations"].append(
                        "Review and secure all data storage implementations"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in secure storage analysis: {str(e)}")
            secure_storage_analysis["error"] = str(e)
        
        return secure_storage_analysis
    
    def _analyze_data_leakage(self, apk_path: str) -> Dict[str, Any]:
        """Analyze data leakage patterns in code."""
        data_leakage_analysis = {
            "leakage_patterns": [],
            "sensitive_data_logging": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for data leakage patterns
                            for pattern in self.data_leakage_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    data_leakage_analysis["leakage_patterns"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "line": content[:match.start()].count('\n') + 1,
                                        "match": match.group(),
                                        "risk": "Sensitive data may be exposed through logging"
                                    })
                            
                            # Check for sensitive data in logs
                            sensitive_keywords = ['password', 'token', 'api_key', 'secret', 'key', 'credential']
                            for keyword in sensitive_keywords:
                                log_pattern = rf'Log\.[dvwi]\s*\([^)]*{keyword}[^)]*\)'
                                matches = re.finditer(log_pattern, content, re.IGNORECASE)
                                for match in matches:
                                    data_leakage_analysis["sensitive_data_logging"].append({
                                        "file": filename,
                                        "keyword": keyword,
                                        "line": content[:match.start()].count('\n') + 1,
                                        "match": match.group(),
                                        "risk": f"Sensitive data with '{keyword}' may be logged"
                                    })
                            
                        except Exception as e:
                            continue
                
                # Generate security issues
                if data_leakage_analysis["leakage_patterns"]:
                    data_leakage_analysis["security_issues"].append({
                        "type": "data_leakage_patterns",
                        "severity": "high",
                        "description": f"Found {len(data_leakage_analysis['leakage_patterns'])} data leakage patterns",
                        "risk": "Sensitive data may be exposed through logging"
                    })
                    data_leakage_analysis["recommendations"].append(
                        "Remove or secure all sensitive data logging"
                    )
                
                if data_leakage_analysis["sensitive_data_logging"]:
                    data_leakage_analysis["security_issues"].append({
                        "type": "sensitive_data_logging",
                        "severity": "medium",
                        "description": f"Found {len(data_leakage_analysis['sensitive_data_logging'])} instances of sensitive data logging",
                        "risk": "Sensitive data may be logged to system logs"
                    })
                    data_leakage_analysis["recommendations"].append(
                        "Implement secure logging practices for sensitive data"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in data leakage analysis: {str(e)}")
            data_leakage_analysis["error"] = str(e)
        
        return data_leakage_analysis
    
    def _analyze_external_storage(self, apk_path: str) -> Dict[str, Any]:
        """Analyze external storage usage and security."""
        external_storage_analysis = {
            "external_storage_usage": False,
            "storage_permissions": [],
            "file_operations": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for external storage permissions
                if "AndroidManifest.xml" in apk_zip.namelist():
                    manifest_data = apk_zip.read("AndroidManifest.xml")
                    root = ET.fromstring(manifest_data)
                    
                    external_permissions = [
                        "android.permission.READ_EXTERNAL_STORAGE",
                        "android.permission.WRITE_EXTERNAL_STORAGE",
                        "android.permission.MANAGE_EXTERNAL_STORAGE"
                    ]
                    
                    for permission in root.findall(".//uses-permission"):
                        perm_name = permission.get("android:name")
                        if perm_name in external_permissions:
                            external_storage_analysis["storage_permissions"].append({
                                "permission": perm_name,
                                "risk": "External storage access granted"
                            })
                            external_storage_analysis["external_storage_usage"] = True
                
                # Check for external storage file operations
                external_storage_patterns = [
                    r'Environment\.getExternalStorageDirectory',
                    r'Environment\.getExternalStoragePublicDirectory',
                    r'getExternalFilesDir',
                    r'getExternalCacheDir',
                    r'getExternalMediaDirs'
                ]
                
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            for pattern in external_storage_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    external_storage_analysis["file_operations"].append({
                                        "file": filename,
                                        "operation": pattern,
                                        "line": content[:match.start()].count('\n') + 1,
                                        "match": match.group(),
                                        "risk": "External storage access detected"
                                    })
                            
                        except Exception as e:
                            continue
                
                # Generate security issues
                if external_storage_analysis["external_storage_usage"]:
                    external_storage_analysis["security_issues"].append({
                        "type": "external_storage_usage",
                        "severity": "medium",
                        "description": "External storage usage detected",
                        "risk": "Data stored on external storage may be accessible to other apps"
                    })
                    external_storage_analysis["recommendations"].append(
                        "Use internal storage for sensitive data or implement proper encryption"
                    )
                
                if external_storage_analysis["storage_permissions"]:
                    external_storage_analysis["security_issues"].append({
                        "type": "external_storage_permissions",
                        "severity": "medium",
                        "description": f"External storage permissions: {len(external_storage_analysis['storage_permissions'])}",
                        "risk": "Broad external storage access granted"
                    })
                    external_storage_analysis["recommendations"].append(
                        "Review and minimize external storage permissions"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in external storage analysis: {str(e)}")
            external_storage_analysis["error"] = str(e)
        
        return external_storage_analysis
    
    def _analyze_cache_storage(self, apk_path: str) -> Dict[str, Any]:
        """Analyze cache storage usage and security."""
        cache_analysis = {
            "cache_usage": False,
            "cache_operations": [],
            "sensitive_data_in_cache": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                cache_patterns = [
                    r'getCacheDir',
                    r'getExternalCacheDir',
                    r'context\.getCacheDir',
                    r'context\.getExternalCacheDir',
                    r'File\.createTempFile',
                    r'cache'
                ]
                
                sensitive_cache_patterns = [
                    r'password.*cache',
                    r'token.*cache',
                    r'api_key.*cache',
                    r'secret.*cache',
                    r'credential.*cache'
                ]
                
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Check for cache operations
                            for pattern in cache_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    cache_analysis["cache_operations"].append({
                                        "file": filename,
                                        "operation": pattern,
                                        "line": content[:match.start()].count('\n') + 1,
                                        "match": match.group()
                                    })
                                    cache_analysis["cache_usage"] = True
                            
                            # Check for sensitive data in cache
                            for pattern in sensitive_cache_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    cache_analysis["sensitive_data_in_cache"].append({
                                        "file": filename,
                                        "pattern": pattern,
                                        "line": content[:match.start()].count('\n') + 1,
                                        "match": match.group(),
                                        "risk": "Sensitive data may be stored in cache"
                                    })
                            
                        except Exception as e:
                            continue
                
                # Generate security issues
                if cache_analysis["sensitive_data_in_cache"]:
                    cache_analysis["security_issues"].append({
                        "type": "sensitive_data_in_cache",
                        "severity": "high",
                        "description": f"Found {len(cache_analysis['sensitive_data_in_cache'])} instances of sensitive data in cache",
                        "risk": "Sensitive data may be stored in cache directories"
                    })
                    cache_analysis["recommendations"].append(
                        "Avoid storing sensitive data in cache directories"
                    )
                
                if cache_analysis["cache_usage"]:
                    cache_analysis["security_issues"].append({
                        "type": "cache_usage",
                        "severity": "info",
                        "description": "Cache storage usage detected",
                        "risk": "Review cache storage for sensitive data"
                    })
                    cache_analysis["recommendations"].append(
                        "Ensure no sensitive data is stored in cache"
                    )
        
        except Exception as e:
            self.logger.error(f"Error in cache analysis: {str(e)}")
            cache_analysis["error"] = str(e)
        
        return cache_analysis 