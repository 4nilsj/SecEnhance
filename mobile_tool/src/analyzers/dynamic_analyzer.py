#!/usr/bin/env python3
"""
Dynamic Analyzer for Mobile Security Testing
Performs runtime analysis of mobile applications.
"""

import os
import subprocess
import json
import logging
import time
import re
import zipfile
from typing import Dict, List, Any, Optional
import requests
import tempfile
import shutil

class DynamicAnalyzer:
    """Dynamic analysis of mobile applications."""
    
    def __init__(self, debug: bool = False):
        """Initialize dynamic analyzer."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        
        # Dynamic analysis patterns
        self.runtime_permission_patterns = [
            r'requestPermissions',
            r'checkSelfPermission',
            r'ContextCompat\.checkSelfPermission',
            r'ActivityCompat\.requestPermissions',
            r'PERMISSION_GRANTED',
            r'PERMISSION_DENIED'
        ]
        
        self.dynamic_code_loading_patterns = [
            r'DexClassLoader',
            r'PathClassLoader',
            r'loadClass',
            r'defineClass',
            r'loadLibrary',
            r'System\.load',
            r'System\.loadLibrary'
        ]
        
        self.root_detection_patterns = [
            r'/system/app/Superuser.apk',
            r'/system/xbin/su',
            r'/system/bin/su',
            r'/sbin/su',
            r'/system/su',
            r'/system/bin/.ext/.su',
            r'/system/etc/init.d/99SuperSUDaemon',
            r'/dev/com.koushikdutta.superuser.daemon/',
            r'ro.secure',
            r'ro.debuggable',
            r'ro.build.type'
        ]
        
        self.memory_tampering_patterns = [
            r'Runtime\.getRuntime\(\)\.exec',
            r'ProcessBuilder',
            r'Process\.start',
            r'System\.exit',
            r'Runtime\.halt',
            r'Process\.destroy'
        ]
        
        self.runtime_security_patterns = [
            r'isEmulator',
            r'Build\.FINGERPRINT',
            r'Build\.MODEL',
            r'Build\.MANUFACTURER',
            r'Build\.BRAND',
            r'Build\.PRODUCT',
            r'Build\.DEVICE',
            r'Build\.HARDWARE'
        ]
        
    def analyze_apk(self, apk_path: str) -> Dict[str, Any]:
        """Analyze APK dynamically (requires device/emulator)."""
        self.logger.info(f"Starting dynamic analysis of APK: {apk_path}")
        
        results = {
            "runtime_behavior": {},
            "network_activity": {},
            "file_system": {},
            "memory_analysis": {},
            "runtime_permissions": {},
            "dynamic_code_loading": {},
            "root_detection": {},
            "memory_tampering": {},
            "runtime_security": {},
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check if device is connected
            if not self._check_device_connection():
                self.logger.warning("No device connected. Dynamic analysis limited.")
                results["error"] = "No device connected for dynamic analysis"
                # Perform static dynamic analysis
                results.update(self._perform_static_dynamic_analysis(apk_path))
                return results
            
            # Install APK on device
            package_name = self._install_apk(apk_path)
            if not package_name:
                results["error"] = "Failed to install APK"
                # Perform static dynamic analysis
                results.update(self._perform_static_dynamic_analysis(apk_path))
                return results
            
            # Perform dynamic analysis
            results["runtime_behavior"] = self._analyze_runtime_behavior(package_name)
            results["network_activity"] = self._analyze_network_activity(package_name)
            results["file_system"] = self._analyze_file_system(package_name)
            results["memory_analysis"] = self._analyze_memory(package_name)
            results["runtime_permissions"] = self._analyze_runtime_permissions(package_name)
            results["dynamic_code_loading"] = self._analyze_dynamic_code_loading(package_name)
            results["root_detection"] = self._analyze_root_detection(package_name)
            results["memory_tampering"] = self._analyze_memory_tampering(package_name)
            results["runtime_security"] = self._analyze_runtime_security(package_name)
            
            # Uninstall APK
            self._uninstall_apk(package_name)
            
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}")
            results["error"] = str(e)
            # Perform static dynamic analysis as fallback
            results.update(self._perform_static_dynamic_analysis(apk_path))
        
        # Generate vulnerability findings
        results["vulnerabilities"] = self._identify_dynamic_vulnerabilities(results)
        results["security_issues"] = self._identify_dynamic_security_issues(results)
        results["recommendations"] = self._generate_dynamic_recommendations(results)
        
        return results
    
    def analyze_device(self, device_type: str, package_name: str = None) -> Dict[str, Any]:
        """Analyze live device."""
        self.logger.info(f"Starting device analysis: {device_type}")
        
        results = {
            "device_info": {},
            "installed_apps": [],
            "running_processes": [],
            "network_connections": [],
            "vulnerabilities": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            if device_type.lower() == "android":
                results["device_info"] = self._get_android_device_info()
                results["installed_apps"] = self._get_installed_apps()
                results["running_processes"] = self._get_running_processes()
                results["network_connections"] = self._get_network_connections()
                
                if package_name:
                    results["app_analysis"] = self._analyze_running_app(package_name)
            
            elif device_type.lower() == "ios":
                results["device_info"] = self._get_ios_device_info()
                # iOS analysis would require additional tools like libimobiledevice
                results["error"] = "iOS device analysis requires additional setup"
        
        except Exception as e:
            self.logger.error(f"Error during device analysis: {str(e)}")
            results["error"] = str(e)
        
        return results
    
    def _check_device_connection(self) -> bool:
        """Check if Android device/emulator is connected."""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                connected_devices = [line for line in lines if line.strip() and 'device' in line]
                return len(connected_devices) > 0
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking device connection: {str(e)}")
            return False
    
    def _install_apk(self, apk_path: str) -> Optional[str]:
        """Install APK on device and return package name."""
        try:
            # Install APK
            result = subprocess.run(
                ["adb", "install", "-r", apk_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and "Success" in result.stdout:
                # Extract package name from APK
                package_name = self._extract_package_name(apk_path)
                self.logger.info(f"APK installed successfully: {package_name}")
                return package_name
            
            self.logger.error(f"Failed to install APK: {result.stderr}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error installing APK: {str(e)}")
            return None
    
    def _extract_package_name(self, apk_path: str) -> str:
        """Extract package name from APK."""
        try:
            # Use aapt to get package name
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith("package:"):
                        parts = line.split()
                        for part in parts:
                            if part.startswith("name="):
                                return part.split("=")[1].strip("'")
            
            # Fallback: use filename as package name
            return os.path.basename(apk_path).replace(".apk", "")
            
        except Exception as e:
            self.logger.error(f"Error extracting package name: {str(e)}")
            return os.path.basename(apk_path).replace(".apk", "")
    
    def _uninstall_apk(self, package_name: str) -> bool:
        """Uninstall APK from device."""
        try:
            result = subprocess.run(
                ["adb", "uninstall", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error uninstalling APK: {str(e)}")
            return False
    
    def _analyze_runtime_behavior(self, package_name: str) -> Dict[str, Any]:
        """Analyze runtime behavior of the app."""
        behavior = {
            "activities": [],
            "services": [],
            "permissions_used": [],
            "api_calls": [],
            "security_issues": []
        }
        
        try:
            # Get running activities
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "activity", "activities"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if package_name in line and "ActivityRecord" in line:
                        behavior["activities"].append(line.strip())
            
            # Get running services
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "activity", "services"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if package_name in line and "ServiceRecord" in line:
                        behavior["services"].append(line.strip())
            
            # Monitor app for a short period
            behavior["monitoring_results"] = self._monitor_app_behavior(package_name)
            
        except Exception as e:
            self.logger.error(f"Error analyzing runtime behavior: {str(e)}")
            behavior["error"] = str(e)
        
        return behavior
    
    def _monitor_app_behavior(self, package_name: str) -> Dict[str, Any]:
        """Monitor app behavior for a short period."""
        monitoring = {
            "cpu_usage": [],
            "memory_usage": [],
            "network_activity": [],
            "file_access": []
        }
        
        try:
            # Monitor for 30 seconds
            start_time = time.time()
            while time.time() - start_time < 30:
                # Get CPU usage
                result = subprocess.run(
                    ["adb", "shell", "top", "-n", "1", "-p", package_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    monitoring["cpu_usage"].append(result.stdout.strip())
                
                # Get memory usage
                result = subprocess.run(
                    ["adb", "shell", "dumpsys", "meminfo", package_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    monitoring["memory_usage"].append(result.stdout.strip())
                
                time.sleep(5)  # Wait 5 seconds between checks
            
        except Exception as e:
            self.logger.error(f"Error monitoring app behavior: {str(e)}")
            monitoring["error"] = str(e)
        
        return monitoring
    
    def _analyze_network_activity(self, package_name: str) -> Dict[str, Any]:
        """Analyze network activity of the app."""
        network = {
            "connections": [],
            "requests": [],
            "ssl_info": [],
            "security_issues": []
        }
        
        try:
            # Get network connections
            result = subprocess.run(
                ["adb", "shell", "netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        network["connections"].append(line.strip())
            
            # Monitor network traffic (simplified)
            network["traffic_analysis"] = self._monitor_network_traffic(package_name)
            
        except Exception as e:
            self.logger.error(f"Error analyzing network activity: {str(e)}")
            network["error"] = str(e)
        
        return network
    
    def _monitor_network_traffic(self, package_name: str) -> Dict[str, Any]:
        """Monitor network traffic for the app."""
        traffic = {
            "http_requests": [],
            "https_requests": [],
            "dns_queries": [],
            "suspicious_activity": []
        }
        
        try:
            # Use tcpdump to capture traffic (requires root)
            # This is a simplified version
            result = subprocess.run(
                ["adb", "shell", "su", "-c", "tcpdump", "-i", "any", "-w", "/sdcard/capture.pcap"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # In a real implementation, you would analyze the captured traffic
            traffic["note"] = "Network traffic analysis requires root access and additional tools"
            
        except Exception as e:
            self.logger.error(f"Error monitoring network traffic: {str(e)}")
            traffic["error"] = str(e)
        
        return traffic
    
    def _analyze_file_system(self, package_name: str) -> Dict[str, Any]:
        """Analyze file system access and storage."""
        file_system = {
            "app_data": {},
            "shared_preferences": {},
            "databases": [],
            "cache_files": [],
            "external_storage": [],
            "security_issues": []
        }
        
        try:
            # Get app data directory
            app_data_path = f"/data/data/{package_name}"
            
            # List app data files
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", app_data_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                file_system["app_data"]["files"] = result.stdout.strip().split('\n')
            
            # Check shared preferences
            prefs_path = f"{app_data_path}/shared_prefs"
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", prefs_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                file_system["shared_preferences"]["files"] = result.stdout.strip().split('\n')
            
            # Check databases
            db_path = f"{app_data_path}/databases"
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", db_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                file_system["databases"] = result.stdout.strip().split('\n')
            
            # Check external storage
            external_path = f"/sdcard/Android/data/{package_name}"
            result = subprocess.run(
                ["adb", "shell", "ls", "-la", external_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                file_system["external_storage"] = result.stdout.strip().split('\n')
            
        except Exception as e:
            self.logger.error(f"Error analyzing file system: {str(e)}")
            file_system["error"] = str(e)
        
        return file_system
    
    def _analyze_memory(self, package_name: str) -> Dict[str, Any]:
        """Analyze memory usage and potential memory leaks."""
        memory = {
            "memory_info": {},
            "heap_dump": {},
            "memory_leaks": [],
            "security_issues": []
        }
        
        try:
            # Get memory info
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "meminfo", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                memory["memory_info"]["dump"] = result.stdout.strip()
            
            # Check for memory leaks (simplified)
            memory["memory_leaks"] = self._check_memory_leaks(package_name)
            
        except Exception as e:
            self.logger.error(f"Error analyzing memory: {str(e)}")
            memory["error"] = str(e)
        
        return memory
    
    def _check_memory_leaks(self, package_name: str) -> List[Dict[str, Any]]:
        """Check for potential memory leaks."""
        leaks = []
        
        try:
            # This is a simplified check
            # In a real implementation, you would use tools like MAT or LeakCanary
            
            # Check if app is using excessive memory
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "meminfo", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse memory info to detect potential leaks
                # This is a placeholder for actual memory leak detection
                leaks.append({
                    "type": "Potential Memory Leak",
                    "description": "Memory usage analysis requires additional tools",
                    "severity": "medium"
                })
        
        except Exception as e:
            self.logger.error(f"Error checking memory leaks: {str(e)}")
        
        return leaks
    
    def _get_android_device_info(self) -> Dict[str, Any]:
        """Get Android device information."""
        device_info = {}
        
        try:
            # Get device model
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.product.model"],
                capture_output=True,
                text=True,
                timeout=10
            )
            device_info["model"] = result.stdout.strip() if result.returncode == 0 else "Unknown"
            
            # Get Android version
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.build.version.release"],
                capture_output=True,
                text=True,
                timeout=10
            )
            device_info["android_version"] = result.stdout.strip() if result.returncode == 0 else "Unknown"
            
            # Get build number
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True,
                text=True,
                timeout=10
            )
            device_info["sdk_version"] = result.stdout.strip() if result.returncode == 0 else "Unknown"
            
            # Check if device is rooted
            result = subprocess.run(
                ["adb", "shell", "which", "su"],
                capture_output=True,
                text=True,
                timeout=10
            )
            device_info["rooted"] = result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error getting device info: {str(e)}")
            device_info["error"] = str(e)
        
        return device_info
    
    def _get_ios_device_info(self) -> Dict[str, Any]:
        """Get iOS device information."""
        device_info = {
            "note": "iOS device analysis requires libimobiledevice tools",
            "error": "Not implemented - requires additional setup"
        }
        
        return device_info
    
    def _get_installed_apps(self) -> List[Dict[str, Any]]:
        """Get list of installed apps."""
        apps = []
        
        try:
            result = subprocess.run(
                ["adb", "shell", "pm", "list", "packages", "-3"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and line.startswith("package:"):
                        package_name = line.replace("package:", "").strip()
                        apps.append({
                            "package": package_name,
                            "name": self._get_app_name(package_name)
                        })
        
        except Exception as e:
            self.logger.error(f"Error getting installed apps: {str(e)}")
        
        return apps
    
    def _get_app_name(self, package_name: str) -> str:
        """Get app name from package name."""
        try:
            result = subprocess.run(
                ["adb", "shell", "pm", "dump", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if "applicationLabel=" in line:
                        return line.split("=")[1].strip()
            
            return package_name
            
        except Exception as e:
            self.logger.error(f"Error getting app name: {str(e)}")
            return package_name
    
    def _get_running_processes(self) -> List[Dict[str, Any]]:
        """Get list of running processes."""
        processes = []
        
        try:
            result = subprocess.run(
                ["adb", "shell", "ps"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 9:
                            processes.append({
                                "pid": parts[1],
                                "ppid": parts[2],
                                "name": parts[8],
                                "user": parts[0]
                            })
        
        except Exception as e:
            self.logger.error(f"Error getting running processes: {str(e)}")
        
        return processes
    
    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """Get network connections."""
        connections = []
        
        try:
            result = subprocess.run(
                ["adb", "shell", "netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith("Proto"):
                        parts = line.split()
                        if len(parts) >= 4:
                            connections.append({
                                "protocol": parts[0],
                                "local_address": parts[3],
                                "state": parts[5] if len(parts) > 5 else "UNKNOWN"
                            })
        
        except Exception as e:
            self.logger.error(f"Error getting network connections: {str(e)}")
        
        return connections
    
    def _analyze_running_app(self, package_name: str) -> Dict[str, Any]:
        """Analyze a running app."""
        app_analysis = {
            "process_info": {},
            "memory_usage": {},
            "network_activity": {},
            "file_access": {}
        }
        
        try:
            # Get process info
            result = subprocess.run(
                ["adb", "shell", "ps", "|", "grep", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                app_analysis["process_info"]["ps_output"] = result.stdout.strip()
            
            # Get memory usage
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "meminfo", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                app_analysis["memory_usage"]["dump"] = result.stdout.strip()
        
        except Exception as e:
            self.logger.error(f"Error analyzing running app: {str(e)}")
            app_analysis["error"] = str(e)
        
        return app_analysis
    
    def _identify_dynamic_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify vulnerabilities from dynamic analysis results."""
        vulnerabilities = []
        
        try:
            # Runtime permission vulnerabilities
            if "runtime_permissions" in results:
                runtime_perms = results["runtime_permissions"]
                if "security_issues" in runtime_perms:
                    for issue in runtime_perms["security_issues"]:
                        vulnerabilities.append({
                            "type": "runtime_permission_vulnerability",
                            "severity": issue.get("severity", "medium"),
                            "description": issue.get("description", ""),
                            "risk": issue.get("risk", ""),
                            "category": "runtime_permissions"
                        })
            
            # Dynamic code loading vulnerabilities
            if "dynamic_code_loading" in results:
                dynamic_loading = results["dynamic_code_loading"]
                if "security_issues" in dynamic_loading:
                    for issue in dynamic_loading["security_issues"]:
                        vulnerabilities.append({
                            "type": "dynamic_code_loading_vulnerability",
                            "severity": issue.get("severity", "high"),
                            "description": issue.get("description", ""),
                            "risk": issue.get("risk", ""),
                            "category": "dynamic_code_loading"
                        })
            
            # Root detection vulnerabilities
            if "root_detection" in results:
                root_detection = results["root_detection"]
                if "security_issues" in root_detection:
                    for issue in root_detection["security_issues"]:
                        vulnerabilities.append({
                            "type": "root_detection_vulnerability",
                            "severity": issue.get("severity", "medium"),
                            "description": issue.get("description", ""),
                            "risk": issue.get("risk", ""),
                            "category": "root_detection"
                        })
            
            # Memory tampering vulnerabilities
            if "memory_tampering" in results:
                memory_tampering = results["memory_tampering"]
                if "security_issues" in memory_tampering:
                    for issue in memory_tampering["security_issues"]:
                        vulnerabilities.append({
                            "type": "memory_tampering_vulnerability",
                            "severity": issue.get("severity", "high"),
                            "description": issue.get("description", ""),
                            "risk": issue.get("risk", ""),
                            "category": "memory_tampering"
                        })
            
            # Runtime security vulnerabilities
            if "runtime_security" in results:
                runtime_security = results["runtime_security"]
                if "security_issues" in runtime_security:
                    for issue in runtime_security["security_issues"]:
                        vulnerabilities.append({
                            "type": "runtime_security_vulnerability",
                            "severity": issue.get("severity", "medium"),
                            "description": issue.get("description", ""),
                            "risk": issue.get("risk", ""),
                            "category": "runtime_security"
                        })
            
            # Network activity vulnerabilities
            if "network_activity" in results:
                network_activity = results["network_activity"]
                if "insecure_connections" in network_activity:
                    for conn in network_activity.get("insecure_connections", []):
                        vulnerabilities.append({
                            "type": "insecure_network_connection",
                            "severity": "high",
                            "description": f"Insecure connection detected: {conn}",
                            "risk": "Data transmitted over insecure channel",
                            "category": "network_security"
                        })
            
            # File system vulnerabilities
            if "file_system" in results:
                file_system = results["file_system"]
                if "insecure_files" in file_system:
                    for file_info in file_system.get("insecure_files", []):
                        vulnerabilities.append({
                            "type": "insecure_file_storage",
                            "severity": "medium",
                            "description": f"Insecure file storage: {file_info}",
                            "risk": "Sensitive data stored insecurely",
                            "category": "data_storage"
                        })
            
            # Memory analysis vulnerabilities
            if "memory_analysis" in results:
                memory_analysis = results["memory_analysis"]
                if "memory_leaks" in memory_analysis:
                    for leak in memory_analysis.get("memory_leaks", []):
                        vulnerabilities.append({
                            "type": "memory_leak",
                            "severity": "medium",
                            "description": f"Memory leak detected: {leak}",
                            "risk": "Potential resource exhaustion",
                            "category": "memory_management"
                        })
            
            # Legacy checks for backward compatibility
            runtime = results.get("runtime_behavior", {})
            if runtime.get("security_issues"):
                vulnerabilities.extend(runtime["security_issues"])
            
            network = results.get("network_activity", {})
            if network.get("security_issues"):
                vulnerabilities.extend(network["security_issues"])
            
            file_system = results.get("file_system", {})
            if file_system.get("security_issues"):
                vulnerabilities.extend(file_system["security_issues"])
            
        except Exception as e:
            self.logger.error(f"Error identifying dynamic vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _identify_dynamic_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify security issues from dynamic analysis."""
        issues = []
        
        # Check for excessive permissions usage
        runtime = results.get("runtime_behavior", {})
        if runtime.get("permissions_used"):
            issues.append({
                "type": "Excessive Permissions",
                "severity": "medium",
                "description": "App is using more permissions than necessary"
            })
        
        # Check for insecure network communications
        network = results.get("network_activity", {})
        if network.get("connections"):
            issues.append({
                "type": "Insecure Network",
                "severity": "high",
                "description": "App may be using insecure network communications"
            })
        
        return issues
    
    def _generate_dynamic_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations from dynamic analysis."""
        recommendations = [
            "Implement runtime security monitoring",
            "Use secure network communications (HTTPS/TLS)",
            "Implement proper session management",
            "Monitor for memory leaks and performance issues",
            "Implement proper error handling",
            "Use secure storage for sensitive data",
            "Implement proper logging without sensitive information"
        ]
        
        return recommendations 

    def _perform_static_dynamic_analysis(self, apk_path: str) -> Dict[str, Any]:
        """Perform static analysis of dynamic behavior patterns."""
        static_dynamic_analysis = {
            "runtime_permissions": {},
            "dynamic_code_loading": {},
            "root_detection": {},
            "memory_tampering": {},
            "runtime_security": {},
            "security_issues": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                for filename in apk_zip.namelist():
                    if filename.endswith(('.java', '.kt', '.xml')):
                        try:
                            content = apk_zip.read(filename).decode('utf-8', errors='ignore')
                            
                            # Analyze runtime permissions
                            static_dynamic_analysis["runtime_permissions"] = self._analyze_static_runtime_permissions(content, filename)
                            
                            # Analyze dynamic code loading
                            static_dynamic_analysis["dynamic_code_loading"] = self._analyze_static_dynamic_code_loading(content, filename)
                            
                            # Analyze root detection
                            static_dynamic_analysis["root_detection"] = self._analyze_static_root_detection(content, filename)
                            
                            # Analyze memory tampering
                            static_dynamic_analysis["memory_tampering"] = self._analyze_static_memory_tampering(content, filename)
                            
                            # Analyze runtime security
                            static_dynamic_analysis["runtime_security"] = self._analyze_static_runtime_security(content, filename)
                            
                        except Exception as e:
                            continue
        
        except Exception as e:
            self.logger.error(f"Error in static dynamic analysis: {str(e)}")
            static_dynamic_analysis["error"] = str(e)
        
        return static_dynamic_analysis
    
    def _analyze_static_runtime_permissions(self, content: str, filename: str) -> Dict[str, Any]:
        """Analyze static runtime permission patterns."""
        runtime_permissions = {
            "runtime_permission_usage": False,
            "permission_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            for pattern in self.runtime_permission_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    runtime_permissions["permission_patterns"].append({
                        "file": filename,
                        "pattern": pattern,
                        "line": content[:match.start()].count('\n') + 1,
                        "match": match.group(),
                        "usage": "Runtime permission handling detected"
                    })
                    runtime_permissions["runtime_permission_usage"] = True
            
            if not runtime_permissions["runtime_permission_usage"]:
                runtime_permissions["security_issues"].append({
                    "type": "no_runtime_permissions",
                    "severity": "medium",
                    "description": "No runtime permission handling detected",
                    "risk": "App may not properly handle runtime permissions"
                })
                runtime_permissions["recommendations"].append(
                    "Implement proper runtime permission handling"
                )
        
        except Exception as e:
            self.logger.error(f"Error in static runtime permission analysis: {str(e)}")
        
        return runtime_permissions
    
    def _analyze_static_dynamic_code_loading(self, content: str, filename: str) -> Dict[str, Any]:
        """Analyze static dynamic code loading patterns."""
        dynamic_loading = {
            "dynamic_code_loading_used": False,
            "loading_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            for pattern in self.dynamic_code_loading_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    dynamic_loading["loading_patterns"].append({
                        "file": filename,
                        "pattern": pattern,
                        "line": content[:match.start()].count('\n') + 1,
                        "match": match.group(),
                        "usage": "Dynamic code loading detected"
                    })
                    dynamic_loading["dynamic_code_loading_used"] = True
            
            if dynamic_loading["dynamic_code_loading_used"]:
                dynamic_loading["security_issues"].append({
                    "type": "dynamic_code_loading",
                    "severity": "high",
                    "description": "Dynamic code loading detected",
                    "risk": "May be used for code injection or obfuscation"
                })
                dynamic_loading["recommendations"].append(
                    "Review dynamic code loading for security implications"
                )
        
        except Exception as e:
            self.logger.error(f"Error in static dynamic code loading analysis: {str(e)}")
        
        return dynamic_loading
    
    def _analyze_static_root_detection(self, content: str, filename: str) -> Dict[str, Any]:
        """Analyze static root detection patterns."""
        root_detection = {
            "root_detection_used": False,
            "detection_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            for pattern in self.root_detection_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    root_detection["detection_patterns"].append({
                        "file": filename,
                        "pattern": pattern,
                        "line": content[:match.start()].count('\n') + 1,
                        "match": match.group(),
                        "usage": "Root detection pattern detected"
                    })
                    root_detection["root_detection_used"] = True
            
            if not root_detection["root_detection_used"]:
                root_detection["security_issues"].append({
                    "type": "no_root_detection",
                    "severity": "medium",
                    "description": "No root detection mechanisms detected",
                    "risk": "App may not detect rooted devices"
                })
                root_detection["recommendations"].append(
                    "Implement root detection mechanisms"
                )
        
        except Exception as e:
            self.logger.error(f"Error in static root detection analysis: {str(e)}")
        
        return root_detection
    
    def _analyze_static_memory_tampering(self, content: str, filename: str) -> Dict[str, Any]:
        """Analyze static memory tampering patterns."""
        memory_tampering = {
            "memory_tampering_detected": False,
            "tampering_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            for pattern in self.memory_tampering_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    memory_tampering["tampering_patterns"].append({
                        "file": filename,
                        "pattern": pattern,
                        "line": content[:match.start()].count('\n') + 1,
                        "match": match.group(),
                        "usage": "Memory tampering pattern detected"
                    })
                    memory_tampering["memory_tampering_detected"] = True
            
            if memory_tampering["memory_tampering_detected"]:
                memory_tampering["security_issues"].append({
                    "type": "memory_tampering",
                    "severity": "high",
                    "description": "Memory tampering patterns detected",
                    "risk": "May be used for process manipulation or debugging"
                })
                memory_tampering["recommendations"].append(
                    "Review memory tampering patterns for security implications"
                )
        
        except Exception as e:
            self.logger.error(f"Error in static memory tampering analysis: {str(e)}")
        
        return memory_tampering
    
    def _analyze_static_runtime_security(self, content: str, filename: str) -> Dict[str, Any]:
        """Analyze static runtime security patterns."""
        runtime_security = {
            "runtime_security_used": False,
            "security_patterns": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            for pattern in self.runtime_security_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    runtime_security["security_patterns"].append({
                        "file": filename,
                        "pattern": pattern,
                        "line": content[:match.start()].count('\n') + 1,
                        "match": match.group(),
                        "usage": "Runtime security pattern detected"
                    })
                    runtime_security["runtime_security_used"] = True
            
            if not runtime_security["runtime_security_used"]:
                runtime_security["security_issues"].append({
                    "type": "no_runtime_security",
                    "severity": "medium",
                    "description": "No runtime security mechanisms detected",
                    "risk": "App may not detect emulator or device tampering"
                })
                runtime_security["recommendations"].append(
                    "Implement runtime security mechanisms"
                )
        
        except Exception as e:
            self.logger.error(f"Error in static runtime security analysis: {str(e)}")
        
        return runtime_security
    
    def _analyze_runtime_permissions(self, package_name: str) -> Dict[str, Any]:
        """Analyze runtime permissions usage."""
        runtime_permissions = {
            "permissions_granted": [],
            "permissions_denied": [],
            "permission_requests": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Get app permissions
            result = subprocess.run(
                ["adb", "shell", "dumpsys", "package", package_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                content = result.stdout
                
                # Extract granted permissions
                granted_pattern = r'grantedPermissions:\s*\[(.*?)\]'
                granted_match = re.search(granted_pattern, content)
                if granted_match:
                    permissions = granted_match.group(1).split(',')
                    runtime_permissions["permissions_granted"] = [p.strip() for p in permissions if p.strip()]
                
                # Check for dangerous permissions
                dangerous_permissions = [
                    "android.permission.READ_EXTERNAL_STORAGE",
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                    "android.permission.READ_CONTACTS",
                    "android.permission.READ_PHONE_STATE",
                    "android.permission.CAMERA",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION"
                ]
                
                for perm in runtime_permissions["permissions_granted"]:
                    if perm in dangerous_permissions:
                        runtime_permissions["security_issues"].append({
                            "type": "dangerous_permission_granted",
                            "severity": "medium",
                            "description": f"Dangerous permission granted: {perm}",
                            "risk": "App has access to sensitive data"
                        })
        
        except Exception as e:
            self.logger.error(f"Error analyzing runtime permissions: {str(e)}")
            runtime_permissions["error"] = str(e)
        
        return runtime_permissions
    
    def _analyze_dynamic_code_loading(self, package_name: str) -> Dict[str, Any]:
        """Analyze dynamic code loading behavior."""
        dynamic_loading = {
            "loaded_libraries": [],
            "dynamic_classes": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check for loaded native libraries
            result = subprocess.run(
                ["adb", "shell", "cat", "/proc/$(pidof " + package_name + ")/maps"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                content = result.stdout
                
                # Extract loaded libraries
                library_pattern = r'([^\s]+\.so)'
                libraries = re.findall(library_pattern, content)
                dynamic_loading["loaded_libraries"] = list(set(libraries))
                
                # Check for suspicious libraries
                suspicious_libs = [
                    "libfrida", "libxposed", "libsubstrate", "libsandhook"
                ]
                
                for lib in dynamic_loading["loaded_libraries"]:
                    for suspicious in suspicious_libs:
                        if suspicious in lib.lower():
                            dynamic_loading["security_issues"].append({
                                "type": "suspicious_library",
                                "severity": "high",
                                "description": f"Suspicious library loaded: {lib}",
                                "risk": "May indicate hooking or tampering"
                            })
        
        except Exception as e:
            self.logger.error(f"Error analyzing dynamic code loading: {str(e)}")
            dynamic_loading["error"] = str(e)
        
        return dynamic_loading
    
    def _analyze_root_detection(self, package_name: str) -> Dict[str, Any]:
        """Analyze root detection mechanisms."""
        root_detection = {
            "root_detection_mechanisms": [],
            "root_status": "unknown",
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check for common root indicators
            root_indicators = [
                "/system/app/Superuser.apk",
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/system/su",
                "/system/bin/.ext/.su"
            ]
            
            for indicator in root_indicators:
                result = subprocess.run(
                    ["adb", "shell", "test", "-f", indicator, "&&", "echo", "exists"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and "exists" in result.stdout:
                    root_detection["root_detection_mechanisms"].append({
                        "indicator": indicator,
                        "status": "found"
                    })
                    root_detection["root_status"] = "rooted"
            
            # Check build properties
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.secure"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                ro_secure = result.stdout.strip()
                if ro_secure == "0":
                    root_detection["root_detection_mechanisms"].append({
                        "indicator": "ro.secure=0",
                        "status": "insecure"
                    })
                    root_detection["root_status"] = "potentially_rooted"
            
            if root_detection["root_status"] in ["rooted", "potentially_rooted"]:
                root_detection["security_issues"].append({
                    "type": "device_rooted",
                    "severity": "high",
                    "description": f"Device appears to be rooted: {root_detection['root_status']}",
                    "risk": "Device may be compromised"
                })
        
        except Exception as e:
            self.logger.error(f"Error analyzing root detection: {str(e)}")
            root_detection["error"] = str(e)
        
        return root_detection
    
    def _analyze_memory_tampering(self, package_name: str) -> Dict[str, Any]:
        """Analyze memory tampering detection."""
        memory_tampering = {
            "memory_protection": [],
            "tampering_indicators": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check for debugging indicators
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.debuggable"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                debuggable = result.stdout.strip()
                if debuggable == "1":
                    memory_tampering["tampering_indicators"].append({
                        "indicator": "ro.debuggable=1",
                        "status": "debuggable"
                    })
                    memory_tampering["security_issues"].append({
                        "type": "device_debuggable",
                        "severity": "high",
                        "description": "Device is debuggable",
                        "risk": "App may be vulnerable to debugging attacks"
                    })
            
            # Check for common hooking frameworks
            hooking_frameworks = [
                "com.android.internal.os.ZygoteInit",
                "de.robv.android.xposed.XposedBridge",
                "com.saurik.substrate.MS$MethodPointer"
            ]
            
            for framework in hooking_frameworks:
                result = subprocess.run(
                    ["adb", "shell", "pm", "list", "packages", framework],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0 and framework in result.stdout:
                    memory_tampering["tampering_indicators"].append({
                        "indicator": f"Hooking framework: {framework}",
                        "status": "detected"
                    })
                    memory_tampering["security_issues"].append({
                        "type": "hooking_framework",
                        "severity": "high",
                        "description": f"Hooking framework detected: {framework}",
                        "risk": "App may be subject to hooking attacks"
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing memory tampering: {str(e)}")
            memory_tampering["error"] = str(e)
        
        return memory_tampering
    
    def _analyze_runtime_security(self, package_name: str) -> Dict[str, Any]:
        """Analyze runtime security mechanisms."""
        runtime_security = {
            "emulator_detection": [],
            "integrity_checks": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check for emulator indicators
            emulator_indicators = [
                "goldfish",
                "ranchu",
                "vbox86",
                "generic",
                "sdk"
            ]
            
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.product.model"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                model = result.stdout.strip().lower()
                for indicator in emulator_indicators:
                    if indicator in model:
                        runtime_security["emulator_detection"].append({
                            "indicator": f"Model: {model}",
                            "status": "emulator_likely"
                        })
                        runtime_security["security_issues"].append({
                            "type": "emulator_detected",
                            "severity": "medium",
                            "description": f"Emulator likely detected: {model}",
                            "risk": "App may be running in emulator"
                        })
            
            # Check for build fingerprint
            result = subprocess.run(
                ["adb", "shell", "getprop", "ro.build.fingerprint"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                fingerprint = result.stdout.strip()
                if "generic" in fingerprint.lower() or "sdk" in fingerprint.lower():
                    runtime_security["emulator_detection"].append({
                        "indicator": f"Fingerprint: {fingerprint}",
                        "status": "emulator_likely"
                    })
        
        except Exception as e:
            self.logger.error(f"Error analyzing runtime security: {str(e)}")
            runtime_security["error"] = str(e)
        
        return runtime_security 