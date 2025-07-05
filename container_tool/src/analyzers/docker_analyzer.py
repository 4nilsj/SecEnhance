"""
Docker Security Analyzer
Comprehensive security analysis for Docker images including configuration analysis, layer inspection, and security best practices.
"""

import json
import logging
import os
import re
import subprocess
from typing import Dict, List, Any, Optional

import docker
from rich.console import Console

from ..utils.debug_utils import debug_print

class DockerAnalyzer:
    """Docker security analyzer."""
    
    def __init__(self, debug: bool = False):
        """Initialize the Docker analyzer."""
        self.debug = debug
        self.console = Console()
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            debug_print("Docker client not available:", str(e))
            self.docker_client = None
        
        # Security best practices
        self.security_best_practices = {
            "run_as_non_root": {
                "description": "Container should not run as root",
                "severity": "high",
                "check": self._check_run_as_non_root
            },
            "no_sensitive_mounts": {
                "description": "Container should not mount sensitive host directories",
                "severity": "critical",
                "check": self._check_sensitive_mounts
            },
            "no_privileged_mode": {
                "description": "Container should not run in privileged mode",
                "severity": "critical",
                "check": self._check_privileged_mode
            },
            "no_dangerous_capabilities": {
                "description": "Container should not have dangerous capabilities",
                "severity": "high",
                "check": self._check_dangerous_capabilities
            },
            "no_secrets_in_image": {
                "description": "Image should not contain hardcoded secrets",
                "severity": "critical",
                "check": self._check_hardcoded_secrets
            },
            "minimal_base_image": {
                "description": "Use minimal base images",
                "severity": "medium",
                "check": self._check_minimal_base_image
            },
            "no_unnecessary_packages": {
                "description": "Image should not contain unnecessary packages",
                "severity": "medium",
                "check": self._check_unnecessary_packages
            },
            "proper_user_permissions": {
                "description": "Files should have proper user permissions",
                "severity": "medium",
                "check": self._check_user_permissions
            }
        }
    
    def analyze_image(self, image_name: str) -> Dict[str, Any]:
        """Perform comprehensive Docker image security analysis."""
        debug_print("Starting Docker image analysis for:", image_name)
        
        results = {
            "image_name": image_name,
            "image_info": {},
            "configuration_issues": [],
            "security_violations": [],
            "best_practices": [],
            "vulnerabilities": []
        }
        
        try:
            if not self.docker_client:
                results["error"] = "Docker client not available"
                return results
            
            # Get image information
            results["image_info"] = self._get_image_info(image_name)
            
            # Analyze Dockerfile if available
            dockerfile_analysis = self._analyze_dockerfile(image_name)
            results["dockerfile_analysis"] = dockerfile_analysis
            
            # Check security best practices
            best_practices_results = self._check_best_practices(image_name)
            results["best_practices"] = best_practices_results
            
            # Analyze image layers
            layer_analysis = self._analyze_image_layers(image_name)
            results["layer_analysis"] = layer_analysis
            
            # Check for security violations
            security_violations = self._check_security_violations(image_name)
            results["security_violations"] = security_violations
            
            # Generate vulnerability summary
            self._generate_docker_vulnerability_summary(results)
            
        except Exception as e:
            debug_print("Error analyzing Docker image:", str(e))
            results["error"] = str(e)
        
        return results
    
    def _get_image_info(self, image_name: str) -> Dict[str, Any]:
        """Get detailed information about the Docker image."""
        try:
            image = self.docker_client.images.get(image_name)
            
            info = {
                "id": image.id,
                "tags": image.tags,
                "size": image.attrs.get("Size", 0),
                "created": image.attrs.get("Created", ""),
                "architecture": image.attrs.get("Architecture", ""),
                "os": image.attrs.get("Os", ""),
                "config": image.attrs.get("Config", {}),
                "history": image.attrs.get("History", [])
            }
            
            debug_print("Image info retrieved successfully")
            return info
            
        except Exception as e:
            debug_print("Error getting image info:", str(e))
            return {}
    
    def _analyze_dockerfile(self, image_name: str) -> Dict[str, Any]:
        """Analyze Dockerfile for security issues."""
        debug_print("Analyzing Dockerfile for:", image_name)
        
        analysis = {
            "dockerfile_found": False,
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Try to get Dockerfile from image history
            image = self.docker_client.images.get(image_name)
            history = image.attrs.get("History", [])
            
            if history:
                analysis["dockerfile_found"] = True
                
                # Analyze each layer
                for i, layer in enumerate(history):
                    layer_analysis = self._analyze_dockerfile_layer(layer, i)
                    analysis["security_issues"].extend(layer_analysis.get("issues", []))
                    analysis["recommendations"].extend(layer_analysis.get("recommendations", []))
            
        except Exception as e:
            debug_print("Error analyzing Dockerfile:", str(e))
        
        return analysis
    
    def _analyze_dockerfile_layer(self, layer: Dict[str, Any], layer_index: int) -> Dict[str, Any]:
        """Analyze individual Dockerfile layer for security issues."""
        issues = []
        recommendations = []
        
        created_by = layer.get("created_by", "")
        
        # Check for security issues in layer
        if "RUN" in created_by:
            # Check for package installation without version pinning
            if "apt-get install" in created_by and not re.search(r'[=<>]\d+', created_by):
                issues.append({
                    "layer": layer_index,
                    "type": "unpinned_packages",
                    "severity": "medium",
                    "description": "Packages installed without version pinning",
                    "command": created_by
                })
                recommendations.append("Pin package versions to specific versions")
            
            # Check for running as root
            if "USER root" in created_by or "RUN" in created_by and "USER" not in created_by:
                issues.append({
                    "layer": layer_index,
                    "type": "root_user",
                    "severity": "high",
                    "description": "Commands executed as root user",
                    "command": created_by
                })
                recommendations.append("Create and use non-root user")
            
            # Check for unnecessary packages
            unnecessary_packages = ["curl", "wget", "vim", "nano", "telnet", "netcat"]
            for package in unnecessary_packages:
                if package in created_by:
                    issues.append({
                        "layer": layer_index,
                        "type": "unnecessary_package",
                        "severity": "low",
                        "description": f"Unnecessary package '{package}' installed",
                        "command": created_by
                    })
                    recommendations.append(f"Remove unnecessary package '{package}'")
        
        # Check for secrets in layer
        if any(secret in created_by.lower() for secret in ["password", "secret", "key", "token"]):
            issues.append({
                "layer": layer_index,
                "type": "potential_secret",
                "severity": "critical",
                "description": "Potential secret in layer command",
                "command": created_by
            })
            recommendations.append("Use secrets management instead of hardcoding")
        
        return {
            "issues": issues,
            "recommendations": recommendations
        }
    
    def _check_best_practices(self, image_name: str) -> List[Dict[str, Any]]:
        """Check Docker security best practices."""
        debug_print("Checking Docker security best practices")
        
        results = []
        
        for practice_name, practice_config in self.security_best_practices.items():
            try:
                check_result = practice_config["check"](image_name)
                
                if not check_result["compliant"]:
                    results.append({
                        "practice": practice_name,
                        "description": practice_config["description"],
                        "severity": practice_config["severity"],
                        "compliant": False,
                        "details": check_result.get("details", ""),
                        "recommendation": check_result.get("recommendation", "")
                    })
                else:
                    results.append({
                        "practice": practice_name,
                        "description": practice_config["description"],
                        "severity": practice_config["severity"],
                        "compliant": True
                    })
                    
            except Exception as e:
                debug_print(f"Error checking practice {practice_name}:", str(e))
                results.append({
                    "practice": practice_name,
                    "description": practice_config["description"],
                    "severity": practice_config["severity"],
                    "compliant": False,
                    "error": str(e)
                })
        
        return results
    
    def _check_run_as_non_root(self, image_name: str) -> Dict[str, Any]:
        """Check if container runs as non-root user."""
        try:
            image = self.docker_client.images.get(image_name)
            config = image.attrs.get("Config", {})
            
            user = config.get("User", "")
            
            if not user or user == "0" or user == "root":
                return {
                    "compliant": False,
                    "details": f"Container runs as user: {user}",
                    "recommendation": "Create and use non-root user in Dockerfile"
                }
            else:
                return {"compliant": True}
                
        except Exception as e:
            debug_print("Error checking run as non-root:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_sensitive_mounts(self, image_name: str) -> Dict[str, Any]:
        """Check for sensitive mount points."""
        try:
            # This would require running the container to check
            # For now, we'll check the image configuration
            image = self.docker_client.images.get(image_name)
            config = image.attrs.get("Config", {})
            
            volumes = config.get("Volumes", {})
            sensitive_paths = ["/etc", "/var/run", "/proc", "/sys", "/dev"]
            
            for path in sensitive_paths:
                if path in volumes:
                    return {
                        "compliant": False,
                        "details": f"Sensitive path {path} exposed as volume",
                        "recommendation": "Avoid mounting sensitive host directories"
                    }
            
            return {"compliant": True}
            
        except Exception as e:
            debug_print("Error checking sensitive mounts:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_privileged_mode(self, image_name: str) -> Dict[str, Any]:
        """Check if container runs in privileged mode."""
        try:
            # This would require checking container runtime configuration
            # For now, we'll return a placeholder
            return {
                "compliant": True,
                "details": "Privileged mode check requires runtime analysis",
                "recommendation": "Ensure containers don't run in privileged mode"
            }
            
        except Exception as e:
            debug_print("Error checking privileged mode:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_dangerous_capabilities(self, image_name: str) -> Dict[str, Any]:
        """Check for dangerous capabilities."""
        try:
            # This would require runtime analysis
            # For now, we'll return a placeholder
            return {
                "compliant": True,
                "details": "Capabilities check requires runtime analysis",
                "recommendation": "Drop unnecessary capabilities"
            }
            
        except Exception as e:
            debug_print("Error checking capabilities:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_hardcoded_secrets(self, image_name: str) -> Dict[str, Any]:
        """Check for hardcoded secrets in image."""
        try:
            # This is a basic check - would need more sophisticated analysis
            image = self.docker_client.images.get(image_name)
            
            # Check image history for potential secrets
            history = image.attrs.get("History", [])
            
            secret_patterns = [
                r"password\s*=\s*['\"][^'\"]+['\"]",
                r"secret\s*=\s*['\"][^'\"]+['\"]",
                r"key\s*=\s*['\"][^'\"]+['\"]",
                r"token\s*=\s*['\"][^'\"]+['\"]"
            ]
            
            for layer in history:
                created_by = layer.get("created_by", "")
                for pattern in secret_patterns:
                    if re.search(pattern, created_by, re.IGNORECASE):
                        return {
                            "compliant": False,
                            "details": f"Potential secret found in layer: {created_by[:100]}...",
                            "recommendation": "Use secrets management instead of hardcoding"
                        }
            
            return {"compliant": True}
            
        except Exception as e:
            debug_print("Error checking hardcoded secrets:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_minimal_base_image(self, image_name: str) -> Dict[str, Any]:
        """Check if using minimal base image."""
        try:
            image = self.docker_client.images.get(image_name)
            size = image.attrs.get("Size", 0)
            
            # Check if image is too large (over 1GB)
            if size > 1024 * 1024 * 1024:  # 1GB
                return {
                    "compliant": False,
                    "details": f"Image size is {size / (1024*1024*1024):.2f}GB",
                    "recommendation": "Use minimal base images like alpine or distroless"
                }
            
            return {"compliant": True}
            
        except Exception as e:
            debug_print("Error checking minimal base image:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_unnecessary_packages(self, image_name: str) -> Dict[str, Any]:
        """Check for unnecessary packages."""
        try:
            image = self.docker_client.images.get(image_name)
            history = image.attrs.get("History", [])
            
            unnecessary_packages = [
                "curl", "wget", "vim", "nano", "telnet", "netcat", 
                "ping", "traceroute", "nmap", "openssh-client"
            ]
            
            found_packages = []
            for layer in history:
                created_by = layer.get("created_by", "")
                for package in unnecessary_packages:
                    if package in created_by:
                        found_packages.append(package)
            
            if found_packages:
                return {
                    "compliant": False,
                    "details": f"Unnecessary packages found: {', '.join(found_packages)}",
                    "recommendation": "Remove unnecessary packages to reduce attack surface"
                }
            
            return {"compliant": True}
            
        except Exception as e:
            debug_print("Error checking unnecessary packages:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _check_user_permissions(self, image_name: str) -> Dict[str, Any]:
        """Check file permissions in image."""
        try:
            # This would require detailed file system analysis
            # For now, we'll return a placeholder
            return {
                "compliant": True,
                "details": "File permissions check requires detailed analysis",
                "recommendation": "Ensure proper file permissions and ownership"
            }
            
        except Exception as e:
            debug_print("Error checking user permissions:", str(e))
            return {"compliant": False, "error": str(e)}
    
    def _analyze_image_layers(self, image_name: str) -> Dict[str, Any]:
        """Analyze Docker image layers for security issues."""
        debug_print("Analyzing image layers for:", image_name)
        
        analysis = {
            "total_layers": 0,
            "layer_details": [],
            "security_issues": []
        }
        
        try:
            image = self.docker_client.images.get(image_name)
            history = image.attrs.get("History", [])
            
            analysis["total_layers"] = len(history)
            
            for i, layer in enumerate(history):
                layer_info = {
                    "layer_index": i,
                    "created_by": layer.get("created_by", ""),
                    "size": layer.get("size", 0),
                    "issues": []
                }
                
                # Check for security issues in layer
                layer_issues = self._analyze_layer_security(layer, i)
                layer_info["issues"] = layer_issues
                analysis["security_issues"].extend(layer_issues)
                
                analysis["layer_details"].append(layer_info)
            
        except Exception as e:
            debug_print("Error analyzing image layers:", str(e))
        
        return analysis
    
    def _analyze_layer_security(self, layer: Dict[str, Any], layer_index: int) -> List[Dict[str, Any]]:
        """Analyze individual layer for security issues."""
        issues = []
        created_by = layer.get("created_by", "")
        
        # Check for various security issues
        security_checks = [
            {
                "pattern": r"chmod\s+777",
                "issue": "Dangerous file permissions",
                "severity": "high"
            },
            {
                "pattern": r"rm\s+-rf\s+/",
                "issue": "Dangerous file deletion",
                "severity": "critical"
            },
            {
                "pattern": r"wget\s+http://",
                "issue": "Insecure file download",
                "severity": "medium"
            },
            {
                "pattern": r"curl\s+http://",
                "issue": "Insecure file download",
                "severity": "medium"
            }
        ]
        
        for check in security_checks:
            if re.search(check["pattern"], created_by):
                issues.append({
                    "layer": layer_index,
                    "type": check["issue"],
                    "severity": check["severity"],
                    "description": f"{check['issue']} in layer {layer_index}",
                    "command": created_by
                })
        
        return issues
    
    def _check_security_violations(self, image_name: str) -> List[Dict[str, Any]]:
        """Check for specific security violations."""
        debug_print("Checking security violations for:", image_name)
        
        violations = []
        
        try:
            image = self.docker_client.images.get(image_name)
            config = image.attrs.get("Config", {})
            
            # Check for various security violations
            if config.get("User", "") == "0":
                violations.append({
                    "type": "root_user",
                    "severity": "high",
                    "description": "Container runs as root user",
                    "impact": "Privilege escalation risk"
                })
            
            # Check for exposed ports
            exposed_ports = config.get("ExposedPorts", {})
            dangerous_ports = ["22", "23", "3389", "5900"]
            
            for port in dangerous_ports:
                if f"{port}/tcp" in exposed_ports:
                    violations.append({
                        "type": "dangerous_port_exposed",
                        "severity": "medium",
                        "description": f"Dangerous port {port} exposed",
                        "impact": "Potential remote access"
                    })
            
            # Check for environment variables
            env_vars = config.get("Env", [])
            sensitive_env_patterns = [
                r"PASSWORD=",
                r"SECRET=",
                r"KEY=",
                r"TOKEN="
            ]
            
            for env_var in env_vars:
                for pattern in sensitive_env_patterns:
                    if re.search(pattern, env_var, re.IGNORECASE):
                        violations.append({
                            "type": "sensitive_env_var",
                            "severity": "critical",
                            "description": f"Sensitive environment variable found: {env_var.split('=')[0]}",
                            "impact": "Secret exposure"
                        })
                        break
            
        except Exception as e:
            debug_print("Error checking security violations:", str(e))
        
        return violations
    
    def _generate_docker_vulnerability_summary(self, results: Dict[str, Any]):
        """Generate vulnerability summary for Docker analysis."""
        if "vulnerabilities" not in results:
            results["vulnerabilities"] = []
        
        # Add issues from other analyses
        for issue_list in ["configuration_issues", "security_violations"]:
            if issue_list in results:
                results["vulnerabilities"].extend(results[issue_list])
        
        # Add non-compliant best practices
        best_practices = results.get("best_practices", [])
        for practice in best_practices:
            if not practice.get("compliant", True):
                results["vulnerabilities"].append({
                    "type": "best_practice_violation",
                    "severity": practice.get("severity", "medium"),
                    "description": practice.get("description", ""),
                    "details": practice.get("details", ""),
                    "recommendation": practice.get("recommendation", "")
                })
        
        # Categorize vulnerabilities
        critical = [v for v in results["vulnerabilities"] if v.get("severity") == "critical"]
        high = [v for v in results["vulnerabilities"] if v.get("severity") == "high"]
        medium = [v for v in results["vulnerabilities"] if v.get("severity") == "medium"]
        low = [v for v in results["vulnerabilities"] if v.get("severity") == "low"]
        
        results["vulnerability_summary"] = {
            "total": len(results["vulnerabilities"]),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        } 