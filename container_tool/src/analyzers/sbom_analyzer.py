"""
SBOM (Software Bill of Materials) Analyzer
Extracts container images, generates SBOM for each layer, and analyzes OS and language-specific packages.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

import docker
from rich.console import Console

from ..utils.debug_utils import debug_print

class SBOMAnalyzer:
    """SBOM analyzer for container images."""
    
    def __init__(self, debug: bool = False):
        """Initialize the SBOM analyzer."""
        self.debug = debug
        self.console = Console()
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            debug_print("Docker client not available:", str(e))
            self.docker_client = None
        
        # Supported package managers
        self.package_managers = {
            "apt": {
                "package_list_cmd": "dpkg -l",
                "package_info_cmd": "dpkg -s {package}",
                "file_paths": ["/var/lib/dpkg/status", "/var/lib/dpkg/available"]
            },
            "rpm": {
                "package_list_cmd": "rpm -qa",
                "package_info_cmd": "rpm -qi {package}",
                "file_paths": ["/var/lib/rpm/Packages", "/var/lib/rpm/Name"]
            },
            "apk": {
                "package_list_cmd": "apk info",
                "package_info_cmd": "apk info {package}",
                "file_paths": ["/lib/apk/db/installed", "/lib/apk/db/scripts.tar"]
            },
            "yum": {
                "package_list_cmd": "yum list installed",
                "package_info_cmd": "yum info {package}",
                "file_paths": ["/var/lib/yum/history", "/var/lib/yum/yumdb"]
            }
        }
        
        # Language-specific package managers
        self.language_package_managers = {
            "python": {
                "requirements_file": "requirements.txt",
                "pip_list_cmd": "pip list --format=json",
                "poetry_lock": "poetry.lock",
                "pipfile": "Pipfile"
            },
            "nodejs": {
                "package_json": "package.json",
                "package_lock": "package-lock.json",
                "yarn_lock": "yarn.lock",
                "npm_list_cmd": "npm list --json"
            },
            "java": {
                "pom_xml": "pom.xml",
                "gradle_files": ["build.gradle", "build.gradle.kts"],
                "maven_dependencies": "target/dependency-tree.txt"
            },
            "go": {
                "go_mod": "go.mod",
                "go_sum": "go.sum",
                "go_list_cmd": "go list -m all"
            },
            "ruby": {
                "gemfile": "Gemfile",
                "gemfile_lock": "Gemfile.lock",
                "gem_list_cmd": "gem list"
            },
            "php": {
                "composer_json": "composer.json",
                "composer_lock": "composer.lock",
                "composer_list_cmd": "composer show"
            }
        }
    
    def extract_image_and_generate_sbom(self, image_name: str) -> Dict[str, Any]:
        """Extract container image and generate comprehensive SBOM."""
        debug_print("Extracting image and generating SBOM for:", image_name)
        
        results = {
            "image_name": image_name,
            "extraction_path": None,
            "layers": [],
            "sbom": {
                "os_packages": [],
                "language_packages": [],
                "total_packages": 0,
                "package_managers_detected": []
            },
            "metadata": {},
            "errors": []
        }
        
        try:
            if not self.docker_client:
                results["errors"].append("Docker client not available")
                return results
            
            # Extract image to temporary directory
            extraction_path = self._extract_image(image_name)
            results["extraction_path"] = extraction_path
            
            if not extraction_path:
                results["errors"].append("Failed to extract image")
                return results
            
            # Get image metadata
            results["metadata"] = self._get_image_metadata(image_name)
            
            # Analyze layers
            results["layers"] = self._analyze_image_layers(extraction_path)
            
            # Generate SBOM for each layer
            for layer in results["layers"]:
                layer_sbom = self._generate_layer_sbom(layer["path"])
                layer["sbom"] = layer_sbom
                
                # Aggregate packages
                results["sbom"]["os_packages"].extend(layer_sbom.get("os_packages", []))
                results["sbom"]["language_packages"].extend(layer_sbom.get("language_packages", []))
            
            # Remove duplicates and count
            results["sbom"]["os_packages"] = self._deduplicate_packages(results["sbom"]["os_packages"])
            results["sbom"]["language_packages"] = self._deduplicate_packages(results["sbom"]["language_packages"])
            results["sbom"]["total_packages"] = len(results["sbom"]["os_packages"]) + len(results["sbom"]["language_packages"])
            
            # Detect package managers
            results["sbom"]["package_managers_detected"] = self._detect_package_managers(results["sbom"])
            
            debug_print(f"SBOM generated successfully: {results['sbom']['total_packages']} packages found")
            
        except Exception as e:
            debug_print("Error generating SBOM:", str(e))
            results["errors"].append(str(e))
        
        return results
    
    def _extract_image(self, image_name: str) -> Optional[str]:
        """Extract Docker image to temporary directory."""
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix="container_sbom_")
            debug_print(f"Extracting image to: {temp_dir}")
            
            # Use docker save to extract image
            image = self.docker_client.images.get(image_name)
            
            # Save image to tar file
            tar_path = os.path.join(temp_dir, "image.tar")
            with open(tar_path, 'wb') as f:
                for chunk in image.save():
                    f.write(chunk)
            
            # Extract tar file
            import tarfile
            with tarfile.open(tar_path, 'r') as tar:
                tar.extractall(temp_dir)
            
            # Remove tar file
            os.remove(tar_path)
            
            debug_print("Image extracted successfully")
            return temp_dir
            
        except Exception as e:
            debug_print("Error extracting image:", str(e))
            return None
    
    def _get_image_metadata(self, image_name: str) -> Dict[str, Any]:
        """Get detailed image metadata."""
        try:
            image = self.docker_client.images.get(image_name)
            
            metadata = {
                "id": image.id,
                "tags": image.tags,
                "size": image.attrs.get("Size", 0),
                "created": image.attrs.get("Created", ""),
                "architecture": image.attrs.get("Architecture", ""),
                "os": image.attrs.get("Os", ""),
                "config": image.attrs.get("Config", {}),
                "history": image.attrs.get("History", [])
            }
            
            return metadata
            
        except Exception as e:
            debug_print("Error getting image metadata:", str(e))
            return {}
    
    def _analyze_image_layers(self, extraction_path: str) -> List[Dict[str, Any]]:
        """Analyze extracted image layers."""
        layers = []
        
        try:
            # Look for layer directories
            layer_dirs = []
            for item in os.listdir(extraction_path):
                item_path = os.path.join(extraction_path, item)
                if os.path.isdir(item_path) and len(item) == 64:  # SHA256 hash length
                    layer_dirs.append(item)
            
            # Sort layers by creation time
            layer_dirs.sort()
            
            for i, layer_id in enumerate(layer_dirs):
                layer_path = os.path.join(extraction_path, layer_id)
                
                layer_info = {
                    "index": i,
                    "id": layer_id,
                    "path": layer_path,
                    "size": self._get_directory_size(layer_path),
                    "files": self._analyze_layer_files(layer_path)
                }
                
                layers.append(layer_info)
            
            debug_print(f"Analyzed {len(layers)} layers")
            
        except Exception as e:
            debug_print("Error analyzing layers:", str(e))
        
        return layers
    
    def _get_directory_size(self, path: str) -> int:
        """Get directory size in bytes."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        except Exception:
            pass
        return total_size
    
    def _analyze_layer_files(self, layer_path: str) -> Dict[str, Any]:
        """Analyze files in a layer."""
        analysis = {
            "total_files": 0,
            "executables": 0,
            "config_files": 0,
            "package_files": 0,
            "language_files": 0
        }
        
        try:
            for root, dirs, files in os.walk(layer_path):
                for file in files:
                    analysis["total_files"] += 1
                    file_path = os.path.join(root, file)
                    
                    # Check if executable
                    if os.access(file_path, os.X_OK):
                        analysis["executables"] += 1
                    
                    # Check for config files
                    if file.endswith(('.conf', '.config', '.ini', '.yaml', '.yml', '.json')):
                        analysis["config_files"] += 1
                    
                    # Check for package manager files
                    if any(pkg_file in file for pkg_file in ['package.json', 'requirements.txt', 'pom.xml', 'go.mod']):
                        analysis["package_files"] += 1
                    
                    # Check for language-specific files
                    if file.endswith(('.py', '.js', '.java', '.go', '.rb', '.php')):
                        analysis["language_files"] += 1
                        
        except Exception as e:
            debug_print("Error analyzing layer files:", str(e))
        
        return analysis
    
    def _generate_layer_sbom(self, layer_path: str) -> Dict[str, Any]:
        """Generate SBOM for a specific layer."""
        sbom = {
            "os_packages": [],
            "language_packages": [],
            "package_managers": []
        }
        
        try:
            # Detect and analyze OS packages
            os_packages = self._analyze_os_packages(layer_path)
            sbom["os_packages"] = os_packages
            
            # Detect and analyze language packages
            language_packages = self._analyze_language_packages(layer_path)
            sbom["language_packages"] = language_packages
            
            # Detect package managers
            package_managers = self._detect_layer_package_managers(layer_path)
            sbom["package_managers"] = package_managers
            
        except Exception as e:
            debug_print("Error generating layer SBOM:", str(e))
        
        return sbom
    
    def _analyze_os_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Analyze OS packages in the layer."""
        packages = []
        
        for pkg_manager, config in self.package_managers.items():
            try:
                # Check if package manager files exist
                pkg_files_exist = any(
                    os.path.exists(os.path.join(layer_path, file_path.lstrip('/')))
                    for file_path in config["file_paths"]
                )
                
                if pkg_files_exist:
                    pkg_manager_packages = self._extract_os_packages(layer_path, pkg_manager, config)
                    packages.extend(pkg_manager_packages)
                    
            except Exception as e:
                debug_print(f"Error analyzing {pkg_manager} packages:", str(e))
        
        return packages
    
    def _extract_os_packages(self, layer_path: str, pkg_manager: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract packages for a specific package manager."""
        packages = []
        
        try:
            if pkg_manager == "apt":
                packages = self._extract_apt_packages(layer_path)
            elif pkg_manager == "rpm":
                packages = self._extract_rpm_packages(layer_path)
            elif pkg_manager == "apk":
                packages = self._extract_apk_packages(layer_path)
            elif pkg_manager == "yum":
                packages = self._extract_yum_packages(layer_path)
                
        except Exception as e:
            debug_print(f"Error extracting {pkg_manager} packages:", str(e))
        
        return packages
    
    def _extract_apt_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Extract Debian/Ubuntu packages."""
        packages = []
        
        try:
            status_file = os.path.join(layer_path, "var/lib/dpkg/status")
            if os.path.exists(status_file):
                with open(status_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Parse dpkg status file
                package_blocks = content.split('\n\n')
                for block in package_blocks:
                    if block.strip():
                        package_info = self._parse_dpkg_status_block(block)
                        if package_info:
                            packages.append(package_info)
                            
        except Exception as e:
            debug_print("Error extracting apt packages:", str(e))
        
        return packages
    
    def _parse_dpkg_status_block(self, block: str) -> Optional[Dict[str, Any]]:
        """Parse a dpkg status block."""
        try:
            lines = block.strip().split('\n')
            package_info = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "Package":
                        package_info["name"] = value
                    elif key == "Version":
                        package_info["version"] = value
                    elif key == "Architecture":
                        package_info["architecture"] = value
                    elif key == "Description":
                        package_info["description"] = value
                    elif key == "Source":
                        package_info["source"] = value
            
            if "name" in package_info and "version" in package_info:
                package_info["package_manager"] = "apt"
                return package_info
                
        except Exception as e:
            debug_print("Error parsing dpkg status block:", str(e))
        
        return None
    
    def _extract_rpm_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Extract RPM packages."""
        packages = []
        
        try:
            # Look for RPM database
            rpm_db_path = os.path.join(layer_path, "var/lib/rpm")
            if os.path.exists(rpm_db_path):
                # This would require more complex RPM database parsing
                # For now, return basic structure
                packages.append({
                    "name": "rpm-package",
                    "version": "unknown",
                    "architecture": "unknown",
                    "package_manager": "rpm",
                    "description": "RPM package detected"
                })
                
        except Exception as e:
            debug_print("Error extracting rpm packages:", str(e))
        
        return packages
    
    def _extract_apk_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Extract Alpine packages."""
        packages = []
        
        try:
            installed_db = os.path.join(layer_path, "lib/apk/db/installed")
            if os.path.exists(installed_db):
                # Parse Alpine package database
                with open(installed_db, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Parse Alpine package format
                package_blocks = content.split('\n\n')
                for block in package_blocks:
                    if block.strip():
                        package_info = self._parse_apk_package_block(block)
                        if package_info:
                            packages.append(package_info)
                            
        except Exception as e:
            debug_print("Error extracting apk packages:", str(e))
        
        return packages
    
    def _parse_apk_package_block(self, block: str) -> Optional[Dict[str, Any]]:
        """Parse an Alpine package block."""
        try:
            lines = block.strip().split('\n')
            package_info = {}
            
            for line in lines:
                if line.startswith('P:'):
                    package_info["name"] = line[2:]
                elif line.startswith('V:'):
                    package_info["version"] = line[2:]
                elif line.startswith('A:'):
                    package_info["architecture"] = line[2:]
                elif line.startswith('T:'):
                    package_info["description"] = line[2:]
            
            if "name" in package_info and "version" in package_info:
                package_info["package_manager"] = "apk"
                return package_info
                
        except Exception as e:
            debug_print("Error parsing apk package block:", str(e))
        
        return None
    
    def _extract_yum_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Extract YUM packages."""
        packages = []
        
        try:
            # Look for YUM database
            yum_db_path = os.path.join(layer_path, "var/lib/yum")
            if os.path.exists(yum_db_path):
                # This would require more complex YUM database parsing
                # For now, return basic structure
                packages.append({
                    "name": "yum-package",
                    "version": "unknown",
                    "architecture": "unknown",
                    "package_manager": "yum",
                    "description": "YUM package detected"
                })
                
        except Exception as e:
            debug_print("Error extracting yum packages:", str(e))
        
        return packages
    
    def _analyze_language_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Analyze language-specific packages in the layer."""
        packages = []
        
        for language, config in self.language_package_managers.items():
            try:
                language_packages = self._extract_language_packages(layer_path, language, config)
                packages.extend(language_packages)
                
            except Exception as e:
                debug_print(f"Error analyzing {language} packages:", str(e))
        
        return packages
    
    def _extract_language_packages(self, layer_path: str, language: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract packages for a specific language."""
        packages = []
        
        try:
            if language == "python":
                packages = self._extract_python_packages(layer_path, config)
            elif language == "nodejs":
                packages = self._extract_nodejs_packages(layer_path, config)
            elif language == "java":
                packages = self._extract_java_packages(layer_path, config)
            elif language == "go":
                packages = self._extract_go_packages(layer_path, config)
            elif language == "ruby":
                packages = self._extract_ruby_packages(layer_path, config)
            elif language == "php":
                packages = self._extract_php_packages(layer_path, config)
                
        except Exception as e:
            debug_print(f"Error extracting {language} packages:", str(e))
        
        return packages
    
    def _extract_python_packages(self, layer_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Python packages."""
        packages = []
        
        try:
            # Look for requirements.txt
            requirements_file = os.path.join(layer_path, config["requirements_file"])
            if os.path.exists(requirements_file):
                with open(requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            package_info = self._parse_python_requirement(line)
                            if package_info:
                                packages.append(package_info)
            
            # Look for poetry.lock
            poetry_lock = os.path.join(layer_path, config["poetry_lock"])
            if os.path.exists(poetry_lock):
                poetry_packages = self._parse_poetry_lock(poetry_lock)
                packages.extend(poetry_packages)
                
        except Exception as e:
            debug_print("Error extracting Python packages:", str(e))
        
        return packages
    
    def _parse_python_requirement(self, requirement: str) -> Optional[Dict[str, Any]]:
        """Parse Python requirement line."""
        try:
            # Handle different requirement formats
            if '==' in requirement:
                name, version = requirement.split('==', 1)
            elif '>=' in requirement:
                name, version = requirement.split('>=', 1)
            elif '<=' in requirement:
                name, version = requirement.split('<=', 1)
            else:
                name = requirement
                version = "unknown"
            
            return {
                "name": name.strip(),
                "version": version.strip(),
                "language": "python",
                "package_manager": "pip"
            }
            
        except Exception as e:
            debug_print("Error parsing Python requirement:", str(e))
            return None
    
    def _parse_poetry_lock(self, poetry_lock_path: str) -> List[Dict[str, Any]]:
        """Parse poetry.lock file."""
        packages = []
        
        try:
            with open(poetry_lock_path, 'r') as f:
                content = f.read()
            
            # Simple parsing - look for package sections
            import re
            package_sections = re.findall(r'\[\[package\]\]\n(.*?)(?=\[\[package\]\]|\Z)', content, re.DOTALL)
            
            for section in package_sections:
                lines = section.strip().split('\n')
                package_info = {}
                
                for line in lines:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        
                        if key == "name":
                            package_info["name"] = value
                        elif key == "version":
                            package_info["version"] = value
                
                if "name" in package_info and "version" in package_info:
                    package_info["language"] = "python"
                    package_info["package_manager"] = "poetry"
                    packages.append(package_info)
                    
        except Exception as e:
            debug_print("Error parsing poetry.lock:", str(e))
        
        return packages
    
    def _extract_nodejs_packages(self, layer_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Node.js packages."""
        packages = []
        
        try:
            # Look for package.json
            package_json = os.path.join(layer_path, config["package_json"])
            if os.path.exists(package_json):
                with open(package_json, 'r') as f:
                    data = json.load(f)
                
                # Extract dependencies
                dependencies = data.get("dependencies", {})
                dev_dependencies = data.get("devDependencies", {})
                
                for name, version in dependencies.items():
                    packages.append({
                        "name": name,
                        "version": version,
                        "language": "nodejs",
                        "package_manager": "npm",
                        "type": "dependency"
                    })
                
                for name, version in dev_dependencies.items():
                    packages.append({
                        "name": name,
                        "version": version,
                        "language": "nodejs",
                        "package_manager": "npm",
                        "type": "devDependency"
                    })
                    
        except Exception as e:
            debug_print("Error extracting Node.js packages:", str(e))
        
        return packages
    
    def _extract_java_packages(self, layer_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Java packages."""
        packages = []
        
        try:
            # Look for pom.xml
            pom_xml = os.path.join(layer_path, config["pom_xml"])
            if os.path.exists(pom_xml):
                # This would require XML parsing
                # For now, return basic structure
                packages.append({
                    "name": "java-dependency",
                    "version": "unknown",
                    "language": "java",
                    "package_manager": "maven",
                    "description": "Java dependency detected"
                })
                
        except Exception as e:
            debug_print("Error extracting Java packages:", str(e))
        
        return packages
    
    def _extract_go_packages(self, layer_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Go packages."""
        packages = []
        
        try:
            # Look for go.mod
            go_mod = os.path.join(layer_path, config["go_mod"])
            if os.path.exists(go_mod):
                with open(go_mod, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('require '):
                            # Parse require line
                            parts = line.split()
                            if len(parts) >= 3:
                                name = parts[1]
                                version = parts[2]
                                packages.append({
                                    "name": name,
                                    "version": version,
                                    "language": "go",
                                    "package_manager": "go"
                                })
                                
        except Exception as e:
            debug_print("Error extracting Go packages:", str(e))
        
        return packages
    
    def _extract_ruby_packages(self, layer_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Ruby packages."""
        packages = []
        
        try:
            # Look for Gemfile
            gemfile = os.path.join(layer_path, config["gemfile"])
            if os.path.exists(gemfile):
                with open(gemfile, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('gem '):
                            # Parse gem line
                            parts = line.split()
                            if len(parts) >= 2:
                                name = parts[1].strip("'\"")
                                version = "unknown"
                                if len(parts) >= 4 and parts[2] == ",":
                                    version = parts[3].strip("'\"")
                                
                                packages.append({
                                    "name": name,
                                    "version": version,
                                    "language": "ruby",
                                    "package_manager": "bundler"
                                })
                                
        except Exception as e:
            debug_print("Error extracting Ruby packages:", str(e))
        
        return packages
    
    def _extract_php_packages(self, layer_path: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract PHP packages."""
        packages = []
        
        try:
            # Look for composer.json
            composer_json = os.path.join(layer_path, config["composer_json"])
            if os.path.exists(composer_json):
                with open(composer_json, 'r') as f:
                    data = json.load(f)
                
                # Extract dependencies
                require = data.get("require", {})
                require_dev = data.get("require-dev", {})
                
                for name, version in require.items():
                    packages.append({
                        "name": name,
                        "version": version,
                        "language": "php",
                        "package_manager": "composer",
                        "type": "dependency"
                    })
                
                for name, version in require_dev.items():
                    packages.append({
                        "name": name,
                        "version": version,
                        "language": "php",
                        "package_manager": "composer",
                        "type": "devDependency"
                    })
                    
        except Exception as e:
            debug_print("Error extracting PHP packages:", str(e))
        
        return packages
    
    def _detect_layer_package_managers(self, layer_path: str) -> List[str]:
        """Detect package managers present in the layer."""
        detected = []
        
        # Check for OS package managers
        for pkg_manager, config in self.package_managers.items():
            for file_path in config["file_paths"]:
                if os.path.exists(os.path.join(layer_path, file_path.lstrip('/'))):
                    detected.append(pkg_manager)
                    break
        
        # Check for language package managers
        for language, config in self.language_package_managers.items():
            for file_name in config.values():
                if isinstance(file_name, str):
                    if os.path.exists(os.path.join(layer_path, file_name)):
                        detected.append(f"{language}_{config.get('package_manager', 'unknown')}")
                elif isinstance(file_name, list):
                    for file in file_name:
                        if os.path.exists(os.path.join(layer_path, file)):
                            detected.append(f"{language}_{config.get('package_manager', 'unknown')}")
                            break
        
        return list(set(detected))
    
    def _detect_package_managers(self, sbom: Dict[str, Any]) -> List[str]:
        """Detect package managers from SBOM."""
        detected = set()
        
        # Check OS packages
        for package in sbom.get("os_packages", []):
            if "package_manager" in package:
                detected.add(package["package_manager"])
        
        # Check language packages
        for package in sbom.get("language_packages", []):
            if "package_manager" in package:
                detected.add(package["package_manager"])
        
        return list(detected)
    
    def _deduplicate_packages(self, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate packages based on name and version."""
        seen = set()
        unique_packages = []
        
        for package in packages:
            key = f"{package.get('name', '')}-{package.get('version', '')}-{package.get('package_manager', '')}"
            if key not in seen:
                seen.add(key)
                unique_packages.append(package)
        
        return unique_packages 