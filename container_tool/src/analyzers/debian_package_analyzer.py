"""
Debian Package Analyzer
Phase 1: Basic OS Package Vulnerability Scanning for Debian-based images
Step 1: Image Extraction - Use Docker SDK to pull an image and extract its layers.
"""

import json
import logging
import os
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

import docker
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ..utils.debug_utils import debug_print

class DebianPackageAnalyzer:
    """Specialized analyzer for Debian-based container images."""
    
    def __init__(self, debug: bool = False):
        """Initialize the Debian package analyzer."""
        self.debug = debug
        self.console = Console()
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
            debug_print("Docker client initialized successfully")
        except Exception as e:
            debug_print(f"Docker client initialization failed: {str(e)}")
            self.docker_client = None
        
        # Debian-specific package manager files
        self.debian_package_files = {
            "dpkg_status": "/var/lib/dpkg/status",
            "dpkg_available": "/var/lib/dpkg/available",
            "apt_sources": "/etc/apt/sources.list",
            "apt_sources_d": "/etc/apt/sources.list.d/",
            "package_cache": "/var/cache/apt/archives/",
            "installed_packages": "/var/lib/dpkg/info/"
        }
        
        # Debian package patterns
        self.package_patterns = {
            "deb_package": r'^[a-zA-Z0-9._-]+$',
            "version_pattern": r'^\d+\.\d+\.\d+(-[a-zA-Z0-9._-]+)?(\+[a-zA-Z0-9._-]+)?$',
            "architecture_pattern": r'^(amd64|arm64|armhf|i386|ppc64el|s390x)$'
        }
    
    def extract_debian_image(self, image_name: str, output_dir: str = None) -> Dict[str, Any]:
        """
        Phase 1, Step 1: Extract Debian-based Docker image and its layers.
        
        Args:
            image_name: Docker image name (e.g., 'ubuntu:20.04', 'debian:bullseye')
            output_dir: Directory to extract layers to (optional)
            
        Returns:
            Dictionary containing extraction results and layer information
        """
        debug_print(f"Starting Debian image extraction: {image_name}")
        
        results = {
            "image_name": image_name,
            "extraction_path": None,
            "layers": [],
            "metadata": {},
            "debian_info": {},
            "errors": [],
            "extraction_time": None,
            "total_size": 0
        }
        
        if not self.docker_client:
            results["errors"].append("Docker client not available")
            return results
        
        start_time = datetime.now()
        
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=self.console
            ) as progress:
                
                # Step 1.1: Pull image if not present
                task_pull = progress.add_task("Pulling Docker image...", total=None)
                image = self._pull_image(image_name)
                if not image:
                    results["errors"].append(f"Failed to pull image: {image_name}")
                    return results
                progress.update(task_pull, completed=True)
                
                # Step 1.2: Get image metadata
                task_metadata = progress.add_task("Extracting image metadata...", total=None)
                results["metadata"] = self._get_image_metadata(image)
                progress.update(task_metadata, completed=True)
                
                # Step 1.3: Extract image layers
                task_extract = progress.add_task("Extracting image layers...", total=None)
                extraction_path = self._extract_image_layers(image, output_dir)
                if not extraction_path:
                    results["errors"].append("Failed to extract image layers")
                    return results
                results["extraction_path"] = extraction_path
                progress.update(task_extract, completed=True)
                
                # Step 1.4: Analyze extracted layers
                task_analyze = progress.add_task("Analyzing extracted layers...", total=None)
                layer_results = self._analyze_extracted_layers(extraction_path)
                results["layers"] = layer_results["layers"]
                results["total_size"] = layer_results["total_size"]
                progress.update(task_analyze, completed=True)
                
                # Step 1.5: Detect Debian-specific information
                task_debian = progress.add_task("Detecting Debian information...", total=None)
                debian_info = self._detect_debian_information(extraction_path)
                results["debian_info"] = debian_info
                progress.update(task_debian, completed=True)
            
            # Calculate extraction time
            results["extraction_time"] = (datetime.now() - start_time).total_seconds()
            
            debug_print(f"Debian image extraction completed in {results['extraction_time']:.2f} seconds")
            debug_print(f"Extracted {len(results['layers'])} layers")
            debug_print(f"Total size: {results['total_size'] / (1024*1024):.2f} MB")
            
        except Exception as e:
            debug_print(f"Error during Debian image extraction: {str(e)}")
            results["errors"].append(str(e))
        
        return results
    
    def _pull_image(self, image_name: str) -> Optional[docker.models.images.Image]:
        """Pull Docker image if not present locally."""
        try:
            debug_print(f"Checking for image: {image_name}")
            
            # Try to get existing image
            try:
                image = self.docker_client.images.get(image_name)
                debug_print(f"Image {image_name} already exists locally")
                return image
            except docker.errors.ImageNotFound:
                debug_print(f"Image {image_name} not found locally, pulling...")
            
            # Pull the image
            image = self.docker_client.images.pull(image_name)
            debug_print(f"Successfully pulled image: {image_name}")
            return image
            
        except Exception as e:
            debug_print(f"Error pulling image {image_name}: {str(e)}")
            return None
    
    def _get_image_metadata(self, image: docker.models.images.Image) -> Dict[str, Any]:
        """Extract comprehensive image metadata."""
        try:
            metadata = {
                "id": image.id,
                "tags": image.tags,
                "size": image.attrs.get("Size", 0),
                "created": image.attrs.get("Created", ""),
                "architecture": image.attrs.get("Architecture", ""),
                "os": image.attrs.get("Os", ""),
                "variant": image.attrs.get("Variant", ""),
                "config": {
                    "env": image.attrs.get("Config", {}).get("Env", []),
                    "cmd": image.attrs.get("Config", {}).get("Cmd", []),
                    "entrypoint": image.attrs.get("Config", {}).get("Entrypoint", []),
                    "working_dir": image.attrs.get("Config", {}).get("WorkingDir", ""),
                    "user": image.attrs.get("Config", {}).get("User", "")
                },
                "history": image.attrs.get("History", []),
                "rootfs": {
                    "type": image.attrs.get("RootFS", {}).get("Type", ""),
                    "layers": image.attrs.get("RootFS", {}).get("Layers", [])
                }
            }
            
            debug_print(f"Extracted metadata for image: {image.tags[0] if image.tags else image.id}")
            return metadata
            
        except Exception as e:
            debug_print(f"Error extracting image metadata: {str(e)}")
            return {}
    
    def _extract_image_layers(self, image: docker.models.images.Image, output_dir: str = None) -> Optional[str]:
        """Extract all layers from Docker image to directory."""
        try:
            # Create output directory
            if output_dir:
                extraction_path = Path(output_dir) / f"debian_extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            else:
                extraction_path = Path(tempfile.mkdtemp(prefix="debian_extraction_"))
            
            extraction_path.mkdir(parents=True, exist_ok=True)
            debug_print(f"Extraction path: {extraction_path}")
            
            # Save image to tar file
            tar_path = extraction_path / "image.tar"
            debug_print("Saving image to tar file...")
            
            with open(tar_path, 'wb') as f:
                for chunk in image.save():
                    f.write(chunk)
            
            # Extract tar file
            debug_print("Extracting tar file...")
            with tarfile.open(tar_path, 'r') as tar:
                tar.extractall(extraction_path)
            
            # Remove tar file
            tar_path.unlink()
            
            debug_print(f"Successfully extracted image layers to: {extraction_path}")
            return str(extraction_path)
            
        except Exception as e:
            debug_print(f"Error extracting image layers: {str(e)}")
            return None
    
    def _analyze_extracted_layers(self, extraction_path: str) -> Dict[str, Any]:
        """Analyze extracted layers and their contents."""
        try:
            layers = []
            total_size = 0
            
            # Look for layer directories (SHA256 hashes)
            layer_dirs = []
            for item in os.listdir(extraction_path):
                item_path = os.path.join(extraction_path, item)
                if os.path.isdir(item_path) and len(item) == 64:  # SHA256 hash length
                    layer_dirs.append(item)
            
            # Sort layers by creation time (layer order matters)
            layer_dirs.sort()
            
            debug_print(f"Found {len(layer_dirs)} layer directories")
            
            for i, layer_id in enumerate(layer_dirs):
                layer_path = os.path.join(extraction_path, layer_id)
                
                # Analyze layer
                layer_info = self._analyze_single_layer(layer_path, i, layer_id)
                layers.append(layer_info)
                total_size += layer_info.get("size", 0)
            
            return {
                "layers": layers,
                "total_size": total_size,
                "layer_count": len(layers)
            }
            
        except Exception as e:
            debug_print(f"Error analyzing extracted layers: {str(e)}")
            return {"layers": [], "total_size": 0, "layer_count": 0}
    
    def _analyze_single_layer(self, layer_path: str, layer_index: int, layer_id: str) -> Dict[str, Any]:
        """Analyze a single layer directory."""
        try:
            layer_info = {
                "index": layer_index,
                "id": layer_id,
                "path": layer_path,
                "size": 0,
                "files": {
                    "total": 0,
                    "executables": 0,
                    "config_files": 0,
                    "package_files": 0,
                    "debian_files": 0
                },
                "debian_packages": [],
                "debian_files_found": [],
                "modifications": []
            }
            
            # Calculate layer size
            layer_info["size"] = self._calculate_directory_size(layer_path)
            
            # Analyze files in layer
            file_analysis = self._analyze_layer_files(layer_path)
            layer_info["files"] = file_analysis["files"]
            layer_info["debian_files_found"] = file_analysis["debian_files"]
            
            # Extract Debian package information
            if file_analysis["debian_files"]:
                packages = self._extract_debian_packages(layer_path)
                layer_info["debian_packages"] = packages
            
            # Detect layer modifications
            modifications = self._detect_layer_modifications(layer_path)
            layer_info["modifications"] = modifications
            
            debug_print(f"Layer {layer_index}: {layer_info['files']['total']} files, {len(layer_info['debian_packages'])} packages")
            
            return layer_info
            
        except Exception as e:
            debug_print(f"Error analyzing layer {layer_id}: {str(e)}")
            return {
                "index": layer_index,
                "id": layer_id,
                "path": layer_path,
                "size": 0,
                "files": {"total": 0, "executables": 0, "config_files": 0, "package_files": 0, "debian_files": 0},
                "debian_packages": [],
                "debian_files_found": [],
                "modifications": [],
                "error": str(e)
            }
    
    def _calculate_directory_size(self, path: str) -> int:
        """Calculate total size of directory in bytes."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        except Exception as e:
            debug_print(f"Error calculating directory size: {str(e)}")
        return total_size
    
    def _analyze_layer_files(self, layer_path: str) -> Dict[str, Any]:
        """Analyze files in a layer for Debian-specific content."""
        analysis = {
            "files": {
                "total": 0,
                "executables": 0,
                "config_files": 0,
                "package_files": 0,
                "debian_files": 0
            },
            "debian_files": []
        }
        
        try:
            for root, dirs, files in os.walk(layer_path):
                for file in files:
                    analysis["files"]["total"] += 1
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, layer_path)
                    
                    # Check if executable
                    if os.access(file_path, os.X_OK):
                        analysis["files"]["executables"] += 1
                    
                    # Check for config files
                    if file.endswith(('.conf', '.config', '.ini', '.yaml', '.yml', '.json')):
                        analysis["files"]["config_files"] += 1
                    
                    # Check for package manager files
                    if any(pkg_file in file for pkg_file in ['package.json', 'requirements.txt', 'pom.xml', 'go.mod']):
                        analysis["files"]["package_files"] += 1
                    
                    # Check for Debian-specific files
                    if self._is_debian_file(relative_path):
                        analysis["files"]["debian_files"] += 1
                        analysis["debian_files"].append({
                            "path": relative_path,
                            "type": self._get_debian_file_type(relative_path),
                            "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
                        })
                        
        except Exception as e:
            debug_print(f"Error analyzing layer files: {str(e)}")
        
        return analysis
    
    def _is_debian_file(self, file_path: str) -> bool:
        """Check if file is Debian-specific."""
        debian_paths = [
            "var/lib/dpkg/",
            "etc/apt/",
            "var/cache/apt/",
            "var/lib/apt/",
            "usr/share/doc/",
            "DEBIAN/",
            "debian/"
        ]
        
        return any(debian_path in file_path for debian_path in debian_paths)
    
    def _get_debian_file_type(self, file_path: str) -> str:
        """Get the type of Debian file."""
        if "dpkg/status" in file_path:
            return "dpkg_status"
        elif "dpkg/available" in file_path:
            return "dpkg_available"
        elif "apt/sources.list" in file_path:
            return "apt_sources"
        elif "apt/sources.list.d/" in file_path:
            return "apt_sources_d"
        elif "cache/apt/" in file_path:
            return "apt_cache"
        elif "lib/apt/" in file_path:
            return "apt_lib"
        elif "share/doc/" in file_path:
            return "package_docs"
        elif "DEBIAN/" in file_path:
            return "debian_control"
        else:
            return "debian_other"
    
    def _extract_debian_packages(self, layer_path: str) -> List[Dict[str, Any]]:
        """Extract Debian package information from layer."""
        packages = []
        
        try:
            # Look for dpkg status file
            status_file = os.path.join(layer_path, "var/lib/dpkg/status")
            if os.path.exists(status_file):
                packages.extend(self._parse_dpkg_status(status_file))
            
            # Look for package information in /var/lib/dpkg/info/
            info_dir = os.path.join(layer_path, "var/lib/dpkg/info")
            if os.path.exists(info_dir):
                packages.extend(self._extract_package_info_from_dir(info_dir))
            
            debug_print(f"Extracted {len(packages)} Debian packages from layer")
            
        except Exception as e:
            debug_print(f"Error extracting Debian packages: {str(e)}")
        
        return packages
    
    def _parse_dpkg_status(self, status_file: str) -> List[Dict[str, Any]]:
        """Parse dpkg status file to extract package information."""
        packages = []
        
        try:
            with open(status_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split into package blocks
            package_blocks = content.split('\n\n')
            
            for block in package_blocks:
                if block.strip():
                    package_info = self._parse_dpkg_status_block(block)
                    if package_info:
                        packages.append(package_info)
            
        except Exception as e:
            debug_print(f"Error parsing dpkg status file: {str(e)}")
        
        return packages
    
    def _parse_dpkg_status_block(self, block: str) -> Optional[Dict[str, Any]]:
        """Parse a single dpkg status block."""
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
                    elif key == "Depends":
                        package_info["depends"] = value
                    elif key == "Installed-Size":
                        package_info["installed_size"] = value
                    elif key == "Status":
                        package_info["status"] = value
            
            if "name" in package_info and "version" in package_info:
                package_info["package_manager"] = "dpkg"
                package_info["language"] = "os"
                return package_info
                
        except Exception as e:
            debug_print(f"Error parsing dpkg status block: {str(e)}")
        
        return None
    
    def _extract_package_info_from_dir(self, info_dir: str) -> List[Dict[str, Any]]:
        """Extract package information from /var/lib/dpkg/info/ directory."""
        packages = []
        
        try:
            for filename in os.listdir(info_dir):
                if filename.endswith('.list'):
                    package_name = filename[:-5]  # Remove .list extension
                    
                    # Try to get version from control file
                    control_file = os.path.join(info_dir, f"{package_name}.control")
                    version = "unknown"
                    
                    if os.path.exists(control_file):
                        try:
                            with open(control_file, 'r') as f:
                                for line in f:
                                    if line.startswith('Version:'):
                                        version = line.split(':', 1)[1].strip()
                                        break
                        except:
                            pass
                    
                    packages.append({
                        "name": package_name,
                        "version": version,
                        "package_manager": "dpkg",
                        "language": "os",
                        "source": "info_dir"
                    })
            
        except Exception as e:
            debug_print(f"Error extracting package info from directory: {str(e)}")
        
        return packages
    
    def _detect_layer_modifications(self, layer_path: str) -> List[Dict[str, Any]]:
        """Detect what modifications were made in this layer."""
        modifications = []
        
        try:
            # Check for common modification patterns
            modification_patterns = [
                {"type": "package_installation", "indicators": ["var/lib/dpkg/status", "var/lib/dpkg/info/"]},
                {"type": "file_creation", "indicators": ["usr/bin/", "usr/sbin/", "usr/lib/"]},
                {"type": "configuration", "indicators": ["etc/", "var/lib/"]},
                {"type": "user_creation", "indicators": ["etc/passwd", "etc/group"]},
                {"type": "permission_changes", "indicators": ["var/lib/dpkg/info/"]}
            ]
            
            for pattern in modification_patterns:
                for indicator in pattern["indicators"]:
                    indicator_path = os.path.join(layer_path, indicator)
                    if os.path.exists(indicator_path):
                        modifications.append({
                            "type": pattern["type"],
                            "indicator": indicator,
                            "path": indicator_path
                        })
            
        except Exception as e:
            debug_print(f"Error detecting layer modifications: {str(e)}")
        
        return modifications
    
    def _detect_debian_information(self, extraction_path: str) -> Dict[str, Any]:
        """Detect Debian-specific information from extracted image."""
        debian_info = {
            "distribution": "unknown",
            "version": "unknown",
            "codename": "unknown",
            "architecture": "unknown",
            "package_count": 0,
            "package_managers": [],
            "sources": [],
            "features": []
        }
        
        try:
            # Look for Debian/Ubuntu release information
            release_files = [
                "etc/debian_version",
                "etc/os-release",
                "usr/lib/os-release",
                "etc/lsb-release"
            ]
            
            for release_file in release_files:
                file_path = os.path.join(extraction_path, release_file.lstrip('/'))
                if os.path.exists(file_path):
                    release_info = self._parse_release_file(file_path)
                    debian_info.update(release_info)
                    break
            
            # Count total packages across all layers
            total_packages = 0
            for root, dirs, files in os.walk(extraction_path):
                if "var/lib/dpkg/status" in root:
                    # Count packages in this status file
                    try:
                        with open(os.path.join(root, "var/lib/dpkg/status"), 'r') as f:
                            content = f.read()
                            package_count = content.count('\nPackage: ')
                            total_packages += package_count
                    except:
                        pass
            
            debian_info["package_count"] = total_packages
            
            # Detect package managers
            if os.path.exists(os.path.join(extraction_path, "usr/bin/apt")):
                debian_info["package_managers"].append("apt")
            if os.path.exists(os.path.join(extraction_path, "usr/bin/dpkg")):
                debian_info["package_managers"].append("dpkg")
            if os.path.exists(os.path.join(extraction_path, "usr/bin/apt-get")):
                debian_info["package_managers"].append("apt-get")
            
            # Detect APT sources
            sources_list = os.path.join(extraction_path, "etc/apt/sources.list")
            if os.path.exists(sources_list):
                try:
                    with open(sources_list, 'r') as f:
                        debian_info["sources"] = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                except:
                    pass
            
            debug_print(f"Detected Debian distribution: {debian_info['distribution']} {debian_info['version']}")
            
        except Exception as e:
            debug_print(f"Error detecting Debian information: {str(e)}")
        
        return debian_info
    
    def _parse_release_file(self, file_path: str) -> Dict[str, Any]:
        """Parse Debian/Ubuntu release file."""
        release_info = {
            "distribution": "unknown",
            "version": "unknown",
            "codename": "unknown",
            "architecture": "unknown"
        }
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        
                        if key == "PRETTY_NAME":
                            release_info["distribution"] = value
                        elif key == "VERSION_ID":
                            release_info["version"] = value
                        elif key == "VERSION_CODENAME":
                            release_info["codename"] = value
                        elif key == "UBUNTU_CODENAME":
                            release_info["codename"] = value
                        elif key == "DEBIAN_CODENAME":
                            release_info["codename"] = value
                        elif key == "ARCH":
                            release_info["architecture"] = value
            
        except Exception as e:
            debug_print(f"Error parsing release file {file_path}: {str(e)}")
        
        return release_info
    
    def generate_extraction_report(self, extraction_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive extraction report."""
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "image_name": extraction_results.get("image_name", ""),
                "extraction_time": extraction_results.get("extraction_time", 0),
                "total_layers": len(extraction_results.get("layers", [])),
                "total_size_mb": extraction_results.get("total_size", 0) / (1024 * 1024)
            },
            "image_metadata": extraction_results.get("metadata", {}),
            "debian_information": extraction_results.get("debian_info", {}),
            "layer_analysis": {
                "layers": extraction_results.get("layers", []),
                "summary": self._generate_layer_summary(extraction_results.get("layers", []))
            },
            "package_analysis": self._generate_package_summary(extraction_results.get("layers", [])),
            "extraction_path": extraction_results.get("extraction_path", ""),
            "errors": extraction_results.get("errors", [])
        }
        
        return report
    
    def _generate_layer_summary(self, layers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of layer analysis."""
        summary = {
            "total_layers": len(layers),
            "total_size": sum(layer.get("size", 0) for layer in layers),
            "files_by_layer": [],
            "debian_files_by_layer": [],
            "packages_by_layer": []
        }
        
        for layer in layers:
            summary["files_by_layer"].append({
                "layer_index": layer.get("index", 0),
                "total_files": layer.get("files", {}).get("total", 0),
                "executables": layer.get("files", {}).get("executables", 0),
                "config_files": layer.get("files", {}).get("config_files", 0),
                "debian_files": layer.get("files", {}).get("debian_files", 0)
            })
            
            summary["debian_files_by_layer"].append({
                "layer_index": layer.get("index", 0),
                "debian_files": layer.get("debian_files_found", [])
            })
            
            summary["packages_by_layer"].append({
                "layer_index": layer.get("index", 0),
                "packages": layer.get("debian_packages", [])
            })
        
        return summary
    
    def _generate_package_summary(self, layers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of package analysis."""
        all_packages = []
        
        for layer in layers:
            all_packages.extend(layer.get("debian_packages", []))
        
        # Remove duplicates based on name and version
        unique_packages = []
        seen = set()
        
        for package in all_packages:
            key = f"{package.get('name', '')}-{package.get('version', '')}"
            if key not in seen:
                seen.add(key)
                unique_packages.append(package)
        
        return {
            "total_packages": len(unique_packages),
            "packages": unique_packages,
            "package_managers": list(set(pkg.get("package_manager", "") for pkg in unique_packages)),
            "architectures": list(set(pkg.get("architecture", "") for pkg in unique_packages if pkg.get("architecture")))
        } 