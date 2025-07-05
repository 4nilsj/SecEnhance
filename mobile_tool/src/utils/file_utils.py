#!/usr/bin/env python3
"""
File Utilities for Mobile Security Testing
Utility functions for file operations and validation.
"""

import os
import zipfile
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import tempfile
import shutil

class FileUtils:
    """Utility functions for file operations."""
    
    def __init__(self, debug: bool = False):
        """Initialize file utils."""
        self.debug = debug
        self.logger = logging.getLogger(__name__)
    
    def validate_apk_file(self, file_path: str) -> Dict[str, Any]:
        """Validate APK file format and structure."""
        validation = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "file_info": {}
        }
        
        try:
            if not os.path.exists(file_path):
                validation["errors"].append("File does not exist")
                return validation
            
            if not file_path.lower().endswith('.apk'):
                validation["errors"].append("File is not an APK file")
                return validation
            
            # Check file size
            file_size = os.path.getsize(file_path)
            validation["file_info"]["size"] = file_size
            
            if file_size == 0:
                validation["errors"].append("File is empty")
                return validation
            
            if file_size < 1024:  # Less than 1KB
                validation["warnings"].append("File size is very small, may be corrupted")
            
            # Validate ZIP structure
            try:
                with zipfile.ZipFile(file_path, 'r') as apk_zip:
                    # Check for required files
                    required_files = ['AndroidManifest.xml', 'classes.dex']
                    missing_files = []
                    
                    for required_file in required_files:
                        if required_file not in apk_zip.namelist():
                            missing_files.append(required_file)
                    
                    if missing_files:
                        validation["errors"].append(f"Missing required files: {', '.join(missing_files)}")
                        return validation
                    
                    # Check for additional important files
                    important_files = ['resources.arsc', 'META-INF/']
                    for important_file in important_files:
                        if not any(name.startswith(important_file) for name in apk_zip.namelist()):
                            validation["warnings"].append(f"Missing important file: {important_file}")
                    
                    validation["file_info"]["total_files"] = len(apk_zip.namelist())
                    validation["file_info"]["compressed_size"] = sum(info.file_size for info in apk_zip.filelist)
                    
            except zipfile.BadZipFile:
                validation["errors"].append("File is not a valid ZIP archive")
                return validation
            
            validation["valid"] = True
            
        except Exception as e:
            self.logger.error(f"Error validating APK file: {str(e)}")
            validation["errors"].append(f"Validation error: {str(e)}")
        
        return validation
    
    def validate_ipa_file(self, file_path: str) -> Dict[str, Any]:
        """Validate IPA file format and structure."""
        validation = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "file_info": {}
        }
        
        try:
            if not os.path.exists(file_path):
                validation["errors"].append("File does not exist")
                return validation
            
            if not file_path.lower().endswith('.ipa'):
                validation["errors"].append("File is not an IPA file")
                return validation
            
            # Check file size
            file_size = os.path.getsize(file_path)
            validation["file_info"]["size"] = file_size
            
            if file_size == 0:
                validation["errors"].append("File is empty")
                return validation
            
            if file_size < 1024:  # Less than 1KB
                validation["warnings"].append("File size is very small, may be corrupted")
            
            # Validate ZIP structure
            try:
                with zipfile.ZipFile(file_path, 'r') as ipa_zip:
                    # Check for required structure
                    required_dirs = ['Payload/']
                    missing_dirs = []
                    
                    for required_dir in required_dirs:
                        if not any(name.startswith(required_dir) for name in ipa_zip.namelist()):
                            missing_dirs.append(required_dir)
                    
                    if missing_dirs:
                        validation["errors"].append(f"Missing required directories: {', '.join(missing_dirs)}")
                        return validation
                    
                    # Look for .app bundle
                    app_bundles = [name for name in ipa_zip.namelist() if name.endswith('.app/')]
                    if not app_bundles:
                        validation["errors"].append("No .app bundle found in IPA")
                        return validation
                    
                    validation["file_info"]["app_bundles"] = len(app_bundles)
                    validation["file_info"]["total_files"] = len(ipa_zip.namelist())
                    validation["file_info"]["compressed_size"] = sum(info.file_size for info in ipa_zip.filelist)
                    
            except zipfile.BadZipFile:
                validation["errors"].append("File is not a valid ZIP archive")
                return validation
            
            validation["valid"] = True
            
        except Exception as e:
            self.logger.error(f"Error validating IPA file: {str(e)}")
            validation["errors"].append(f"Validation error: {str(e)}")
        
        return validation
    
    def extract_apk_contents(self, apk_path: str, extract_dir: str = None) -> Dict[str, Any]:
        """Extract APK contents to directory."""
        extraction = {
            "success": False,
            "extract_dir": None,
            "files": [],
            "errors": []
        }
        
        try:
            if extract_dir is None:
                extract_dir = tempfile.mkdtemp(prefix="apk_")
            
            extraction["extract_dir"] = extract_dir
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                apk_zip.extractall(extract_dir)
                
                # List extracted files
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        extraction["files"].append(rel_path)
            
            extraction["success"] = True
            
        except Exception as e:
            self.logger.error(f"Error extracting APK contents: {str(e)}")
            extraction["errors"].append(str(e))
        
        return extraction
    
    def extract_ipa_contents(self, ipa_path: str, extract_dir: str = None) -> Dict[str, Any]:
        """Extract IPA contents to directory."""
        extraction = {
            "success": False,
            "extract_dir": None,
            "files": [],
            "errors": []
        }
        
        try:
            if extract_dir is None:
                extract_dir = tempfile.mkdtemp(prefix="ipa_")
            
            extraction["extract_dir"] = extract_dir
            
            with zipfile.ZipFile(ipa_path, 'r') as ipa_zip:
                ipa_zip.extractall(extract_dir)
                
                # List extracted files
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        extraction["files"].append(rel_path)
            
            extraction["success"] = True
            
        except Exception as e:
            self.logger.error(f"Error extracting IPA contents: {str(e)}")
            extraction["errors"].append(str(e))
        
        return extraction
    
    def find_files_by_extension(self, directory: str, extensions: List[str]) -> List[str]:
        """Find files with specific extensions in directory."""
        files = []
        
        try:
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    if any(filename.lower().endswith(ext.lower()) for ext in extensions):
                        file_path = os.path.join(root, filename)
                        files.append(file_path)
        
        except Exception as e:
            self.logger.error(f"Error finding files by extension: {str(e)}")
        
        return files
    
    def find_files_by_pattern(self, directory: str, pattern: str) -> List[str]:
        """Find files matching pattern in directory."""
        import fnmatch
        
        files = []
        
        try:
            for root, dirs, filenames in os.walk(directory):
                for filename in filenames:
                    if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                        file_path = os.path.join(root, filename)
                        files.append(file_path)
        
        except Exception as e:
            self.logger.error(f"Error finding files by pattern: {str(e)}")
        
        return files
    
    def read_file_content(self, file_path: str, encoding: str = 'utf-8') -> Optional[str]:
        """Read file content with error handling."""
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {str(e)}")
            return None
    
    def read_binary_file(self, file_path: str) -> Optional[bytes]:
        """Read binary file content."""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading binary file {file_path}: {str(e)}")
            return None
    
    def write_file_content(self, file_path: str, content: str, encoding: str = 'utf-8') -> bool:
        """Write content to file with error handling."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"Error writing file {file_path}: {str(e)}")
            return False
    
    def write_binary_file(self, file_path: str, content: bytes) -> bool:
        """Write binary content to file."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"Error writing binary file {file_path}: {str(e)}")
            return False
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get detailed file information."""
        file_info = {
            "path": file_path,
            "exists": False,
            "size": 0,
            "modified": None,
            "permissions": None,
            "type": "unknown"
        }
        
        try:
            if os.path.exists(file_path):
                file_info["exists"] = True
                file_info["size"] = os.path.getsize(file_path)
                file_info["modified"] = os.path.getmtime(file_path)
                file_info["permissions"] = oct(os.stat(file_path).st_mode)[-3:]
                
                # Determine file type
                if file_path.lower().endswith('.apk'):
                    file_info["type"] = "apk"
                elif file_path.lower().endswith('.ipa'):
                    file_info["type"] = "ipa"
                elif file_path.lower().endswith('.dex'):
                    file_info["type"] = "dex"
                elif file_path.lower().endswith('.so'):
                    file_info["type"] = "native_library"
                elif file_path.lower().endswith('.xml'):
                    file_info["type"] = "xml"
                elif file_path.lower().endswith('.json'):
                    file_info["type"] = "json"
                else:
                    file_info["type"] = "other"
        
        except Exception as e:
            self.logger.error(f"Error getting file info for {file_path}: {str(e)}")
        
        return file_info
    
    def cleanup_temp_directory(self, directory: str) -> bool:
        """Clean up temporary directory."""
        try:
            if os.path.exists(directory):
                shutil.rmtree(directory)
            return True
        except Exception as e:
            self.logger.error(f"Error cleaning up directory {directory}: {str(e)}")
            return False
    
    def create_backup(self, file_path: str, backup_suffix: str = ".backup") -> Optional[str]:
        """Create backup of file."""
        try:
            if not os.path.exists(file_path):
                return None
            
            backup_path = file_path + backup_suffix
            shutil.copy2(file_path, backup_path)
            return backup_path
        
        except Exception as e:
            self.logger.error(f"Error creating backup of {file_path}: {str(e)}")
            return None
    
    def restore_backup(self, backup_path: str, original_path: str = None) -> bool:
        """Restore file from backup."""
        try:
            if not os.path.exists(backup_path):
                return False
            
            if original_path is None:
                original_path = backup_path.replace(".backup", "")
            
            shutil.copy2(backup_path, original_path)
            return True
        
        except Exception as e:
            self.logger.error(f"Error restoring backup {backup_path}: {str(e)}")
            return False
    
    def get_directory_size(self, directory: str) -> int:
        """Get total size of directory in bytes."""
        total_size = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    if os.path.exists(file_path):
                        total_size += os.path.getsize(file_path)
        
        except Exception as e:
            self.logger.error(f"Error calculating directory size for {directory}: {str(e)}")
        
        return total_size
    
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        if size_bytes == 0:
            return "0B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f}{size_names[i]}"
    
    def is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary."""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except Exception:
            return False
    
    def get_file_hash(self, file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """Get file hash using specified algorithm."""
        import hashlib
        
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            return None 