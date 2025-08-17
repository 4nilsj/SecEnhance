#!/usr/bin/env python3
"""
BCheck Loader for Burp Suite
Dynamically loads and manages BChecks for web application security testing
"""

import os
import sys
import importlib
import inspect
from typing import Dict, List, Any, Optional, Type
from pathlib import Path
import logging

class BCheckLoader:
    """
    Dynamic BCheck loader for Burp Suite extensions
    """
    
    def __init__(self, bchecks_dir: str = "bchecks"):
        self.bchecks_dir = Path(bchecks_dir)
        self.loaded_bchecks: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        
    def discover_bchecks(self) -> List[str]:
        """Discover all available BCheck files"""
        bcheck_files = []
        
        if not self.bchecks_dir.exists():
            self.logger.warning(f"BChecks directory {self.bchecks_dir} does not exist")
            return bcheck_files
        
        # Discover BChecks in subdirectories (web, api)
        for subdir in ['web', 'api']:
            subdir_path = self.bchecks_dir / subdir
            if subdir_path.exists():
                for file_path in subdir_path.glob("*.py"):
                    if file_path.name.startswith("__"):
                        continue
                    bcheck_files.append(f"{subdir}.{file_path.stem}")
        
        # Discover BChecks in root directory
        for file_path in self.bchecks_dir.glob("*.py"):
            if file_path.name.startswith("__"):
                continue
            if file_path.name == "bcheck_loader.py":
                continue
            bcheck_files.append(file_path.stem)
            
        self.logger.info(f"Discovered {len(bcheck_files)} BCheck files: {bcheck_files}")
        return bcheck_files
    
    def load_bcheck(self, bcheck_name: str) -> Optional[Any]:
        """Load a specific BCheck module"""
        try:
            # Add bchecks directory to Python path
            if str(self.bchecks_dir.parent) not in sys.path:
                sys.path.insert(0, str(self.bchecks_dir.parent))
            
            # Import the BCheck module (handle subdirectory structure)
            if '.' in bcheck_name:
                # Subdirectory BCheck (e.g., web.sql_injection_bcheck)
                module = importlib.import_module(f"bchecks.{bcheck_name}")
            else:
                # Root directory BCheck
                module = importlib.import_module(f"bchecks.{bcheck_name}")
            
            # Find BurpExtender class in the module
            burp_extender_class = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    name == "BurpExtender" and 
                    hasattr(obj, 'registerExtenderCallbacks')):
                    burp_extender_class = obj
                    break
            
            if burp_extender_class:
                self.loaded_bchecks[bcheck_name] = {
                    'module': module,
                    'class': burp_extender_class,
                    'name': bcheck_name
                }
                self.logger.info(f"Successfully loaded BCheck: {bcheck_name}")
                return self.loaded_bchecks[bcheck_name]
            else:
                self.logger.error(f"No BurpExtender class found in {bcheck_name}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to load BCheck {bcheck_name}: {e}")
            return None
    
    def load_all_bchecks(self) -> Dict[str, Any]:
        """Load all discovered BChecks"""
        bcheck_files = self.discover_bchecks()
        
        for bcheck_name in bcheck_files:
            self.load_bcheck(bcheck_name)
            
        self.logger.info(f"Loaded {len(self.loaded_bchecks)} BChecks")
        return self.loaded_bchecks
    
    def get_bcheck_info(self, bcheck_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a loaded BCheck"""
        if bcheck_name not in self.loaded_bchecks:
            return None
            
        bcheck = self.loaded_bchecks[bcheck_name]
        module = bcheck['module']
        
        info = {
            'name': bcheck_name,
            'module': module.__name__,
            'file': getattr(module, '__file__', 'Unknown'),
            'doc': getattr(module, '__doc__', 'No documentation'),
            'version': getattr(module, '__version__', 'Unknown'),
            'author': getattr(module, '__author__', 'Unknown')
        }
        
        return info
    
    def get_all_bcheck_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all loaded BChecks"""
        info = {}
        for bcheck_name in self.loaded_bchecks:
            info[bcheck_name] = self.get_bcheck_info(bcheck_name)
        return info
    
    def create_bcheck_instance(self, bcheck_name: str, callbacks: Any) -> Optional[Any]:
        """Create an instance of a BCheck for use with Burp Suite"""
        if bcheck_name not in self.loaded_bchecks:
            self.logger.error(f"BCheck {bcheck_name} not loaded")
            return None
            
        try:
            bcheck_class = self.loaded_bchecks[bcheck_name]['class']
            instance = bcheck_class()
            instance.registerExtenderCallbacks(callbacks)
            self.logger.info(f"Created instance of BCheck: {bcheck_name}")
            return instance
        except Exception as e:
            self.logger.error(f"Failed to create instance of BCheck {bcheck_name}: {e}")
            return None
    
    def validate_bcheck(self, bcheck_name: str) -> Dict[str, Any]:
        """Validate a BCheck for proper structure and requirements"""
        if bcheck_name not in self.loaded_bchecks:
            return {'valid': False, 'error': 'BCheck not loaded'}
            
        bcheck = self.loaded_bchecks[bcheck_name]
        module = bcheck['module']
        bcheck_class = bcheck['class']
        
        validation = {
            'valid': True,
            'name': bcheck_name,
            'checks': []
        }
        
        # Check for required imports
        required_imports = ['burp', 'java.net']
        for imp in required_imports:
            try:
                __import__(imp)
                validation['checks'].append(f"✓ Import {imp} available")
            except ImportError:
                validation['checks'].append(f"✗ Import {imp} not available (expected in Burp environment)")
        
        # Check for required methods
        required_methods = ['registerExtenderCallbacks']
        for method in required_methods:
            if hasattr(bcheck_class, method):
                validation['checks'].append(f"✓ Method {method} found")
            else:
                validation['checks'].append(f"✗ Method {method} missing")
                validation['valid'] = False
        
        # Check for documentation
        if module.__doc__:
            validation['checks'].append("✓ Module documentation present")
        else:
            validation['checks'].append("⚠ Module documentation missing")
        
        return validation
    
    def get_bcheck_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded BChecks"""
        total_discovered = len(self.discover_bchecks())
        total_loaded = len(self.loaded_bchecks)
        
        stats = {
            'total_discovered': total_discovered,
            'total_loaded': total_loaded,
            'load_success_rate': (total_loaded / total_discovered * 100) if total_discovered > 0 else 0,
            'loaded_bchecks': list(self.loaded_bchecks.keys()),
            'validation_results': {}
        }
        
        # Validate all loaded BChecks
        for bcheck_name in self.loaded_bchecks:
            stats['validation_results'][bcheck_name] = self.validate_bcheck(bcheck_name)
        
        return stats


def main():
    """Test the BCheck loader"""
    print("🔍 BCheck Loader Test")
    print("=" * 50)
    
    loader = BCheckLoader()
    
    # Discover and load BChecks
    print("\n📁 Discovering BChecks...")
    discovered = loader.discover_bchecks()
    print(f"Found {len(discovered)} BCheck files: {discovered}")
    
    print("\n📦 Loading BChecks...")
    loaded = loader.load_all_bchecks()
    print(f"Loaded {len(loaded)} BChecks")
    
    # Get statistics
    print("\n📊 BCheck Statistics:")
    stats = loader.get_bcheck_statistics()
    print(f"  • Total discovered: {stats['total_discovered']}")
    print(f"  • Total loaded: {stats['total_loaded']}")
    print(f"  • Load success rate: {stats['load_success_rate']:.1f}%")
    
    # Show validation results
    print("\n✅ Validation Results:")
    for bcheck_name, validation in stats['validation_results'].items():
        print(f"\n  {bcheck_name}:")
        for check in validation['checks']:
            print(f"    {check}")
    
    # Show BCheck information
    print("\n📋 BCheck Information:")
    for bcheck_name in loaded:
        info = loader.get_bcheck_info(bcheck_name)
        if info:
            print(f"\n  {bcheck_name}:")
            print(f"    • Module: {info['module']}")
            print(f"    • Version: {info['version']}")
            print(f"    • Author: {info['author']}")
            print(f"    • File: {info['file']}")


if __name__ == "__main__":
    main()
