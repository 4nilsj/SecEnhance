#!/usr/bin/env python3
"""
Test script to verify API Security Scanner installation.
"""

import sys
import importlib
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported."""
    print("Testing imports...")
    
    try:
        import click
        print("✓ click imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import click: {e}")
        return False
    
    try:
        import requests
        print("✓ requests imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import requests: {e}")
        return False
    
    try:
        import yaml
        print("✓ pyyaml imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import pyyaml: {e}")
        return False
    
    try:
        import jinja2
        print("✓ jinja2 imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import jinja2: {e}")
        return False
    
    return True

def test_project_structure():
    """Test that project structure is correct."""
    print("\nTesting project structure...")
    
    required_dirs = ['src', 'utils', 'plugins', 'examples', 'logs', 'reports']
    required_files = ['main.py', 'requirements.txt', 'README.md']
    
    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if dir_path.exists() and dir_path.is_dir():
            print(f"✓ Directory {dir_name} exists")
        else:
            print(f"✗ Directory {dir_name} missing")
            return False
    
    for file_name in required_files:
        file_path = Path(file_name)
        if file_path.exists() and file_path.is_file():
            print(f"✓ File {file_name} exists")
        else:
            print(f"✗ File {file_name} missing")
            return False
    
    return True

def test_core_modules():
    """Test that core modules can be imported."""
    print("\nTesting core modules...")
    
    # Add src and utils to path
    sys.path.insert(0, str(Path('src')))
    sys.path.insert(0, str(Path('utils')))
    sys.path.insert(0, str(Path('plugins')))
    
    try:
        from utils.logger import get_logger
        print("✓ Logger module imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import logger: {e}")
        return False
    
    try:
        from utils.input_parsers import parse_input
        print("✓ Input parsers imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import input parsers: {e}")
        return False
    
    try:
        from utils.auth_handler import create_auth_handler
        print("✓ Auth handler imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import auth handler: {e}")
        return False
    
    try:
        from src.db_manager import DatabaseManager
        print("✓ Database manager imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import database manager: {e}")
        return False
    
    try:
        from src.scanner_plugins import PluginManager
        print("✓ Plugin system imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import plugin system: {e}")
        return False
    
    try:
        from src.report_generator import ReportGenerator
        print("✓ Report generator imported successfully")
    except ImportError as e:
        print(f"✗ Failed to import report generator: {e}")
        return False
    
    return True

def test_plugins():
    """Test that plugins can be loaded."""
    print("\nTesting plugins...")
    
    try:
        from src.scanner_plugins import PluginManager
        plugin_manager = PluginManager()
        plugins = plugin_manager.get_plugin_list()
        
        if plugins:
            print(f"✓ Loaded {len(plugins)} plugins:")
            for plugin in plugins:
                print(f"  - {plugin['name']} v{plugin['version']}")
        else:
            print("⚠ No plugins loaded (this is normal if no plugins are present)")
        
        return True
    except Exception as e:
        print(f"✗ Failed to load plugins: {e}")
        return False

def main():
    """Run all tests."""
    print("API Security Scanner - Installation Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_project_structure,
        test_core_modules,
        test_plugins
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! Installation is successful.")
        return 0
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
