#!/usr/bin/env python3
"""
Health check script for API Security Scanner container.
This script performs basic health checks to ensure the container is functioning properly.
"""

import sys
import os
import importlib
from pathlib import Path


def check_python_imports():
    """Check if all required Python modules can be imported."""
    required_modules = [
        'click',
        'requests',
        'yaml',
        'jinja2',
        'colorama',
        'tqdm',
        'dotenv'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            importlib.import_module(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"ERROR: Missing required modules: {', '.join(missing_modules)}")
        return False
    
    return True


def check_directories():
    """Check if required directories exist and are writable."""
    required_dirs = [
        '/app/data',
        '/app/logs',
        '/app/reports',
        '/app/templates'
    ]
    
    for dir_path in required_dirs:
        path = Path(dir_path)
        if not path.exists():
            print(f"ERROR: Directory {dir_path} does not exist")
            return False
        
        if not os.access(dir_path, os.W_OK):
            print(f"ERROR: Directory {dir_path} is not writable")
            return False
    
    return True


def check_application():
    """Check if the main application can be imported."""
    try:
        # Add the app directory to Python path
        sys.path.insert(0, '/app')
        
        # Try to import the main CLI module
        from api_security_scanner.cli.main import cli
        return True
    except ImportError as e:
        print(f"ERROR: Cannot import main application: {e}")
        return False
    except Exception as e:
        print(f"ERROR: Application check failed: {e}")
        return False


def check_environment():
    """Check if required environment variables are set."""
    required_env_vars = [
        'SCAN_DB_PATH',
        'LOG_DIR',
        'REPORTS_DIR'
    ]
    
    missing_vars = []
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"WARNING: Missing environment variables: {', '.join(missing_vars)}")
        # Don't fail on missing env vars as they have defaults
    
    return True


def main():
    """Run all health checks."""
    print("Running API Security Scanner health checks...")
    
    checks = [
        ("Python imports", check_python_imports),
        ("Directories", check_directories),
        ("Application", check_application),
        ("Environment", check_environment),
    ]
    
    failed_checks = []
    
    for check_name, check_func in checks:
        print(f"Checking {check_name}...")
        try:
            if check_func():
                print(f"✓ {check_name} check passed")
            else:
                print(f"✗ {check_name} check failed")
                failed_checks.append(check_name)
        except Exception as e:
            print(f"✗ {check_name} check failed with exception: {e}")
            failed_checks.append(check_name)
    
    if failed_checks:
        print(f"\nHealth check failed. Failed checks: {', '.join(failed_checks)}")
        sys.exit(1)
    else:
        print("\n✓ All health checks passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
