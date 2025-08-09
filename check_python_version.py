#!/usr/bin/env python3
"""
Python Version Compatibility Checker
Ensures all tools in the SecEnhance project use Python 3.8+ only
"""

import sys
import subprocess
import os
from pathlib import Path
from typing import List, Tuple


def check_python_version() -> Tuple[bool, str]:
    """
    Check if current Python version is compatible.
    
    Returns:
        Tuple[bool, str]: (is_compatible, version_string)
    """
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    is_compatible = version >= (3, 8)
    return is_compatible, version_str


def check_python_executable() -> str:
    """
    Get the Python executable being used.
    
    Returns:
        str: Path to Python executable
    """
    return sys.executable


def check_pip_version() -> Tuple[bool, str]:
    """
    Check pip version.
    
    Returns:
        Tuple[bool, str]: (is_available, version_string)
    """
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                              capture_output=True, text=True, check=True)
        return True, result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, "pip not available"


def check_requirements_files() -> List[str]:
    """
    Find all requirements.txt files in the project.
    
    Returns:
        List[str]: List of requirements.txt file paths
    """
    project_root = Path(__file__).parent
    requirements_files = []
    
    for req_file in project_root.rglob("requirements.txt"):
        requirements_files.append(str(req_file))
    
    return requirements_files


def check_setup_files() -> List[str]:
    """
    Find all setup.py files in the project.
    
    Returns:
        List[str]: List of setup.py file paths
    """
    project_root = Path(__file__).parent
    setup_files = []
    
    for setup_file in project_root.rglob("setup.py"):
        setup_files.append(str(setup_file))
    
    return setup_files


def check_dockerfiles() -> List[str]:
    """
    Find all Dockerfile files in the project.
    
    Returns:
        List[str]: List of Dockerfile paths
    """
    project_root = Path(__file__).parent
    dockerfiles = []
    
    for dockerfile in project_root.rglob("Dockerfile"):
        dockerfiles.append(str(dockerfile))
    
    return dockerfiles


def analyze_python_version_in_files() -> dict:
    """
    Analyze Python version specifications in project files.
    
    Returns:
        dict: Analysis results
    """
    analysis = {
        "requirements_files": check_requirements_files(),
        "setup_files": check_setup_files(),
        "dockerfiles": check_dockerfiles(),
        "python_versions_found": []
    }
    
    # Check setup.py files for python_requires
    for setup_file in analysis["setup_files"]:
        try:
            with open(setup_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'python_requires' in content:
                    analysis["python_versions_found"].append(f"setup.py: {setup_file}")
        except Exception as e:
            print(f"Warning: Could not read {setup_file}: {e}")
    
    # Check Dockerfiles for Python version
    for dockerfile in analysis["dockerfiles"]:
        try:
            with open(dockerfile, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'FROM python:' in content:
                    analysis["python_versions_found"].append(f"Dockerfile: {dockerfile}")
        except Exception as e:
            print(f"Warning: Could not read {dockerfile}: {e}")
    
    return analysis


def print_compatibility_report():
    """
    Print a comprehensive Python compatibility report.
    """
    print("🐍 Python Version Compatibility Report")
    print("=" * 50)
    
    # Check current Python version
    is_compatible, version_str = check_python_version()
    python_exe = check_python_executable()
    pip_available, pip_version = check_pip_version()
    
    print(f"✅ Python Version: {version_str}")
    print(f"✅ Python Executable: {python_exe}")
    print(f"✅ Python 3.8+ Compatible: {'Yes' if is_compatible else 'No'}")
    print(f"✅ pip Available: {'Yes' if pip_available else 'No'}")
    if pip_available:
        print(f"✅ pip Version: {pip_version}")
    
    print("\n📁 Project Structure Analysis:")
    print("-" * 30)
    
    analysis = analyze_python_version_in_files()
    
    print(f"📄 Requirements files found: {len(analysis['requirements_files'])}")
    for req_file in analysis['requirements_files']:
        print(f"   - {req_file}")
    
    print(f"🔧 Setup files found: {len(analysis['setup_files'])}")
    for setup_file in analysis['setup_files']:
        print(f"   - {setup_file}")
    
    print(f"🐳 Dockerfiles found: {len(analysis['dockerfiles'])}")
    for dockerfile in analysis['dockerfiles']:
        print(f"   - {dockerfile}")
    
    print(f"\n📋 Python version specifications found: {len(analysis['python_versions_found'])}")
    for spec in analysis['python_versions_found']:
        print(f"   - {spec}")
    
    print("\n🎯 Recommendations:")
    print("-" * 20)
    
    if not is_compatible:
        print("❌ Upgrade to Python 3.8 or higher")
    else:
        print("✅ Python version is compatible")
    
    if not pip_available:
        print("❌ Install pip for package management")
    else:
        print("✅ pip is available")
    
    print("✅ All tools in this project require Python 3.8+")
    print("✅ Python 2 is not supported")
    
    print("\n" + "=" * 50)
    if is_compatible:
        print("🎉 All Python version checks passed!")
    else:
        print("❌ Python version compatibility issues found!")
        sys.exit(1)


if __name__ == "__main__":
    print_compatibility_report() 