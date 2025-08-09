#!/usr/bin/env python3
"""
Python Version Check Utility
Ensures all tools use Python 3.8+ only
"""

import sys
from typing import Optional


def check_python_version(min_version: tuple = (3, 8)) -> bool:
    """
    Check if the current Python version meets the minimum requirement.
    
    Args:
        min_version: Minimum Python version as (major, minor)
        
    Returns:
        bool: True if version is compatible, False otherwise
    """
    current_version = sys.version_info[:2]
    return current_version >= min_version


def get_python_version_string() -> str:
    """
    Get the current Python version as a string.
    
    Returns:
        str: Python version string (e.g., "3.11.0")
    """
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def require_python_version(min_version: tuple = (3, 8), tool_name: str = "Tool") -> None:
    """
    Require a minimum Python version and exit if not met.
    
    Args:
        min_version: Minimum Python version as (major, minor)
        tool_name: Name of the tool for error message
    """
    if not check_python_version(min_version):
        print(f"❌ Error: {tool_name} requires Python {min_version[0]}.{min_version[1]} or higher.")
        print(f"Current version: {get_python_version_string()}")
        print("Please upgrade your Python installation.")
        sys.exit(1)


def print_version_info(tool_name: str = "Tool") -> None:
    """
    Print version information for the current Python installation.
    
    Args:
        tool_name: Name of the tool
    """
    version_str = get_python_version_string()
    print(f"✅ {tool_name} running on Python {version_str}")
    print(f"✅ Python 3.8+ compatibility: {'Yes' if check_python_version() else 'No'}")


if __name__ == "__main__":
    # Test the version check
    print_version_info("Python Version Check Utility")
    require_python_version((3, 8), "Python Version Check Utility")
    print("✅ All version checks passed!") 