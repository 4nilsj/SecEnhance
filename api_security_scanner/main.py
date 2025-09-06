#!/usr/bin/env python3
"""
API Security Scanner - Main Entry Point

A comprehensive command-line tool for automated API security scanning
with extensibility for custom vulnerability checks and detailed reporting.
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_dir))

# Add utils directory to Python path
utils_dir = Path(__file__).parent / 'utils'
sys.path.insert(0, str(utils_dir))

# Add plugins directory to Python path
plugins_dir = Path(__file__).parent / 'plugins'
sys.path.insert(0, str(plugins_dir))

from src.cli import cli

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
