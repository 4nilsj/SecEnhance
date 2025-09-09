#!/usr/bin/env python3
"""
API Security Scanner - Main Entry Point

A comprehensive command-line tool for automated API security scanning
with extensibility for custom vulnerability checks and detailed reporting.
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from api_security_scanner.cli import cli

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
