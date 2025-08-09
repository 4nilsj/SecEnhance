#!/usr/bin/env python3
"""
Jira Tool Web Interface Launcher - Python 3 Specific
Ensures all web modules run with Python 3.8+
"""

import os
import sys
import subprocess
from pathlib import Path


def check_python_version():
    """Check if running on Python 3.8 or higher."""
    if sys.version_info < (3, 8):
        print("❌ Error: This application requires Python 3.8 or higher!")
        print(f"Current version: {sys.version}")
        print("Please upgrade your Python installation.")
        sys.exit(1)
    else:
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected")


def check_python_executable():
    """Check if python3 is available."""
    try:
        result = subprocess.run(["python3", "--version"], 
                              capture_output=True, text=True, check=True)
        print(f"✅ python3 found: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ python3 not found in PATH")
        return False


def main():
    """Launch the Jira Tool web interface with Python 3."""
    
    print("🔧 Jira Tool Web Interface Launcher - Python 3")
    print("=" * 50)
    
    # Check Python version
    check_python_version()
    
    # Check if we're in the right directory
    current_dir = Path.cwd()
    if not (current_dir / "web" / "app.py").exists():
        print("❌ Error: Please run this script from the jira_tool directory")
        print(f"Current directory: {current_dir}")
        print("Expected to find: web/app.py")
        sys.exit(1)
    
    # Check if python3 is available
    python3_available = check_python_executable()
    
    # Check if streamlit is installed
    try:
        import streamlit
        print("✅ Streamlit is installed")
    except ImportError:
        print("❌ Streamlit is not installed")
        print("Installing required dependencies...")
        subprocess.run([sys.executable, "-m", "pip", "install", "streamlit", "pandas", "requests"], check=True)
        print("✅ Dependencies installed")
    
    # Check if requirements are met
    try:
        import pandas
        import requests
        print("✅ All required packages are available")
    except ImportError as e:
        print(f"❌ Missing package: {e}")
        print("Installing requirements...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        print("✅ Requirements installed")
    
    # Launch the web interface
    print("\n🚀 Launching Jira Tool Web Interface with Python 3...")
    print("The interface will open in your browser at: http://localhost:8501")
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        # Use python3 if available, otherwise use sys.executable
        python_cmd = "python3" if python3_available else sys.executable
        
        # Run streamlit with Python 3
        subprocess.run([
            python_cmd, "-m", "streamlit", "run", "web/app.py",
            "--server.port", "8501",
            "--server.address", "localhost",
            "--browser.gatherUsageStats", "false"
        ])
    except KeyboardInterrupt:
        print("\n👋 Web interface stopped")
    except Exception as e:
        print(f"❌ Error launching web interface: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 