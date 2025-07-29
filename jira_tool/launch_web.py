#!/usr/bin/env python3
"""
Jira Tool Web Interface Launcher
Simple script to launch the web interface with proper configuration.
"""

import os
import sys
import subprocess
from pathlib import Path


def main():
    """Launch the Jira Tool web interface."""
    
    print("🔧 Jira Tool Web Interface Launcher")
    print("=" * 40)
    
    # Check if we're in the right directory
    current_dir = Path.cwd()
    if not (current_dir / "web" / "app.py").exists():
        print("❌ Error: Please run this script from the jira_tool directory")
        print(f"Current directory: {current_dir}")
        print("Expected to find: web/app.py")
        sys.exit(1)
    
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
    print("\n🚀 Launching Jira Tool Web Interface...")
    print("The interface will open in your browser at: http://localhost:8501")
    print("Press Ctrl+C to stop the server")
    print("=" * 40)
    
    try:
        # Run streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", "web/app.py",
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