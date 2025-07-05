#!/usr/bin/env python3
"""
Quick Start Script for SAST Scanner
Helps users get started quickly with the AI-enabled SAST scanner.
"""

import sys
import os
import subprocess
from pathlib import Path

def print_banner():
    """Print the SAST Scanner banner."""
    print("=" * 60)
    print("🔒 SAST Scanner - Quick Start")
    print("=" * 60)
    print("AI-enabled Static Application Security Testing tool")
    print("=" * 60)

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required.")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_dependencies():
    """Check if required dependencies are installed."""
    print("\n📦 Checking dependencies...")
    
    required_packages = [
        "click", "rich", "jinja2", "markdown", "ast", "pathlib"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} (missing)")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    return True

def install_dependencies():
    """Install required dependencies."""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def create_example_files():
    """Create example files for testing."""
    print("\n📝 Creating example files...")
    
    examples_dir = Path("examples")
    examples_dir.mkdir(exist_ok=True)
    
    # Create a simple vulnerable Python file
    vulnerable_py = examples_dir / "simple_vulnerable.py"
    if not vulnerable_py.exists():
        vulnerable_py.write_text('''
# Simple vulnerable Python file for testing
import os
import sqlite3

# VULNERABILITY: Hardcoded credentials
PASSWORD = "admin123"

# VULNERABILITY: SQL injection
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
    cursor.execute(query)
    return cursor.fetchone()

# VULNERABILITY: Command injection
def run_command(command):
    os.system(command)  # Command injection

# VULNERABILITY: Debug code
print("Debug: This should not be in production")

if __name__ == "__main__":
    user_id = input("Enter user ID: ")
    user = get_user(user_id)
    print(f"User: {user}")
''')
        print("✅ Created simple_vulnerable.py")
    
    # Create a simple vulnerable JavaScript file
    vulnerable_js = examples_dir / "simple_vulnerable.js"
    if not vulnerable_js.exists():
        vulnerable_js.write_text('''
// Simple vulnerable JavaScript file for testing
const express = require('express');
const { exec } = require('child_process');

// VULNERABILITY: Hardcoded credentials
const API_KEY = "sk-1234567890abcdef";

// VULNERABILITY: Command injection
function executeCommand(command) {
    exec(command, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// VULNERABILITY: XSS
function renderUser(username) {
    const template = `<h1>Welcome ${username}!</h1>`;  // XSS
    document.getElementById('content').innerHTML = template;
}

// VULNERABILITY: Debug code
console.log('Debug: This should not be in production');

module.exports = { executeCommand, renderUser };
''')
        print("✅ Created simple_vulnerable.js")

def run_test_scan():
    """Run a test scan on example files."""
    print("\n🔍 Running test scan...")
    
    try:
        # Run scan on examples directory
        result = subprocess.run([
            sys.executable, "sast_scanner_cli.py", "scan", "directory", "examples",
            "--output", "html", "--output-file", "quick_start_report.html"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Test scan completed successfully")
            print("📄 Report generated: reports/quick_start_report.html")
        else:
            print(f"⚠️  Test scan completed with warnings: {result.stderr}")
        
        return True
    except Exception as e:
        print(f"❌ Error running test scan: {e}")
        return False

def show_next_steps():
    """Show next steps for the user."""
    print("\n" + "=" * 60)
    print("🎉 Quick Start Complete!")
    print("=" * 60)
    
    print("\n📋 Next Steps:")
    print("1. 📄 View the generated report: reports/quick_start_report.html")
    print("2. 🔍 Scan your own code:")
    print("   python sast_scanner_cli.py scan file your_file.py")
    print("   python sast_scanner_cli.py scan directory your_project/")
    print("3. 📚 Read the documentation: README.md")
    print("4. 🧪 Run the test suite: python test_scanner.py")
    
    print("\n🚀 Common Commands:")
    print("  # Scan a single file")
    print("  python sast_scanner_cli.py scan file app.py")
    print("")
    print("  # Scan a directory")
    print("  python sast_scanner_cli.py scan directory ./src")
    print("")
    print("  # Generate JSON report")
    print("  python sast_scanner_cli.py scan file app.py --output json")
    print("")
    print("  # Enable debug mode")
    print("  python sast_scanner_cli.py scan file app.py --debug")
    
    print("\n📖 For more information:")
    print("  - Documentation: README.md")
    print("  - Examples: examples/")
    print("  - Issues: GitHub Issues")

def main():
    """Main quick start function."""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Check if we're in the right directory
    if not Path("sast_scanner_cli.py").exists():
        print("❌ Error: sast_scanner_cli.py not found.")
        print("Please run this script from the sast_scanner directory.")
        return 1
    
    # Check dependencies
    if not check_dependencies():
        print("\n🔧 Installing dependencies...")
        if not install_dependencies():
            return 1
    
    # Create example files
    create_example_files()
    
    # Run test scan
    run_test_scan()
    
    # Show next steps
    show_next_steps()
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 