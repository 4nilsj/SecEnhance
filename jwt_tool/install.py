#!/usr/bin/env python3
"""
Installation Script for JWT Security Testing Tool
This script checks dependencies and installs missing packages.
"""

import sys
import subprocess
import os
import platform
from pathlib import Path

def print_header(message):
    """Print a formatted header."""
    print("=" * 60)
    print(f"🔒 {message}")
    print("=" * 60)

def print_success(message):
    """Print a success message."""
    print(f"✅ {message}")

def print_error(message):
    """Print an error message."""
    print(f"❌ {message}")

def print_warning(message):
    """Print a warning message."""
    print(f"⚠️ {message}")

def print_info(message):
    """Print an info message."""
    print(f"ℹ️ {message}")

def check_python_version():
    """Check if Python version is compatible."""
    print_info("Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print_error(f"Python 3.7+ required. Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print_success(f"Python version: {version.major}.{version.minor}.{version.micro}")
    return True

def check_pip():
    """Check if pip is available."""
    print_info("Checking pip availability...")
    
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      capture_output=True, check=True)
        print_success("pip is available")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error("pip is not available")
        return False

def install_requirements():
    """Install required packages from requirements.txt."""
    print_info("Installing required packages...")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    if not requirements_file.exists():
        print_error("requirements.txt not found")
        return False
    
    try:
        # Upgrade pip first
        print_info("Upgrading pip...")
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                      capture_output=True, check=True)
        
        # Install requirements
        print_info("Installing packages from requirements.txt...")
        result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(requirements_file)], 
                               capture_output=True, text=True)
        
        if result.returncode == 0:
            print_success("All packages installed successfully")
            return True
        else:
            print_error(f"Failed to install packages: {result.stderr}")
            return False
            
    except Exception as e:
        print_error(f"Error installing packages: {str(e)}")
        return False

def check_dependencies():
    """Check if all required packages are installed."""
    print_info("Checking installed packages...")
    
    required_packages = [
        ("PyJWT", "jwt"),
        ("cryptography", "cryptography"),
        ("requests", "requests"),
        ("tqdm", "tqdm"),
        ("colorama", "colorama")
    ]
    
    missing_packages = []
    
    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
            print_success(f"{package_name} is installed")
        except ImportError:
            print_warning(f"{package_name} is missing")
            missing_packages.append(package_name)
    
    if missing_packages:
        print_error(f"Missing packages: {', '.join(missing_packages)}")
        return False
    
    print_success("All required packages are installed")
    return True

def create_directories():
    """Create necessary directories."""
    print_info("Creating necessary directories...")
    
    directories = ["reports", "logs", "examples"]
    
    for directory in directories:
        dir_path = Path(__file__).parent / directory
        dir_path.mkdir(exist_ok=True)
        print_success(f"Created directory: {directory}")

def test_installation():
    """Test the installation by running a simple test."""
    print_info("Testing installation...")
    
    try:
        # Test importing the main module
        sys.path.append(str(Path(__file__).parent / "src"))
        from jwt_security_tester import JWTSecurityTester
        
        # Create a test instance
        tester = JWTSecurityTester(debug=False)
        
        # Test with a sample token
        sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        
        # Run a simple test
        results = tester.analyze_token_structure(sample_token)
        
        if "error" not in results:
            print_success("Installation test passed")
            return True
        else:
            print_error(f"Installation test failed: {results['error']}")
            return False
            
    except Exception as e:
        print_error(f"Installation test failed: {str(e)}")
        return False

def main():
    """Main installation function."""
    print_header("JWT Security Testing Tool - Installation")
    
    print_info(f"Platform: {platform.system()} {platform.release()}")
    print_info(f"Python executable: {sys.executable}")
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check pip
    if not check_pip():
        print_error("Please install pip first")
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        print_error("Failed to install required packages")
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        print_error("Some dependencies are missing")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Test installation
    if not test_installation():
        print_error("Installation test failed")
        sys.exit(1)
    
    print_header("Installation Completed Successfully!")
    
    print_info("You can now use the JWT Security Testing Tool:")
    print("  python src/jwt_security_tester.py --help")
    print("  python src/jwt_security_tester.py --token 'your.jwt.token'")
    print("  python examples/quick_start.py")
    
    print_info("For more information, see the README.md file")

if __name__ == "__main__":
    main() 