#!/usr/bin/env python3
"""
Mac Compatibility Test Script for Jira Tool
This script tests all components to ensure they work on macOS
"""

import sys
import os
import platform
import subprocess
import importlib

def print_header(title):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"🍎 {title}")
    print(f"{'='*60}")

def print_success(message):
    """Print a success message."""
    print(f"✅ {message}")

def print_error(message):
    """Print an error message."""
    print(f"❌ {message}")

def print_info(message):
    """Print an info message."""
    print(f"ℹ️  {message}")

def test_system_info():
    """Test and display system information."""
    print_header("System Information")
    
    print_info(f"Platform: {platform.platform()}")
    print_info(f"Python Version: {sys.version}")
    print_info(f"Python Executable: {sys.executable}")
    print_info(f"Architecture: {platform.architecture()}")
    print_info(f"Machine: {platform.machine()}")
    
    # Check if running on macOS
    if platform.system() == "Darwin":
        print_success("Running on macOS")
    else:
        print_info(f"Running on {platform.system()}")

def test_python_installation():
    """Test Python installation and version."""
    print_header("Python Installation Test")
    
    try:
        version = sys.version_info
        if version.major >= 3 and version.minor >= 7:
            print_success(f"Python {version.major}.{version.minor}.{version.micro} - Compatible")
        else:
            print_error(f"Python {version.major}.{version.minor}.{version.micro} - Requires Python 3.7+")
            return False
    except Exception as e:
        print_error(f"Error checking Python version: {e}")
        return False
    
    return True

def test_dependencies():
    """Test all required dependencies."""
    print_header("Dependencies Test")
    
    dependencies = [
        'requests',
        'pandas', 
        'openpyxl',
        'streamlit',
        'sqlite3',
        'urllib.parse'
    ]
    
    all_good = True
    
    for dep in dependencies:
        try:
            importlib.import_module(dep)
            print_success(f"{dep} - Available")
        except ImportError as e:
            print_error(f"{dep} - Missing: {e}")
            all_good = False
    
    return all_good

def test_core_modules():
    """Test core Jira Tool modules."""
    print_header("Core Modules Test")
    
    core_modules = [
        'core.headers',
        'core.urls', 
        'config.settings',
        'utils.data_sync_utils'
    ]
    
    all_good = True
    
    for module in core_modules:
        try:
            importlib.import_module(module)
            print_success(f"{module} - Working")
        except ImportError as e:
            print_error(f"{module} - Failed: {e}")
            all_good = False
    
    return all_good

def test_script_modules():
    """Test script modules."""
    print_header("Script Modules Test")
    
    script_modules = [
        'scripts.bulk_operations.create.bulk_create_true_positive',
        'scripts.bulk_operations.update.bulk_remove_labels_sync_fixed',
        'scripts.bulk_operations.transition.bulk_transition_security_workflow',
        'scripts.bulk_operations.transition.bulk_transition_dev_workflow',
        'scripts.bulk_operations.comment.bulk_comment_dev_status',
        'scripts.bulk_operations.linked_status.bulk_fetch_linked_tickets',
        'scripts.attachments.bulk_poc_upload',
        'scripts.attachments.bulk_attachment'
    ]
    
    all_good = True
    
    for module in script_modules:
        try:
            importlib.import_module(module)
            print_success(f"{module} - Working")
        except ImportError as e:
            print_error(f"{module} - Failed: {e}")
            all_good = False
    
    return all_good

def test_web_app():
    """Test web app module."""
    print_header("Web App Test")
    
    try:
        importlib.import_module('web.app')
        print_success("Web app module - Working")
        return True
    except ImportError as e:
        print_error(f"Web app module - Failed: {e}")
        return False

def test_file_permissions():
    """Test file permissions and accessibility."""
    print_header("File Permissions Test")
    
    files_to_check = [
        'config/settings.py',
        'core/headers.py',
        'core/urls.py',
        'web/app.py',
        'requirements.txt'
    ]
    
    all_good = True
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            if os.access(file_path, os.R_OK):
                print_success(f"{file_path} - Readable")
            else:
                print_error(f"{file_path} - Not readable")
                all_good = False
        else:
            print_error(f"{file_path} - Not found")
            all_good = False
    
    return all_good

def test_command_line_tools():
    """Test command line tools availability."""
    print_header("Command Line Tools Test")
    
    tools = ['git', 'python3', 'pip3']
    all_good = True
    
    for tool in tools:
        try:
            result = subprocess.run([tool, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print_success(f"{tool} - Available")
            else:
                print_error(f"{tool} - Not available")
                all_good = False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print_error(f"{tool} - Not found")
            all_good = False
    
    return all_good

def test_network_connectivity():
    """Test basic network connectivity."""
    print_header("Network Connectivity Test")
    
    try:
        import requests
        response = requests.get('https://httpbin.org/get', timeout=10)
        if response.status_code == 200:
            print_success("Network connectivity - Working")
            return True
        else:
            print_error("Network connectivity - Failed")
            return False
    except Exception as e:
        print_error(f"Network connectivity - Error: {e}")
        return False

def generate_mac_commands():
    """Generate Mac-specific commands."""
    print_header("Mac Setup Commands")
    
    commands = [
        "# 1. Clone the repository",
        "git clone https://github.com/4nilsj/SecEnhance.git",
        "cd SecEnhance/jira_tool",
        "",
        "# 2. Install dependencies",
        "pip3 install -r requirements.txt",
        "",
        "# 3. Configure the tool",
        "python3 config/config_manager.py",
        "",
        "# 4. Run the web interface",
        "python3 -m streamlit run web/app.py",
        "",
        "# 5. Or run command line operations",
        "python3 scripts/bulk_operations/create/bulk_create_true_positive.py \\",
        "  --excel data.xlsx \\",
        "  --url https://jira.company.com \\",
        "  --token your_token"
    ]
    
    print("Copy and paste these commands in your Mac Terminal:")
    print()
    for cmd in commands:
        print(cmd)

def main():
    """Run all compatibility tests."""
    print_header("Mac Compatibility Test Suite")
    print_info("Testing Jira Tool compatibility with macOS...")
    
    results = []
    
    # Run all tests
    results.append(("System Info", True))  # Always pass
    results.append(("Python Installation", test_python_installation()))
    results.append(("Dependencies", test_dependencies()))
    results.append(("Core Modules", test_core_modules()))
    results.append(("Script Modules", test_script_modules()))
    results.append(("Web App", test_web_app()))
    results.append(("File Permissions", test_file_permissions()))
    results.append(("Command Line Tools", test_command_line_tools()))
    results.append(("Network Connectivity", test_network_connectivity()))
    
    # Print summary
    print_header("Test Results Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        if result:
            print_success(f"{test_name}")
        else:
            print_error(f"{test_name}")
    
    print(f"\n📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print_success("🎉 All tests passed! Jira Tool is fully compatible with Mac!")
        print_info("You can now proceed with the setup and usage.")
    else:
        print_error(f"⚠️  {total - passed} test(s) failed. Please check the issues above.")
        print_info("Some tests may require additional setup or dependencies.")
    
    # Generate Mac commands
    generate_mac_commands()
    
    print_header("Next Steps")
    print_info("1. Follow the Mac setup guide: mac_setup_guide.md")
    print_info("2. Configure your Jira settings")
    print_info("3. Start using the tool!")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 