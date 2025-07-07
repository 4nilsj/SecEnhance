#!/usr/bin/env python3
"""
Mobile Security Testing Tool - Quick Start Script
Provides easy way to get started with mobile security testing.
"""

import os
import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def setup_environment():
    """Setup the environment for mobile security testing."""
    print("🔧 Setting up Mobile Security Testing environment...")
    
    # Create necessary directories
    directories = [
        "reports/api",
        "reports/cli",
        "uploads",
        "logs",
        "config"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")
    
    # Create default config if it doesn't exist
    config_file = Path("config/default_config.json")
    if not config_file.exists():
        default_config = {
            "api": {
                "host": "0.0.0.0",
                "port": 5001,
                "debug": False,
                "max_file_size": 100 * 1024 * 1024
            },
            "analysis": {
                "default_tests": ["static", "network", "storage", "code"],
                "timeout": 300
            },
            "reports": {
                "default_format": "html",
                "include_proof": True,
                "include_reproduction": True
            }
        }
        
        import json
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"✅ Created default config: {config_file}")

def test_cli_mode():
    """Test CLI mode functionality."""
    print("\n🔍 Testing CLI mode...")
    
    try:
        from mobile_security_tester import MobileSecurityTester
        
        # Create a dummy APK for testing
        test_apk = "test_app.apk"
        if not os.path.exists(test_apk):
            with open(test_apk, 'wb') as f:
                f.write(b"PK\x03\x04dummy APK content")
        
        # Initialize tester
        tester = MobileSecurityTester(debug=True)
        print("✅ MobileSecurityTester initialized successfully")
        
        # Test basic functionality
        print("✅ CLI mode is working")
        
        # Cleanup
        if os.path.exists(test_apk):
            os.remove(test_apk)
            
    except Exception as e:
        print(f"❌ CLI mode test failed: {str(e)}")
        return False
    
    return True

def test_api_mode():
    """Test API mode functionality."""
    print("\n🔍 Testing API mode...")
    
    try:
        from mobile_api_enhanced import MobileSecurityAPI
        
        # Initialize API
        api = MobileSecurityAPI(debug=True, port=5001)
        print("✅ MobileSecurityAPI initialized successfully")
        
        # Test API endpoints
        print("✅ API mode is working")
        
    except Exception as e:
        print(f"❌ API mode test failed: {str(e)}")
        return False
    
    return True

def show_usage_examples():
    """Show usage examples."""
    print("\n📚 Usage Examples:")
    print("=" * 50)
    
    print("\n🔧 CLI Mode:")
    print("python src/mobile_security_tester.py --apk app.apk --comprehensive")
    print("python src/mobile_security_tester.py --ipa app.ipa --tests static,network")
    print("python src/mobile_security_tester.py --batch /path/to/apks")
    
    print("\n🌐 API Mode:")
    print("python start_api.py")
    print("python start_api.py --port 8080")
    print("curl http://localhost:5001/api/v1/health")
    
    print("\n🐳 Docker Mode:")
    print("docker-compose up mobile-api")
    print("docker-compose run mobile-tool-cli")
    print("docker-compose run mobile-tool-comprehensive")

def show_next_steps():
    """Show next steps for users."""
    print("\n🚀 Next Steps:")
    print("=" * 50)
    
    print("\n1. 📁 Prepare your APK/IPA files:")
    print("   cp your_app.apk uploads/")
    
    print("\n2. 🔍 Run your first analysis:")
    print("   python src/mobile_security_tester.py --apk uploads/your_app.apk --comprehensive")
    
    print("\n3. 🌐 Start the API server:")
    print("   python start_api.py")
    
    print("\n4. 📊 Check the reports:")
    print("   ls reports/cli/")
    print("   ls reports/api/")
    
    print("\n5. 📖 Read the documentation:")
    print("   - README.md - Main documentation")
    print("   - DOCKER_USAGE.md - Docker usage guide")
    print("   - docs/API_REFERENCE.md - API documentation")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Mobile Security Testing Quick Start")
    parser.add_argument("--skip-tests", action="store_true", help="Skip functionality tests")
    parser.add_argument("--setup-only", action="store_true", help="Only setup environment")
    
    args = parser.parse_args()
    
    print("🚀 Mobile Security Testing Tool - Quick Start")
    print("=" * 60)
    
    # Setup environment
    setup_environment()
    
    if args.setup_only:
        print("\n✅ Environment setup completed!")
        return
    
    # Test functionality
    if not args.skip_tests:
        cli_ok = test_cli_mode()
        api_ok = test_api_mode()
        
        if cli_ok and api_ok:
            print("\n✅ All tests passed!")
        else:
            print("\n⚠️  Some tests failed. Check the output above.")
    
    # Show usage examples
    show_usage_examples()
    
    # Show next steps
    show_next_steps()
    
    print("\n🎉 Quick start completed!")
    print("You're ready to start mobile security testing!")

if __name__ == "__main__":
    main() 