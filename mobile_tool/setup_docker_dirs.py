#!/usr/bin/env python3
"""
Mobile Security Testing Tool - Docker Directory Setup
Creates necessary directories for Docker usage.
"""

import os
from pathlib import Path

def setup_docker_directories():
    """Create necessary directories for Docker usage."""
    directories = [
        "reports/api",
        "reports/cli", 
        "uploads",
        "logs",
        "config",
        "examples"
    ]
    
    print("🔧 Setting up Mobile Security Testing Tool directories...")
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")
    
    # Create default config file if it doesn't exist
    config_file = Path("config/default_config.json")
    if not config_file.exists():
        default_config = {
            "api": {
                "host": "0.0.0.0",
                "port": 5001,
                "debug": False,
                "max_file_size": 100 * 1024 * 1024,
                "allowed_extensions": [".apk", ".ipa", ".aab"]
            },
            "analysis": {
                "default_tests": ["static", "network", "storage", "code"],
                "comprehensive_tests": ["static", "dynamic", "network", "storage", "code"],
                "timeout": 300,
                "max_concurrent_scans": 5
            },
            "reports": {
                "default_format": "html",
                "output_directory": "reports",
                "include_proof": True,
                "include_reproduction": True
            },
            "logging": {
                "level": "INFO",
                "file": "mobile_security.log",
                "max_size": 10 * 1024 * 1024,
                "backup_count": 5
            },
            "security": {
                "enable_rate_limiting": True,
                "max_requests_per_minute": 60,
                "allowed_origins": ["*"],
                "enable_cors": True
            },
            "tools": {
                "jadx_path": "jadx",
                "apktool_path": "apktool",
                "androguard_path": "androguard",
                "mobsf_path": "mobsf"
            }
        }
        
        import json
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        print(f"✅ Created default config: {config_file}")
    
    print("\n🎉 Directory setup completed successfully!")
    print("📁 Ready for Docker usage")

if __name__ == "__main__":
    setup_docker_directories() 