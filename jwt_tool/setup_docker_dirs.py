#!/usr/bin/env python3
"""
Setup script for Docker directories
Creates necessary directories for JWT Security Testing Tool Docker usage.
"""

import os
import sys
from pathlib import Path

def setup_docker_directories():
    """Create necessary directories for Docker usage."""
    print("🔧 Setting up Docker directories for JWT Security Testing Tool")
    print("=" * 60)
    
    # Define directories to create
    directories = [
        "output",
        "reports",
        "reports/cli",
        "reports/api", 
        "config",
        "tokens"
    ]
    
    created_dirs = []
    existing_dirs = []
    
    for dir_path in directories:
        path = Path(dir_path)
        if path.exists():
            existing_dirs.append(dir_path)
            print(f"✅ {dir_path} (already exists)")
        else:
            path.mkdir(parents=True, exist_ok=True)
            created_dirs.append(dir_path)
            print(f"📁 Created: {dir_path}")
    
    print("\n" + "=" * 60)
    print("📋 Summary:")
    print(f"   Created directories: {len(created_dirs)}")
    print(f"   Existing directories: {len(existing_dirs)}")
    
    if created_dirs:
        print("\n✅ New directories created:")
        for dir_path in created_dirs:
            print(f"   - {dir_path}")
    
    if existing_dirs:
        print("\nℹ️  Existing directories:")
        for dir_path in existing_dirs:
            print(f"   - {dir_path}")
    
    print("\n🚀 Ready for Docker usage!")
    print("\n💡 Next steps:")
    print("   1. Build the Docker image:")
    print("      docker build -t jwt-security-tester .")
    print("   2. Start the enhanced API:")
    print("      docker-compose up jwt-api-enhanced")
    print("   3. Or run CLI tool:")
    print("      docker-compose run jwt-tool --help")

if __name__ == "__main__":
    setup_docker_directories() 