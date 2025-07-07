#!/usr/bin/env python3
"""
Mobile Security Testing API Starter Script
Provides easy way to start the API server with custom port configuration.
"""

import os
import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mobile_api_enhanced import MobileSecurityAPI

def main():
    """Main function to start the API server."""
    parser = argparse.ArgumentParser(description="Mobile Security Testing API Starter")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, help="Port to bind to (overrides env var)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Get port from environment variable or argument
    port = args.port
    if port is None:
        port = int(os.getenv('MOBILE_API_PORT', 5001))
    
    print("🚀 Mobile Security Testing API Starter")
    print(f"📍 Host: {args.host}")
    print(f"🔌 Port: {port}")
    print(f"🐛 Debug: {'enabled' if args.debug else 'disabled'}")
    print(f"⚙️  Config: {args.config or 'default'}")
    print()
    
    # Create and run API
    api = MobileSecurityAPI(debug=args.debug, port=port)
    api.run(host=args.host, port=port, debug=args.debug)

if __name__ == "__main__":
    main() 