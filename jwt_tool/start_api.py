#!/usr/bin/env python3
"""
JWT Security Testing Tool - API Server Starter
Helper script to start the API server with custom port configuration.
"""

import os
import sys
import argparse
from pathlib import Path

def start_api_server(api_type="enhanced", port=None, host="0.0.0.0", debug=True):
    """Start the API server with specified configuration."""
    
    # Add src directory to path
    src_dir = Path(__file__).parent / "src"
    sys.path.insert(0, str(src_dir))
    
    if api_type == "enhanced":
        print("🚀 Starting Enhanced JWT Security Testing API...")
        print(f"   Port: {port or '5000 (default)'}")
        print(f"   Host: {host}")
        print(f"   Debug: {debug}")
        print("   Press Ctrl+C to stop the server")
        print("-" * 50)
        
        # Set environment variable if port is specified
        if port:
            os.environ['JWT_API_PORT'] = str(port)
        
        # Import and start the enhanced API
        from jwt_api_enhanced import app
        app.run(host=host, port=port or 5000, debug=debug)
        
    elif api_type == "basic":
        print("🚀 Starting Basic JWT Security Testing API...")
        print(f"   Port: {port or '5000 (default)'}")
        print(f"   Host: {host}")
        print(f"   Debug: {debug}")
        print("   Press Ctrl+C to stop the server")
        print("-" * 50)
        
        # Set environment variable if port is specified
        if port:
            os.environ['JWT_API_PORT'] = str(port)
        
        # Import and start the basic API
        from jwt_api import app
        app.run(host=host, port=port or 5000, debug=debug)
    
    else:
        print(f"❌ Unknown API type: {api_type}")
        print("   Available types: 'basic', 'enhanced'")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Start JWT Security Testing API Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start enhanced API on default port (5000)
  python start_api.py

  # Start enhanced API on port 8080
  python start_api.py --port 8080

  # Start basic API on port 3000
  python start_api.py --api-type basic --port 3000

  # Start with environment variable
  JWT_API_PORT=8080 python start_api.py
        """
    )
    
    parser.add_argument(
        "--api-type",
        choices=["basic", "enhanced"],
        default="enhanced",
        help="Type of API to start (default: enhanced)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        help="Port to run the server on (default: 5000 or JWT_API_PORT env var)"
    )
    
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind the server to (default: 0.0.0.0)"
    )
    
    parser.add_argument(
        "--no-debug",
        action="store_true",
        help="Disable debug mode"
    )
    
    args = parser.parse_args()
    
    # Check if port is already set in environment
    env_port = os.environ.get('JWT_API_PORT')
    if env_port and not args.port:
        print(f"📡 Using port from environment variable: {env_port}")
    
    # Start the server
    start_api_server(
        api_type=args.api_type,
        port=args.port,
        host=args.host,
        debug=not args.no_debug
    )

if __name__ == "__main__":
    main() 