#!/usr/bin/env python3
"""
API Security Scanner - Main Entry Point
A comprehensive API security scanning tool with web interface
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path

def setup_environment():
    """Setup the Python path and environment"""
    # Add src directory to Python path
    src_path = Path(__file__).parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

def launch_web_ui():
    """Launch the enhanced web UI"""
    try:
        setup_environment()
        web_app_path = Path(__file__).parent / "src" / "web" / "app.py"
        
        if not web_app_path.exists():
            print(f"❌ Web app not found at: {web_app_path}")
            return False
            
        print("🚀 Launching API Security Scanner Web UI...")
        print("📱 Access the interface at: http://localhost:5000")
        print("⏹️  Press Ctrl+C to stop the server")
        print("-" * 50)
        
        subprocess.run([sys.executable, str(web_app_path)])
        return True
        
    except KeyboardInterrupt:
        print("\n🛑 Web UI stopped by user")
        return True
    except Exception as e:
        print(f"❌ Error launching web UI: {e}")
        return False

def run_cli_scanner():
    """Run the scanner in CLI mode"""
    try:
        setup_environment()
        from src.core.api_security_scanner import APISecurityScanner
        
        print("🔍 API Security Scanner - CLI Mode")
        print("📝 Use the web interface for a better experience: python main.py web")
        
        # Example usage
        scanner = APISecurityScanner()
        print(f"✅ Scanner initialized successfully")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure all dependencies are installed: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="API Security Scanner - Comprehensive API security testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py web          # Launch web interface
  python main.py cli          # Run in CLI mode
  python main.py --help       # Show this help message
        """
    )
    
    parser.add_argument(
        'mode',
        nargs='?',
        choices=['web', 'cli'],
        default='web',
        help='Run mode: web (default) or cli'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port for web interface (default: 5000)'
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Host for web interface (default: 0.0.0.0)'
    )
    
    args = parser.parse_args()
    
    print("🔒 API Security Scanner")
    print("=" * 50)
    
    if args.mode == 'web':
        # Set environment variables for Flask
        os.environ['FLASK_HOST'] = args.host
        os.environ['FLASK_PORT'] = str(args.port)
        launch_web_ui()
    elif args.mode == 'cli':
        run_cli_scanner()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
