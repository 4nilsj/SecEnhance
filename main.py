#!/usr/bin/env python3
"""
API Security Scanner - Main Entry Point
=======================================

This is the main entry point for the API Security Scanner application.
It provides command-line interface and web interface options.

Usage:
    python main.py --help
    python main.py scan --collection path/to/collection.json
    python main.py web --port 8080
"""

import argparse
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.scanner import APISecurityScanner
from src.web.app import create_app
from src.utils.logger import setup_logging


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="API Security Scanner - Comprehensive API security testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan --collection test_collection.json
  %(prog)s scan --collection test_collection.json --output reports/
  %(prog)s web --port 8080
  %(prog)s web --host 0.0.0.0 --port 5000
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan on API collection')
    scan_parser.add_argument('--collection', '-c', required=True,
                           help='Path to Postman collection JSON file')
    scan_parser.add_argument('--output', '-o', default='reports/',
                           help='Output directory for reports (default: reports/)')
    scan_parser.add_argument('--config', default='src/config/default_config.json',
                           help='Configuration file path')
    scan_parser.add_argument('--verbose', '-v', action='store_true',
                           help='Enable verbose logging')
    
    # Web command
    web_parser = subparsers.add_parser('web', help='Start web interface')
    web_parser.add_argument('--host', default='127.0.0.1',
                           help='Host to bind to (default: 127.0.0.1)')
    web_parser.add_argument('--port', '-p', type=int, default=5000,
                           help='Port to bind to (default: 5000)')
    web_parser.add_argument('--debug', action='store_true',
                           help='Enable debug mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'web':
        run_web(args)


def run_scan(args):
    """Run security scan on API collection."""
    try:
        scanner = APISecurityScanner(config_path=args.config)
        results = scanner.scan_collection(args.collection)
        
        # Save results
        output_dir = args.output
        os.makedirs(output_dir, exist_ok=True)
        
        scanner.save_results(results, output_dir)
        print(f"Scan completed. Results saved to {output_dir}")
        
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


def run_web(args):
    """Start web interface."""
    try:
        app = create_app()
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
    except Exception as e:
        print(f"Error starting web interface: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 