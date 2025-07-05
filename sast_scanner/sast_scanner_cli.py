#!/usr/bin/env python3
"""
SAST Scanner CLI
AI-enabled Static Application Security Testing tool.
"""

import sys
import os
import argparse
from pathlib import Path
from typing import List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.sast_scanner import SASTScanner
from src.debug_utils import setup_debug_logging, debug_print, get_debug_info

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AI-enabled SAST Scanner for security vulnerability detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single file
  python sast_scanner_cli.py scan file app.py

  # Scan a directory with specific file patterns
  python sast_scanner_cli.py scan directory /path/to/code --patterns "*.py,*.js"

  # Scan with debug output
  python sast_scanner_cli.py scan file app.py --debug

  # Generate HTML report
  python sast_scanner_cli.py scan file app.py --output html --output-file report.html

  # Scan with custom patterns and max workers
  python sast_scanner_cli.py scan directory /path/to/code --patterns "*.py,*.js,*.php" --max-workers 8
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files or directories for vulnerabilities')
    scan_parser.add_argument('type', choices=['file', 'directory'], help='Type of scan target')
    scan_parser.add_argument('target', help='File or directory path to scan')
    
    # Scan options
    scan_parser.add_argument('--patterns', help='File patterns to include (comma-separated)')
    scan_parser.add_argument('--exclude', help='File patterns to exclude (comma-separated)')
    scan_parser.add_argument('--max-workers', type=int, default=4, help='Maximum number of worker threads')
    scan_parser.add_argument('--output', choices=['html', 'json', 'markdown', 'pdf'], 
                           default='html', help='Output format for report')
    scan_parser.add_argument('--output-file', help='Output file path for report')
    scan_parser.add_argument('--summary-only', action='store_true', 
                           help='Generate summary report only')
    scan_parser.add_argument('--debug', action='store_true', help='Enable debug output')
    scan_parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show scanner information')
    info_parser.add_argument('--debug', action='store_true', help='Show debug information')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup debug logging
    setup_debug_logging(args.debug)
    
    if args.command == 'scan':
        return handle_scan_command(args)
    elif args.command == 'info':
        return handle_info_command(args)
    elif args.command == 'version':
        return handle_version_command(args)
    
    return 1

def handle_scan_command(args):
    """Handle the scan command."""
    try:
        debug_print("Starting SAST scan", "INFO", "cli")
        
        # Initialize scanner
        scanner = SASTScanner(debug=args.debug, max_workers=args.max_workers)
        
        # Parse file patterns
        file_patterns = None
        if args.patterns:
            file_patterns = [p.strip() for p in args.patterns.split(',')]
        
        # Perform scan
        if args.type == 'file':
            debug_print(f"Scanning single file: {args.target}", "INFO", "cli")
            
            # Check if file exists
            if not Path(args.target).exists():
                print(f"Error: File '{args.target}' not found.")
                return 1
            
            # Scan single file
            file_result = scanner.scan_file(args.target)
            scanner.scan_results = {
                "scan_info": {
                    "scan_type": "single_file",
                    "file_path": args.target,
                    "start_time": file_result.get("scan_timestamp", ""),
                    "end_time": file_result.get("scan_timestamp", ""),
                    "total_duration": file_result.get("scan_duration", 0)
                },
                "files_analyzed": [file_result],
                "vulnerabilities": file_result.get("vulnerabilities", []),
                "ai_insights": file_result.get("ai_insights", []),
                "summary": {
                    "total_files": 1,
                    "total_vulnerabilities": len(file_result.get("vulnerabilities", [])),
                    "files_with_vulnerabilities": 1 if file_result.get("vulnerabilities") else 0
                }
            }
            
        elif args.type == 'directory':
            debug_print(f"Scanning directory: {args.target}", "INFO", "cli")
            
            # Check if directory exists
            if not Path(args.target).exists() or not Path(args.target).is_dir():
                print(f"Error: Directory '{args.target}' not found.")
                return 1
            
            # Scan directory
            scanner.scan_directory(args.target, file_patterns)
        
        # Display summary
        scanner.display_summary()
        
        # Generate report
        if args.summary_only:
            report_path = scanner.report_generator.generate_summary_report(
                scanner.scan_results, args.output
            )
        else:
            report_path = scanner.generate_report(args.output, args.output_file)
        
        print(f"\nReport generated: {report_path}")
        
        # Export results
        export_path = scanner.export_results("json")
        print(f"Results exported: {export_path}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 1
    except Exception as e:
        debug_print(f"Error during scan: {e}", "ERROR", "cli")
        print(f"Error: {e}")
        return 1

def handle_info_command(args):
    """Handle the info command."""
    print("SAST Scanner Information")
    print("=" * 50)
    
    # Basic info
    print(f"Version: 1.0.0")
    print(f"Description: AI-enabled Static Application Security Testing tool")
    print(f"Supported Languages: Python, JavaScript, Java, C/C++, PHP, Ruby, Go, Rust")
    
    # Features
    print("\nFeatures:")
    print("- Pattern-based vulnerability detection")
    print("- AI-powered code analysis")
    print("- Context-aware security analysis")
    print("- Multiple output formats (HTML, JSON, Markdown, PDF)")
    print("- Parallel scanning with configurable workers")
    print("- Comprehensive reporting and export")
    
    # Debug info if requested
    if args.debug:
        debug_info = get_debug_info()
        print(f"\nDebug Information:")
        print(f"Python Version: {debug_info['python_version']}")
        print(f"Platform: {debug_info['platform']}")
        print(f"Working Directory: {debug_info['working_directory']}")
        print(f"Debug Mode: {debug_info['debug_mode']}")
    
    return 0

def handle_version_command(args):
    """Handle the version command."""
    print("SAST Scanner v1.0.0")
    print("AI-enabled Static Application Security Testing tool")
    return 0

def validate_scan_target(target_path: str, scan_type: str) -> bool:
    """Validate the scan target."""
    path = Path(target_path)
    
    if scan_type == 'file':
        if not path.exists():
            print(f"Error: File '{target_path}' not found.")
            return False
        if not path.is_file():
            print(f"Error: '{target_path}' is not a file.")
            return False
    elif scan_type == 'directory':
        if not path.exists():
            print(f"Error: Directory '{target_path}' not found.")
            return False
        if not path.is_dir():
            print(f"Error: '{target_path}' is not a directory.")
            return False
    
    return True

if __name__ == "__main__":
    sys.exit(main()) 