#!/usr/bin/env python3
"""
Universal API Security Scanner Script with Progress Tracking

Usage examples:
  python run_api_scan.py --type endpoints --endpoints '[{"url": "https://httpbin.org/get", "method": "GET"}]'
  python run_api_scan.py --type collection --collection data/test_collection.json --base-url https://api.example.com
  python run_api_scan.py --type swagger --swagger-url https://petstore.swagger.io/v2/swagger.json
  python run_api_scan.py --type json --json-file data/test_collection.json --base-url https://api.example.com
"""

import sys
import os
import argparse
import json
import time
from pathlib import Path
from datetime import datetime

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from src.core.api_security_scanner import APISecurityScanner

class ProgressTracker:
    """Track and display scan progress"""
    
    def __init__(self, total_items=0):
        self.total_items = total_items
        self.current_item = 0
        self.start_time = time.time()
        self.current_phase = "Initializing"
    
    def update_phase(self, phase):
        """Update the current scan phase"""
        self.current_phase = phase
        self._print_progress()
    
    def update_progress(self, current, total=None):
        """Update progress count"""
        self.current_item = current
        if total:
            self.total_items = total
        self._print_progress()
    
    def _print_progress(self):
        """Print current progress"""
        elapsed = time.time() - self.start_time
        
        if self.total_items > 0:
            percentage = (self.current_item / self.total_items) * 100
            progress_bar = self._create_progress_bar(percentage)
            print(f"\r🔍 {self.current_phase}: {progress_bar} {percentage:.1f}% ({self.current_item}/{self.total_items}) - {elapsed:.1f}s", end="", flush=True)
        else:
            print(f"\r🔍 {self.current_phase} - {elapsed:.1f}s", end="", flush=True)
    
    def _create_progress_bar(self, percentage, width=30):
        """Create a visual progress bar"""
        filled = int(width * percentage / 100)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}]"
    
    def complete(self):
        """Mark scan as complete"""
        elapsed = time.time() - self.start_time
        print(f"\n✅ Scan completed in {elapsed:.2f} seconds!")

def main():
    parser = argparse.ArgumentParser(description="Universal API Security Scanner with Progress Tracking")
    parser.add_argument('--type', choices=['endpoints', 'collection', 'swagger', 'json'], required=True, help='Type of scan to perform')
    parser.add_argument('--endpoints', type=str, help='JSON string of endpoints (for endpoints scan)')
    parser.add_argument('--collection', type=str, help='Path to Postman/Insomnia collection file')
    parser.add_argument('--swagger-url', type=str, help='URL to Swagger/OpenAPI spec')
    parser.add_argument('--json-file', type=str, help='Path to raw JSON file')
    parser.add_argument('--base-url', type=str, help='Base URL for the API (optional)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed progress')
    args = parser.parse_args()

    print("🚀 API Security Scanner - Universal Script")
    print("=" * 50)
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🎯 Scan Type: {args.type.upper()}")
    
    # Initialize scanner
    progress = ProgressTracker()
    progress.update_phase("Initializing scanner")
    
    try:
        scanner = APISecurityScanner()
        progress.update_phase("Scanner initialized")
        
        # Determine scan parameters and run scan
        if args.type == 'endpoints':
            if not args.endpoints:
                print("\n❌ Error: You must provide --endpoints as a JSON string for endpoints scan.")
                sys.exit(1)
            
            progress.update_phase("Parsing endpoints")
            endpoints = json.loads(args.endpoints)
            progress.update_progress(0, len(endpoints))
            
            progress.update_phase("Starting endpoint scan")
            results = scanner.scan_api_endpoints(endpoints)
            
        elif args.type == 'collection':
            if not args.collection:
                print("\n❌ Error: You must provide --collection for collection scan.")
                sys.exit(1)
            
            progress.update_phase("Loading collection file")
            if not os.path.exists(args.collection):
                print(f"\n❌ Error: Collection file not found: {args.collection}")
                sys.exit(1)
            
            progress.update_phase("Scanning collection")
            results = scanner.upload_and_scan_collection(args.collection, base_url=args.base_url)
            
        elif args.type == 'swagger':
            if not args.swagger_url:
                print("\n❌ Error: You must provide --swagger-url for Swagger/OpenAPI scan.")
                sys.exit(1)
            
            progress.update_phase("Fetching Swagger/OpenAPI spec")
            results = scanner.scan_from_swagger_url(args.swagger_url, base_url=args.base_url)
            
        elif args.type == 'json':
            if not args.json_file:
                print("\n❌ Error: You must provide --json-file for raw JSON scan.")
                sys.exit(1)
            
            progress.update_phase("Loading JSON file")
            if not os.path.exists(args.json_file):
                print(f"\n❌ Error: JSON file not found: {args.json_file}")
                sys.exit(1)
            
            progress.update_phase("Scanning JSON endpoints")
            results = scanner.scan_from_json_file(args.json_file, base_url=args.base_url)
        
        progress.complete()
        
        # Display results summary
        print("\n📊 Scan Results Summary:")
        print("-" * 30)
        
        if 'error' in results:
            print(f"❌ Scan failed: {results['error']}")
            sys.exit(1)
        
        # Extract key metrics
        scan_id = results.get('scan_id', 'N/A')
        endpoints_scanned = results.get('endpoints_scanned', 0)
        vulnerabilities_found = len(results.get('vulnerabilities_found', []))
        scan_duration = results.get('scan_duration', 0)
        
        print(f"🔍 Scan ID: {scan_id}")
        print(f"📡 Endpoints Scanned: {endpoints_scanned}")
        print(f"🚨 Vulnerabilities Found: {vulnerabilities_found}")
        print(f"⏱️  Scan Duration: {scan_duration:.2f} seconds")
        
        # Show vulnerability breakdown if verbose
        if args.verbose and vulnerabilities_found > 0:
            print("\n🚨 Vulnerability Details:")
            vulns = results.get('vulnerabilities_found', [])
            for i, vuln in enumerate(vulns, 1):
                print(f"   {i}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
                print(f"      URL: {vuln.get('url', 'N/A')}")
                print(f"      Evidence: {vuln.get('evidence', 'N/A')[:100]}...")
                print()
        
        # Generate reports
        print("\n📄 Generating reports...")
        progress.update_phase("Generating JSON report")
        
        try:
            json_report = scanner.generate_api_security_report(results, 'json')
            progress.update_phase("Generating HTML report")
            html_report = scanner.generate_owasp_report(results, 'html')
            
            print(f"\n✅ Reports generated successfully!")
            print(f"📄 JSON Report: {json_report}")
            print(f"📄 HTML Report: {html_report}")
            
            # Show web UI instructions
            print(f"\n🌐 View reports in Web UI:")
            print(f"   1. Start web UI: python main.py web")
            print(f"   2. Open browser: http://localhost:5000")
            print(f"   3. Go to 'Reports' tab to view all reports")
            
        except Exception as e:
            print(f"\n❌ Error generating reports: {e}")
        
        print(f"\n🎉 Scan completed successfully!")
        print(f"📅 Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 