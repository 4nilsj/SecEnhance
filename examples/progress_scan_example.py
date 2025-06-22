#!/usr/bin/env python3
"""
Progress-Enabled Scan Example
Demonstrates how to add progress tracking to any scan script
"""

import sys
import time
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from src.core.api_security_scanner import APISecurityScanner

class SimpleProgressBar:
    """Simple progress bar for terminal output"""
    
    def __init__(self, total=100, width=50):
        self.total = total
        self.width = width
        self.current = 0
        self.start_time = time.time()
    
    def update(self, current, message=""):
        """Update progress"""
        self.current = current
        percentage = (current / self.total) * 100 if self.total > 0 else 0
        filled = int(self.width * current / self.total) if self.total > 0 else 0
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start_time
        
        print(f"\r🔍 {message} [{bar}] {percentage:.1f}% ({current}/{self.total}) - {elapsed:.1f}s", end="", flush=True)
    
    def complete(self, message="Complete"):
        """Mark as complete"""
        elapsed = time.time() - self.start_time
        print(f"\n✅ {message} in {elapsed:.2f} seconds!")

def run_progress_scan():
    """Run a scan with progress tracking"""
    print("🚀 Progress-Enabled API Security Scan")
    print("=" * 40)
    
    # Initialize scanner
    progress = SimpleProgressBar(100, "Initializing scanner")
    progress.update(10, "Initializing scanner")
    
    scanner = APISecurityScanner()
    progress.update(20, "Scanner ready")
    
    # Define endpoints to scan
    endpoints = [
        {'url': 'https://httpbin.org/get', 'method': 'GET', 'description': 'Test GET'},
        {'url': 'https://httpbin.org/post', 'method': 'POST', 'description': 'Test POST'},
        {'url': 'https://httpbin.org/status/404', 'method': 'GET', 'description': 'Test 404'},
        {'url': 'https://httpbin.org/delay/1', 'method': 'GET', 'description': 'Test delay'},
        {'url': 'https://httpbin.org/headers', 'method': 'GET', 'description': 'Test headers'}
    ]
    
    progress.update(30, f"Preparing to scan {len(endpoints)} endpoints")
    
    # Run the scan
    progress.update(40, "Starting scan")
    results = scanner.scan_api_endpoints(endpoints)
    
    progress.update(90, "Scan completed, processing results")
    
    # Display results
    vulnerabilities = results.get('vulnerabilities_found', [])
    endpoints_scanned = results.get('endpoints_scanned', 0)
    
    progress.complete(f"Scan completed - {endpoints_scanned} endpoints, {len(vulnerabilities)} vulnerabilities")
    
    # Generate reports
    print("\n📄 Generating reports...")
    try:
        json_report = scanner.generate_api_security_report(results, 'json')
        html_report = scanner.generate_owasp_report(results, 'html')
        
        print(f"✅ JSON Report: {json_report}")
        print(f"✅ HTML Report: {html_report}")
        
    except Exception as e:
        print(f"❌ Error generating reports: {e}")
    
    # Show summary
    print(f"\n📊 Scan Summary:")
    print(f"   🔍 Scan ID: {results.get('scan_id', 'N/A')}")
    print(f"   📡 Endpoints: {endpoints_scanned}")
    print(f"   🚨 Vulnerabilities: {len(vulnerabilities)}")
    print(f"   ⏱️  Duration: {results.get('scan_duration', 0):.2f}s")
    
    if vulnerabilities:
        print(f"\n🚨 Vulnerabilities Found:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"   {i}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
    
    print(f"\n🌐 View in Web UI: python main.py web → http://localhost:5000 → Reports tab")

if __name__ == "__main__":
    try:
        run_progress_scan()
    except KeyboardInterrupt:
        print(f"\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("💡 Make sure all dependencies are installed: pip install -r requirements.txt") 