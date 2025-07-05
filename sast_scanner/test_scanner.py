#!/usr/bin/env python3
"""
Test script for SAST Scanner
Demonstrates the scanner functionality with example vulnerable files.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.sast_scanner import SASTScanner
from src.debug_utils import setup_debug_logging, debug_print

def test_single_file_scan():
    """Test scanning a single vulnerable file."""
    print("=" * 60)
    print("Testing Single File Scan")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SASTScanner(debug=True)
    
    # Test Python file
    python_file = "examples/vulnerable_app.py"
    if Path(python_file).exists():
        print(f"\nScanning Python file: {python_file}")
        result = scanner.scan_file(python_file)
        
        print(f"File analyzed: {result['file_name']}")
        print(f"File type: {result['file_type']}")
        print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
        print(f"AI insights: {len(result['ai_insights'])}")
        print(f"Scan duration: {result['scan_duration']:.2f} seconds")
        
        # Display vulnerabilities
        if result['vulnerabilities']:
            print("\nVulnerabilities found:")
            for i, vuln in enumerate(result['vulnerabilities'][:5], 1):  # Show first 5
                print(f"  {i}. {vuln['type']} - {vuln['severity']} - Line {vuln['line_number']}")
        
        # Generate report
        report_path = scanner.generate_report("html", "test_python_report.html")
        print(f"\nReport generated: {report_path}")
    
    # Test JavaScript file
    js_file = "examples/vulnerable_app.js"
    if Path(js_file).exists():
        print(f"\nScanning JavaScript file: {js_file}")
        result = scanner.scan_file(js_file)
        
        print(f"File analyzed: {result['file_name']}")
        print(f"File type: {result['file_type']}")
        print(f"Vulnerabilities found: {len(result['vulnerabilities'])}")
        print(f"AI insights: {len(result['ai_insights'])}")
        print(f"Scan duration: {result['scan_duration']:.2f} seconds")
        
        # Display vulnerabilities
        if result['vulnerabilities']:
            print("\nVulnerabilities found:")
            for i, vuln in enumerate(result['vulnerabilities'][:5], 1):  # Show first 5
                print(f"  {i}. {vuln['type']} - {vuln['severity']} - Line {vuln['line_number']}")
        
        # Generate report
        report_path = scanner.generate_report("html", "test_javascript_report.html")
        print(f"\nReport generated: {report_path}")

def test_directory_scan():
    """Test scanning a directory of vulnerable files."""
    print("\n" + "=" * 60)
    print("Testing Directory Scan")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SASTScanner(debug=True, max_workers=2)
    
    # Test examples directory
    examples_dir = "examples"
    if Path(examples_dir).exists():
        print(f"\nScanning directory: {examples_dir}")
        results = scanner.scan_directory(examples_dir, ["*.py", "*.js"])
        
        print(f"Files analyzed: {results['summary']['total_files']}")
        print(f"Total vulnerabilities: {results['summary']['total_vulnerabilities']}")
        print(f"Files with vulnerabilities: {results['summary']['files_with_vulnerabilities']}")
        
        # Display severity breakdown
        severity_breakdown = results['summary']['severity_breakdown']
        print("\nSeverity breakdown:")
        for severity, count in severity_breakdown.items():
            print(f"  {severity.title()}: {count}")
        
        # Display top vulnerability types
        type_breakdown = results['summary']['type_breakdown']
        print("\nTop vulnerability types:")
        sorted_types = sorted(type_breakdown.items(), key=lambda x: x[1], reverse=True)
        for vuln_type, count in sorted_types[:5]:
            print(f"  {vuln_type}: {count}")
        
        # Generate comprehensive report
        report_path = scanner.generate_report("html", "test_directory_report.html")
        print(f"\nComprehensive report generated: {report_path}")
        
        # Generate summary report
        summary_path = scanner.report_generator.generate_summary_report(results, "html")
        print(f"Summary report generated: {summary_path}")
        
        # Export results
        export_path = scanner.export_results("json")
        print(f"Results exported: {export_path}")

def test_different_output_formats():
    """Test different output formats."""
    print("\n" + "=" * 60)
    print("Testing Different Output Formats")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SASTScanner(debug=False)
    
    # Test with Python file
    python_file = "examples/vulnerable_app.py"
    if Path(python_file).exists():
        print(f"\nTesting output formats with: {python_file}")
        
        # Scan file
        result = scanner.scan_file(python_file)
        
        # Test different formats
        formats = ["html", "json", "markdown"]
        for fmt in formats:
            report_path = scanner.generate_report(fmt, f"test_output_{fmt}.{fmt}")
            print(f"  {fmt.upper()} report: {report_path}")

def test_ai_analysis():
    """Test AI analysis capabilities."""
    print("\n" + "=" * 60)
    print("Testing AI Analysis")
    print("=" * 60)
    
    # Initialize scanner
    scanner = SASTScanner(debug=True)
    
    # Test with Python file
    python_file = "examples/vulnerable_app.py"
    if Path(python_file).exists():
        print(f"\nTesting AI analysis with: {python_file}")
        
        # Scan file
        result = scanner.scan_file(python_file)
        
        # Display AI insights
        ai_insights = result.get('ai_insights', [])
        print(f"AI insights generated: {len(ai_insights)}")
        
        if ai_insights:
            print("\nAI Insights:")
            for i, insight in enumerate(ai_insights[:3], 1):  # Show first 3
                print(f"  {i}. {insight['type']} - Confidence: {insight.get('confidence', 'N/A')}")
                print(f"     Description: {insight['description']}")

def test_performance():
    """Test scanner performance."""
    print("\n" + "=" * 60)
    print("Testing Performance")
    print("=" * 60)
    
    import time
    
    # Test different worker configurations
    worker_configs = [1, 2, 4]
    
    for workers in worker_configs:
        print(f"\nTesting with {workers} worker(s):")
        
        start_time = time.time()
        scanner = SASTScanner(debug=False, max_workers=workers)
        
        # Scan examples directory
        examples_dir = "examples"
        if Path(examples_dir).exists():
            results = scanner.scan_directory(examples_dir, ["*.py", "*.js"])
            
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"  Files analyzed: {results['summary']['total_files']}")
            print(f"  Vulnerabilities found: {results['summary']['total_vulnerabilities']}")
            print(f"  Scan duration: {duration:.2f} seconds")
            print(f"  Files per second: {results['summary']['total_files'] / duration:.2f}")

def main():
    """Main test function."""
    print("SAST Scanner Test Suite")
    print("Testing AI-enabled Static Application Security Testing tool")
    
    # Setup debug logging
    setup_debug_logging(debug=True)
    
    try:
        # Run tests
        test_single_file_scan()
        test_directory_scan()
        test_different_output_formats()
        test_ai_analysis()
        test_performance()
        
        print("\n" + "=" * 60)
        print("All tests completed successfully!")
        print("=" * 60)
        
        print("\nGenerated files:")
        reports_dir = Path("reports")
        if reports_dir.exists():
            for report_file in reports_dir.glob("test_*"):
                print(f"  - {report_file}")
        
        print("\nNext steps:")
        print("1. Review the generated HTML reports in the 'reports' directory")
        print("2. Check the JSON export for programmatic access to results")
        print("3. Use the CLI tool for scanning your own code:")
        print("   python sast_scanner_cli.py scan file your_file.py")
        print("   python sast_scanner_cli.py scan directory your_project/")
        
    except Exception as e:
        debug_print(f"Test failed: {e}", "ERROR", "test")
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 