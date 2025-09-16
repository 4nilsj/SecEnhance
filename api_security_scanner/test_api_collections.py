#!/usr/bin/env python3
"""
Test script for API Security Scanner against API collection files.
Demonstrates scanning Postman collections, OpenAPI specs, and curl commands.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from api_security_scanner.utils.input_parsers import parse_input, InputParserError
from api_security_scanner.utils.logger import get_logger

logger = get_logger(__name__)


class APICollectionTester:
    """Test the API Security Scanner against various API collection formats."""
    
    def __init__(self):
        self.test_results = []
        self.examples_dir = project_root / "examples"
        self.reports_dir = project_root / "reports"
        self.reports_dir.mkdir(exist_ok=True)
    
    def test_input_parsing(self) -> Dict[str, Any]:
        """Test input parsing for different collection formats."""
        print("🔍 Testing Input Parsing...")
        print("=" * 60)
        
        parsing_results = {
            'postman': {'success': False, 'requests': 0, 'error': None},
            'openapi': {'success': False, 'requests': 0, 'error': None},
            'curl': {'success': False, 'requests': 0, 'error': None}
        }
        
        # Test Postman Collection
        postman_file = self.examples_dir / "sample_postman_collection.json"
        if postman_file.exists():
            try:
                requests = parse_input(str(postman_file))
                parsing_results['postman'] = {
                    'success': True,
                    'requests': len(requests),
                    'error': None
                }
                print(f"✅ Postman Collection: {len(requests)} requests parsed successfully")
                self._display_parsed_requests("Postman", requests)
            except Exception as e:
                parsing_results['postman']['error'] = str(e)
                print(f"❌ Postman Collection: Failed - {e}")
        else:
            print("⚠️  Postman collection file not found")
        
        # Test OpenAPI Specification
        openapi_file = self.examples_dir / "sample_openapi.yaml"
        if openapi_file.exists():
            try:
                requests = parse_input(str(openapi_file))
                parsing_results['openapi'] = {
                    'success': True,
                    'requests': len(requests),
                    'error': None
                }
                print(f"✅ OpenAPI Specification: {len(requests)} requests parsed successfully")
                self._display_parsed_requests("OpenAPI", requests)
            except Exception as e:
                parsing_results['openapi']['error'] = str(e)
                print(f"❌ OpenAPI Specification: Failed - {e}")
        else:
            print("⚠️  OpenAPI specification file not found")
        
        # Test Curl Command
        curl_command = 'curl -X GET "https://api.example.com/api/users" -H "Accept: application/json"'
        try:
            requests = parse_input(curl_command)
            parsing_results['curl'] = {
                'success': True,
                'requests': len(requests),
                'error': None
            }
            print(f"✅ Curl Command: {len(requests)} requests parsed successfully")
            self._display_parsed_requests("Curl", requests)
        except Exception as e:
            parsing_results['curl']['error'] = str(e)
            print(f"❌ Curl Command: Failed - {e}")
        
        return parsing_results
    
    def _display_parsed_requests(self, source_type: str, requests: List[Dict[str, Any]]):
        """Display parsed requests in a formatted way."""
        print(f"\n📋 {source_type} Parsed Requests:")
        print("-" * 50)
        for i, req in enumerate(requests, 1):
            print(f"{i}. {req.get('name', 'Unnamed')}")
            print(f"   Method: {req.get('method', 'GET')}")
            print(f"   URL: {req.get('url', 'N/A')}")
            if req.get('headers'):
                print(f"   Headers: {len(req['headers'])} headers")
            if req.get('body'):
                print(f"   Body: {len(str(req['body']))} characters")
            print()
    
    def test_scanner_with_collections(self) -> Dict[str, Any]:
        """Test the actual scanner against API collections."""
        print("\n🚀 Testing Scanner with API Collections...")
        print("=" * 60)
        
        scan_results = {}
        
        # Test with Postman Collection
        postman_file = self.examples_dir / "sample_postman_collection.json"
        if postman_file.exists():
            print(f"\n🔍 Scanning Postman Collection: {postman_file.name}")
            result = self._run_scanner_scan(str(postman_file), "postman")
            scan_results['postman'] = result
        else:
            print("⚠️  Postman collection file not found")
        
        # Test with OpenAPI Specification
        openapi_file = self.examples_dir / "sample_openapi.yaml"
        if openapi_file.exists():
            print(f"\n🔍 Scanning OpenAPI Specification: {openapi_file.name}")
            result = self._run_scanner_scan(str(openapi_file), "openapi")
            scan_results['openapi'] = result
        else:
            print("⚠️  OpenAPI specification file not found")
        
        # Test with Curl Command
        curl_command = 'curl -X GET "https://httpbin.org/get" -H "Accept: application/json"'
        print(f"\n🔍 Scanning Curl Command")
        result = self._run_scanner_scan(curl_command, "curl")
        scan_results['curl'] = result
        
        return scan_results
    
    def _run_scanner_scan(self, input_source: str, input_type: str) -> Dict[str, Any]:
        """Run the scanner on a specific input source."""
        try:
            # Generate unique report names
            timestamp = self._get_timestamp()
            html_report = self.reports_dir / f"test_{input_type}_{timestamp}.html"
            json_report = self.reports_dir / f"test_{input_type}_{timestamp}.json"
            
            # Build scanner command
            cmd = [
                sys.executable, "-m", "api_security_scanner.cli.main", "scan",
                "--no-zap",  # Skip ZAP for faster testing
                "--export", str(html_report),
                "--export-json", str(json_report),
                "--no-progress"  # Disable progress bars for cleaner output
            ]
            
            # Add input source
            if input_type == "curl":
                cmd.extend(["--curl", input_source])
            else:
                cmd.extend(["--file", input_source])
            
            print(f"Running command: {' '.join(cmd)}")
            
            # Run the scanner
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                print("✅ Scan completed successfully")
                return {
                    'success': True,
                    'html_report': str(html_report),
                    'json_report': str(json_report),
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                print(f"❌ Scan failed with return code {result.returncode}")
                print(f"Error: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr,
                    'returncode': result.returncode
                }
                
        except subprocess.TimeoutExpired:
            print("⏰ Scan timed out after 5 minutes")
            return {
                'success': False,
                'error': 'Scan timed out',
                'timeout': True
            }
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def test_advanced_scenarios(self) -> Dict[str, Any]:
        """Test advanced scanning scenarios."""
        print("\n🎯 Testing Advanced Scenarios...")
        print("=" * 60)
        
        advanced_results = {}
        
        # Test with authentication
        print("\n🔐 Testing with Authentication")
        postman_file = self.examples_dir / "sample_postman_collection.json"
        if postman_file.exists():
            result = self._run_scanner_with_auth(str(postman_file))
            advanced_results['auth_test'] = result
        
        # Test with custom plugins only
        print("\n🔧 Testing Custom Plugins Only")
        curl_command = 'curl -X GET "https://httpbin.org/headers"'
        result = self._run_scanner_plugins_only(curl_command)
        advanced_results['plugins_only'] = result
        
        return advanced_results
    
    def _run_scanner_with_auth(self, input_file: str) -> Dict[str, Any]:
        """Run scanner with authentication."""
        try:
            timestamp = self._get_timestamp()
            html_report = self.reports_dir / f"test_auth_{timestamp}.html"
            
            cmd = [
                sys.executable, "-m", "api_security_scanner.cli.main", "scan",
                "--file", input_file,
                "--auth-type", "header",
                "--auth-name", "Authorization",
                "--auth-value", "Bearer test-token-123",
                "--no-zap",
                "--export", str(html_report),
                "--no-progress"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                print("✅ Authentication test completed successfully")
                return {'success': True, 'report': str(html_report)}
            else:
                print(f"❌ Authentication test failed: {result.stderr}")
                return {'success': False, 'error': result.stderr}
                
        except Exception as e:
            print(f"❌ Authentication test error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _run_scanner_plugins_only(self, curl_command: str) -> Dict[str, Any]:
        """Run scanner with custom plugins only (no ZAP)."""
        try:
            timestamp = self._get_timestamp()
            html_report = self.reports_dir / f"test_plugins_{timestamp}.html"
            
            cmd = [
                sys.executable, "-m", "api_security_scanner.cli.main", "scan",
                "--curl", curl_command,
                "--no-zap",  # Only custom plugins
                "--export", str(html_report),
                "--no-progress"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                print("✅ Plugins-only test completed successfully")
                return {'success': True, 'report': str(html_report)}
            else:
                print(f"❌ Plugins-only test failed: {result.stderr}")
                return {'success': False, 'error': result.stderr}
                
        except Exception as e:
            print(f"❌ Plugins-only test error: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_test_report(self, parsing_results: Dict, scan_results: Dict, advanced_results: Dict):
        """Generate a comprehensive test report."""
        print("\n📊 Generating Test Report...")
        print("=" * 60)
        
        report = {
            'test_summary': {
                'timestamp': self._get_timestamp(),
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0
            },
            'parsing_results': parsing_results,
            'scan_results': scan_results,
            'advanced_results': advanced_results,
            'recommendations': []
        }
        
        # Count test results
        for category in [parsing_results, scan_results, advanced_results]:
            for test_name, result in category.items():
                report['test_summary']['total_tests'] += 1
                if result.get('success', False):
                    report['test_summary']['passed_tests'] += 1
                else:
                    report['test_summary']['failed_tests'] += 1
        
        # Generate recommendations
        if parsing_results.get('postman', {}).get('success'):
            report['recommendations'].append("✅ Postman collection parsing works correctly")
        else:
            report['recommendations'].append("❌ Fix Postman collection parsing issues")
        
        if parsing_results.get('openapi', {}).get('success'):
            report['recommendations'].append("✅ OpenAPI specification parsing works correctly")
        else:
            report['recommendations'].append("❌ Fix OpenAPI specification parsing issues")
        
        if parsing_results.get('curl', {}).get('success'):
            report['recommendations'].append("✅ Curl command parsing works correctly")
        else:
            report['recommendations'].append("❌ Fix curl command parsing issues")
        
        # Save report
        report_file = self.reports_dir / f"api_collection_test_report_{self._get_timestamp()}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📄 Test report saved to: {report_file}")
        
        # Display summary
        print(f"\n📈 Test Summary:")
        print(f"   Total Tests: {report['test_summary']['total_tests']}")
        print(f"   Passed: {report['test_summary']['passed_tests']}")
        print(f"   Failed: {report['test_summary']['failed_tests']}")
        
        if report['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in report['recommendations']:
                print(f"   {rec}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for file naming."""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def run_all_tests(self):
        """Run all tests and generate comprehensive report."""
        print("🚀 API Security Scanner - Collection Testing Suite")
        print("=" * 80)
        print("This script tests the scanner against various API collection formats:")
        print("• Postman Collections (JSON)")
        print("• OpenAPI/Swagger Specifications (YAML/JSON)")
        print("• Curl Commands")
        print("=" * 80)
        
        try:
            # Test 1: Input Parsing
            parsing_results = self.test_input_parsing()
            
            # Test 2: Scanner Execution
            scan_results = self.test_scanner_with_collections()
            
            # Test 3: Advanced Scenarios
            advanced_results = self.test_advanced_scenarios()
            
            # Generate comprehensive report
            self.generate_test_report(parsing_results, scan_results, advanced_results)
            
            print("\n🎉 All tests completed!")
            print(f"📁 Check the 'reports' directory for detailed results and HTML reports")
            
        except KeyboardInterrupt:
            print("\n⏹️  Testing interrupted by user")
        except Exception as e:
            print(f"\n❌ Testing failed with error: {e}")
            logger.error(f"Testing failed: {e}", exc_info=True)


def main():
    """Main function to run the API collection tests."""
    tester = APICollectionTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
