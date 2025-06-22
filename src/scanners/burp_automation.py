#!/usr/bin/env python3
"""
Burp Suite Automation Script
Automates security testing using Burp Suite Professional API
"""

import json
import time
import requests
import base64
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import threading

class BurpAutomation:
    """Burp Suite automation class for security testing"""
    
    def __init__(self, burp_url: str = "http://127.0.0.1:1337", api_key: str = None):
        """
        Initialize Burp automation
        
        Args:
            burp_url: Burp Suite API URL
            api_key: API key for authentication
        """
        self.burp_url = burp_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            })
        
        # Test connection
        self.test_connection()
    
    def test_connection(self):
        """Test connection to Burp Suite"""
        try:
            response = self.session.get(f"{self.burp_url}/api/v0.1/")
            if response.status_code == 200:
                print("✓ Connected to Burp Suite successfully")
            else:
                print(f"⚠ Warning: Burp Suite responded with status {response.status_code}")
        except Exception as e:
            print(f"✗ Failed to connect to Burp Suite: {e}")
            print("Make sure Burp Suite is running and API is enabled")
    
    def start_scan(self, target_url: str, scan_config: Dict[str, Any] = None) -> str:
        """
        Start a new scan
        
        Args:
            target_url: Target URL to scan
            scan_config: Scan configuration
            
        Returns:
            Scan ID
        """
        if scan_config is None:
            scan_config = self.get_default_scan_config()
        
        payload = {
            "urls": [target_url],
            "scan_configurations": [scan_config]
        }
        
        try:
            response = self.session.post(
                f"{self.burp_url}/api/v0.1/scan",
                json=payload
            )
            
            if response.status_code == 201:
                scan_id = response.json().get('scan_id')
                print(f"✓ Scan started with ID: {scan_id}")
                return scan_id
            else:
                print(f"✗ Failed to start scan: {response.text}")
                return None
                
        except Exception as e:
            print(f"✗ Error starting scan: {e}")
            return None
    
    def get_default_scan_config(self) -> Dict[str, Any]:
        """Get default scan configuration"""
        return {
            "name": "Critical Vulnerability Scan",
            "type": "NamedConfiguration",
            "application_logins": [],
            "insertion_points": [],
            "scan_issues": [
                "SQL injection",
                "Cross-site scripting",
                "Server-side request forgery",
                "XML external entity injection",
                "Command injection",
                "Path traversal",
                "Open redirect",
                "Insecure direct object reference",
                "NoSQL injection",
                "Template injection"
            ],
            "scan_optimizations": {
                "scanning_mode": "Thorough",
                "reporting_accuracy": "Maximum"
            }
        }
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status and progress"""
        try:
            response = self.session.get(f"{self.burp_url}/api/v0.1/scan/{scan_id}")
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"✗ Failed to get scan status: {response.text}")
                return {}
                
        except Exception as e:
            print(f"✗ Error getting scan status: {e}")
            return {}
    
    def wait_for_scan_completion(self, scan_id: str, timeout: int = 3600) -> bool:
        """
        Wait for scan to complete
        
        Args:
            scan_id: Scan ID to monitor
            timeout: Timeout in seconds
            
        Returns:
            True if scan completed successfully
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_scan_status(scan_id)
            
            if not status:
                time.sleep(10)
                continue
            
            scan_status = status.get('scan_status', '')
            progress = status.get('scan_progress', 0)
            
            print(f"Scan status: {scan_status} - Progress: {progress}%")
            
            if scan_status == 'succeeded':
                print("✓ Scan completed successfully")
                return True
            elif scan_status == 'failed':
                print("✗ Scan failed")
                return False
            elif scan_status == 'paused':
                print("⚠ Scan paused")
                return False
            
            time.sleep(30)  # Check every 30 seconds
        
        print(f"✗ Scan timeout after {timeout} seconds")
        return False
    
    def get_scan_issues(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get issues found by the scan"""
        try:
            response = self.session.get(f"{self.burp_url}/api/v0.1/scan/{scan_id}/issues")
            
            if response.status_code == 200:
                return response.json().get('issues', [])
            else:
                print(f"✗ Failed to get scan issues: {response.text}")
                return []
                
        except Exception as e:
            print(f"✗ Error getting scan issues: {e}")
            return []
    
    def get_site_map(self, target_url: str) -> List[Dict[str, Any]]:
        """Get site map for target URL"""
        try:
            response = self.session.get(
                f"{self.burp_url}/api/v0.1/sitemap",
                params={'url': target_url}
            )
            
            if response.status_code == 200:
                return response.json().get('sitemap', [])
            else:
                print(f"✗ Failed to get site map: {response.text}")
                return []
                
        except Exception as e:
            print(f"✗ Error getting site map: {e}")
            return []
    
    def crawl_site(self, target_url: str, max_depth: int = 3) -> str:
        """
        Start site crawling
        
        Args:
            target_url: Target URL to crawl
            max_depth: Maximum crawl depth
            
        Returns:
            Crawl ID
        """
        payload = {
            "urls": [target_url],
            "application_logins": [],
            "max_depth": max_depth,
            "max_children": 100,
            "respect_robots_txt": False,
            "check_robots_txt": False,
            "ignore_robots_txt": True
        }
        
        try:
            response = self.session.post(
                f"{self.burp_url}/api/v0.1/spider",
                json=payload
            )
            
            if response.status_code == 201:
                crawl_id = response.json().get('crawl_id')
                print(f"✓ Crawl started with ID: {crawl_id}")
                return crawl_id
            else:
                print(f"✗ Failed to start crawl: {response.text}")
                return None
                
        except Exception as e:
            print(f"✗ Error starting crawl: {e}")
            return None
    
    def get_crawl_status(self, crawl_id: str) -> Dict[str, Any]:
        """Get crawl status"""
        try:
            response = self.session.get(f"{self.burp_url}/api/v0.1/spider/{crawl_id}")
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"✗ Failed to get crawl status: {response.text}")
                return {}
                
        except Exception as e:
            print(f"✗ Error getting crawl status: {e}")
            return {}
    
    def wait_for_crawl_completion(self, crawl_id: str, timeout: int = 1800) -> bool:
        """Wait for crawl to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status = self.get_crawl_status(crawl_id)
            
            if not status:
                time.sleep(10)
                continue
            
            crawl_status = status.get('crawl_status', '')
            progress = status.get('crawl_progress', 0)
            
            print(f"Crawl status: {crawl_status} - Progress: {progress}%")
            
            if crawl_status == 'succeeded':
                print("✓ Crawl completed successfully")
                return True
            elif crawl_status == 'failed':
                print("✗ Crawl failed")
                return False
            
            time.sleep(30)
        
        print(f"✗ Crawl timeout after {timeout} seconds")
        return False
    
    def run_comprehensive_scan(self, target_url: str) -> Dict[str, Any]:
        """
        Run comprehensive security scan including crawl and scan
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Scan results
        """
        print(f"Starting comprehensive scan of: {target_url}")
        
        # Step 1: Crawl the site
        print("\n1. Starting site crawl...")
        crawl_id = self.crawl_site(target_url)
        
        if crawl_id:
            if self.wait_for_crawl_completion(crawl_id):
                print("✓ Site crawl completed")
            else:
                print("⚠ Site crawl failed or timed out")
        
        # Step 2: Get site map
        print("\n2. Getting site map...")
        site_map = self.get_site_map(target_url)
        print(f"Found {len(site_map)} URLs in site map")
        
        # Step 3: Start security scan
        print("\n3. Starting security scan...")
        scan_id = self.start_scan(target_url)
        
        if scan_id:
            if self.wait_for_scan_completion(scan_id):
                print("✓ Security scan completed")
                
                # Step 4: Get scan results
                print("\n4. Collecting scan results...")
                issues = self.get_scan_issues(scan_id)
                
                return {
                    'target_url': target_url,
                    'crawl_id': crawl_id,
                    'scan_id': scan_id,
                    'site_map': site_map,
                    'issues': issues,
                    'total_issues': len(issues),
                    'critical_issues': len([i for i in issues if i.get('severity') == 'Critical']),
                    'high_issues': len([i for i in issues if i.get('severity') == 'High']),
                    'medium_issues': len([i for i in issues if i.get('severity') == 'Medium']),
                    'low_issues': len([i for i in issues if i.get('severity') == 'Low'])
                }
            else:
                print("✗ Security scan failed or timed out")
        
        return {
            'target_url': target_url,
            'error': 'Scan failed'
        }
    
    def generate_report(self, scan_results: Dict[str, Any], output_file: str = None) -> str:
        """Generate comprehensive security report"""
        if not output_file:
            output_file = f"burp_scan_report_{int(time.time())}.json"
        
        # Add timestamp
        scan_results['scan_timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Save to file
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        print(f"✓ Report saved to: {output_file}")
        
        # Print summary
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {scan_results.get('target_url', 'N/A')}")
        print(f"Total Issues: {scan_results.get('total_issues', 0)}")
        print(f"Critical: {scan_results.get('critical_issues', 0)}")
        print(f"High: {scan_results.get('high_issues', 0)}")
        print(f"Medium: {scan_results.get('medium_issues', 0)}")
        print(f"Low: {scan_results.get('low_issues', 0)}")
        print("="*50)
        
        return output_file
    
    def scan_multiple_targets(self, target_urls: List[str], max_workers: int = 3) -> List[Dict[str, Any]]:
        """Scan multiple targets in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.run_comprehensive_scan, url): url 
                for url in target_urls
            }
            
            for future in future_to_url:
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"✓ Completed scan for: {url}")
                except Exception as e:
                    print(f"✗ Failed scan for {url}: {e}")
                    results.append({
                        'target_url': url,
                        'error': str(e)
                    })
        
        return results

# Example usage
if __name__ == "__main__":
    # Initialize Burp automation
    burp = BurpAutomation()
    
    # Example targets
    targets = [
        "http://testphp.vulnweb.com",
        "http://testasp.vulnweb.com"
    ]
    
    # Run comprehensive scan
    for target in targets:
        print(f"\n{'='*60}")
        print(f"SCANNING: {target}")
        print(f"{'='*60}")
        
        results = burp.run_comprehensive_scan(target)
        report_file = burp.generate_report(results)
        
        # Print critical and high issues
        issues = results.get('issues', [])
        critical_high = [i for i in issues if i.get('severity') in ['Critical', 'High']]
        
        if critical_high:
            print(f"\nCritical/High Issues Found: {len(critical_high)}")
            for issue in critical_high:
                print(f"- {issue.get('name', 'Unknown')} ({issue.get('severity', 'Unknown')})")
        else:
            print("\nNo critical or high severity issues found.")
    
    print("\nAll scans completed!") 