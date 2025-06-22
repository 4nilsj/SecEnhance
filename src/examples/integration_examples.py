#!/usr/bin/env python3
"""
Burp Suite Integration Examples
Practical examples for integrating the framework with Burp Suite
"""

import json
import os
import time
import requests
from typing import Dict, List, Any
from datetime import datetime

# Import our framework components
from workflow_automation import WorkflowAutomation
from custom_bchecks import BCheckGenerator

class BurpIntegrationExamples:
    """Practical integration examples for Burp Suite"""
    
    def __init__(self, burp_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.burp_url = burp_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            })
        
        # Initialize framework components
        self.automation = WorkflowAutomation(burp_url, api_key)
        self.generator = BCheckGenerator()

class Example1_BasicExtensionIntegration:
    """Example 1: Basic Burp Suite Extension Integration"""
    
    @staticmethod
    def setup_extension():
        """Setup basic extension integration"""
        setup_guide = {
            'title': 'Basic Burp Suite Extension Integration',
            'description': 'Load and configure the custom extension in Burp Suite',
            'steps': [
                {
                    'step': 1,
                    'action': 'Configure Jython',
                    'details': [
                        'Download Jython standalone JAR from https://www.jython.org/downloads.html',
                        'In Burp Suite: Extensions → Extensions → Add',
                        'Select "Python" as extension type',
                        'Set Jython standalone JAR file path',
                        'Click "Next"'
                    ]
                },
                {
                    'step': 2,
                    'action': 'Load Extension',
                    'details': [
                        'Browse to burp_extension.py file',
                        'Select the extension file',
                        'Click "Next"',
                        'Verify extension loads without errors',
                        'Check Extensions tab for "Advanced Scanner"'
                    ]
                },
                {
                    'step': 3,
                    'action': 'Test Extension',
                    'details': [
                        'Navigate to Target tab',
                        'Select a target URL',
                        'Right-click → "Do active scan"',
                        'Verify custom vulnerability detection works',
                        'Check Scanner tab for results'
                    ]
                }
            ],
            'expected_results': [
                'Extension loads without errors',
                'Advanced Scanner tab appears',
                'Custom vulnerability detection active',
                'Enhanced scanning capabilities available'
            ]
        }
        return setup_guide

class Example2_APIWorkflowIntegration:
    """Example 2: API-based Workflow Integration"""
    
    def __init__(self, burp_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.automation = WorkflowAutomation(burp_url, api_key)
    
    def run_comprehensive_scan(self, target_url: str):
        """Run comprehensive security scan via API"""
        print(f"Starting comprehensive scan of: {target_url}")
        
        # Step 1: Generate custom BCheck scripts
        print("\n1. Generating custom BCheck scripts...")
        scripts = self.automation.generator.generate_custom_bchecks(target_url, ["id", "user", "data"])
        self.automation.generator.save_bchecks(scripts, f"bchecks_{int(time.time())}.json")
        print(f"✓ Generated {len(scripts)} BCheck scripts")
        
        # Step 2: Start comprehensive workflow
        print("\n2. Starting comprehensive workflow...")
        workflow_id = self.automation.start_workflow('comprehensive_scan', target_url)
        
        # Step 3: Monitor workflow progress
        print("\n3. Monitoring workflow progress...")
        while True:
            status = self.automation.get_workflow_status(workflow_id)
            print(f"   Status: {status['status']} - Step {status['current_step']}/{status['total_steps']}")
            
            if status['status'] in ['completed', 'failed']:
                break
            
            time.sleep(30)
        
        # Step 4: Get results
        print("\n4. Collecting results...")
        results = self.automation.get_workflow_results(workflow_id)
        
        # Step 5: Generate report
        print("\n5. Generating report...")
        if results['status'] == 'completed':
            report_file = f"comprehensive_scan_report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"✓ Scan completed successfully!")
            print(f"✓ Report saved to: {report_file}")
            
            # Summary
            total_issues = 0
            for step, result in results['results'].items():
                if result.get('success') and 'issues_found' in result:
                    total_issues += result['issues_found']
                    print(f"   {step}: {result['issues_found']} issues")
            
            print(f"\nTotal vulnerabilities found: {total_issues}")
        else:
            print("✗ Scan failed")
            for error in results['errors']:
                print(f"   Error: {error['message']}")
        
        return results
    
    def run_api_security_test(self, target_url: str):
        """Run API security testing workflow"""
        print(f"Starting API security test of: {target_url}")
        
        # Start API security workflow
        workflow_id = self.automation.start_workflow('api_security_test', target_url)
        
        # Monitor progress
        while True:
            status = self.automation.get_workflow_status(workflow_id)
            print(f"API Test Status: {status['status']} - Step {status['current_step']}")
            
            if status['status'] in ['completed', 'failed']:
                break
            
            time.sleep(30)
        
        # Get results
        results = self.automation.get_workflow_results(workflow_id)
        
        if results['status'] == 'completed':
            print("✓ API security test completed")
            
            # Analyze API-specific results
            api_results = {}
            for step, result in results['results'].items():
                if step.startswith('api_'):
                    api_results[step] = result
            
            print(f"API endpoints discovered: {api_results.get('api_discovery', {}).get('apis_found', 0)}")
            print(f"Authentication bypasses found: {api_results.get('authentication_testing', {}).get('bypasses_found', 0)}")
            print(f"Rate limiting tests performed: {api_results.get('rate_limiting_testing', {}).get('tests_performed', 0)}")
        
        return results

class Example3_BCheckScriptIntegration:
    """Example 3: BCheck Script Integration"""
    
    def __init__(self):
        self.generator = BCheckGenerator()
    
    def generate_and_import_bchecks(self, target_url: str, parameters: List[str]):
        """Generate and prepare BCheck scripts for import"""
        print(f"Generating BCheck scripts for: {target_url}")
        
        # Generate scripts
        scripts = self.generator.generate_custom_bchecks(target_url, parameters)
        
        # Save to file
        filename = f"bcheck_scripts_{int(time.time())}.json"
        self.generator.save_bchecks(scripts, filename)
        
        # Generate import guide
        import_guide = self.create_import_guide(filename, len(scripts))
        
        # Generate report
        report = self.generator.generate_report(scripts)
        
        print(f"✓ Generated {len(scripts)} BCheck scripts")
        print(f"✓ Saved to: {filename}")
        print(f"✓ Report generated")
        
        return {
            'scripts': scripts,
            'filename': filename,
            'import_guide': import_guide,
            'report': report
        }
    
    def create_import_guide(self, filename: str, script_count: int):
        """Create step-by-step import guide"""
        guide = {
            'title': f'Import {script_count} BCheck Scripts into Burp Suite',
            'filename': filename,
            'steps': [
                {
                    'step': 1,
                    'action': 'Enable BCheck Extension',
                    'details': [
                        'Open Burp Suite Professional',
                        'Go to Extensions → Extensions',
                        'Find "BCheck" in the list',
                        'Check the "Loaded" checkbox',
                        'Click "Next" if prompted'
                    ]
                },
                {
                    'step': 2,
                    'action': 'Import Scripts',
                    'details': [
                        'Go to Extensions → BCheck',
                        'Click "Import" button',
                        f'Select file: {filename}',
                        'Verify scripts are loaded',
                        'Review script configurations'
                    ]
                },
                {
                    'step': 3,
                    'action': 'Configure Scripts',
                    'details': [
                        'Set target URLs for each script',
                        'Configure scan parameters',
                        'Set custom payloads if needed',
                        'Configure reporting options',
                        'Test individual scripts'
                    ]
                },
                {
                    'step': 4,
                    'action': 'Run Automated Scans',
                    'details': [
                        'Select target URLs',
                        'Choose scripts to run',
                        'Configure scan settings',
                        'Start automated scan',
                        'Monitor scan progress',
                        'Review scan results'
                    ]
                }
            ],
            'script_types': [
                'SQL Injection Detection',
                'XSS Detection',
                'SSRF Detection',
                'XXE Detection',
                'Command Injection Detection',
                'JWT Vulnerability Detection',
                'GraphQL Vulnerability Detection',
                'Prototype Pollution Detection',
                'SSTI Detection',
                'Mass Assignment Detection'
            ]
        }
        return guide

class Example4_HybridIntegration:
    """Example 4: Hybrid Integration (Extension + API)"""
    
    def __init__(self, burp_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.burp_url = burp_url
        self.api_key = api_key
        self.automation = WorkflowAutomation(burp_url, api_key)
        self.generator = BCheckGenerator()
    
    def run_hybrid_scan(self, target_url: str):
        """Run hybrid scan using both extension and API"""
        print(f"Starting hybrid scan of: {target_url}")
        
        # Phase 1: Extension-based scanning
        print("\nPhase 1: Extension-based scanning")
        extension_results = self.run_extension_scan(target_url)
        
        # Phase 2: API-based workflow
        print("\nPhase 2: API-based workflow")
        api_results = self.run_api_workflow(target_url)
        
        # Phase 3: BCheck script generation
        print("\nPhase 3: BCheck script generation")
        bcheck_results = self.generate_bcheck_scripts(target_url)
        
        # Phase 4: Combine and analyze results
        print("\nPhase 4: Combining and analyzing results")
        combined_results = self.combine_results(extension_results, api_results, bcheck_results)
        
        # Phase 5: Generate comprehensive report
        print("\nPhase 5: Generating comprehensive report")
        report = self.generate_comprehensive_report(combined_results, target_url)
        
        return report
    
    def run_extension_scan(self, target_url: str):
        """Simulate extension-based scanning"""
        # This would be done through the Burp Suite extension
        # For this example, we'll simulate the results
        extension_results = {
            'method': 'extension',
            'target_url': target_url,
            'scan_type': 'passive_and_active',
            'vulnerabilities_found': [
                {'type': 'SQL Injection', 'severity': 'High', 'confidence': 'Certain'},
                {'type': 'XSS', 'severity': 'Medium', 'confidence': 'Certain'},
                {'type': 'Information Disclosure', 'severity': 'Low', 'confidence': 'Certain'}
            ],
            'scan_duration': '5 minutes',
            'status': 'completed'
        }
        
        print(f"✓ Extension scan completed: {len(extension_results['vulnerabilities_found'])} vulnerabilities found")
        return extension_results
    
    def run_api_workflow(self, target_url: str):
        """Run API-based workflow"""
        workflow_id = self.automation.start_workflow('comprehensive_scan', target_url)
        
        # Monitor progress
        while True:
            status = self.automation.get_workflow_status(workflow_id)
            if status['status'] in ['completed', 'failed']:
                break
            time.sleep(30)
        
        results = self.automation.get_workflow_results(workflow_id)
        print(f"✓ API workflow completed: {results['status']}")
        return results
    
    def generate_bcheck_scripts(self, target_url: str):
        """Generate BCheck scripts"""
        scripts = self.generator.generate_custom_bchecks(target_url, ["id", "user", "data"])
        filename = f"hybrid_bchecks_{int(time.time())}.json"
        self.generator.save_bchecks(scripts, filename)
        
        print(f"✓ BCheck scripts generated: {len(scripts)} scripts")
        return {
            'scripts_count': len(scripts),
            'filename': filename,
            'scripts': scripts
        }
    
    def combine_results(self, extension_results, api_results, bcheck_results):
        """Combine results from different methods"""
        combined = {
            'target_url': extension_results['target_url'],
            'scan_timestamp': datetime.now().isoformat(),
            'methods_used': ['extension', 'api', 'bcheck'],
            'extension_results': extension_results,
            'api_results': api_results,
            'bcheck_results': bcheck_results,
            'summary': {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Count vulnerabilities from extension
        for vuln in extension_results['vulnerabilities_found']:
            combined['summary']['total_vulnerabilities'] += 1
            severity = vuln['severity'].lower()
            if severity in combined['summary']:
                combined['summary'][severity] += 1
        
        # Count vulnerabilities from API
        if api_results.get('status') == 'completed':
            for step, result in api_results.get('results', {}).items():
                if result.get('success') and 'issues_found' in result:
                    combined['summary']['total_vulnerabilities'] += result['issues_found']
        
        return combined
    
    def generate_comprehensive_report(self, combined_results, target_url):
        """Generate comprehensive report"""
        report = {
            'title': 'Hybrid Security Scan Report',
            'target_url': target_url,
            'scan_date': combined_results['scan_timestamp'],
            'methods_used': combined_results['methods_used'],
            'summary': combined_results['summary'],
            'detailed_results': combined_results,
            'recommendations': self.generate_recommendations(combined_results)
        }
        
        # Save report
        filename = f"hybrid_scan_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✓ Comprehensive report saved to: {filename}")
        return report
    
    def generate_recommendations(self, results):
        """Generate security recommendations"""
        recommendations = []
        
        if results['summary']['critical'] > 0:
            recommendations.append("Immediate action required: Critical vulnerabilities found")
        
        if results['summary']['high'] > 0:
            recommendations.append("High priority: Address high severity vulnerabilities")
        
        if results['summary']['medium'] > 0:
            recommendations.append("Medium priority: Review and fix medium severity issues")
        
        if results['summary']['low'] > 0:
            recommendations.append("Low priority: Consider addressing low severity findings")
        
        recommendations.append("Implement security best practices")
        recommendations.append("Regular security testing recommended")
        
        return recommendations

class Example5_AutomatedTestingPipeline:
    """Example 5: Automated Testing Pipeline"""
    
    def __init__(self, burp_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.automation = WorkflowAutomation(burp_url, api_key)
        self.generator = BCheckGenerator()
    
    def run_automated_pipeline(self, targets: List[str]):
        """Run automated testing pipeline for multiple targets"""
        print(f"Starting automated testing pipeline for {len(targets)} targets")
        
        pipeline_results = {
            'start_time': datetime.now().isoformat(),
            'targets': targets,
            'results': {},
            'summary': {
                'total_targets': len(targets),
                'completed': 0,
                'failed': 0,
                'total_vulnerabilities': 0
            }
        }
        
        # Process each target
        for i, target in enumerate(targets, 1):
            print(f"\nProcessing target {i}/{len(targets)}: {target}")
            
            try:
                # Run comprehensive scan
                result = self.automation.run_comprehensive_scan(target)
                pipeline_results['results'][target] = result
                pipeline_results['summary']['completed'] += 1
                
                # Count vulnerabilities
                if result.get('status') == 'completed':
                    total_issues = 0
                    for step, step_result in result.get('results', {}).items():
                        if step_result.get('success') and 'issues_found' in step_result:
                            total_issues += step_result['issues_found']
                    
                    pipeline_results['summary']['total_vulnerabilities'] += total_issues
                    print(f"✓ Completed: {total_issues} vulnerabilities found")
                else:
                    print(f"✗ Failed: {result.get('error', 'Unknown error')}")
                    pipeline_results['summary']['failed'] += 1
                    
            except Exception as e:
                print(f"✗ Error processing {target}: {str(e)}")
                pipeline_results['results'][target] = {'error': str(e)}
                pipeline_results['summary']['failed'] += 1
        
        # Generate pipeline report
        pipeline_results['end_time'] = datetime.now().isoformat()
        pipeline_results['duration'] = self.calculate_duration(
            pipeline_results['start_time'], 
            pipeline_results['end_time']
        )
        
        # Save pipeline report
        filename = f"automated_pipeline_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(pipeline_results, f, indent=2)
        
        print(f"\n✓ Pipeline completed!")
        print(f"✓ Targets processed: {pipeline_results['summary']['completed']}")
        print(f"✓ Targets failed: {pipeline_results['summary']['failed']}")
        print(f"✓ Total vulnerabilities: {pipeline_results['summary']['total_vulnerabilities']}")
        print(f"✓ Report saved to: {filename}")
        
        return pipeline_results
    
    def calculate_duration(self, start_time: str, end_time: str):
        """Calculate duration between start and end times"""
        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)
        duration = end - start
        return str(duration)

# Main execution examples
def run_integration_examples():
    """Run all integration examples"""
    print("=" * 60)
    print("BURP SUITE INTEGRATION EXAMPLES")
    print("=" * 60)
    
    # Example 1: Basic Extension Integration
    print("\n1. Basic Extension Integration")
    print("-" * 40)
    extension_guide = Example1_BasicExtensionIntegration.setup_extension()
    print(f"Title: {extension_guide['title']}")
    print(f"Description: {extension_guide['description']}")
    print("Steps:")
    for step in extension_guide['steps']:
        print(f"  {step['step']}. {step['action']}")
    
    # Example 2: API Workflow Integration
    print("\n2. API Workflow Integration")
    print("-" * 40)
    api_example = Example2_APIWorkflowIntegration()
    
    # Example 3: BCheck Script Integration
    print("\n3. BCheck Script Integration")
    print("-" * 40)
    bcheck_example = Example3_BCheckScriptIntegration()
    
    # Example 4: Hybrid Integration
    print("\n4. Hybrid Integration")
    print("-" * 40)
    hybrid_example = Example4_HybridIntegration()
    
    # Example 5: Automated Testing Pipeline
    print("\n5. Automated Testing Pipeline")
    print("-" * 40)
    pipeline_example = Example5_AutomatedTestingPipeline()
    
    print("\n" + "=" * 60)
    print("EXAMPLES READY FOR EXECUTION!")
    print("=" * 60)
    print("\nTo run specific examples:")
    print("1. Configure your Burp Suite API settings")
    print("2. Set target URLs")
    print("3. Run the desired example function")
    print("4. Review results and reports")

if __name__ == "__main__":
    run_integration_examples() 