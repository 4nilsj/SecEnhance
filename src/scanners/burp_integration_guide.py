#!/usr/bin/env python3
"""
Burp Suite Integration Guide
Complete guide for integrating the custom framework with Burp Suite
"""

import json
import os
import sys
from typing import Dict, List, Any
import requests
from datetime import datetime

class BurpIntegrationGuide:
    """Comprehensive guide for Burp Suite integration"""
    
    def __init__(self):
        self.integration_methods = {
            'extension': 'Burp Suite Extension',
            'api': 'Burp Suite REST API',
            'bcheck': 'BCheck Scripts',
            'workflow': 'Workflow Automation'
        }
    
    def get_integration_methods(self) -> Dict[str, str]:
        """Get available integration methods"""
        return self.integration_methods

class BurpExtensionIntegration:
    """Guide for Burp Suite Extension integration"""
    
    @staticmethod
    def setup_extension():
        """Setup Burp Suite Extension"""
        setup_steps = {
            'prerequisites': [
                'Burp Suite Professional (required for extensions)',
                'Python 3.7+ installed',
                'Jython 2.7+ (for Python extension support)',
                'Required Python packages installed'
            ],
            'installation_steps': [
                '1. Download Jython standalone JAR file',
                '2. Configure Jython in Burp Suite',
                '3. Load the extension',
                '4. Configure extension settings',
                '5. Test the extension'
            ],
            'configuration': {
                'jython_path': 'Path to Jython JAR file',
                'extension_file': 'Path to burp_extension.py',
                'python_path': 'Path to Python packages'
            }
        }
        return setup_steps
    
    @staticmethod
    def load_extension_in_burp():
        """Step-by-step guide to load extension in Burp Suite"""
        steps = [
            {
                'step': 1,
                'title': 'Configure Jython',
                'description': 'Set up Jython for Python extension support',
                'actions': [
                    'Open Burp Suite Professional',
                    'Go to Extensions → Extensions',
                    'Click "Add" button',
                    'Select "Python" as extension type',
                    'Set Jython standalone JAR file path',
                    'Click "Next"'
                ]
            },
            {
                'step': 2,
                'title': 'Load Extension',
                'description': 'Load the custom extension file',
                'actions': [
                    'Browse to burp_extension.py file',
                    'Select the extension file',
                    'Click "Next"',
                    'Verify extension loads without errors',
                    'Click "Close"'
                ]
            },
            {
                'step': 3,
                'title': 'Verify Extension',
                'description': 'Verify extension is working correctly',
                'actions': [
                    'Check Extensions tab for "Advanced Scanner"',
                    'Verify no errors in extension output',
                    'Test basic functionality',
                    'Configure extension settings if needed'
                ]
            },
            {
                'step': 4,
                'title': 'Configure Settings',
                'description': 'Configure extension for your environment',
                'actions': [
                    'Set target URLs',
                    'Configure scan parameters',
                    'Enable/disable vulnerability types',
                    'Set custom payloads',
                    'Configure reporting options'
                ]
            }
        ]
        return steps
    
    @staticmethod
    def extension_configuration_example():
        """Example extension configuration"""
        config = {
            'target_urls': [
                'http://example.com',
                'https://test.example.com'
            ],
            'scan_settings': {
                'passive_scanning': True,
                'active_scanning': True,
                'custom_payloads': True,
                'parallel_scanning': True
            },
            'vulnerability_types': {
                'sql_injection': True,
                'xss': True,
                'ssrf': True,
                'xxe': True,
                'command_injection': True,
                'path_traversal': True,
                'jwt_vulnerabilities': True,
                'graphql_vulnerabilities': True,
                'prototype_pollution': True,
                'ssti': True
            },
            'custom_payloads': {
                'sql_injection': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--"
                ],
                'xss': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>'
                ]
            },
            'reporting': {
                'generate_html_report': True,
                'generate_json_report': True,
                'include_evidence': True,
                'severity_filter': ['Critical', 'High']
            }
        }
        return config

class BurpAPIIntegration:
    """Guide for Burp Suite REST API integration"""
    
    def __init__(self, burp_url: str = "http://127.0.0.1:1337", api_key: str = None):
        self.burp_url = burp_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            })
    
    def setup_burp_api(self):
        """Setup Burp Suite REST API"""
        setup_steps = {
            'prerequisites': [
                'Burp Suite Professional',
                'REST API extension enabled',
                'API key generated',
                'Network access to Burp Suite'
            ],
            'configuration_steps': [
                '1. Enable REST API in Burp Suite',
                '2. Generate API key',
                '3. Configure API settings',
                '4. Test API connection',
                '5. Integrate with framework'
            ],
            'api_settings': {
                'port': 1337,
                'bind_address': '127.0.0.1',
                'api_key_required': True,
                'cors_enabled': False
            }
        }
        return setup_steps
    
    def enable_rest_api_in_burp(self):
        """Step-by-step guide to enable REST API"""
        steps = [
            {
                'step': 1,
                'title': 'Enable REST API Extension',
                'description': 'Enable the REST API extension in Burp Suite',
                'actions': [
                    'Open Burp Suite Professional',
                    'Go to Extensions → Extensions',
                    'Find "REST API" in the list',
                    'Check the "Loaded" checkbox',
                    'Click "Next" if prompted'
                ]
            },
            {
                'step': 2,
                'title': 'Configure API Settings',
                'description': 'Configure REST API settings',
                'actions': [
                    'Go to Extensions → APIs → REST API',
                    'Check "Enable REST API"',
                    'Set port (default: 1337)',
                    'Set bind address (default: 127.0.0.1)',
                    'Click "Generate API key"',
                    'Copy the generated API key',
                    'Click "OK"'
                ]
            },
            {
                'step': 3,
                'title': 'Test API Connection',
                'description': 'Test the API connection',
                'actions': [
                    'Open browser or use curl',
                    'Navigate to http://127.0.0.1:1337/api/v0.1/',
                    'Verify you get a response',
                    'Test with API key if required'
                ]
            },
            {
                'step': 4,
                'title': 'Integrate with Framework',
                'description': 'Integrate API with the framework',
                'actions': [
                    'Set BURP_URL environment variable',
                    'Set BURP_API_KEY environment variable',
                    'Test integration with framework',
                    'Verify all functionality works'
                ]
            }
        ]
        return steps
    
    def test_api_connection(self):
        """Test Burp Suite API connection"""
        try:
            response = self.session.get(f"{self.burp_url}/api/v0.1/")
            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'API connection successful',
                    'status_code': response.status_code,
                    'response': response.json()
                }
            else:
                return {
                    'success': False,
                    'message': f'API connection failed: {response.status_code}',
                    'status_code': response.status_code
                }
        except Exception as e:
            return {
                'success': False,
                'message': f'API connection error: {str(e)}',
                'error': str(e)
            }
    
    def api_integration_example(self):
        """Example API integration with the framework"""
        example_code = '''
# Example: Integrate workflow automation with Burp API
from workflow_automation import WorkflowAutomation

# Initialize with Burp API
automation = WorkflowAutomation(
    burp_url="http://127.0.0.1:1337",
    api_key="your_api_key_here"
)

# Test connection
connection_test = automation.test_connection()
if connection_test:
    print("✓ Connected to Burp Suite API")
    
    # Start workflow
    target_url = "http://example.com"
    workflow_id = automation.start_workflow('comprehensive_scan', target_url)
    
    # Monitor progress
    while True:
        status = automation.get_workflow_status(workflow_id)
        print(f"Status: {status['status']} - Step {status['current_step']}")
        
        if status['status'] in ['completed', 'failed']:
            break
        
        time.sleep(30)
    
    # Get results
    results = automation.get_workflow_results(workflow_id)
    print(f"Workflow completed: {results['status']}")
else:
    print("✗ Failed to connect to Burp Suite API")
'''
        return example_code

class BCheckIntegration:
    """Guide for BCheck script integration"""
    
    @staticmethod
    def setup_bcheck_scripts():
        """Setup BCheck scripts in Burp Suite"""
        setup_steps = {
            'prerequisites': [
                'Burp Suite Professional',
                'BCheck extension enabled',
                'Custom BCheck scripts generated'
            ],
            'installation_steps': [
                '1. Generate BCheck scripts using the framework',
                '2. Import scripts into Burp Suite',
                '3. Configure script settings',
                '4. Test script functionality',
                '5. Run automated scans'
            ],
            'script_types': [
                'SQL Injection Detection',
                'XSS Detection',
                'SSRF Detection',
                'XXE Detection',
                'Command Injection Detection',
                'JWT Vulnerability Detection',
                'GraphQL Vulnerability Detection',
                'Custom Vulnerability Detection'
            ]
        }
        return setup_steps
    
    @staticmethod
    def import_bcheck_scripts():
        """Step-by-step guide to import BCheck scripts"""
        steps = [
            {
                'step': 1,
                'title': 'Generate BCheck Scripts',
                'description': 'Generate custom BCheck scripts using the framework',
                'actions': [
                    'Run the BCheck generator',
                    'Specify target URLs and parameters',
                    'Generate all vulnerability types',
                    'Save scripts to JSON file'
                ],
                'code_example': '''
from custom_bchecks import BCheckGenerator

generator = BCheckGenerator()
target_url = "http://example.com/api"
parameters = ["id", "user", "data"]

scripts = generator.generate_custom_bchecks(target_url, parameters)
generator.save_bchecks(scripts, "my_bcheck_scripts.json")
'''
            },
            {
                'step': 2,
                'title': 'Enable BCheck Extension',
                'description': 'Enable BCheck extension in Burp Suite',
                'actions': [
                    'Open Burp Suite Professional',
                    'Go to Extensions → Extensions',
                    'Find "BCheck" in the list',
                    'Check the "Loaded" checkbox',
                    'Click "Next" if prompted'
                ]
            },
            {
                'step': 3,
                'title': 'Import Scripts',
                'description': 'Import BCheck scripts into Burp Suite',
                'actions': [
                    'Go to Extensions → BCheck',
                    'Click "Import" button',
                    'Select the generated JSON file',
                    'Verify scripts are loaded',
                    'Review script configurations'
                ]
            },
            {
                'step': 4,
                'title': 'Configure Scripts',
                'description': 'Configure BCheck scripts for your environment',
                'actions': [
                    'Set target URLs for each script',
                    'Configure scan parameters',
                    'Set custom payloads if needed',
                    'Configure reporting options',
                    'Test individual scripts'
                ]
            },
            {
                'step': 5,
                'title': 'Run Automated Scans',
                'description': 'Run automated scans with BCheck scripts',
                'actions': [
                    'Select target URLs',
                    'Choose scripts to run',
                    'Configure scan settings',
                    'Start automated scan',
                    'Monitor scan progress',
                    'Review scan results'
                ]
            }
        ]
        return steps
    
    @staticmethod
    def bcheck_script_example():
        """Example BCheck script configuration"""
        example_script = {
            "metadata": {
                "name": "Custom SQL Injection Detector",
                "description": "Detects SQL injection vulnerabilities",
                "severity": "High",
                "confidence": "Certain",
                "tags": ["sql-injection", "database", "high"]
            },
            "request": {
                "method": "GET",
                "url": "http://example.com/vulnerable.php",
                "parameters": {
                    "id": "{{payload}}"
                }
            },
            "response": {
                "status_code": 200,
                "body_contains": [
                    "sql syntax",
                    "mysql_fetch_array",
                    "ORA-",
                    "PostgreSQL"
                ]
            },
            "payloads": [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--"
            ]
        }
        return example_script

class WorkflowIntegration:
    """Guide for workflow automation integration"""
    
    @staticmethod
    def setup_workflow_automation():
        """Setup workflow automation with Burp Suite"""
        setup_steps = {
            'prerequisites': [
                'Burp Suite Professional with REST API',
                'Python environment with required packages',
                'API key configured',
                'Network access to target applications'
            ],
            'integration_methods': [
                'Direct API integration',
                'Extension integration',
                'Hybrid approach (API + Extension)',
                'Custom workflow automation'
            ],
            'workflow_types': [
                'Comprehensive Security Scan',
                'Quick Security Assessment',
                'API Security Testing',
                'Critical Vulnerability Focus'
            ]
        }
        return setup_steps
    
    @staticmethod
    def workflow_integration_example():
        """Example workflow integration"""
        example_code = '''
# Complete workflow integration example
from workflow_automation import WorkflowAutomation
from custom_bchecks import BCheckGenerator
import os
import time

# Set up environment
os.environ['BURP_URL'] = 'http://127.0.0.1:1337'
os.environ['BURP_API_KEY'] = 'your_api_key_here'

# Initialize components
automation = WorkflowAutomation()
generator = BCheckGenerator()

# Target configuration
target_url = "http://vulnerable-app.example.com"

# Step 1: Generate custom BCheck scripts
print("Generating custom BCheck scripts...")
scripts = generator.generate_custom_bchecks(target_url, ["id", "user", "data"])
generator.save_bchecks(scripts, "custom_bchecks.json")

# Step 2: Start comprehensive workflow
print("Starting comprehensive security scan...")
workflow_id = automation.start_workflow('comprehensive_scan', target_url)

# Step 3: Monitor workflow progress
while True:
    status = automation.get_workflow_status(workflow_id)
    print(f"Progress: {status['current_step']}/{status['total_steps']} - {status['status']}")
    
    if status['status'] in ['completed', 'failed']:
        break
    
    time.sleep(60)

# Step 4: Get and analyze results
results = automation.get_workflow_results(workflow_id)

if results['status'] == 'completed':
    print("✓ Workflow completed successfully")
    
    # Analyze results
    total_issues = 0
    for step, result in results['results'].items():
        if result.get('success') and 'issues_found' in result:
            total_issues += result['issues_found']
            print(f"Step {step}: {result['issues_found']} issues found")
    
    print(f"Total vulnerabilities found: {total_issues}")
    
    # Generate final report
    with open('workflow_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("Detailed report saved to workflow_report.json")
else:
    print("✗ Workflow failed")
    for error in results['errors']:
        print(f"Error: {error['message']}")
'''
        return example_code

class IntegrationTroubleshooting:
    """Troubleshooting guide for integration issues"""
    
    @staticmethod
    def common_issues():
        """Common integration issues and solutions"""
        issues = {
            'extension_not_loading': {
                'symptoms': ['Extension fails to load', 'Jython errors', 'Python import errors'],
                'causes': ['Jython not configured', 'Missing Python packages', 'Incorrect file paths'],
                'solutions': [
                    'Verify Jython is properly configured',
                    'Install required Python packages',
                    'Check file paths and permissions',
                    'Review Burp Suite extension logs'
                ]
            },
            'api_connection_failed': {
                'symptoms': ['Connection refused', 'Timeout errors', 'Authentication failed'],
                'causes': ['REST API not enabled', 'Wrong port/address', 'Invalid API key'],
                'solutions': [
                    'Enable REST API in Burp Suite',
                    'Verify port and bind address',
                    'Check API key configuration',
                    'Test with curl or browser'
                ]
            },
            'bcheck_scripts_not_working': {
                'symptoms': ['Scripts not detecting vulnerabilities', 'False positives', 'Script errors'],
                'causes': ['Incorrect script format', 'Wrong target URLs', 'Missing parameters'],
                'solutions': [
                    'Validate BCheck script format',
                    'Verify target URLs and parameters',
                    'Test scripts individually',
                    'Review script configurations'
                ]
            },
            'workflow_automation_failed': {
                'symptoms': ['Workflow fails to start', 'Steps not executing', 'Results not generated'],
                'causes': ['API connection issues', 'Invalid workflow configuration', 'Target accessibility'],
                'solutions': [
                    'Test API connection first',
                    'Verify workflow configuration',
                    'Check target accessibility',
                    'Review workflow logs'
                ]
            }
        }
        return issues
    
    @staticmethod
    def diagnostic_commands():
        """Diagnostic commands for troubleshooting"""
        commands = {
            'test_api_connection': '''
# Test Burp Suite API connection
import requests

try:
    response = requests.get("http://127.0.0.1:1337/api/v0.1/")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
''',
            'test_extension_loading': '''
# Test extension loading in Burp Suite
# 1. Check Extensions tab for errors
# 2. Review extension output
# 3. Verify Jython configuration
# 4. Check Python package installation
''',
            'test_bcheck_scripts': '''
# Test BCheck script generation
from custom_bchecks import BCheckGenerator

generator = BCheckGenerator()
scripts = generator.generate_custom_bchecks("http://test.com", ["id"])
print(f"Generated {len(scripts)} scripts")
''',
            'test_workflow_automation': '''
# Test workflow automation
from workflow_automation import WorkflowAutomation

automation = WorkflowAutomation()
workflows = automation.list_workflows()
print(f"Available workflows: {len(workflows)}")
'''
        }
        return commands

# Main integration guide
def main():
    """Main integration guide"""
    guide = BurpIntegrationGuide()
    
    print("=" * 60)
    print("BURP SUITE INTEGRATION GUIDE")
    print("=" * 60)
    
    # Show available integration methods
    methods = guide.get_integration_methods()
    print("\nAvailable Integration Methods:")
    for key, value in methods.items():
        print(f"- {key}: {value}")
    
    # Extension integration
    print("\n" + "=" * 40)
    print("1. BURP SUITE EXTENSION INTEGRATION")
    print("=" * 40)
    
    extension_guide = BurpExtensionIntegration()
    setup_steps = extension_guide.setup_extension()
    
    print("\nPrerequisites:")
    for prereq in setup_steps['prerequisites']:
        print(f"  ✓ {prereq}")
    
    print("\nInstallation Steps:")
    for step in setup_steps['installation_steps']:
        print(f"  {step}")
    
    # API integration
    print("\n" + "=" * 40)
    print("2. BURP SUITE API INTEGRATION")
    print("=" * 40)
    
    api_guide = BurpAPIIntegration()
    api_setup = api_guide.setup_burp_api()
    
    print("\nPrerequisites:")
    for prereq in api_setup['prerequisites']:
        print(f"  ✓ {prereq}")
    
    print("\nConfiguration Steps:")
    for step in api_setup['configuration_steps']:
        print(f"  {step}")
    
    # BCheck integration
    print("\n" + "=" * 40)
    print("3. BCHECK SCRIPT INTEGRATION")
    print("=" * 40)
    
    bcheck_guide = BCheckIntegration()
    bcheck_setup = bcheck_guide.setup_bcheck_scripts()
    
    print("\nPrerequisites:")
    for prereq in bcheck_setup['prerequisites']:
        print(f"  ✓ {prereq}")
    
    print("\nScript Types:")
    for script_type in bcheck_setup['script_types']:
        print(f"  - {script_type}")
    
    # Workflow integration
    print("\n" + "=" * 40)
    print("4. WORKFLOW AUTOMATION INTEGRATION")
    print("=" * 40)
    
    workflow_guide = WorkflowIntegration()
    workflow_setup = workflow_guide.setup_workflow_automation()
    
    print("\nPrerequisites:")
    for prereq in workflow_setup['prerequisites']:
        print(f"  ✓ {prereq}")
    
    print("\nWorkflow Types:")
    for workflow_type in workflow_setup['workflow_types']:
        print(f"  - {workflow_type}")
    
    # Troubleshooting
    print("\n" + "=" * 40)
    print("5. TROUBLESHOOTING")
    print("=" * 40)
    
    troubleshooting = IntegrationTroubleshooting()
    issues = troubleshooting.common_issues()
    
    print("\nCommon Issues:")
    for issue, details in issues.items():
        print(f"\n  {issue.replace('_', ' ').title()}:")
        print(f"    Symptoms: {', '.join(details['symptoms'])}")
        print(f"    Solutions: {', '.join(details['solutions'][:2])}...")
    
    print("\n" + "=" * 60)
    print("INTEGRATION COMPLETE!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Choose your integration method")
    print("2. Follow the setup steps")
    print("3. Test the integration")
    print("4. Start security testing!")
    print("=" * 60)

if __name__ == "__main__":
    main() 