# Burp Suite Workflow Automation & Custom BCheck Framework

A comprehensive framework for creating custom BCheck scripts and automating security testing workflows in Burp Suite.

## 🎯 Overview

This framework provides:
- **Custom BCheck Scripts** for advanced vulnerability detection
- **Burp Suite Extension** for enhanced scanning capabilities
- **Workflow Automation** for streamlined security testing
- **Advanced Payload Generation** for comprehensive testing

## 📁 Project Structure

```
├── custom_bchecks.py          # Custom BCheck script generator
├── burp_extension.py          # Burp Suite extension
├── workflow_automation.py     # Workflow automation system
├── requirements.txt           # Python dependencies
└── README_workflow.md         # This documentation
```

## 🚀 Quick Start

### 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Set up Burp Suite API (if using automation)
export BURP_API_KEY="your_api_key_here"
export BURP_URL="http://127.0.0.1:1337"
```

### 2. Using Custom BCheck Scripts

```python
from custom_bchecks import BCheckGenerator

# Generate custom BCheck scripts
generator = BCheckGenerator()
target_url = "http://example.com/api"
parameters = ["id", "user", "data"]

# Generate all custom scripts
scripts = generator.generate_custom_bchecks(target_url, parameters)

# Save to file
generator.save_bchecks(scripts, "my_custom_bchecks.json")

# Generate report
report = generator.generate_report(scripts)
print(report)
```

### 3. Using Workflow Automation

```python
from workflow_automation import WorkflowAutomation

# Initialize automation
automation = WorkflowAutomation()

# List available workflows
workflows = automation.list_workflows()
for workflow in workflows:
    print(f"- {workflow['name']}: {workflow['description']}")

# Start a workflow
target_url = "http://example.com"
workflow_id = automation.start_workflow('comprehensive_scan', target_url)

# Monitor progress
while True:
    status = automation.get_workflow_status(workflow_id)
    print(f"Status: {status['status']} - Step {status['current_step']}/{status['total_steps']}")
    
    if status['status'] in ['completed', 'failed']:
        break
    
    time.sleep(30)

# Get results
results = automation.get_workflow_results(workflow_id)
print(f"Workflow completed: {results['status']}")
```

## 🔧 Custom BCheck Scripts

### Available Vulnerability Types

#### 1. **JWT Vulnerabilities**
- Weak algorithms (none)
- No signature verification
- Secret exposure
- Algorithm confusion

#### 2. **GraphQL Vulnerabilities**
- Introspection enabled
- Field suggestions
- Information disclosure
- Query depth attacks

#### 3. **API Rate Limiting Bypasses**
- Header manipulation
- IP spoofing
- Parameter pollution
- Null/undefined values

#### 4. **Deserialization Vulnerabilities**
- Java deserialization
- PHP deserialization
- .NET deserialization
- Custom object injection

#### 5. **Business Logic Vulnerabilities**
- Price manipulation
- Race conditions
- Privilege escalation
- Discount abuse

#### 6. **Cache Poisoning**
- HTTP cache poisoning
- Host header injection
- Cache key manipulation
- Response splitting

#### 7. **Prototype Pollution**
- JavaScript prototype pollution
- Object injection
- Property pollution
- Constructor pollution

#### 8. **Server-Side Template Injection**
- Various template engines
- Code execution detection
- Mathematical operations
- System command execution

#### 9. **Mass Assignment**
- Object property injection
- Role escalation
- Privilege assignment
- Admin access

#### 10. **Race Conditions**
- Concurrent request testing
- Time-based vulnerabilities
- Resource exhaustion
- State manipulation

### Creating Custom BCheck Scripts

```python
# Custom BCheck template
custom_script = {
    "metadata": {
        "name": "Custom Vulnerability Detector",
        "description": "Detects custom vulnerability type",
        "severity": "High",
        "confidence": "Certain",
        "tags": ["custom", "vulnerability", "high"]
    },
    "request": {
        "method": "POST",
        "url": "{{url}}",
        "headers": {
            "Content-Type": "application/json"
        },
        "body": "{{payload}}"
    },
    "response": {
        "status_code": 200,
        "body_contains": ["vulnerability_indicator"]
    },
    "payloads": [
        "custom_payload_1",
        "custom_payload_2"
    ]
}

# Generate and save
generator = BCheckGenerator()
scripts = [custom_script]
generator.save_bchecks(scripts, "custom_scripts.json")
```

## 🔄 Workflow Automation

### Available Workflows

#### 1. **Comprehensive Security Scan**
- Site discovery and crawling
- Passive and active scanning
- Vulnerability analysis
- Comprehensive reporting

#### 2. **Quick Security Assessment**
- Basic crawling
- Passive scanning
- Critical vulnerability focus
- Basic reporting

#### 3. **API Security Testing**
- API discovery and mapping
- Authentication testing
- Authorization testing
- Input validation testing
- Rate limiting testing

#### 4. **Critical Vulnerability Focus**
- Critical vulnerability scanning
- High severity focus
- Safe exploitation attempts
- Critical reporting

### Workflow Configuration

```python
# Custom workflow configuration
custom_config = {
    'crawl_depth': 5,
    'scan_intensity': 'thorough',
    'include_custom_checks': True,
    'parallel_scanning': True,
    'api_specific': True,
    'auth_testing': True
}

# Start workflow with custom config
workflow_id = automation.start_workflow(
    'comprehensive_scan', 
    target_url, 
    custom_config
)
```

### Workflow Steps

Each workflow consists of multiple steps:

1. **Site Discovery** - Map application structure
2. **Crawling** - Automated content discovery
3. **Passive Scan** - Non-intrusive vulnerability detection
4. **Active Scan** - Intrusive vulnerability testing
5. **Vulnerability Analysis** - Result analysis and categorization
6. **Report Generation** - Comprehensive reporting

## 🔌 Burp Suite Extension

### Features

- **Advanced Vulnerability Detection** - Custom detection patterns
- **Workflow Integration** - Seamless workflow automation
- **Custom Payload Generation** - Advanced payload libraries
- **Real-time Monitoring** - Live scan progress tracking
- **Comprehensive Reporting** - Detailed vulnerability reports

### Installation

1. **Load Extension in Burp Suite**:
   - Go to Extensions → Extensions
   - Click "Add"
   - Select "Python" as extension type
   - Choose the `burp_extension.py` file

2. **Configure Extension**:
   - Set target URLs
   - Configure scan parameters
   - Enable/disable vulnerability types

### Extension Capabilities

#### Passive Scanning
- Automatic vulnerability detection
- Pattern matching
- Error analysis
- Response analysis

#### Active Scanning
- Custom payload injection
- Vulnerability exploitation
- Response validation
- False positive reduction

#### Custom Payloads
- SQL injection payloads
- XSS payloads
- SSRF payloads
- Command injection payloads
- Path traversal payloads

## 📊 Advanced Features

### 1. **Parallel Processing**
```python
# Run multiple workflows simultaneously
targets = [
    "http://app1.example.com",
    "http://app2.example.com",
    "http://app3.example.com"
]

workflow_ids = []
for target in targets:
    workflow_id = automation.start_workflow('quick_assessment', target)
    workflow_ids.append(workflow_id)

# Monitor all workflows
for workflow_id in workflow_ids:
    status = automation.get_workflow_status(workflow_id)
    print(f"Workflow {workflow_id}: {status['status']}")
```

### 2. **Custom Payload Development**
```python
# Add custom payloads
custom_payloads = [
    "custom_sql_payload",
    "custom_xss_payload",
    "custom_ssrf_payload"
]

# Integrate with existing framework
scanner.config['sql_injection']['payloads'].extend(custom_payloads)
```

### 3. **Workflow Customization**
```python
# Create custom workflow
custom_workflow = {
    'name': 'Custom Security Test',
    'description': 'Custom security testing workflow',
    'steps': [
        'custom_step_1',
        'custom_step_2',
        'custom_step_3'
    ],
    'config': {
        'custom_setting': True,
        'custom_parameter': 'value'
    }
}

# Add to available workflows
automation.workflows['custom_test'] = custom_workflow
```

### 4. **Integration with Other Tools**
```python
# Export results for other tools
results = automation.get_workflow_results(workflow_id)

# Convert to different formats
import json
with open('results.json', 'w') as f:
    json.dump(results, f, indent=2)

# Generate HTML report
html_report = generate_html_report(results)
with open('report.html', 'w') as f:
    f.write(html_report)
```

## 🛡️ Security Considerations

### Safe Testing Practices
- **Always test on authorized systems**
- **Use test environments when possible**
- **Respect rate limits and robots.txt**
- **Avoid destructive payloads in production**

### Payload Safety
- **Non-destructive payloads included**
- **Safe error detection methods**
- **Controlled file read attempts**
- **Safe exploitation testing**

### Workflow Safety
- **Configurable intensity levels**
- **Safe exploitation options**
- **Error handling and recovery**
- **Progress monitoring and cancellation**

## 📈 Performance Optimization

### 1. **Parallel Scanning**
- Multiple concurrent scans
- Resource management
- Progress tracking
- Error handling

### 2. **Intelligent Crawling**
- Depth-limited crawling
- Respect robots.txt
- Rate limiting
- Resource optimization

### 3. **Efficient Payload Testing**
- Payload prioritization
- Early termination
- Result caching
- False positive reduction

## 🔍 Monitoring and Reporting

### Real-time Monitoring
```python
# Monitor workflow progress
def monitor_workflow(workflow_id):
    while True:
        status = automation.get_workflow_status(workflow_id)
        
        print(f"Step {status['current_step']}/{status['total_steps']}")
        print(f"Status: {status['status']}")
        
        if status['status'] in ['completed', 'failed']:
            break
        
        time.sleep(30)

# Start monitoring
threading.Thread(target=monitor_workflow, args=(workflow_id,)).start()
```

### Comprehensive Reporting
```python
# Generate detailed report
def generate_detailed_report(workflow_id):
    results = automation.get_workflow_results(workflow_id)
    
    report = {
        'workflow_info': {
            'id': workflow_id,
            'name': results['name'],
            'target': results['target_url'],
            'status': results['status'],
            'duration': calculate_duration(results)
        },
        'vulnerabilities': {
            'critical': count_vulnerabilities(results, 'Critical'),
            'high': count_vulnerabilities(results, 'High'),
            'medium': count_vulnerabilities(results, 'Medium'),
            'low': count_vulnerabilities(results, 'Low')
        },
        'step_results': results['results'],
        'recommendations': generate_recommendations(results)
    }
    
    return report
```

## 🚨 Troubleshooting

### Common Issues

#### 1. **Burp Suite Connection**
```python
# Test connection
try:
    response = requests.get("http://127.0.0.1:1337/api/v0.1/")
    if response.status_code == 200:
        print("✓ Connected to Burp Suite")
    else:
        print(f"⚠ Warning: Status {response.status_code}")
except Exception as e:
    print(f"✗ Connection failed: {e}")
```

#### 2. **Workflow Failures**
```python
# Check workflow status
status = automation.get_workflow_status(workflow_id)
if status['status'] == 'failed':
    print("Errors:")
    for error in status['errors']:
        print(f"- {error['message']}")
```

#### 3. **BCheck Script Issues**
```python
# Validate BCheck script
def validate_bcheck(script):
    required_fields = ['metadata', 'request', 'response']
    for field in required_fields:
        if field not in script:
            return False, f"Missing required field: {field}"
    return True, "Valid"
```

## 📚 Examples

### Complete Workflow Example
```python
from workflow_automation import WorkflowAutomation
from custom_bchecks import BCheckGenerator
import json

# Initialize components
automation = WorkflowAutomation()
generator = BCheckGenerator()

# Target configuration
target_url = "http://vulnerable-app.example.com"

# 1. Generate custom BCheck scripts
print("Generating custom BCheck scripts...")
scripts = generator.generate_custom_bchecks(target_url, ["id", "user", "data"])
generator.save_bchecks(scripts, "custom_bchecks.json")

# 2. Start comprehensive workflow
print("Starting comprehensive security scan...")
workflow_id = automation.start_workflow('comprehensive_scan', target_url)

# 3. Monitor progress
while True:
    status = automation.get_workflow_status(workflow_id)
    print(f"Progress: {status['current_step']}/{status['total_steps']} - {status['status']}")
    
    if status['status'] in ['completed', 'failed']:
        break
    
    time.sleep(60)

# 4. Get results
results = automation.get_workflow_results(workflow_id)

# 5. Generate final report
if results['status'] == 'completed':
    print("✓ Workflow completed successfully")
    
    # Summary
    total_issues = 0
    for step, result in results['results'].items():
        if result.get('success') and 'issues_found' in result:
            total_issues += result['issues_found']
    
    print(f"Total vulnerabilities found: {total_issues}")
    
    # Save detailed report
    with open('final_report.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("Detailed report saved to final_report.json")
else:
    print("✗ Workflow failed")
    for error in results['errors']:
        print(f"Error: {error['message']}")
```

## 🤝 Contributing

### Adding New Vulnerability Types
1. **Define detection logic** in `CustomBChecks`
2. **Add payloads** to configuration
3. **Create BCheck script** template
4. **Update documentation**

### Improving Workflows
1. **Add new workflow steps** in `WorkflowAutomation`
2. **Enhance automation** capabilities
3. **Improve error handling**
4. **Add new workflow types**

### Extending the Extension
1. **Add new detection methods** in `BurpExtender`
2. **Enhance payload generation**
3. **Improve UI components**
4. **Add new scan types**

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always ensure you have proper authorization before testing any system. The authors are not responsible for any misuse of this tool.

## 🆘 Support

For issues, questions, or contributions:
1. Check the troubleshooting section
2. Review the examples
3. Open an issue on the project repository
4. Contact the development team

---

**Remember**: Always test responsibly and ethically. This framework is designed to help security professionals find and fix vulnerabilities, not to exploit them maliciously. 