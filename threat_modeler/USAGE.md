# Threat Modeling Tool Usage Guide

This guide provides comprehensive instructions for using the Threat Modeling Tool effectively.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Interactive Mode](#interactive-mode)
3. [File Input Mode](#file-input-mode)
4. [Methodologies](#methodologies)
5. [Input Formats](#input-formats)
6. [Output Formats](#output-formats)
7. [Advanced Usage](#advanced-usage)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)
10. [Examples](#examples)

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd threat_modeler

# Install dependencies
pip install -r requirements.txt

# Run interactive mode
python threat_modeler_cli.py
```

### Basic Usage

```bash
# Interactive threat modeling
python threat_modeler_cli.py

# File-based threat modeling
python threat_modeler_cli.py -i architecture.yaml -m STRIDE

# Generate HTML report
python threat_modeler_cli.py -i architecture.json -o html -f report.html
```

## Interactive Mode

Interactive mode guides you through the threat modeling process step by step.

### Starting Interactive Mode

```bash
python threat_modeler_cli.py
```

### Interactive Workflow

1. **Application Information**
   - Enter application name and description
   - Provide context about the application

2. **Components**
   - Add each component of your architecture
   - Specify component type, description, and technologies
   - Indicate if components are external

3. **Data Flows**
   - Define how data moves between components
   - Specify protocols, data types, and encryption

4. **Trust Boundaries**
   - Define security boundaries
   - Group components by trust levels

5. **Assets**
   - Identify valuable resources
   - Assign value levels (low, medium, high, critical)

6. **Methodology Selection**
   - Choose STRIDE, PASTA, or DREAD
   - Understand the differences between methodologies

### Example Interactive Session

```
Application name: My Web App
Application description: E-commerce platform

Add a component? (y/n): y
Component name: Web Server
Component type: web_server
Component description: Apache web server
Technologies used: Apache, PHP
Is this an external component? (y/n): n

Add a component? (y/n): y
Component name: Database
Component type: database
Component description: MySQL database
Technologies used: MySQL
Is this an external component? (y/n): n

Add a component? (y/n): n

Add a data flow? (y/n): y
From component: Web Server
To component: Database
Data type: user_data
Protocol: HTTPS
Is data encrypted in transit? (y/n): y

Add a data flow? (y/n): n

Select methodology:
1. STRIDE
2. PASTA
3. DREAD
Select methodology: 1
```

## File Input Mode

File input mode allows you to define your architecture in a file and process it automatically.

### Supported File Formats

- **JSON**: Structured data format
- **YAML**: Human-readable structured format
- **Text**: Simple text-based format

### Basic File Input

```bash
# YAML file
python threat_modeler_cli.py -i architecture.yaml -m STRIDE

# JSON file
python threat_modeler_cli.py -i architecture.json -m PASTA

# Text file
python threat_modeler_cli.py -i architecture.txt -m DREAD
```

### File Input with Output

```bash
# Generate HTML report
python threat_modeler_cli.py -i architecture.yaml -o html -f report.html

# Generate JSON report
python threat_modeler_cli.py -i architecture.json -o json -f report.json

# Generate markdown report
python threat_modeler_cli.py -i architecture.yaml -o markdown -f report.md
```

## Methodologies

### STRIDE

**Best for**: General application security analysis

**Categories**:
- **S**poofing: Identity spoofing and session hijacking
- **T**ampering: Data and configuration tampering
- **R**epudiation: Action repudiation and audit failures
- **I**nformation Disclosure: Sensitive data exposure
- **D**enial of Service: Resource exhaustion and service disruption
- **E**levation of Privilege: Privilege escalation and code execution

**When to use**:
- General security assessments
- Development team education
- Initial threat modeling

### PASTA

**Best for**: Business-focused threat analysis

**Focus areas**:
- Business impact analysis
- Attack simulation
- Threat intelligence integration
- Risk-based approach

**When to use**:
- Business-critical applications
- Risk management focus
- Executive reporting

### DREAD

**Best for**: Risk scoring and prioritization

**Categories**:
- **D**amage: Potential damage to business
- **R**eproducibility: How easy to reproduce the attack
- **E**xploitability: How easy to exploit the vulnerability
- **A**ffected Users: Number of affected users
- **D**iscoverability: How easy to discover the vulnerability

**When to use**:
- Risk prioritization
- Quantitative risk assessment
- Security metrics

## Input Formats

### JSON Format

```json
{
  "name": "My Application",
  "description": "Application description",
  "components": [
    {
      "name": "Web Server",
      "type": "web_server",
      "description": "Web server description",
      "technologies": ["Apache", "PHP"],
      "external": false
    }
  ],
  "data_flows": [
    {
      "from": "Web Server",
      "to": "Database",
      "protocol": "HTTPS",
      "data_type": "user_data",
      "encrypted": true
    }
  ],
  "trust_boundaries": [
    {
      "name": "Internal Network",
      "components": ["Web Server", "Database"],
      "description": "Internal components"
    }
  ],
  "assets": [
    {
      "name": "User Data",
      "type": "data",
      "value": "high",
      "description": "User information"
    }
  ]
}
```

### YAML Format

```yaml
name: "My Application"
description: "Application description"
components:
  - name: "Web Server"
    type: "web_server"
    description: "Web server description"
    technologies: ["Apache", "PHP"]
    external: false
data_flows:
  - from: "Web Server"
    to: "Database"
    protocol: "HTTPS"
    data_type: "user_data"
    encrypted: true
trust_boundaries:
  - name: "Internal Network"
    components: ["Web Server", "Database"]
    description: "Internal components"
assets:
  - name: "User Data"
    type: "data"
    value: "high"
    description: "User information"
```

### Text Format

```
Name: My Application
Description: Application description

Components:
- Web Server (web_server) - Apache web server
- Database (database) - MySQL database

Data Flows:
- Web Server -> Database (HTTPS) - user_data

Trust Boundaries:
- Internal Network: Web Server, Database - Internal components

Assets:
- User Data (data) - high - User information
```

## Output Formats

### Markdown Report

Default format with comprehensive analysis:

```bash
python threat_modeler_cli.py -i architecture.yaml -o markdown -f report.md
```

**Features**:
- Executive summary
- Architecture overview
- Detailed threat analysis
- Risk assessment
- Recommendations

### HTML Report

Rich HTML format with styling:

```bash
python threat_modeler_cli.py -i architecture.yaml -o html -f report.html
```

**Features**:
- Professional styling
- Color-coded severity levels
- Interactive elements
- Print-friendly layout

### JSON Report

Machine-readable format:

```bash
python threat_modeler_cli.py -i architecture.yaml -o json -f report.json
```

**Features**:
- Structured data
- API integration
- Custom analysis
- Data processing

## Advanced Usage

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
python threat_modeler_cli.py --debug -i architecture.yaml
```

**Debug output includes**:
- Architecture parsing details
- Threat analysis steps
- Risk calculation process
- Report generation information

### Batch Processing

Process multiple architectures:

```bash
#!/bin/bash
for file in architectures/*.yaml; do
    python threat_modeler_cli.py -i "$file" -o html -f "reports/$(basename "$file" .yaml).html"
done
```

### Custom Threat Libraries

Extend the tool with custom threats:

```python
# Add custom threats to threat_engine.py
custom_threats = {
    "Custom Category": [
        {
            "title": "Custom Threat",
            "description": "Custom threat description",
            "examples": ["Example 1", "Example 2"],
            "risk_factors": ["factor1", "factor2"]
        }
    ]
}
```

### Integration with CI/CD

```yaml
# GitHub Actions example
name: Threat Modeling
on: [push, pull_request]
jobs:
  threat-modeling:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - name: Install dependencies
        run: |
          pip install -r threat_modeler/requirements.txt
      - name: Run threat modeling
        run: |
          python threat_modeler/threat_modeler_cli.py -i architecture.yaml -o json -f threat_report.json
      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: threat-report
          path: threat_report.json
```

## Best Practices

### Architecture Definition

1. **Be Comprehensive**
   - Include all components, even external ones
   - Define all data flows
   - Identify all trust boundaries

2. **Be Specific**
   - Use clear, descriptive names
   - Specify technologies and protocols
   - Define data types accurately

3. **Consider Context**
   - Include business context
   - Consider regulatory requirements
   - Account for deployment environment

### Threat Analysis

1. **Use Multiple Methodologies**
   - Start with STRIDE for general analysis
   - Use PASTA for business focus
   - Use DREAD for risk scoring

2. **Validate Results**
   - Review threat relevance
   - Verify risk scores
   - Check mitigation suggestions

3. **Document Decisions**
   - Record methodology choices
   - Document assumptions
   - Track risk acceptance

### Report Generation

1. **Choose Appropriate Format**
   - Markdown for documentation
   - HTML for presentations
   - JSON for integration

2. **Review and Customize**
   - Review generated reports
   - Add business context
   - Customize recommendations

3. **Share Effectively**
   - Share with stakeholders
   - Include in security reviews
   - Use for training

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Solution: Install dependencies
   pip install -r requirements.txt
   ```

2. **File Format Errors**
   ```bash
   # Check file syntax
   python -c "import yaml; yaml.safe_load(open('architecture.yaml'))"
   ```

3. **Permission Errors**
   ```bash
   # Check file permissions
   ls -la architecture.yaml
   chmod 644 architecture.yaml
   ```

4. **Memory Issues**
   ```bash
   # Use debug mode to identify issues
   python threat_modeler_cli.py --debug -i architecture.yaml
   ```

### Debug Tips

1. **Enable Debug Mode**
   ```bash
   python threat_modeler_cli.py --debug -i architecture.yaml
   ```

2. **Check File Format**
   ```bash
   # Validate JSON
   python -m json.tool architecture.json
   
   # Validate YAML
   python -c "import yaml; yaml.safe_load(open('architecture.yaml'))"
   ```

3. **Verify Dependencies**
   ```bash
   pip list | grep -E "(click|pyyaml|jinja2|rich)"
   ```

4. **Check Python Version**
   ```bash
   python --version
   # Should be 3.8 or higher
   ```

### Performance Optimization

1. **Large Architectures**
   - Break into smaller components
   - Use external components for third-party services
   - Focus on critical data flows

2. **Memory Usage**
   - Close other applications
   - Use simpler output formats
   - Process in batches

3. **Processing Time**
   - Use appropriate methodology
   - Limit threat categories
   - Optimize architecture definition

## Examples

### Basic Web Application

```bash
# Run with basic web app
python threat_modeler_cli.py -i examples/basic_web_app.yaml -m STRIDE
```

### Microservices Architecture

```bash
# Run with microservices
python threat_modeler_cli.py -i examples/microservices.json -m PASTA -o html -f microservices_report.html
```

### Cloud-Native Application

```bash
# Run with cloud-native app
python threat_modeler_cli.py -i examples/cloud_native.yaml -m DREAD --debug
```

### Custom Architecture

```bash
# Create your own architecture file
cat > my_architecture.yaml << EOF
name: "My Custom App"
description: "Custom application description"
components:
  - name: "My Component"
    type: "service"
    description: "Custom component"
    technologies: ["Python"]
    external: false
EOF

# Run analysis
python threat_modeler_cli.py -i my_architecture.yaml -m STRIDE
```

### Batch Processing

```bash
# Process multiple architectures
for methodology in STRIDE PASTA DREAD; do
    python threat_modeler_cli.py -i architecture.yaml -m $methodology -o html -f "report_${methodology}.html"
done
```

### Integration Example

```python
# Python integration
from src.threat_modeler import ThreatModeler

# Initialize
modeler = ThreatModeler()

# Load architecture
with open('architecture.yaml', 'r') as f:
    architecture = yaml.safe_load(f)

# Analyze threats
threats = modeler.engine.analyze_threats(architecture, 'STRIDE')

# Generate report
report = modeler.report_gen.generate_report(threats, architecture, 'STRIDE', 'markdown')

# Save report
with open('report.md', 'w') as f:
    f.write(report)
```

This usage guide provides comprehensive information for using the Threat Modeling Tool effectively. For additional support, refer to the main README or create an issue in the repository. 