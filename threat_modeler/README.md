# Threat Modeling Tool

A comprehensive threat modeling tool for application security analysis, supporting multiple methodologies including STRIDE, PASTA, and DREAD.

## Features

- **Multiple Methodologies**: Support for STRIDE, PASTA, and DREAD threat modeling approaches
- **Flexible Input**: Interactive CLI and file-based input (JSON, YAML, text)
- **Comprehensive Analysis**: Automated threat enumeration and risk assessment
- **Rich Reporting**: Generate reports in Markdown, HTML, and JSON formats
- **Debug Support**: Built-in debugging and verbose logging
- **Extensible**: Easy to extend with custom threat libraries and methodologies
- **AI-Assisted Threat Discovery**: Advanced machine learning capabilities for enhanced threat detection

### AI Capabilities

The tool includes advanced AI-assisted threat discovery features:

- **CVE Analysis**: Transformer models trained on CVE databases to identify potential vulnerabilities
- **Architecture Pattern Recognition**: ML-based recognition of common architectural patterns and their associated threats
- **Natural Language Processing**: Analysis of design documents and requirements for security insights
- **Predictive Threat Modeling**: Machine learning models that predict potential threats based on historical data
- **Intelligent Threat Synthesis**: Combines traditional and AI-identified threats for comprehensive analysis

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
cd threat_modeler
pip install -r requirements.txt
```

### Optional Dependencies

For PDF generation (requires additional system dependencies):
```bash
# On Ubuntu/Debian
sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

# On macOS
brew install cairo pango gdk-pixbuf libffi
```

## Quick Start

### Interactive Mode

Run the tool interactively to guide you through the threat modeling process:

```bash
python threat_modeler_cli.py
```

### File Input Mode

Use a predefined architecture file:

```bash
python threat_modeler_cli.py -i architecture.yaml -m STRIDE
```

### AI-Assisted Analysis

Enable AI capabilities for enhanced threat discovery:

```bash
python threat_modeler_cli.py --ai -i architecture.yaml -m STRIDE
```

### Generate HTML Report

```bash
python threat_modeler_cli.py -i architecture.json -o html -f report.html
```

## Usage

### Command Line Options

```bash
python threat_modeler_cli.py [OPTIONS]

Options:
  -i, --input-file TEXT     Input architecture file (JSON, YAML, or text)
  -m, --methodology TEXT    Threat modeling methodology (STRIDE/PASTA/DREAD)
  -o, --output-format TEXT  Output report format (markdown/html/json)
  -f, --output-file TEXT    Output file path
  --ai                      Enable AI-assisted threat discovery
  --debug                   Enable debug mode
  --version                 Show version and exit
  --help                    Show help message
```

### AI-Assisted Analysis

When using the `--ai` flag, the tool will:

1. **CVE Analysis**: Search CVE databases for vulnerabilities matching your architecture
2. **Pattern Recognition**: Identify architectural patterns and their known threats
3. **Predictive Modeling**: Use ML models to predict potential threats
4. **Threat Synthesis**: Combine traditional and AI-identified threats
5. **Enhanced Recommendations**: Provide AI-powered security recommendations

Example AI analysis:
```bash
# Run comprehensive AI-assisted analysis
python threat_modeler_cli.py --ai -i architecture.yaml -m STRIDE --debug

# Test AI capabilities
python examples/test_ai_capabilities.py
```

### Input File Formats

#### JSON Format

```json
{
  "name": "E-commerce Application",
  "description": "Online shopping platform with payment processing",
  "components": [
    {
      "name": "Web Frontend",
      "type": "web_server",
      "description": "React-based user interface",
      "technologies": ["React", "Node.js"],
      "external": false
    },
    {
      "name": "Payment Gateway",
      "type": "api",
      "description": "Third-party payment processing",
      "technologies": ["Stripe API"],
      "external": true
    }
  ],
  "data_flows": [
    {
      "from": "Web Frontend",
      "to": "API Gateway",
      "protocol": "HTTPS",
      "data_type": "user_data",
      "encrypted": true
    }
  ],
  "trust_boundaries": [
    {
      "name": "External Systems",
      "components": ["Payment Gateway"],
      "description": "Third-party services"
    }
  ],
  "assets": [
    {
      "name": "Customer Data",
      "type": "data",
      "value": "high",
      "description": "Personal and payment information"
    }
  ]
}
```

#### YAML Format

```yaml
name: "E-commerce Application"
description: "Online shopping platform with payment processing"
components:
  - name: "Web Frontend"
    type: "web_server"
    description: "React-based user interface"
    technologies: ["React", "Node.js"]
    external: false
  - name: "Payment Gateway"
    type: "api"
    description: "Third-party payment processing"
    technologies: ["Stripe API"]
    external: true
data_flows:
  - from: "Web Frontend"
    to: "API Gateway"
    protocol: "HTTPS"
    data_type: "user_data"
    encrypted: true
trust_boundaries:
  - name: "External Systems"
    components: ["Payment Gateway"]
    description: "Third-party services"
assets:
  - name: "Customer Data"
    type: "data"
    value: "high"
    description: "Personal and payment information"
```

#### Text Format

```
Name: E-commerce Application
Description: Online shopping platform with payment processing

Components:
- Web Frontend (web_server) - React-based user interface
- Payment Gateway (api) - Third-party payment processing
- Database (database) - PostgreSQL database for user data

Data Flows:
- Web Frontend -> API Gateway (HTTPS) - user_data
- API Gateway -> Database (TCP) - config_data

Trust Boundaries:
- External Systems: Payment Gateway - Third-party services
- Internal Systems: Web Frontend, API Gateway, Database - Application components

Assets:
- Customer Data (data) - high - Personal and payment information
- Payment Tokens (data) - critical - Payment processing tokens
```

## Methodologies

### STRIDE

**S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege

- **Spoofing**: Identity spoofing and session hijacking
- **Tampering**: Data and configuration tampering
- **Repudiation**: Action repudiation and audit failures
- **Information Disclosure**: Sensitive data exposure
- **Denial of Service**: Resource exhaustion and service disruption
- **Elevation of Privilege**: Privilege escalation and code execution

### PASTA

**P**rocess for **A**ttack **S**imulation and **T**hreat **A**nalysis

- Focuses on business impact and attack simulation
- Considers threat intelligence and attack vectors
- Emphasizes risk-based approach to security

### DREAD

**D**amage, **R**eproducibility, **E**xploitability, **A**ffected Users, **D**iscoverability

- **Damage**: Potential damage to business
- **Reproducibility**: How easy to reproduce the attack
- **Exploitability**: How easy to exploit the vulnerability
- **Affected Users**: Number of affected users
- **Discoverability**: How easy to discover the vulnerability

## Examples

### Basic Web Application

```bash
# Interactive analysis
python threat_modeler_cli.py

# File-based analysis
python threat_modeler_cli.py -i examples/basic_web_app.yaml -m STRIDE
```

### Microservices Architecture

```bash
python threat_modeler_cli.py -i examples/microservices.json -m PASTA -o html -f microservices_report.html
```

### Cloud-Native Application

```bash
python threat_modeler_cli.py -i examples/cloud_native.yaml -m DREAD --debug
```

## Output Formats

### Markdown Report

Default format with comprehensive threat analysis, including:
- Executive summary
- Architecture overview
- Detailed threat analysis
- Risk assessment
- Recommendations

### HTML Report

Rich HTML format with:
- Styled tables and sections
- Color-coded severity levels
- Interactive elements
- Professional formatting

### JSON Report

Machine-readable format for:
- Integration with other tools
- Custom analysis
- API consumption
- Data processing

## Debug Mode

Enable debug mode for detailed logging and troubleshooting:

```bash
python threat_modeler_cli.py --debug -i architecture.yaml
```

Debug output includes:
- Architecture parsing details
- Threat analysis steps
- Risk calculation process
- Report generation information

## Architecture Components

### Components

Define the building blocks of your application:
- **Name**: Component identifier
- **Type**: Component category (web_server, api, database, etc.)
- **Description**: Component purpose and functionality
- **Technologies**: Used technologies and frameworks
- **External**: Whether it's an external/third-party component

### Data Flows

Define how data moves between components:
- **From/To**: Source and destination components
- **Protocol**: Communication protocol (HTTP, HTTPS, TCP, etc.)
- **Data Type**: Type of data being transmitted
- **Encrypted**: Whether data is encrypted in transit

### Trust Boundaries

Define security boundaries:
- **Name**: Boundary identifier
- **Components**: Components within the boundary
- **Description**: Boundary purpose and security implications

### Assets

Define valuable resources:
- **Name**: Asset identifier
- **Type**: Asset category (data, service, infrastructure, etc.)
- **Value**: Asset value (low, medium, high, critical)
- **Description**: Asset description and importance

## Risk Assessment

The tool automatically calculates risk scores based on:

- **Threat Severity**: High, Medium, Low
- **Affected Components**: Number and importance
- **Data Sensitivity**: Type and value of data
- **Architecture Complexity**: Number of components and flows
- **External Dependencies**: Third-party components

## Recommendations

The tool provides actionable recommendations:

- **Immediate Actions**: High-priority threats requiring immediate attention
- **Short-term Actions**: Medium-priority threats for near-term planning
- **Long-term Actions**: Low-priority threats for ongoing monitoring

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **File Format Errors**: Check input file syntax and format
3. **Permission Errors**: Ensure write permissions for output files
4. **Memory Issues**: Large architectures may require more memory

### Debug Tips

1. Use `--debug` flag for detailed logging
2. Check input file format and syntax
3. Verify component names in data flows
4. Review trust boundary definitions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review example files
3. Enable debug mode for detailed logging
4. Create an issue with detailed information 