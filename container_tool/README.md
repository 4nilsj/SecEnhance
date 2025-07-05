# Container Security Scanner

A comprehensive container security testing tool designed for senior AppSec engineers. Supports Docker images, Kubernetes configurations, runtime security, vulnerability scanning, and compliance checking.

## 🚀 Features

### **Docker Image Security**
- **Configuration Analysis**: Dockerfile security best practices
- **Layer Inspection**: Security analysis of image layers
- **Base Image Analysis**: Vulnerability assessment of base images
- **Secret Detection**: Hardcoded secrets and credentials
- **Best Practices**: Security compliance checking

### **Kubernetes Security**
- **RBAC Analysis**: Role-based access control validation
- **Network Policies**: Network security configuration analysis
- **Pod Security Standards**: Compliance with security standards
- **Configuration Validation**: Security misconfiguration detection
- **Privilege Escalation**: Risk assessment and detection

### **Runtime Security**
- **Process Analysis**: Running processes and security risks
- **Network Analysis**: Network connections and traffic patterns
- **Filesystem Analysis**: File permissions and sensitive data
- **Capabilities Analysis**: Container capabilities assessment
- **Privilege Analysis**: Privilege escalation detection

### **Vulnerability Scanning**
- **CVE Detection**: Known vulnerability identification
- **Package Analysis**: Outdated and vulnerable packages
- **Dependency Scanning**: Third-party dependency risks
- **Custom Signatures**: Custom vulnerability patterns
- **Severity Assessment**: Risk prioritization

### **Compliance Checking**
- **SOC2 Compliance**: Security controls validation
- **PCI DSS**: Payment card industry standards
- **HIPAA**: Healthcare data protection
- **NIST Framework**: Cybersecurity framework
- **Custom Policies**: Organization-specific compliance

### **Enterprise Features**
- **Batch Processing**: Multiple container analysis
- **Comprehensive Reporting**: Multiple output formats
- **Integration Ready**: CI/CD pipeline integration
- **Policy Enforcement**: Automated compliance checking
- **Risk Scoring**: Quantitative risk assessment

## 📋 Requirements

- Python 3.8+
- Docker Engine (for image analysis)
- Kubernetes cluster access (for K8s analysis)
- Network access for vulnerability databases

## 🛠️ Installation

```bash
# Clone the repository
git clone <repository-url>
cd container_tool

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Optional: Install Docker and Kubernetes tools
# Docker: https://docs.docker.com/get-docker/
# kubectl: https://kubernetes.io/docs/tasks/tools/
```

## 🎯 Quick Start

### **Docker Image Scanning**
```bash
# Basic Docker image scan
python src/container_security_scanner.py --image nginx:latest

# Comprehensive image analysis
python src/container_security_scanner.py --image nginx:latest --comprehensive

# Specific tests only
python src/container_security_scanner.py --image nginx:latest --tests vulnerabilities,secrets

# Debug mode
python src/container_security_scanner.py --image nginx:latest --debug
```

### **Kubernetes Manifest Scanning**
```bash
# Scan Kubernetes manifests
python src/container_security_scanner.py --kubernetes manifests/

# Scan specific manifest file
python src/container_security_scanner.py --kubernetes deployment.yaml

# RBAC analysis
python src/container_security_scanner.py --kubernetes manifests/ --tests rbac,network_policies

# Pod security standards
python src/container_security_scanner.py --kubernetes manifests/ --tests compliance
```

### **Runtime Security Analysis**
```bash
# Scan running container
python src/container_security_scanner.py --runtime container_id

# Scan all running containers
python src/container_security_scanner.py --runtime all

# Specific runtime tests
python src/container_security_scanner.py --runtime container_id --tests processes,network
```

### **Container Registry Scanning**
```bash
# Scan container registry
python src/container_security_scanner.py --registry registry.example.com

# Scan with specific tests
python src/container_security_scanner.py --registry registry.example.com --tests vulnerabilities,policies
```

### **Batch Analysis**
```bash
# Analyze multiple targets
python src/container_security_scanner.py --batch targets.json --verbose
```

## 📊 Output Formats

The tool generates comprehensive reports in multiple formats:

- **JSON**: Machine-readable detailed results
- **HTML**: Interactive web-based reports
- **PDF**: Executive summary reports
- **CSV**: Spreadsheet-compatible data

## 🔧 Configuration

### **Configuration File Example**
```yaml
# config.yaml
docker:
  scan_layers: true
  check_secrets: true
  analyze_history: true

kubernetes:
  rbac_analysis: true
  network_policies: true
  pod_security_standards: true

vulnerability:
  cve_databases:
    - nvd
    - redhat
    - ubuntu
  severity_threshold: medium

compliance:
  frameworks:
    - soc2
    - pci_dss
    - hipaa
  custom_policies: true

reporting:
  include_details: true
  risk_scoring: true
  remediation_guidance: true
```

### **Batch Analysis File Example**
```json
[
  {
    "type": "docker_image",
    "target": "nginx:latest",
    "tests": ["vulnerabilities", "secrets", "compliance"]
  },
  {
    "type": "kubernetes_manifests",
    "target": "manifests/",
    "tests": ["rbac", "network_policies", "compliance"]
  },
  {
    "type": "runtime_security",
    "target": "all",
    "tests": ["processes", "network", "filesystem"]
  }
]
```

## 🎯 Advanced Usage

### **Custom Test Scenarios**
```python
from src.container_security_scanner import ContainerSecurityScanner

# Initialize scanner
scanner = ContainerSecurityScanner(debug=True)

# Custom Docker image analysis
results = scanner.scan_docker_image(
    image_name="nginx:latest",
    tests=["vulnerabilities", "secrets", "compliance"]
)

# Custom Kubernetes analysis
results = scanner.scan_kubernetes_manifests(
    manifest_path="manifests/",
    tests=["rbac", "network_policies", "compliance"]
)
```

### **Integration with CI/CD**
```yaml
# GitHub Actions example
- name: Container Security Scan
  run: |
    python src/container_security_scanner.py \
      --image ${{ steps.build.outputs.image }} \
      --tests vulnerabilities,secrets,compliance \
      --output security_report.json \
      --format json
```

## 🔍 Test Categories

### **Docker Security Tests**
- Image configuration analysis
- Layer security inspection
- Base image vulnerability assessment
- Secret detection and analysis
- Security best practices validation

### **Kubernetes Security Tests**
- RBAC configuration analysis
- Network policy validation
- Pod security standards compliance
- Configuration misconfiguration detection
- Privilege escalation risk assessment

### **Runtime Security Tests**
- Process analysis and monitoring
- Network connection analysis
- Filesystem security assessment
- Container capabilities analysis
- Privilege escalation detection

### **Vulnerability Tests**
- CVE database scanning
- Package vulnerability assessment
- Dependency security analysis
- Custom vulnerability patterns
- Severity-based prioritization

### **Compliance Tests**
- SOC2 control validation
- PCI DSS requirement checking
- HIPAA compliance assessment
- NIST framework alignment
- Custom policy enforcement

## 📈 Reporting

### **Executive Summary**
- Overall risk assessment
- Critical findings summary
- Compliance status overview
- Remediation priorities

### **Technical Details**
- Vulnerability descriptions
- Configuration issues
- Security violation details
- Impact assessment

### **Remediation Guidance**
- Fix recommendations
- Configuration examples
- Security best practices
- Reference links

## 🛡️ Security Considerations

- **Access Control**: Ensure proper access to containers and clusters
- **Data Protection**: Avoid scanning production data
- **Network Security**: Secure communication with vulnerability databases
- **Compliance**: Follow organizational security policies
- **Reporting**: Report findings through proper channels

## 🔧 Troubleshooting

### **Common Issues**

**Docker Connection Errors**
```bash
# Check Docker daemon
docker ps

# Verify Docker socket permissions
ls -la /var/run/docker.sock
```

**Kubernetes Access Issues**
```bash
# Check kubectl configuration
kubectl config current-context

# Verify cluster access
kubectl get nodes
```

**Vulnerability Database Issues**
```bash
# Check network connectivity
curl -I https://nvd.nist.gov/vuln/data-feeds

# Verify proxy settings
echo $http_proxy $https_proxy
```

**Performance Issues**
```bash
# Reduce scan scope
python src/container_security_scanner.py --image nginx:latest --tests vulnerabilities

# Use specific configuration
python src/container_security_scanner.py --image nginx:latest --config fast_scan.yaml
```

## 📚 Examples

See the `examples/` directory for:
- Sample Docker images
- Kubernetes manifest examples
- Configuration templates
- Integration examples

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check the docs/ directory
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Security**: Report security issues privately

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Always ensure you have proper authorization before scanning containers and clusters. 