# Container Security Scanner - Core Components

The Container Security Scanner is built around four core components that work together to provide comprehensive container security analysis:

## 🔍 Core Component 1: Image Extraction & Layer Analysis

### Overview
Extracts container images and analyzes their layers to understand the complete structure and contents.

### Features
- **Docker Image Extraction**: Uses Docker API to extract images to temporary directories
- **Layer Analysis**: Analyzes each layer individually to understand changes and additions
- **File System Analysis**: Examines files, directories, and metadata in each layer
- **Package Manager Detection**: Identifies OS and language-specific package managers

### Technical Details
```python
# Example usage
sbom_analyzer = SBOMAnalyzer(debug=True)
sbom_results = sbom_analyzer.extract_image_and_generate_sbom("nginx:latest")

# Results include:
# - Image metadata (ID, tags, size, architecture, OS)
# - Layer information (index, ID, size, file analysis)
# - Package manager detection
# - File system structure
```

### Supported Image Formats
- Docker images (via Docker API)
- OCI-compliant images
- Multi-platform images
- Multi-stage builds

### Layer Analysis Capabilities
- **File Count**: Total files, executables, config files
- **Size Analysis**: Layer sizes and compression ratios
- **Change Detection**: Files added, modified, or removed per layer
- **Security Context**: File permissions, ownership, capabilities

## 📦 Core Component 2: SBOM Generation

### Overview
Generates a comprehensive Software Bill of Materials (SBOM) for each layer, identifying all OS packages and language-specific dependencies.

### Features
- **OS Package Detection**: Identifies packages from major Linux distributions
- **Language Package Analysis**: Detects dependencies for multiple programming languages
- **Package Manager Support**: Comprehensive coverage of package managers
- **Deduplication**: Removes duplicate packages across layers

### Supported Package Managers

#### OS Package Managers
- **APT** (Debian/Ubuntu): `dpkg`, `apt`
- **RPM** (Red Hat/CentOS): `rpm`, `yum`, `dnf`
- **APK** (Alpine): `apk`
- **Pacman** (Arch): `pacman`

#### Language Package Managers
- **Python**: `pip`, `poetry`, `pipenv`
- **Node.js**: `npm`, `yarn`
- **Java**: `maven`, `gradle`
- **Go**: `go mod`
- **Ruby**: `bundler`, `gem`
- **PHP**: `composer`
- **Rust**: `cargo`
- **.NET**: `nuget`

### SBOM Structure
```json
{
  "sbom": {
    "os_packages": [
      {
        "name": "openssl",
        "version": "1.1.1f-1ubuntu2",
        "architecture": "amd64",
        "package_manager": "apt",
        "description": "Secure Sockets Layer toolkit"
      }
    ],
    "language_packages": [
      {
        "name": "requests",
        "version": "2.25.1",
        "language": "python",
        "package_manager": "pip",
        "type": "dependency"
      }
    ],
    "total_packages": 150,
    "package_managers_detected": ["apt", "pip", "npm"]
  }
}
```

### Package Detection Methods
- **File System Scanning**: Direct analysis of package manager databases
- **Lock File Parsing**: Analysis of dependency lock files
- **Manifest Analysis**: Parsing of package manifests and configuration files
- **Binary Analysis**: Detection of compiled dependencies

## 🛡️ Core Component 3: Vulnerability Database Matching

### Overview
Matches identified packages against multiple vulnerability databases to identify known security issues.

### Features
- **Multi-Database Support**: Queries multiple vulnerability databases
- **Real-time Updates**: Access to latest vulnerability information
- **Intelligent Matching**: Sophisticated package-to-CVE matching
- **Caching**: Efficient caching to reduce API calls
- **Rate Limiting**: Respects database API rate limits

### Supported Vulnerability Databases

#### National Vulnerability Database (NVD)
- **API Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Coverage**: Comprehensive CVE database
- **Features**: CVSS scoring, detailed descriptions, references
- **Rate Limit**: 5 requests per 6 seconds

#### Red Hat Security Data
- **API Endpoint**: `https://access.redhat.com/hydra/rest/securitydata`
- **Coverage**: Red Hat-specific vulnerabilities
- **Features**: Red Hat severity ratings, affected packages
- **Rate Limit**: 100 requests per hour

#### Ubuntu Security
- **API Endpoint**: `https://ubuntu.com/security/cves.json`
- **Coverage**: Ubuntu-specific vulnerabilities
- **Features**: Ubuntu priority ratings, package information
- **Rate Limit**: 100 requests per hour

### Vulnerability Matching Process
1. **Package Normalization**: Standardize package names and versions
2. **CPE Matching**: Match against Common Platform Enumeration (CPE) identifiers
3. **Version Range Analysis**: Check if package version falls within affected ranges
4. **Severity Assessment**: Determine vulnerability severity using CVSS scores
5. **False Positive Reduction**: Apply filters to reduce false positives

### CVE Data Structure
```json
{
  "cve_id": "CVE-2021-3711",
  "description": "OpenSSL vulnerability in SM2 decryption",
  "severity": "critical",
  "cvss_score": 9.8,
  "published_date": "2021-08-24",
  "last_modified": "2021-08-24",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3711"],
  "database": "nvd",
  "query_package": "openssl",
  "query_version": "1.1.1f-1ubuntu2"
}
```

### Severity Classification
- **Critical**: CVSS 9.0-10.0, immediate action required
- **High**: CVSS 7.0-8.9, prompt remediation needed
- **Medium**: CVSS 4.0-6.9, address within 30 days
- **Low**: CVSS 0.1-3.9, monitor and plan updates
- **Info**: CVSS 0.0, informational findings

## 📊 Core Component 4: Comprehensive Reporting

### Overview
Generates detailed vulnerability reports with risk assessment, remediation guidance, and compliance impact analysis.

### Features
- **Executive Summary**: High-level overview for management
- **Detailed Analysis**: Comprehensive technical details
- **Risk Assessment**: Quantified risk analysis
- **Remediation Guidance**: Actionable remediation steps
- **Compliance Impact**: Regulatory compliance analysis
- **Multiple Formats**: JSON, HTML, PDF, CSV output

### Report Structure

#### Executive Summary
```json
{
  "executive_summary": {
    "overall_risk_level": "High",
    "total_vulnerabilities": 25,
    "critical_vulnerabilities": 2,
    "high_vulnerabilities": 8,
    "medium_vulnerabilities": 12,
    "low_vulnerabilities": 3,
    "packages_scanned": 150,
    "key_findings": [
      "2 critical vulnerabilities require immediate attention",
      "8 high-severity vulnerabilities need prompt remediation"
    ]
  }
}
```

#### Vulnerability Details
- **By Severity**: Grouped by critical, high, medium, low
- **By Package**: Organized by affected packages
- **By Database**: Grouped by vulnerability database source
- **By CVE**: Individual CVE details and references

#### Risk Assessment
```json
{
  "risk_assessment": {
    "risk_level": "High",
    "risk_factors": [
      "Critical vulnerabilities present immediate security risks",
      "High number of high-severity vulnerabilities"
    ],
    "attack_surface": {
      "remote_code_execution": 3,
      "privilege_escalation": 2,
      "information_disclosure": 5,
      "denial_of_service": 1
    }
  }
}
```

#### Remediation Guidance
- **Immediate Actions**: Critical vulnerabilities requiring immediate attention
- **Short-term Actions**: High-severity vulnerabilities (30-day timeline)
- **Long-term Actions**: Medium/low-severity vulnerabilities (90-day timeline)
- **Package Updates**: Specific update commands and versions
- **Security Patches**: Available security patches and workarounds

#### Compliance Impact
```json
{
  "compliance_impact": {
    "soc2": {
      "compliant": false,
      "issues": 10,
      "requirements": ["CC6.1", "CC6.2", "CC6.3"]
    },
    "pci_dss": {
      "compliant": false,
      "issues": 2,
      "requirements": ["6.1", "6.2"]
    },
    "hipaa": {
      "compliant": false,
      "issues": 10,
      "requirements": ["164.312(c)(1)", "164.312(c)(2)"]
    }
  }
}
```

### Supported Compliance Frameworks
- **SOC 2**: Service Organization Control 2
- **PCI DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **ISO 27001**: Information Security Management
- **NIST Cybersecurity Framework**

### Output Formats

#### JSON Format
- Complete structured data
- Machine-readable for automation
- Includes all analysis results
- Suitable for API integration

#### HTML Format
- Rich formatting with tables and charts
- Interactive elements
- Executive-friendly presentation
- Print-ready styling

#### PDF Format
- Professional report layout
- Executive summary and detailed findings
- Compliance-ready documentation
- Archival format

#### CSV Format
- Tabular data export
- Spreadsheet compatibility
- Bulk data analysis
- Integration with other tools

## 🔄 Integration Workflow

### Complete Scan Process
1. **Image Extraction**: Extract and analyze container image layers
2. **SBOM Generation**: Generate comprehensive software bill of materials
3. **Vulnerability Scanning**: Match packages against vulnerability databases
4. **Report Generation**: Create detailed security report with recommendations

### Example Usage
```python
from container_security_scanner import ContainerSecurityScanner

# Initialize scanner
scanner = ContainerSecurityScanner(debug=True)

# Run comprehensive scan
results = scanner.scan_docker_image(
    "nginx:latest",
    tests=["sbom", "vulnerabilities", "secrets", "compliance"]
)

# Generate report
report_file = scanner.generate_report("security_report.json", "json")
```

### Batch Processing
```python
# Batch scan multiple images
scan_list = [
    {"type": "docker_image", "target": "nginx:latest", "tests": ["sbom", "vulnerabilities"]},
    {"type": "docker_image", "target": "python:3.9", "tests": ["sbom", "vulnerabilities"]},
    {"type": "kubernetes_manifests", "target": "./k8s/", "tests": ["rbac", "secrets"]}
]

batch_results = scanner.batch_scan(scan_list)
```

## 🚀 Advanced Features

### Custom Vulnerability Databases
- Add custom vulnerability databases
- Integrate with internal security tools
- Support for proprietary vulnerability feeds
- Custom severity mappings

### SBOM Export Formats
- **SPDX**: Software Package Data Exchange format
- **CycloneDX**: Lightweight SBOM standard
- **SWID**: Software Identification tags
- **Custom formats**: Organization-specific formats

### Vulnerability Prioritization
- **Exploitability**: Consider exploit availability
- **Attack Vector**: Network vs local access
- **Impact Assessment**: Business impact analysis
- **Remediation Effort**: Time and resource requirements

### Integration Capabilities
- **CI/CD Pipelines**: Automated security scanning
- **Container Registries**: Registry-level scanning
- **Kubernetes**: Runtime security monitoring
- **Security Tools**: Integration with existing security stack

## 📈 Performance Optimization

### Caching Strategies
- **Vulnerability Cache**: Cache vulnerability data for 1 hour
- **SBOM Cache**: Cache SBOM results for 24 hours
- **Image Cache**: Cache extracted images for reuse
- **Database Cache**: Cache database query results

### Parallel Processing
- **Multi-threaded Scanning**: Parallel vulnerability database queries
- **Layer Parallelization**: Parallel layer analysis
- **Package Parallelization**: Parallel package scanning
- **Report Generation**: Parallel report format generation

### Resource Management
- **Memory Optimization**: Efficient memory usage for large images
- **Disk Space**: Temporary file cleanup
- **Network Optimization**: Efficient API usage
- **CPU Utilization**: Optimal thread management

## 🔧 Configuration Options

### Scanner Configuration
```yaml
# config.yaml
scanner:
  debug: false
  parallel_workers: 4
  cache_ttl: 3600
  timeout: 300

vulnerability_databases:
  nvd:
    enabled: true
    rate_limit: 5
    timeout: 30
  redhat:
    enabled: true
    rate_limit: 100
    timeout: 30
  ubuntu:
    enabled: true
    rate_limit: 100
    timeout: 30

sbom:
  include_dev_dependencies: false
  include_test_dependencies: false
  max_package_versions: 1000
  deduplicate: true

reporting:
  include_references: true
  include_remediation: true
  compliance_frameworks: ["soc2", "pci_dss", "hipaa"]
  output_formats: ["json", "html"]
```

### Environment Variables
```bash
# Database configuration
NVD_API_KEY=your_nvd_api_key
REDHAT_API_KEY=your_redhat_api_key

# Scanner configuration
CONTAINER_SCANNER_DEBUG=true
CONTAINER_SCANNER_WORKERS=4
CONTAINER_SCANNER_CACHE_TTL=3600

# Output configuration
CONTAINER_SCANNER_OUTPUT_DIR=./reports
CONTAINER_SCANNER_LOG_LEVEL=INFO
```

## 🛠️ Troubleshooting

### Common Issues

#### Docker Connection Issues
```bash
# Check Docker daemon
docker info

# Verify Docker socket permissions
ls -la /var/run/docker.sock

# Test Docker API
curl -s --unix-socket /var/run/docker.sock http://localhost/version
```

#### Vulnerability Database Access
```bash
# Test NVD API access
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssl"

# Check rate limiting
# NVD: 5 requests per 6 seconds
# Red Hat: 100 requests per hour
# Ubuntu: 100 requests per hour
```

#### Memory Issues
```bash
# Monitor memory usage
docker stats

# Increase Docker memory limit
docker run --memory=4g your-image

# Use tmpfs for temporary files
docker run --tmpfs /tmp your-image
```

### Debug Mode
```python
# Enable debug logging
scanner = ContainerSecurityScanner(debug=True)

# Check debug logs
tail -f container_security_debug.log

# Verbose output
python -m container_security_scanner --image nginx:latest --debug --verbose
```

### Performance Tuning
```yaml
# Optimize for large images
scanner:
  parallel_workers: 8
  memory_limit: "4G"
  disk_cache: true
  network_timeout: 60

# Optimize for batch processing
batch:
  max_concurrent_scans: 4
  retry_failed: true
  continue_on_error: true
```

## 📚 Additional Resources

### Documentation
- [Installation Guide](INSTALLATION.md)
- [Usage Guide](USAGE.md)
- [API Reference](API_REFERENCE.md)
- [Examples](examples/)

### Tools and Integrations
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [NVD Database](https://nvd.nist.gov/)
- [Red Hat Security](https://access.redhat.com/security/)

### Standards and Frameworks
- [SPDX Specification](https://spdx.dev/specifications/)
- [CycloneDX Specification](https://cyclonedx.org/specification/)
- [CVSS Scoring](https://www.first.org/cvss/)
- [CPE Naming](https://nvd.nist.gov/products/cpe)

### Community and Support
- [GitHub Issues](https://github.com/your-repo/issues)
- [Security Advisories](https://github.com/your-repo/security/advisories)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md) 