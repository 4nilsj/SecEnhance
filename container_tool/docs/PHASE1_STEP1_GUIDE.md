# Phase 1, Step 1: Debian Image Extraction Guide

## Overview

Phase 1, Step 1 implements **Basic OS Package Vulnerability Scanning for Debian-based images** with a focus on **Image Extraction** using the Docker SDK to pull images and extract their layers as tarballs.

## What This Phase Does

### Core Functionality
- **Image Pulling**: Uses Docker SDK to pull Debian-based container images
- **Layer Extraction**: Extracts all image layers as tarballs for analysis
- **Debian File Detection**: Identifies Debian-specific files and package information
- **Package Analysis**: Extracts and analyzes OS packages from each layer
- **Comprehensive Reporting**: Generates detailed extraction reports

### Technical Implementation
- **Docker SDK Integration**: Leverages `docker-py` for image operations
- **Layer-by-Layer Analysis**: Processes each layer individually
- **File System Analysis**: Scans for Debian package files and metadata
- **Package Database Parsing**: Extracts package information from Debian databases
- **Memory-Efficient Processing**: Handles large images without excessive memory usage

## Prerequisites

### System Requirements
- Python 3.8+
- Docker Engine running locally
- Sufficient disk space for image extraction
- Network access for pulling images

### Dependencies
```bash
pip install docker-py rich pyyaml
```

### Docker Access
Ensure your user has access to Docker:
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER

# Or run with sudo (not recommended for production)
sudo docker images
```

## Usage

### Command Line Interface

#### Basic Usage
```bash
# Scan a Debian image
python container_security_scanner.py --debian-phase1 debian:bullseye-slim

# With debug output
python container_security_scanner.py --debian-phase1 debian:bullseye-slim --debug

# With verbose output
python container_security_scanner.py --debian-phase1 debian:bullseye-slim --verbose
```

#### Advanced Usage
```bash
# Generate HTML report
python container_security_scanner.py --debian-phase1 debian:bullseye-slim --format html --output debian_report.html

# Generate JSON report
python container_security_scanner.py --debian-phase1 debian:bullseye-slim --format json --output debian_analysis.json
```

### Programmatic Usage

#### Basic Analysis
```python
from container_security_scanner import ContainerSecurityScanner

# Initialize scanner
scanner = ContainerSecurityScanner(debug=True)

# Run Phase 1, Step 1 analysis
results = scanner.scan_debian_image_phase1("debian:bullseye-slim")

# Access results
debian_data = results['debian_analysis']
print(f"Extracted {len(debian_data['layers'])} layers")
print(f"Total size: {debian_data['total_size'] / (1024*1024):.2f} MB")
```

#### Batch Processing
```python
# Create batch configuration
batch_config = [
    {
        "type": "debian_phase1",
        "target": "debian:bullseye-slim",
        "description": "Debian Bullseye Slim"
    },
    {
        "type": "debian_phase1",
        "target": "ubuntu:20.04",
        "description": "Ubuntu 20.04"
    }
]

# Run batch analysis
batch_results = scanner.batch_scan(batch_config)
```

## Output Structure

### Scan Information
```json
{
  "scan_info": {
    "target_type": "debian_image_phase1",
    "target_name": "debian:bullseye-slim",
    "scan_date": "2024-01-15T10:30:00",
    "phase": "1",
    "step": "1",
    "description": "Basic OS Package Vulnerability Scanning for Debian-based images - Image Extraction"
  }
}
```

### Debian Analysis Results
```json
{
  "debian_analysis": {
    "image_name": "debian:bullseye-slim",
    "extraction_time": 15.23,
    "total_size": 52428800,
    "extraction_path": "/tmp/debian_extraction_12345",
    "debian_info": {
      "distribution": "debian",
      "version": "11",
      "codename": "bullseye",
      "package_count": 156,
      "architecture": "amd64"
    },
    "layers": [
      {
        "index": 0,
        "digest": "sha256:abc123...",
        "size": 26214400,
        "files": {
          "total": 1250,
          "debian_files": 45
        },
        "debian_packages": [
          {
            "name": "base-files",
            "version": "11.1+deb11u7",
            "architecture": "amd64",
            "size": 102400
          }
        ]
      }
    ],
    "extraction_report": {
      "summary": "...",
      "details": "..."
    }
  }
}
```

## Supported Images

### Debian-Based Distributions
- **Debian**: `debian:bullseye-slim`, `debian:buster`, `debian:bookworm`
- **Ubuntu**: `ubuntu:20.04`, `ubuntu:22.04`, `ubuntu:18.04`
- **Kali Linux**: `kalilinux/kali-rolling`
- **Raspbian**: `arm32v7/debian`

### Non-Debian Images
- **Alpine**: Will be detected but may have limited package analysis
- **CentOS/RHEL**: Will be detected as non-Debian
- **Other**: Will be processed but may show warnings

## Analysis Features

### Layer Analysis
- **Layer Extraction**: Each layer is extracted as a tarball
- **Size Calculation**: Accurate size measurement for each layer
- **File Counting**: Total files and Debian-specific files per layer
- **Package Detection**: OS packages found in each layer

### Debian Package Analysis
- **Package Database Parsing**: Reads `/var/lib/dpkg/status` files
- **Package Information**: Name, version, architecture, size
- **Dependency Analysis**: Package dependencies and conflicts
- **Security Updates**: Identifies packages that may need updates

### File System Analysis
- **Debian File Detection**: Identifies Debian-specific files and directories
- **Package Manager Files**: Detects dpkg, apt, and related files
- **Configuration Files**: Identifies important Debian configuration files
- **Binary Analysis**: Analyzes executable files and libraries

## Performance Considerations

### Memory Usage
- **Streaming Processing**: Large images are processed in chunks
- **Temporary Storage**: Uses temporary directories for extraction
- **Cleanup**: Automatically cleans up temporary files after analysis

### Network Usage
- **Image Pulling**: Downloads images if not locally available
- **Bandwidth**: Consider network speed for large images
- **Caching**: Docker caches pulled images for subsequent runs

### Processing Time
- **Small Images** (< 100MB): 5-15 seconds
- **Medium Images** (100MB-500MB): 15-60 seconds
- **Large Images** (> 500MB): 1-5 minutes

## Error Handling

### Common Errors
```python
# Image not found
"Error: manifest for debian:nonexistent not found"

# Docker daemon not running
"Error: Cannot connect to the Docker daemon"

# Insufficient permissions
"Error: Got permission denied while trying to connect to the Docker daemon"

# Insufficient disk space
"Error: no space left on device"
```

### Error Recovery
- **Automatic Retry**: Failed operations are retried with exponential backoff
- **Partial Results**: Returns partial results even if some layers fail
- **Detailed Logging**: Comprehensive error logging for debugging
- **Graceful Degradation**: Continues processing even with non-critical errors

## Debugging

### Enable Debug Mode
```bash
python container_security_scanner.py --debian-phase1 debian:bullseye-slim --debug
```

### Debug Output
```python
# Debug information includes:
- Docker client initialization
- Image pulling progress
- Layer extraction details
- File analysis steps
- Package parsing information
- Error details and stack traces
```

### Common Debug Scenarios
1. **Docker Connection Issues**: Check Docker daemon status
2. **Permission Problems**: Verify user has Docker access
3. **Network Issues**: Check internet connectivity for image pulling
4. **Disk Space**: Monitor available disk space
5. **Memory Issues**: Check system memory usage

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: Container Security Scan
  run: |
    python container_security_scanner.py \
      --debian-phase1 ${{ steps.meta.outputs.tags }} \
      --format json \
      --output security_report.json
```

### Docker Compose Integration
```yaml
# docker-compose.yml
services:
  security-scanner:
    build: .
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    command: >
      python container_security_scanner.py
      --debian-phase1 myapp:latest
      --format html
      --output /reports/security_report.html
```

### Kubernetes Integration
```yaml
# Kubernetes Job
apiVersion: batch/v1
kind: Job
metadata:
  name: container-security-scan
spec:
  template:
    spec:
      containers:
      - name: scanner
        image: security-scanner:latest
        command:
        - python
        - container_security_scanner.py
        - --debian-phase1
        - myapp:latest
        - --format
        - json
        - --output
        - /reports/security_report.json
```

## Best Practices

### Security Considerations
- **Run in Isolated Environment**: Use containers or VMs for scanning
- **Limit Permissions**: Run with minimal required permissions
- **Network Isolation**: Limit network access during scanning
- **Clean Up**: Ensure temporary files are properly cleaned up

### Performance Optimization
- **Use Local Images**: Pull images beforehand to reduce network time
- **Parallel Processing**: Use batch mode for multiple images
- **Resource Limits**: Set appropriate memory and CPU limits
- **Caching**: Leverage Docker layer caching

### Monitoring and Alerting
- **Scan Duration**: Monitor scan completion times
- **Error Rates**: Track failed scans and errors
- **Resource Usage**: Monitor CPU, memory, and disk usage
- **Success Rates**: Track successful extractions and analyses

## Troubleshooting

### Common Issues

#### Docker Connection Problems
```bash
# Check Docker daemon status
sudo systemctl status docker

# Restart Docker daemon
sudo systemctl restart docker

# Check Docker socket permissions
ls -la /var/run/docker.sock
```

#### Permission Issues
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker
```

#### Disk Space Issues
```bash
# Check available disk space
df -h

# Clean up Docker images
docker system prune -a

# Clean up temporary files
rm -rf /tmp/debian_extraction_*
```

#### Memory Issues
```bash
# Check memory usage
free -h

# Monitor during scan
watch -n 1 'free -h && docker stats --no-stream'
```

### Getting Help

#### Debug Information
```bash
# Enable debug mode
python container_security_scanner.py --debian-phase1 debian:bullseye-slim --debug

# Check logs
tail -f container_security_debug.log
```

#### System Information
```bash
# Docker version
docker version

# Python version
python --version

# Available disk space
df -h

# Memory information
free -h
```

## Next Steps

After completing Phase 1, Step 1, the next phases will include:

1. **Phase 1, Step 2**: Package vulnerability matching against NVD database
2. **Phase 1, Step 3**: Vulnerability reporting and risk assessment
3. **Phase 2**: Language-specific package analysis
4. **Phase 3**: Advanced security scanning and compliance checking

## Contributing

To contribute to Phase 1, Step 1:

1. **Report Issues**: Use GitHub issues for bug reports
2. **Submit PRs**: Pull requests for improvements
3. **Add Tests**: Include tests for new features
4. **Update Documentation**: Keep documentation current

## License

This tool is part of the SecEnhance project and follows the same licensing terms. 