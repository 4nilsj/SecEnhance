# Docker/Podman Usage Guide

This guide provides comprehensive instructions for using the API Security Scanner with Docker and Podman containers.

## Table of Contents

- [Quick Start](#quick-start)
- [Container Architecture](#container-architecture)
- [Docker Compose Setup](#docker-compose-setup)
- [Manual Docker Usage](#manual-docker-usage)
- [Podman Usage](#podman-usage)
- [Environment Configuration](#environment-configuration)
- [Volume Management](#volume-management)
- [Network Configuration](#network-configuration)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

## Quick Start

### Prerequisites

- Docker or Podman installed
- Git (to clone the repository)

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd api_security_scanner

# Setup container environment
# On Linux/macOS:
./setup-container.sh

# On Windows:
setup-container.bat
```

### 2. Build Container

```bash
# Build with Docker
docker build -t api-security-scanner .

# Or with Podman
podman build -t api-security-scanner .
```

### 3. Run Your First Scan

```bash
# Place your API collection in the workspace directory
cp your-collection.json workspace/

# Run scan with Docker Compose (recommended)
docker-compose up -d zap
docker-compose run --rm scanner scan -f /workspace/your-collection.json

# Or run directly with Docker
docker run --rm -v $(pwd):/workspace api-security-scanner scan -f /workspace/your-collection.json
```

## Container Architecture

The API Security Scanner supports multiple deployment modes:

### 1. Integrated Mode (Docker Compose)
- ZAP runs in a separate container
- Scanner connects to ZAP via internal network
- Best for: Development, testing, CI/CD

### 2. Standalone Mode
- Scanner connects to external ZAP instance
- ZAP runs on host or separate server
- Best for: Production, existing ZAP infrastructure

### 3. Plugin-Only Mode
- Scanner runs without ZAP
- Only custom plugins are executed
- Best for: Quick checks, custom security tests

## Docker Compose Setup

### Basic Configuration

The `docker-compose.yml` file provides three services:

```yaml
services:
  zap:              # OWASP ZAP proxy service
  scanner:          # Scanner with ZAP integration
  scanner-standalone: # Scanner for external ZAP
```

### Starting Services

```bash
# Start ZAP service only
docker-compose up -d zap

# Start all services
docker-compose up -d

# View service status
docker-compose ps

# View logs
docker-compose logs zap
docker-compose logs scanner
```

### Running Scans

```bash
# Basic scan
docker-compose run --rm scanner scan -f /workspace/collection.json

# Scan with authentication
docker-compose run --rm scanner scan -f /workspace/collection.json \
  -a header -n "X-API-Key" -v "your-key"

# Scan with custom plugins only
docker-compose run --rm scanner scan -f /workspace/collection.json --no-zap

# List recent scans
docker-compose run --rm scanner list-scans

# Show scan details
docker-compose run --rm scanner show-scan abc12345
```

## Manual Docker Usage

### Basic Container Run

```bash
# Simple scan
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json

# Scan with authentication
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json \
  -a header -n "Authorization" -v "Bearer token123"

# Scan with custom output
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json \
  --export /workspace/report.html --export-json /workspace/report.json
```

### Interactive Mode

```bash
# Get shell access
docker run --rm -it -v $(pwd):/workspace \
  api-security-scanner bash

# Check container environment
docker run --rm api-security-scanner env

# View help
docker run --rm api-security-scanner --help
```

### Custom Configuration

```bash
# Custom ZAP host
docker run --rm -e ZAP_HOST=zap-proxy -e ZAP_PORT=8080 \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json

# Custom paths
docker run --rm \
  -e SCAN_DB_PATH=/app/data/custom.db \
  -e LOG_DIR=/app/logs \
  -e REPORTS_DIR=/app/reports \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json
```

## Podman Usage

### Basic Podman Commands

```bash
# Build with Podman
podman build -t api-security-scanner .

# Run with Podman
podman run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json

# Using Podman Compose
podman-compose up -d zap
podman-compose run --rm scanner scan -f /workspace/collection.json
```

### Podman-Specific Configuration

```bash
# Enable rootless mode
podman system migrate

# Check Podman version
podman version

# Use Podman with Docker Compose
export DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock
docker-compose up -d zap
```

## Environment Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZAP_HOST` | `localhost` | ZAP proxy hostname |
| `ZAP_PORT` | `8080` | ZAP proxy port |
| `SCAN_DB_PATH` | `/app/data/scan_results.db` | Database file path |
| `LOG_DIR` | `/app/logs` | Log directory |
| `REPORTS_DIR` | `/app/reports` | Reports directory |
| `WORKSPACE_DIR` | `/workspace` | Workspace directory |

### Configuration Files

#### .env File
```bash
# Create .env file for default configuration
cat > .env << EOF
ZAP_HOST=zap
ZAP_PORT=8080
SCAN_DB_PATH=/app/data/scan_results.db
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
WORKSPACE_DIR=/workspace
EOF
```

#### docker-compose.override.yml
```yaml
version: '3.8'

services:
  scanner:
    environment:
      - ZAP_HOST=zap
      - ZAP_PORT=8080
    volumes:
      - ./workspace:/workspace:ro
      - ./plugins:/app/plugins:ro
      - ./examples:/app/examples:ro
```

## Volume Management

### Volume Mounts

```bash
# Basic volume mount
-v $(pwd):/workspace

# Multiple volume mounts
-v $(pwd)/data:/app/data \
-v $(pwd)/logs:/app/logs \
-v $(pwd)/reports:/app/reports \
-v $(pwd)/workspace:/workspace:ro

# Named volumes
docker volume create scanner-data
docker run --rm -v scanner-data:/app/data api-security-scanner
```

### Data Persistence

```bash
# Persistent database
docker run --rm -v scanner-db:/app/data \
  api-security-scanner scan -f /workspace/collection.json

# Persistent logs
docker run --rm -v scanner-logs:/app/logs \
  api-security-scanner scan -f /workspace/collection.json

# Backup data
docker run --rm -v scanner-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/scanner-data.tar.gz -C /data .
```

## Network Configuration

### Docker Networks

```bash
# Create custom network
docker network create scanner-network

# Run with custom network
docker run --rm --network scanner-network \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json
```

### Host Network

```bash
# Use host network (Linux only)
docker run --rm --network host \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json
```

### External ZAP Connection

```bash
# Connect to ZAP on host
docker run --rm --network host \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json \
  --zap-host localhost

# Connect to ZAP on different host
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json \
  --zap-host 192.168.1.100
```

## Troubleshooting

### Common Issues

#### ZAP Connectivity Issues
```bash
# Check ZAP container status
docker-compose ps zap

# Check ZAP logs
docker-compose logs zap

# Test ZAP connectivity
docker-compose run --rm scanner curl -f http://zap:8080/JSON/core/view/version/

# Restart ZAP service
docker-compose restart zap
```

#### Volume Mount Issues
```bash
# Check volume mounts
docker run --rm -v $(pwd):/workspace api-security-scanner ls -la /workspace

# Fix permissions (Linux/macOS)
sudo chown -R $USER:$USER data logs reports workspace

# Windows: Check Docker Desktop settings
```

#### Container Build Issues
```bash
# Clean build
docker build --no-cache -t api-security-scanner .

# Check build logs
docker build -t api-security-scanner . 2>&1 | tee build.log

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t api-security-scanner .
```

### Debugging

```bash
# Check container environment
docker run --rm api-security-scanner env

# Interactive debugging
docker run --rm -it api-security-scanner bash

# Check container configuration
docker run --rm api-security-scanner check

# View container logs
docker logs <container-id>
```

## Advanced Usage

### CI/CD Integration

#### GitHub Actions
```yaml
name: API Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run API Security Scanner
        run: |
          docker build -t api-security-scanner .
          docker run --rm -v ${{ github.workspace }}:/workspace \
            api-security-scanner scan -f /workspace/api-collection.json
```

#### GitLab CI
```yaml
security-scan:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t api-security-scanner .
    - docker run --rm -v $PWD:/workspace \
        api-security-scanner scan -f /workspace/api-collection.json
```

### Custom Plugins

```bash
# Mount custom plugins
docker run --rm -v $(pwd)/custom-plugins:/app/plugins:ro \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json
```

### Multi-Stage Scans

```bash
# Spider only
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json --no-plugins

# Custom plugins only
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json --no-zap

# Full scan with custom timing
docker run --rm -v $(pwd):/workspace \
  api-security-scanner scan -f /workspace/collection.json \
  --spider-depth 3 --spider-children 5 --max-scan-time 30
```

### Performance Optimization

```bash
# Resource limits
docker run --rm --memory=2g --cpus=2 \
  -v $(pwd):/workspace api-security-scanner scan -f /workspace/collection.json

# Parallel execution
docker-compose up -d zap
docker-compose run --rm scanner scan -f /workspace/collection1.json &
docker-compose run --rm scanner scan -f /workspace/collection2.json &
wait
```

## Best Practices

1. **Use Docker Compose** for development and testing
2. **Mount volumes** for data persistence
3. **Set resource limits** for production use
4. **Use multi-stage builds** for smaller images
5. **Keep containers updated** with latest security patches
6. **Monitor container logs** for issues
7. **Use named volumes** for production data
8. **Test connectivity** before running scans
9. **Backup important data** regularly
10. **Use environment files** for configuration management
