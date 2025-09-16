# Docker Setup for API Security Scanner

This document provides comprehensive information about the Docker setup for the API Security Scanner.

## 🐳 Quick Start

### Prerequisites
- Docker Desktop or Docker Engine
- Git (to clone the repository)

**Note**: Docker Desktop can be installed without administrator privileges on macOS and Windows.

### 🍎 macOS Setup (No Admin Privileges Required)

If you're on macOS without administrator privileges, Docker is the perfect solution:

#### 1. Install Docker Desktop
1. **Download Docker Desktop** from [docker.com](https://www.docker.com/products/docker-desktop/)
2. **Install Docker Desktop** (user installation, no admin required)
3. **Start Docker Desktop** and ensure it's running
4. **Verify installation**:
   ```bash
   docker --version
   docker-compose --version
   ```

#### 2. Quick Setup
```bash
# Clone the project
git clone <repository-url>
cd api_security_scanner

# Setup container environment
./setup-container.sh

# Build the image
./build-docker.sh

# Run your first scan
cp your-collection.json workspace/
docker-compose up -d zap
docker-compose run --rm scanner scan -f /workspace/your-collection.json
```

#### 3. macOS-Specific Tips
- **File Sharing**: Ensure your project directory is in Docker Desktop's file sharing settings
- **Resources**: Adjust Docker Desktop memory/CPU limits in Settings > Resources
- **Networking**: Use `host.docker.internal` to access services on your Mac from containers

### 1. Setup Container Environment

```bash
# On Linux/macOS:
./setup-container.sh

# On Windows:
setup-container.bat
```

### 2. Build the Docker Image

```bash
# On Linux/macOS:
./build-docker.sh

# On Windows:
build-docker.bat

# Or manually:
docker build -t api-security-scanner .
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

## 🏗️ Docker Architecture

### Multi-Stage Build
The Dockerfile uses a multi-stage build process:

1. **Builder Stage**: Installs build dependencies and Python packages
2. **Runtime Stage**: Creates a minimal runtime environment with only necessary dependencies

### Container Services

#### 1. ZAP Service (`zap`)
- **Image**: `ghcr.io/zaproxy/zaproxy:stable`
- **Ports**: 8080 (API), 8090 (Web UI)
- **Health Check**: Built-in ZAP API health check
- **Configuration**: Runs in daemon mode with API disabled

#### 2. Scanner Service (`scanner`)
- **Build**: Custom image from local Dockerfile
- **Dependencies**: Waits for ZAP service to be healthy
- **Network**: Connected to ZAP via internal Docker network
- **Volumes**: Mounts workspace, plugins, templates, and configuration

#### 3. Standalone Scanner (`scanner-standalone`)
- **Build**: Same as scanner service
- **Dependencies**: None (connects to external ZAP)
- **Network**: Uses host network or external ZAP connection
- **Use Case**: When ZAP runs on host or separate server

## 📁 Directory Structure

```
api_security_scanner/
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # Service orchestration
├── entrypoint.sh             # Container entrypoint script
├── healthcheck.py            # Health check script
├── .dockerignore             # Docker build exclusions
├── build-docker.sh           # Linux/macOS build script
├── build-docker.bat          # Windows build script
├── setup-container.sh        # Linux/macOS setup script
├── setup-container.bat       # Windows setup script
├── config/env.example        # Example environment file
├── config/env.template       # Comprehensive environment template
├── container-config.py       # Container configuration utilities
├── data/                     # Persistent database storage
├── logs/                     # Application logs
├── reports/                  # Generated reports
├── templates/                # Report templates
├── plugins/                  # Custom security plugins
├── examples/                 # Sample API collections
└── workspace/                # User input files
    ├── collections/          # API collections
    ├── specs/               # OpenAPI specifications
    └── reports/             # User reports
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZAP_HOST` | `localhost` | ZAP proxy hostname |
| `ZAP_PORT` | `8080` | ZAP proxy port |
| `SCAN_DB_PATH` | `/app/data/scan_results.db` | Database file path |
| `LOG_DIR` | `/app/logs` | Log directory |
| `REPORTS_DIR` | `/app/reports` | Reports directory |
| `WORKSPACE_DIR` | `/workspace` | Workspace directory |

### Volume Mounts

```yaml
volumes:
  - ./data:/app/data                    # Persistent database
  - ./logs:/app/logs                    # Application logs
  - ./reports:/app/reports              # Generated reports
  - ./templates:/app/templates:ro       # Report templates
  - ./plugins:/app/plugins:ro           # Custom plugins
  - ./examples:/app/examples:ro         # Sample files
  - ./workspace:/workspace:ro           # User input files
  - ./.env:/app/.env:ro                 # Environment configuration
```

## 🚀 Usage Examples

### Basic Scan
```bash
docker-compose run --rm scanner scan -f /workspace/collection.json
```

### Scan with Authentication
```bash
docker-compose run --rm scanner scan -f /workspace/collection.json \
  -a header -n "X-API-Key" -v "your-key"
```

### Custom Plugins Only
```bash
docker-compose run --rm scanner scan -f /workspace/collection.json --no-zap
```

### Standalone Mode
```bash
# Start ZAP on host machine first
docker-compose run --rm scanner-standalone scan -f /workspace/collection.json
```

### Interactive Mode
```bash
docker-compose run --rm -it scanner bash
```

## 🔍 Health Checks

The container includes comprehensive health checks:

- **Python Imports**: Verifies all required modules are available
- **Directories**: Checks required directories exist and are writable
- **Application**: Tests main application can be imported
- **Environment**: Validates environment variables

Run health check manually:
```bash
docker run --rm api-security-scanner python /app/healthcheck.py
```

## 🛠️ Development

### Building with Custom Options

```bash
# Build with specific tag
./build-docker.sh -t v1.0.0

# Multi-platform build
./build-docker.sh --multi-platform

# Build and push to registry
./build-docker.sh --push

# Clean build (no cache)
./build-docker.sh --no-cache
```

### Debugging

```bash
# Check container environment
docker run --rm api-security-scanner env

# Interactive debugging
docker run --rm -it api-security-scanner bash

# View container logs
docker logs <container-id>

# Check ZAP connectivity
docker-compose run --rm scanner curl -f http://zap:8080/JSON/core/view/version/
```

## 🔒 Security Features

### Container Security
- **Non-root User**: Runs as `scanner` user (UID 1000)
- **Minimal Base Image**: Uses Python slim image
- **Read-only Mounts**: Templates, plugins, and examples are read-only
- **Health Checks**: Regular container health monitoring

### Network Security
- **Internal Network**: ZAP and scanner communicate via internal Docker network
- **Port Exposure**: Only necessary ports are exposed
- **API Security**: ZAP API key disabled by default

## 📊 Performance Optimization

### Resource Limits
```yaml
services:
  scanner:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'
        reservations:
          memory: 1G
          cpus: '1'
```

### Parallel Execution
```bash
# Run multiple scans in parallel
docker-compose up -d zap
docker-compose run --rm scanner scan -f /workspace/collection1.json &
docker-compose run --rm scanner scan -f /workspace/collection2.json &
wait
```

## 🐛 Troubleshooting

### Common Issues

#### ZAP Connectivity
```bash
# Check ZAP container status
docker-compose ps zap

# Check ZAP logs
docker-compose logs zap

# Test connectivity
docker-compose run --rm scanner curl -f http://zap:8080/JSON/core/view/version/

# Restart ZAP
docker-compose restart zap
```

#### Volume Mount Issues
```bash
# Check volume mounts
docker run --rm -v $(pwd):/workspace api-security-scanner ls -la /workspace

# Fix permissions (Linux/macOS)
sudo chown -R $USER:$USER data logs reports workspace

# Windows: Check Docker Desktop file sharing settings
```

#### Build Issues
```bash
# Clean build
docker build --no-cache -t api-security-scanner .

# Check build logs
docker build -t api-security-scanner . 2>&1 | tee build.log

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t api-security-scanner .
```

## 🔄 CI/CD Integration

### GitHub Actions
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

### GitLab CI
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

## 📚 Additional Resources

- [Docker Usage Guide](docs/DOCKER_USAGE_GUIDE.md) - Comprehensive usage documentation
- [Environment Configuration](docs/ENVIRONMENT_CONFIGURATION.md) - Configuration options
- [Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md) - Common issues and solutions
- [Custom Plugin Development](docs/CUSTOM_PLUGIN_DEVELOPMENT.md) - Plugin development guide

## 🤝 Contributing

When contributing to the Docker setup:

1. Test changes with both Linux and Windows
2. Update documentation for any new features
3. Ensure health checks pass
4. Test multi-platform builds
5. Verify volume mounts work correctly

## 📄 License

This Docker setup is part of the API Security Scanner project and follows the same license terms.
