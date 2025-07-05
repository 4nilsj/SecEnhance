# Docker Guide for Security Tools

This guide provides comprehensive instructions for running the JWT Security Testing Tool and Mobile Security Testing Tool using Docker.

## 🐳 Prerequisites

- Docker 20.10+ installed
- Docker Compose 2.0+ installed
- At least 4GB RAM available for Docker
- Git (to clone the repository)

## 📦 Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd QuickFix
```

### 2. Build All Images
```bash
# Build JWT tool
cd jwt_tool
docker build -t jwt-security-tester .

# Build Mobile tool
cd ../mobile_tool
docker build -t mobile-security-tester .

# Or build all with docker-compose
cd ..
docker-compose build
```

---

## 🔐 JWT Security Testing Tool

### Basic Usage

#### Single Token Test
```bash
# Test a JWT token
docker run --rm jwt-security-tester --token "your.jwt.token"

# Test with secret
docker run --rm jwt-security-tester \
    --token "your.jwt.token" \
    --secret "your_secret"
```

#### Save Output to Host
```bash
# Create output directory
mkdir -p jwt_output

# Run test and save results
docker run --rm \
    -v $(pwd)/jwt_output:/app/output \
    jwt-security-tester \
    --token "your.jwt.token" \
    --output /app/output/security_report.json
```

#### Comprehensive Testing
```bash
docker run --rm \
    -v $(pwd)/jwt_output:/app/output \
    jwt-security-tester \
    --token "your.jwt.token" \
    --test all \
    --output /app/output/comprehensive_report.json
```

### Advanced Usage

#### JWKS Spoofing Test
```bash
docker run --rm \
    -v $(pwd)/jwt_output:/app/output \
    jwt-security-tester \
    --token "your.jwt.token" \
    --test jwks-spoofing \
    --output /app/output/jwks_spoofing_report.json
```

#### Key Generation
```bash
docker run --rm \
    -v $(pwd)/jwt_output:/app/output \
    jwt-security-tester \
    --test generate-keys \
    --key-size 2048
```

#### Batch Processing
```bash
# Create tokens file
echo "token1.jwt" > tokens.txt
echo "token2.jwt" >> tokens.txt

# Run batch processing
docker run --rm \
    -v $(pwd)/tokens.txt:/app/tokens.txt:ro \
    -v $(pwd)/jwt_output:/app/output \
    jwt-security-tester \
    --file /app/tokens.txt \
    --output /app/output/batch_report.json
```

#### Interactive Mode
```bash
docker run --rm -it jwt-security-tester
```

### Docker Compose Usage

#### Basic Service
```bash
cd jwt_tool
docker-compose run --rm jwt-tool --token "your.jwt.token"
```

#### Interactive Service
```bash
docker-compose run --rm jwt-tool-interactive
```

#### Batch Processing Service
```bash
docker-compose run --rm jwt-tool-batch
```

---

## 📱 Mobile Security Testing Tool

### Basic Usage

#### Single APK Analysis
```bash
# Basic analysis
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    mobile-security-tester \
    /app/input/app.apk

# With output
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/mobile_output:/app/output \
    mobile-security-tester \
    /app/input/app.apk \
    --output /app/output/analysis.json
```

#### Static Analysis
```bash
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/mobile_output:/app/output \
    mobile-security-tester \
    /app/input/app.apk \
    --analysis-type static \
    --output /app/output/static_analysis.json
```

#### Comprehensive Analysis
```bash
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/mobile_output:/app/output \
    -v $(pwd)/mobile_reports:/app/reports \
    mobile-security-tester \
    /app/input/app.apk \
    --analysis-type comprehensive \
    --output /app/output/comprehensive.json \
    --report /app/reports/report.html
```

### Advanced Usage

#### Debug Mode
```bash
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/mobile_output:/app/output \
    mobile-security-tester \
    /app/input/app.apk \
    --debug \
    --output /app/output/debug_report.json
```

#### Network Analysis
```bash
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/mobile_output:/app/output \
    mobile-security-tester \
    /app/input/app.apk \
    --analysis-type network \
    --output /app/output/network_analysis.json
```

#### Storage Analysis
```bash
docker run --rm \
    -v $(pwd)/app.apk:/app/input/app.apk \
    -v $(pwd)/mobile_output:/app/output \
    mobile-security-tester \
    /app/input/app.apk \
    --analysis-type storage \
    --output /app/output/storage_analysis.json
```

#### Batch Processing
```bash
# Create directory with multiple APKs
mkdir -p apks
cp *.apk apks/

# Run batch analysis
docker run --rm \
    -v $(pwd)/apks:/app/input \
    -v $(pwd)/mobile_output:/app/output \
    mobile-security-tester \
    /app/input \
    --output /app/output/batch_results.json \
    --summary /app/output/summary.txt
```

### Docker Compose Usage

#### Basic Service
```bash
cd mobile_tool
docker-compose run --rm mobile-tool /app/input/app.apk
```

#### Static Analysis Service
```bash
docker-compose run --rm mobile-tool-static
```

#### Comprehensive Analysis Service
```bash
docker-compose run --rm mobile-tool-comprehensive
```

#### Interactive Service
```bash
docker-compose run --rm mobile-tool-interactive
```

---

## 🔧 Configuration

### Environment Variables

#### JWT Tool
- `PYTHONPATH=/app/src` - Python path
- `PYTHONUNBUFFERED=1` - Unbuffered output

#### Mobile Tool
- `PYTHONPATH=/app/src` - Python path
- `PYTHONUNBUFFERED=1` - Unbuffered output
- `JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64` - Java home
- `ANDROID_HOME=/opt/android-sdk` - Android SDK path

### Volume Mounts

#### JWT Tool
- `/app/output` - Output directory for reports
- `/app/tokens` - Input directory for token files (read-only)

#### Mobile Tool
- `/app/output` - Output directory for JSON reports
- `/app/input` - Input directory for APK/IPA files
- `/app/reports` - Output directory for HTML/PDF reports

---

## 🚀 Production Deployment

### Using Docker Compose

#### JWT Tool Production
```yaml
version: '3.8'
services:
  jwt-tool:
    build: ./jwt_tool
    image: jwt-security-tester:latest
    volumes:
      - ./jwt_output:/app/output
      - ./jwt_tokens:/app/tokens:ro
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

#### Mobile Tool Production
```yaml
version: '3.8'
services:
  mobile-tool:
    build: ./mobile_tool
    image: mobile-security-tester:latest
    volumes:
      - ./mobile_output:/app/output
      - ./mobile_input:/app/input
      - ./mobile_reports:/app/reports
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

### Security Considerations

1. **Non-root Users**: Both containers run as non-root users
2. **Read-only Mounts**: Input directories are mounted as read-only
3. **Resource Limits**: Consider setting memory and CPU limits
4. **Network Isolation**: Use custom networks for production

---

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix volume permissions
sudo chown -R $USER:$USER jwt_output mobile_output
```

#### Out of Memory
```bash
# Increase Docker memory limit
# In Docker Desktop: Settings > Resources > Memory > 4GB
```

#### Build Failures
```bash
# Clean and rebuild
docker system prune -a
docker build --no-cache -t jwt-security-tester .
docker build --no-cache -t mobile-security-tester .
```

#### Network Issues
```bash
# Check Docker network
docker network ls
docker network inspect bridge
```

### Debug Commands

#### Check Container Logs
```bash
# JWT tool
docker logs jwt-security-tester

# Mobile tool
docker logs mobile-security-tester
```

#### Enter Container
```bash
# JWT tool
docker run --rm -it jwt-security-tester /bin/bash

# Mobile tool
docker run --rm -it mobile-security-tester /bin/bash
```

#### Check Container Resources
```bash
docker stats jwt-security-tester mobile-security-tester
```

---

## 📊 Performance Optimization

### Resource Allocation
```bash
# Limit CPU and memory
docker run --rm \
    --cpus=2 \
    --memory=2g \
    jwt-security-tester --token "your.jwt.token"
```

### Parallel Processing
```bash
# Run multiple containers in parallel
docker run --rm -d jwt-security-tester --token "token1"
docker run --rm -d jwt-security-tester --token "token2"
docker run --rm -d jwt-security-tester --token "token3"
```

### Volume Optimization
```bash
# Use tmpfs for temporary files
docker run --rm \
    --tmpfs /tmp \
    jwt-security-tester --token "your.jwt.token"
```

---

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Testing
on: [push, pull_request]

jobs:
  jwt-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build JWT tool
        run: |
          cd jwt_tool
          docker build -t jwt-security-tester .
      - name: Run JWT tests
        run: |
          docker run --rm jwt-security-tester --token "${{ secrets.TEST_TOKEN }}"

  mobile-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Mobile tool
        run: |
          cd mobile_tool
          docker build -t mobile-security-tester .
      - name: Run Mobile tests
        run: |
          docker run --rm -v ${{ github.workspace }}/test.apk:/app/input/app.apk mobile-security-tester /app/input/app.apk
```

---

## 📝 Best Practices

1. **Always use specific image tags** in production
2. **Mount volumes** for persistent data
3. **Use read-only mounts** for input files
4. **Set resource limits** to prevent resource exhaustion
5. **Run as non-root** (already configured)
6. **Use multi-stage builds** for smaller images
7. **Scan images** for vulnerabilities
8. **Keep base images updated**

---

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review container logs
3. Verify volume permissions
4. Ensure sufficient resources
5. Check Docker and Docker Compose versions 