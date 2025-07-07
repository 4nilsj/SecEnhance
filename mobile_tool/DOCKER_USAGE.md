# Mobile Security Testing Tool - Docker Usage Guide

This guide explains how to use the Mobile Security Testing Tool with Docker, including both CLI and API modes.

## 🐳 Quick Start

### 1. Setup Docker Environment

First, run the setup script to create necessary directories:

```bash
python setup_docker_dirs.py
```

### 2. Build the Docker Image

```bash
docker-compose build
```

## 🚀 Available Services

### CLI Mode Services

#### Basic CLI Tool
```bash
docker-compose run mobile-tool-cli
```

#### Interactive Mode
```bash
docker-compose run mobile-tool-interactive
```

#### Static Analysis
```bash
docker-compose run mobile-tool-static
```

#### Comprehensive Analysis
```bash
docker-compose run mobile-tool-comprehensive
```

#### Batch Processing
```bash
docker-compose run mobile-tool-batch
```

### API Mode Services

#### Production API Server
```bash
docker-compose up mobile-api
```

#### Debug API Server
```bash
docker-compose up mobile-api-debug
```

## 📁 Directory Structure

```
mobile_tool/
├── reports/
│   ├── api/          # API-generated reports
│   └── cli/          # CLI-generated reports
├── uploads/          # Upload files for analysis
├── logs/             # Log files
├── config/           # Configuration files
└── examples/         # Example files
```

## 🔧 Configuration

### Environment Variables

- `MOBILE_API_PORT`: API server port (default: 5001)
- `MOBILE_API_DEBUG`: Enable debug mode (default: false)
- `MOBILE_MAX_FILE_SIZE`: Maximum file size (default: 100MB)
- `MOBILE_DEFAULT_TESTS`: Default tests to run
- `MOBILE_TIMEOUT`: Analysis timeout (default: 300s)

### Custom Configuration

Create a custom configuration file:

```bash
# Create config directory
mkdir -p config

# Create custom config
cat > config/custom_config.json << EOF
{
  "api": {
    "port": 5001,
    "debug": false
  },
  "analysis": {
    "default_tests": ["static", "network", "storage", "code"],
    "timeout": 300
  }
}
EOF
```

## 📊 API Usage

### Start API Server

```bash
# Production mode
docker-compose up mobile-api

# Debug mode
docker-compose up mobile-api-debug
```

### API Endpoints

#### Health Check
```bash
curl http://localhost:5001/api/v1/health
```

#### Start Scan
```bash
curl -X POST http://localhost:5001/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/app/uploads/app.apk",
    "tests": ["static", "network", "storage", "code"]
  }'
```

#### Get Scan Status
```bash
curl http://localhost:5001/api/v1/scan/{scan_id}/status
```

#### Get Scan Report
```bash
curl http://localhost:5001/api/v1/scan/{scan_id}/report \
  -o mobile_scan_report.html
```

#### List All Scans
```bash
curl http://localhost:5001/api/v1/scans
```

#### Delete Scan
```bash
curl -X DELETE http://localhost:5001/api/v1/scan/{scan_id}
```

#### Clear All Scans
```bash
curl -X POST http://localhost:5001/api/v1/clear
```

## 🔍 CLI Usage Examples

### Analyze APK File
```bash
docker-compose run mobile-tool-cli \
  python src/mobile_security_tester.py \
  --apk /app/uploads/app.apk \
  --comprehensive \
  --output /app/reports/cli/analysis.json
```

### Analyze IPA File
```bash
docker-compose run mobile-tool-cli \
  python src/mobile_security_tester.py \
  --ipa /app/uploads/app.ipa \
  --tests static,network,storage \
  --output /app/reports/cli/analysis.json
```

### Batch Analysis
```bash
docker-compose run mobile-tool-cli \
  python src/mobile_security_tester.py \
  --batch /app/uploads \
  --output /app/reports/cli/batch_results.json
```

### Device Analysis
```bash
docker-compose run mobile-tool-cli \
  python src/mobile_security_tester.py \
  --device android \
  --package com.example.app \
  --output /app/reports/cli/device_analysis.json
```

## 📈 Report Organization

### CLI Reports
- Location: `reports/cli/`
- Naming: `cli_scan_*` or custom names
- Formats: JSON, HTML, PDF, CSV

### API Reports
- Location: `reports/api/`
- Naming: `api_scan_{scan_id}_{timestamp}.html`
- Format: HTML (downloadable)

## 🔧 Port Configuration

### Change API Port

#### Method 1: Environment Variable
```bash
export MOBILE_API_PORT=8080
docker-compose up mobile-api
```

#### Method 2: Docker Compose Override
```bash
# Create docker-compose.override.yml
version: '3.8'
services:
  mobile-api:
    ports:
      - "8080:5001"
```

#### Method 3: Direct Command
```bash
docker-compose run -p 8080:5001 mobile-api
```

## 🐛 Troubleshooting

### Port Already in Use
If port 5001 is already in use:

```bash
# Check what's using the port
netstat -tulpn | grep 5001

# Use a different port
export MOBILE_API_PORT=5002
docker-compose up mobile-api
```

### Permission Issues
```bash
# Fix directory permissions
sudo chown -R $USER:$USER reports/ uploads/ logs/ config/

# Or run with proper permissions
docker-compose run --user $(id -u):$(id -g) mobile-tool-cli
```

### File Upload Issues
```bash
# Ensure uploads directory exists
mkdir -p uploads

# Copy files to uploads directory
cp your_app.apk uploads/
```

### Memory Issues
```bash
# Increase Docker memory limit
docker-compose run --memory=4g mobile-tool-comprehensive
```

## 🔒 Security Considerations

### Network Security
- API server binds to `0.0.0.0` by default
- Use reverse proxy for production deployments
- Implement authentication for sensitive environments

### File Security
- Uploads directory should be properly secured
- Reports contain sensitive information
- Use volume mounts with appropriate permissions

### Container Security
- Run containers with minimal privileges
- Use non-root user when possible
- Keep base images updated

## 📚 Advanced Usage

### Custom Analysis Pipeline
```bash
# Create custom analysis script
cat > custom_analysis.sh << EOF
#!/bin/bash
docker-compose run mobile-tool-cli \
  python src/mobile_security_tester.py \
  --apk /app/uploads/\$1 \
  --comprehensive \
  --output /app/reports/cli/\$1_analysis.json
EOF

chmod +x custom_analysis.sh
./custom_analysis.sh my_app.apk
```

### Integration with CI/CD
```yaml
# Example GitHub Actions workflow
name: Mobile Security Scan
on: [push]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Mobile Security Scan
        run: |
          docker-compose run mobile-tool-cli \
            python src/mobile_security_tester.py \
            --apk app.apk \
            --comprehensive \
            --output scan_results.json
```

### Monitoring and Logging
```bash
# View logs
docker-compose logs mobile-api

# Follow logs in real-time
docker-compose logs -f mobile-api

# Check container status
docker-compose ps
```

## 🆘 Support

For issues and questions:
1. Check the logs: `docker-compose logs`
2. Verify configuration: `docker-compose config`
3. Test connectivity: `curl http://localhost:5001/api/v1/health`
4. Check file permissions and directory structure

## 📝 Notes

- Reports are automatically organized by CLI/API usage
- Scan IDs are unique UUIDs for API mode
- All analysis results are stored in the reports directory
- Configuration can be customized via environment variables or config files
- Docker containers are stateless - data persists in mounted volumes 