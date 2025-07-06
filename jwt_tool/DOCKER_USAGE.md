# JWT Security Tester - Docker Usage Guide

## Quick Start

### Build the Image
```bash
docker build -t jwt-security-tester .
```

### Run with Docker Compose
```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up jwt-api-enhanced
docker-compose up jwt-tool
```

## Available Services

### 1. jwt-tool (CLI Tool)
```bash
# Basic usage
docker-compose run jwt-tool --token "your.jwt.token"

# With custom config
docker-compose run jwt-tool --config /app/config/my_config.json --token "your.jwt.token"

# Batch processing
docker-compose run jwt-tool --file /app/tokens/tokens.txt --output /app/reports/batch_report.html
```

### 2. jwt-api-basic (Basic REST API)
```bash
# Start basic API service
docker-compose up jwt-api-basic

# API will be available at http://localhost:5000
curl http://localhost:5000/status
```

### 3. jwt-api-enhanced (Enhanced REST API - Recommended)
```bash
# Start enhanced API service with scan ID management
docker-compose up jwt-api-enhanced

# API will be available at http://localhost:5001
curl http://localhost:5001/status

# Enhanced features:
# - Scan ID management
# - Session persistence
# - Report generation for specific scans
# - Scan management and monitoring
```

### 4. jwt-api-enhanced-custom-port (Enhanced API on Custom Port)
```bash
# Start enhanced API on port 8080
docker-compose up jwt-api-enhanced-custom-port

# API will be available at http://localhost:8080
curl http://localhost:8080/status
```

### 5. jwt-tool-interactive (Interactive Mode)
```bash
# Start interactive container
docker-compose run jwt-tool-interactive

# This gives you a shell inside the container
```

### 6. jwt-tool-batch (Batch Processing)
```bash
# Run batch processing with mounted tokens
docker-compose up jwt-tool-batch
```

### 7. jwt-tests (Unit Tests)
```bash
# Run all tests
docker-compose run jwt-tests
```

## Volume Mounts

- `./output:/app/output` - Output files
- `./reports:/app/reports` - Main reports directory
- `./reports/cli:/app/reports/cli` - CLI-generated reports
- `./reports/api:/app/reports/api` - API-generated reports
- `./config:/app/config` - Configuration files
- `./tokens:/app/tokens:ro` - Token files (read-only)

## Environment Variables

- `PYTHONPATH=/app/src` - Python path
- `PYTHONUNBUFFERED=1` - Unbuffered output
- `JWT_API_HOST=0.0.0.0` - API host (for API services)
- `JWT_API_PORT=5000` - API port (for API services)

## Port Configuration

### Default Ports
- **Basic API**: Port 5000 (http://localhost:5000)
- **Enhanced API**: Port 5001 (http://localhost:5001)
- **Enhanced API Custom**: Port 8080 (http://localhost:8080)

### Change Ports
To use different ports, modify the docker-compose.yml file:
```yaml
ports:
  - "8080:5000"  # Use port 8080 on host, 5000 in container
```

Or use environment variables:
```bash
# Set custom port via environment variable
export JWT_API_PORT=8080
docker-compose up jwt-api-enhanced
```

## Examples

### Analyze a Single Token (CLI)
```bash
docker-compose run jwt-tool --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." --output /app/reports/cli/analysis.html
```

### Start Enhanced API and Test It
```bash
# Start enhanced API
docker-compose up jwt-api-enhanced -d

# Test API status
curl http://localhost:5001/status

# Start a scan session
curl -X POST http://localhost:5001/scan/start \
  -H "Content-Type: application/json" \
  -d '{"scan_type": "single", "description": "Test scan"}'

# Analyze a token
curl -X POST http://localhost:5001/scan/{scan_id}/analyze \
  -H "Content-Type: application/json" \
  -d '{"token": "your.jwt.token"}'

# Get scan results
curl http://localhost:5001/scan/{scan_id}/results

# Generate report
curl http://localhost:5001/scan/{scan_id}/report?format=html
```

### List All Scans and Reports
```bash
# List all scans
curl http://localhost:5001/scans

# List all reports
curl http://localhost:5001/reports
```

### Run Tests
```bash
docker-compose run jwt-tests
```

### Interactive Development
```bash
docker-compose run jwt-tool-interactive
# You'll get a shell inside the container
```

## Report Organization

### Directory Structure
```
reports/
├── cli/          # CLI-generated reports
│   ├── cli_scan_YYYYMMDD_HHMMSS.html
│   └── cli_scan_YYYYMMDD_HHMMSS.json
└── api/          # API-generated reports
    └── api_scan_scan_id_YYYYMMDD_HHMMSS.html
```

### Naming Conventions
- **CLI Reports**: `cli_scan_YYYYMMDD_HHMMSS.html`
- **API Reports**: `api_scan_{scan_id}_{YYYYMMDD_HHMMSS}.html`

## Production Notes

- All API services run in production mode (debug=False)
- All services run as non-root user (jwtuser)
- Volumes are properly mounted for data persistence
- CORS is enabled for the API
- Separate report directories prevent conflicts
- Enhanced API provides scan ID management and session persistence

## Troubleshooting

### Port Already in Use
If a port is already in use, change it in docker-compose.yml:
```yaml
ports:
  - "5002:5000"  # Use port 5002 on host
```

### Permission Issues
Ensure the host directories have proper permissions:
```bash
chmod 755 ./reports ./reports/cli ./reports/api ./output ./config
```

### Build Issues
If you get build errors, try:
```bash
docker-compose build --no-cache
```

### API Connection Issues
Check if the API is running:
```bash
# Check container status
docker-compose ps

# Check API logs
docker-compose logs jwt-api-enhanced

# Test API connectivity
curl http://localhost:5001/status
```

### Report Directory Issues
Ensure report directories exist:
```bash
mkdir -p ./reports/cli ./reports/api
``` 