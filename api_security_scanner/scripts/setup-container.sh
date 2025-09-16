#!/bin/bash

# Setup script for API Security Scanner container environment
# This script creates necessary directories and sets up volume mounts

set -e

echo "Setting up API Security Scanner container environment..."

# Create necessary directories
echo "Creating directories..."
mkdir -p data logs reports workspace examples templates

# Set permissions
echo "Setting permissions..."
chmod 755 data logs reports workspace examples templates

# Create example workspace structure
echo "Setting up workspace structure..."
mkdir -p workspace/collections workspace/specs workspace/reports

# Create a sample .env file for container configuration
echo "Creating container configuration..."
cat > .env << EOF
# API Security Scanner Container Configuration
ZAP_HOST=zap
ZAP_PORT=8080
SCAN_DB_PATH=/app/data/scan_results.db
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
WORKSPACE_DIR=/workspace

# Optional: Custom ZAP configuration
# ZAP_PATH=/usr/local/bin/zap.sh

# Optional: Network configuration
# DOCKER_NETWORK_MODE=docker-compose
EOF

# Create a sample docker-compose override file
echo "Creating docker-compose override..."
cat > docker-compose.override.yml << EOF
version: '3.8'

services:
  scanner:
    environment:
      - ZAP_HOST=zap
      - ZAP_PORT=8080
    volumes:
      # Mount your API collections and specs
      - ./workspace:/workspace:ro
      # Mount custom plugins (optional)
      - ./plugins:/app/plugins:ro
      # Mount custom examples (optional)
      - ./examples:/app/examples:ro

  scanner-standalone:
    environment:
      - ZAP_HOST=host.docker.internal
      - ZAP_PORT=8080
    volumes:
      # Mount your API collections and specs
      - ./workspace:/workspace:ro
      # Mount custom plugins (optional)
      - ./plugins:/app/plugins:ro
      # Mount custom examples (optional)
      - ./examples:/app/examples:ro
EOF

echo "Container environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Place your API collections/specs in the workspace/ directory"
echo "2. Run: docker-compose up -d zap (to start ZAP)"
echo "3. Run: docker-compose run --rm scanner scan -f /workspace/your-collection.json"
echo ""
echo "Or for standalone mode:"
echo "1. Start ZAP on your host machine"
echo "2. Run: docker-compose run --rm scanner-standalone scan -f /workspace/your-collection.json"
