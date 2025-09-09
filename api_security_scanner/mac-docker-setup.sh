#!/bin/bash

# macOS Docker Setup Script for API Security Scanner
# This script sets up the API Security Scanner using Docker on macOS
# No administrator privileges required!

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🍎 macOS Docker Setup for API Security Scanner${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}Error: This script is designed for macOS only${NC}"
    exit 1
fi

# Check if Docker is installed
echo -e "${BLUE}Checking Docker installation...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker is not installed. Please install Docker Desktop first:${NC}"
    echo -e "${YELLOW}1. Download from: https://www.docker.com/products/docker-desktop/${NC}"
    echo -e "${YELLOW}2. Install Docker Desktop (no admin privileges required)${NC}"
    echo -e "${YELLOW}3. Start Docker Desktop${NC}"
    echo -e "${YELLOW}4. Run this script again${NC}"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo -e "${YELLOW}Docker is not running. Please start Docker Desktop and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is installed and running${NC}"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}Docker Compose not found. Using 'docker compose' instead...${NC}"
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

echo -e "${GREEN}✓ Docker Compose is available${NC}"

# Create necessary directories
echo -e "${BLUE}Creating directories...${NC}"
mkdir -p data logs reports workspace examples templates
mkdir -p workspace/collections workspace/specs workspace/reports

echo -e "${GREEN}✓ Directories created${NC}"

# Create .env file for container configuration
echo -e "${BLUE}Creating container configuration...${NC}"
cat > .env << EOF
# API Security Scanner Container Configuration for macOS
ZAP_HOST=zap
ZAP_PORT=8080
SCAN_DB_PATH=/app/data/scan_results.db
LOG_DIR=/app/logs
REPORTS_DIR=/app/reports
WORKSPACE_DIR=/workspace

# macOS-specific settings
DOCKER_NETWORK_MODE=docker-compose
EOF

echo -e "${GREEN}✓ Configuration file created${NC}"

# Build the Docker image
echo -e "${BLUE}Building Docker image...${NC}"
if docker build -t api-security-scanner .; then
    echo -e "${GREEN}✓ Docker image built successfully${NC}"
else
    echo -e "${RED}✗ Docker build failed${NC}"
    exit 1
fi

# Run health check
echo -e "${BLUE}Running health check...${NC}"
if docker run --rm api-security-scanner python /app/healthcheck.py; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${RED}✗ Health check failed${NC}"
    exit 1
fi

# Test ZAP service
echo -e "${BLUE}Testing ZAP service...${NC}"
if $COMPOSE_CMD up -d zap; then
    echo -e "${GREEN}✓ ZAP service started${NC}"
    
    # Wait for ZAP to be ready
    echo -e "${BLUE}Waiting for ZAP to be ready...${NC}"
    sleep 10
    
    # Test ZAP connectivity
    if $COMPOSE_CMD run --rm scanner curl -f http://zap:8080/JSON/core/view/version/ &> /dev/null; then
        echo -e "${GREEN}✓ ZAP is ready and accessible${NC}"
    else
        echo -e "${YELLOW}⚠ ZAP started but may not be fully ready yet${NC}"
    fi
else
    echo -e "${YELLOW}⚠ ZAP service failed to start (this is optional)${NC}"
fi

# Create sample API collection for testing
echo -e "${BLUE}Creating sample API collection...${NC}"
cat > workspace/sample_collection.json << EOF
{
  "info": {
    "name": "Sample API Collection",
    "description": "Sample collection for testing API Security Scanner"
  },
  "item": [
    {
      "name": "Test GET Request",
      "request": {
        "method": "GET",
        "header": [],
        "url": {
          "raw": "https://httpbin.org/get",
          "protocol": "https",
          "host": ["httpbin", "org"],
          "path": ["get"]
        }
      }
    }
  ]
}
EOF

echo -e "${GREEN}✓ Sample collection created${NC}"

# Create convenience scripts
echo -e "${BLUE}Creating convenience scripts...${NC}"

# Create scan script
cat > scan.sh << 'EOF'
#!/bin/bash
# Convenience script for running scans

if [ $# -eq 0 ]; then
    echo "Usage: $0 <collection-file> [additional-args]"
    echo "Example: $0 workspace/sample_collection.json"
    echo "Example: $0 workspace/sample_collection.json --no-zap"
    exit 1
fi

COLLECTION_FILE="$1"
shift

# Check if file exists
if [ ! -f "$COLLECTION_FILE" ]; then
    echo "Error: Collection file '$COLLECTION_FILE' not found"
    exit 1
fi

# Run the scan
docker-compose run --rm scanner scan -f "/workspace/$(basename "$COLLECTION_FILE")" "$@"
EOF

chmod +x scan.sh

# Create quick test script
cat > test-scan.sh << 'EOF'
#!/bin/bash
# Quick test scan using the sample collection

echo "Running quick test scan..."
docker-compose run --rm scanner scan -f /workspace/sample_collection.json --no-zap

echo ""
echo "Test completed! Check the reports/ directory for results."
EOF

chmod +x test-scan.sh

echo -e "${GREEN}✓ Convenience scripts created${NC}"

# Display setup completion message
echo ""
echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo -e "${GREEN}=================${NC}"
echo ""
echo -e "${BLUE}Your API Security Scanner is ready to use!${NC}"
echo ""
echo -e "${YELLOW}Quick Start Commands:${NC}"
echo -e "  ${BLUE}./test-scan.sh${NC}                    # Run a quick test scan"
echo -e "  ${BLUE}./scan.sh workspace/your-file.json${NC} # Scan your API collection"
echo -e "  ${BLUE}./scan.sh workspace/your-file.json --no-zap${NC} # Scan without ZAP"
echo ""
echo -e "${YELLOW}Manual Commands:${NC}"
echo -e "  ${BLUE}docker-compose up -d zap${NC}          # Start ZAP service"
echo -e "  ${BLUE}docker-compose run --rm scanner scan -f /workspace/collection.json${NC}"
echo -e "  ${BLUE}docker-compose logs zap${NC}           # View ZAP logs"
echo -e "  ${BLUE}docker-compose logs scanner${NC}       # View scanner logs"
echo ""
echo -e "${YELLOW}Directory Structure:${NC}"
echo -e "  ${BLUE}workspace/${NC}                        # Place your API collections here"
echo -e "  ${BLUE}reports/${NC}                          # Generated reports appear here"
echo -e "  ${BLUE}logs/${NC}                             # Log files are stored here"
echo -e "  ${BLUE}data/${NC}                             # Database files are stored here"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Place your API collection files in the ${BLUE}workspace/${NC} directory"
echo -e "  2. Run ${BLUE}./test-scan.sh${NC} to test the setup"
echo -e "  3. Use ${BLUE}./scan.sh${NC} to scan your API collections"
echo -e "  4. Check the ${BLUE}reports/${NC} directory for scan results"
echo ""
echo -e "${GREEN}Happy scanning! 🔍${NC}"
