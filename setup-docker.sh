#!/bin/bash

# Security Tools Docker Setup Script
# This script sets up Docker containers for JWT and Mobile Security Testing Tools

set -e

echo "🔧 Security Tools Docker Setup"
echo "=============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    print_status "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Docker and Docker Compose are installed"
}

# Create necessary directories
create_directories() {
    print_status "Creating output directories..."
    
    mkdir -p jwt_output jwt_tokens
    mkdir -p mobile_output mobile_input mobile_reports
    
    print_success "Directories created successfully"
}

# Build Docker images
build_images() {
    print_status "Building Docker images..."
    
    # Build JWT tool
    print_status "Building JWT Security Testing Tool..."
    cd jwt_tool
    docker build -t jwt-security-tester .
    cd ..
    
    # Build Mobile tool
    print_status "Building Mobile Security Testing Tool..."
    cd mobile_tool
    docker build -t mobile-security-tester .
    cd ..
    
    print_success "All Docker images built successfully"
}

# Test the installations
test_installations() {
    print_status "Testing installations..."
    
    # Test JWT tool
    print_status "Testing JWT tool..."
    docker run --rm jwt-security-tester --help > /dev/null 2>&1
    print_success "JWT tool is working correctly"
    
    # Test Mobile tool
    print_status "Testing Mobile tool..."
    docker run --rm mobile-security-tester --help > /dev/null 2>&1
    print_success "Mobile tool is working correctly"
}

# Create example files
create_examples() {
    print_status "Creating example files..."
    
    # Create example JWT token file
    cat > jwt_tokens/example_tokens.txt << EOF
# Example JWT tokens for testing
# Replace these with your actual tokens

# Example 1: Basic JWT token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Example 2: Add your tokens here
# your.jwt.token.here
EOF
    
    # Create example APK placeholder
    cat > mobile_input/README.txt << EOF
# Mobile Security Testing Input Directory

Place your APK or IPA files in this directory for analysis.

Example:
- app.apk
- app.ipa
- test_app.apk

The tool will analyze all files in this directory when running batch processing.
EOF
    
    print_success "Example files created"
}

# Show usage examples
show_usage() {
    echo ""
    echo "🚀 Setup Complete! Here are some usage examples:"
    echo "=============================================="
    echo ""
    
    echo "🔐 JWT Security Testing Tool:"
    echo "  # Test a single token"
    echo "  docker run --rm -v \$(pwd)/jwt_output:/app/output jwt-security-tester \\"
    echo "    --token \"your.jwt.token\" --output /app/output/report.json"
    echo ""
    echo "  # Run comprehensive test"
    echo "  docker run --rm -v \$(pwd)/jwt_output:/app/output jwt-security-tester \\"
    echo "    --token \"your.jwt.token\" --test all --output /app/output/comprehensive.json"
    echo ""
    echo "  # Interactive mode"
    echo "  docker run --rm -it jwt-security-tester"
    echo ""
    
    echo "📱 Mobile Security Testing Tool:"
    echo "  # Analyze APK file"
    echo "  docker run --rm \\"
    echo "    -v \$(pwd)/app.apk:/app/input/app.apk \\"
    echo "    -v \$(pwd)/mobile_output:/app/output \\"
    echo "    mobile-security-tester /app/input/app.apk --output /app/output/analysis.json"
    echo ""
    echo "  # Comprehensive analysis"
    echo "  docker run --rm \\"
    echo "    -v \$(pwd)/app.apk:/app/input/app.apk \\"
    echo "    -v \$(pwd)/mobile_output:/app/output \\"
    echo "    -v \$(pwd)/mobile_reports:/app/reports \\"
    echo "    mobile-security-tester \\"
    echo "    /app/input/app.apk --analysis-type comprehensive \\"
    echo "    --output /app/output/comprehensive.json \\"
    echo "    --report /app/reports/report.html"
    echo ""
    
    echo "🐳 Docker Compose Usage:"
    echo "  # Build all services"
    echo "  docker-compose build"
    echo ""
    echo "  # Run JWT tool"
    echo "  docker-compose run --rm jwt-tool --token \"your.jwt.token\""
    echo ""
    echo "  # Run Mobile tool"
    echo "  docker-compose run --rm mobile-tool /app/input/app.apk"
    echo ""
    
    echo "📚 For more information, see:"
    echo "  - DOCKER_GUIDE.md"
    echo "  - jwt_tool/README.md"
    echo "  - mobile_tool/README.md"
    echo ""
}

# Main execution
main() {
    echo "Starting Docker setup for Security Tools..."
    echo ""
    
    check_docker
    create_directories
    build_images
    test_installations
    create_examples
    show_usage
    
    print_success "Setup completed successfully!"
    echo ""
    print_status "You can now use the security testing tools with Docker."
}

# Run main function
main "$@" 