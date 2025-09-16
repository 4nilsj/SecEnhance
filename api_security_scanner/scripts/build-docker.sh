#!/bin/bash

# Docker build script for API Security Scanner
# This script provides various build options and optimizations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="api-security-scanner"
TAG="latest"
PLATFORM="linux/amd64"
BUILD_ARGS=""
PUSH=false
NO_CACHE=false

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --name NAME        Image name (default: api-security-scanner)"
    echo "  -t, --tag TAG          Image tag (default: latest)"
    echo "  -p, --platform PLAT    Platform (default: linux/amd64)"
    echo "  --push                 Push image to registry after build"
    echo "  --no-cache             Build without cache"
    echo "  --multi-platform       Build for multiple platforms"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Basic build"
    echo "  $0 -t v1.0.0                         # Build with specific tag"
    echo "  $0 --multi-platform --push           # Multi-platform build and push"
    echo "  $0 --no-cache                        # Clean build"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -p|--platform)
            PLATFORM="$2"
            shift 2
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --multi-platform)
            PLATFORM="linux/amd64,linux/arm64"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Set build arguments
if [ "$NO_CACHE" = true ]; then
    BUILD_ARGS="$BUILD_ARGS --no-cache"
fi

# Full image name
FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

echo -e "${BLUE}Building API Security Scanner Docker image...${NC}"
echo -e "Image: ${GREEN}${FULL_IMAGE_NAME}${NC}"
echo -e "Platform: ${GREEN}${PLATFORM}${NC}"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

# Check if buildx is available for multi-platform builds
if [[ "$PLATFORM" == *","* ]] && ! docker buildx version &> /dev/null; then
    echo -e "${YELLOW}Warning: Docker buildx not available, falling back to single platform build${NC}"
    PLATFORM="linux/amd64"
fi

# Build the image
echo -e "${BLUE}Starting Docker build...${NC}"

if [[ "$PLATFORM" == *","* ]]; then
    # Multi-platform build
    echo -e "${BLUE}Building for multiple platforms: ${PLATFORM}${NC}"
    
    # Create and use buildx builder if it doesn't exist
    if ! docker buildx inspect scanner-builder &> /dev/null; then
        echo -e "${BLUE}Creating buildx builder...${NC}"
        docker buildx create --name scanner-builder --use
    else
        docker buildx use scanner-builder
    fi
    
    # Build and optionally push
    if [ "$PUSH" = true ]; then
        echo -e "${BLUE}Building and pushing multi-platform image...${NC}"
        docker buildx build \
            --platform "$PLATFORM" \
            --tag "$FULL_IMAGE_NAME" \
            $BUILD_ARGS \
            --push \
            .
    else
        echo -e "${BLUE}Building multi-platform image (load to local)...${NC}"
        docker buildx build \
            --platform "$PLATFORM" \
            --tag "$FULL_IMAGE_NAME" \
            $BUILD_ARGS \
            --load \
            .
    fi
else
    # Single platform build
    echo -e "${BLUE}Building for platform: ${PLATFORM}${NC}"
    docker build \
        --platform "$PLATFORM" \
        --tag "$FULL_IMAGE_NAME" \
        $BUILD_ARGS \
        .
fi

# Check if build was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Docker image built successfully!${NC}"
    echo -e "Image: ${GREEN}${FULL_IMAGE_NAME}${NC}"
    
    # Show image info
    echo ""
    echo -e "${BLUE}Image information:${NC}"
    docker images "$IMAGE_NAME" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    
    # Run health check
    echo ""
    echo -e "${BLUE}Running health check...${NC}"
    if docker run --rm "$FULL_IMAGE_NAME" python /app/healthcheck.py; then
        echo -e "${GREEN}✓ Health check passed${NC}"
    else
        echo -e "${RED}✗ Health check failed${NC}"
        exit 1
    fi
    
    # Show usage instructions
    echo ""
    echo -e "${BLUE}Usage examples:${NC}"
    echo -e "  ${YELLOW}# Run a basic scan${NC}"
    echo -e "  docker run --rm -v \$(pwd):/workspace ${FULL_IMAGE_NAME} scan -f /workspace/collection.json"
    echo ""
    echo -e "  ${YELLOW}# Run with Docker Compose${NC}"
    echo -e "  docker-compose up -d zap"
    echo -e "  docker-compose run --rm scanner scan -f /workspace/collection.json"
    echo ""
    echo -e "  ${YELLOW}# Get help${NC}"
    echo -e "  docker run --rm ${FULL_IMAGE_NAME} --help"
    
else
    echo -e "${RED}✗ Docker build failed${NC}"
    exit 1
fi
