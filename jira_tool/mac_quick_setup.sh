#!/bin/bash
# Mac Quick Setup Script for Jira Tool
# This script automates the setup process on macOS

set -e  # Exit on any error

echo "🍎 Mac Quick Setup for Jira Tool"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_error "This script is designed for macOS only!"
    exit 1
fi

print_success "Running on macOS"

# Check Python installation
print_info "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    print_success "Python found: $PYTHON_VERSION"
else
    print_error "Python 3 not found. Please install Python 3.7+ first."
    print_info "You can install it from https://www.python.org/downloads/"
    exit 1
fi

# Check pip installation
print_info "Checking pip installation..."
if command -v pip3 &> /dev/null; then
    print_success "pip3 found"
else
    print_error "pip3 not found. Please install pip first."
    exit 1
fi

# Check Git installation
print_info "Checking Git installation..."
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version)
    print_success "Git found: $GIT_VERSION"
else
    print_warning "Git not found. Installing via Homebrew..."
    if command -v brew &> /dev/null; then
        brew install git
        print_success "Git installed via Homebrew"
    else
        print_error "Homebrew not found. Please install Git manually from https://git-scm.com/download/mac"
        exit 1
    fi
fi

# Clone repository if not already present
if [ ! -d "SecEnhance" ]; then
    print_info "Cloning repository..."
    git clone https://github.com/4nilsj/SecEnhance.git
    print_success "Repository cloned"
else
    print_info "Repository already exists"
fi

# Navigate to jira_tool directory
cd SecEnhance/jira_tool

# Install dependencies
print_info "Installing Python dependencies..."
pip3 install -r requirements.txt
print_success "Dependencies installed"

# Make scripts executable
print_info "Setting up file permissions..."
chmod +x scripts/**/*.py
chmod +x web/*.py
chmod +x *.py
print_success "File permissions set"

# Run compatibility test
print_info "Running compatibility test..."
python3 mac_compatibility_test.py

# Create virtual environment (optional)
read -p "Do you want to create a virtual environment? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Creating virtual environment..."
    python3 -m venv jira_tool_env
    print_success "Virtual environment created"
    print_info "To activate: source jira_tool_env/bin/activate"
fi

# Configuration setup
print_info "Setting up configuration..."
if [ -f "config/config_manager.py" ]; then
    print_info "Running configuration manager..."
    python3 config/config_manager.py
else
    print_warning "Configuration manager not found. Please configure manually."
fi

print_success "Setup complete!"
echo
echo "🚀 To start using the Jira Tool:"
echo "1. Web Interface: python3 -m streamlit run web/app.py"
echo "2. Command Line: python3 main.py --help"
echo "3. Configuration: python3 config/config_manager.py"
echo
echo "📖 For detailed instructions, see: mac_setup_guide.md"
echo "🧪 For compatibility test, run: python3 mac_compatibility_test.py" 