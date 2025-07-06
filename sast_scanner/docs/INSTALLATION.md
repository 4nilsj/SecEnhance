# Installation Guide

This guide provides detailed instructions for installing the AI-Enabled SAST Scanner on different platforms and environments.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Installation](#quick-installation)
- [Detailed Installation](#detailed-installation)
- [Docker Installation](#docker-installation)
- [Development Installation](#development-installation)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **OS**: Windows 10+, macOS 10.14+, Ubuntu 18.04+

### Recommended Requirements
- **Python**: 3.9 or higher
- **RAM**: 16GB or more
- **Storage**: 5GB free space
- **CPU**: Multi-core processor
- **GPU**: NVIDIA GPU with CUDA support (optional, for AI acceleration)

### Dependencies
- **pip**: Latest version
- **git**: For cloning repository
- **Docker**: For containerized installation (optional)

## Quick Installation

### Method 1: Using pip (Recommended)

```bash
# Install directly from repository
pip install git+https://github.com/your-repo/sast-scanner.git

# Verify installation
sast-scanner --version
```

### Method 2: Clone and Install

```bash
# Clone the repository
git clone https://github.com/your-repo/sast-scanner.git
cd sast-scanner

# Install dependencies
pip install -r requirements.txt

# Verify installation
python sast_scanner_cli.py version
```

## Detailed Installation

### Step 1: Prepare Environment

#### Windows
```powershell
# Create virtual environment
python -m venv sast-env
sast-env\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip
```

#### macOS/Linux
```bash
# Create virtual environment
python3 -m venv sast-env
source sast-env/bin/activate

# Upgrade pip
pip install --upgrade pip
```

### Step 2: Install Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Install optional AI dependencies (for enhanced features)
pip install torch transformers
```

### Step 3: Verify Installation

```bash
# Check version
python sast_scanner_cli.py version

# Run basic test
python sast_scanner_cli.py scan file examples/sample.py
```

## Docker Installation

### Method 1: Using Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/your-repo/sast-scanner.git
cd sast-scanner

# Build and run with Docker Compose
docker-compose up --build

# Run scan from container
docker-compose exec sast-scanner python sast_scanner_cli.py scan file examples/sample.py
```

### Method 2: Using Dockerfile

```bash
# Build image
docker build -t sast-scanner .

# Run container
docker run -v $(pwd):/workspace sast-scanner python sast_scanner_cli.py scan directory /workspace
```

### Method 3: Using Pre-built Image

```bash
# Pull pre-built image
docker pull your-repo/sast-scanner:latest

# Run container
docker run -v $(pwd):/workspace your-repo/sast-scanner:latest python sast_scanner_cli.py scan directory /workspace
```

## Development Installation

### Step 1: Clone Repository

```bash
# Clone with submodules
git clone --recursive https://github.com/your-repo/sast-scanner.git
cd sast-scanner

# Or clone and update submodules
git clone https://github.com/your-repo/sast-scanner.git
cd sast-scanner
git submodule update --init --recursive
```

### Step 2: Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .
```

### Step 3: Configure Development Tools

```bash
# Install pre-commit hooks
pre-commit install

# Configure git hooks
git config core.hooksPath .githooks
```

### Step 4: Run Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test categories
python -m pytest tests/unit/
python -m pytest tests/integration/

# Run with coverage
python -m pytest --cov=src tests/
```

## Platform-Specific Installation

### Windows

#### Prerequisites
```powershell
# Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Install Windows Subsystem for Linux (WSL) - Optional
wsl --install
```

#### Installation
```powershell
# Use PowerShell with execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install Python dependencies
pip install -r requirements.txt

# For GPU support (optional)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

### macOS

#### Prerequisites
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.9

# Install Xcode Command Line Tools
xcode-select --install
```

#### Installation
```bash
# Install dependencies
pip install -r requirements.txt

# For M1/M2 Macs (optional GPU support)
pip install torch torchvision torchaudio
```

### Linux (Ubuntu/Debian)

#### Prerequisites
```bash
# Update package list
sudo apt update

# Install system dependencies
sudo apt install -y python3 python3-pip python3-venv git build-essential

# Install additional dependencies
sudo apt install -y libffi-dev libssl-dev libjpeg-dev zlib1g-dev
```

#### Installation
```bash
# Create virtual environment
python3 -m venv sast-env
source sast-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Linux (CentOS/RHEL)

#### Prerequisites
```bash
# Install EPEL repository
sudo yum install -y epel-release

# Install system dependencies
sudo yum install -y python3 python3-pip git gcc

# Install development tools
sudo yum groupinstall -y "Development Tools"
```

#### Installation
```bash
# Create virtual environment
python3 -m venv sast-env
source sast-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Debug mode
SAST_DEBUG=true

# Output directory
SAST_OUTPUT_DIR=./reports

# Maximum workers
SAST_MAX_WORKERS=4

# AI model path
SAST_AI_MODEL_PATH=./models

# Log level
SAST_LOG_LEVEL=INFO
```

### Configuration File

Create `sast_config.json`:

```json
{
  "max_workers": 4,
  "default_output_format": "html",
  "exclude_patterns": ["*test*", "*spec*", "node_modules"],
  "include_patterns": ["*.py", "*.js", "*.java"],
  "debug_mode": false,
  "ai_enabled": true,
  "ai_model_path": "./models",
  "log_level": "INFO",
  "output_directory": "./reports"
}
```

## Troubleshooting

### Common Issues

#### Python Version Issues
```bash
# Check Python version
python --version

# If version is too old, upgrade Python
# Windows: Download from python.org
# macOS: brew install python@3.9
# Linux: sudo apt install python3.9
```

#### Dependency Installation Issues
```bash
# Upgrade pip
pip install --upgrade pip

# Clear pip cache
pip cache purge

# Install with verbose output
pip install -r requirements.txt -v

# Install with force reinstall
pip install -r requirements.txt --force-reinstall
```

#### Permission Issues
```bash
# Linux/macOS: Use sudo for system-wide installation
sudo pip install -r requirements.txt

# Or use user installation
pip install --user -r requirements.txt
```

#### Memory Issues
```bash
# Reduce worker threads
export SAST_MAX_WORKERS=2

# Use smaller AI models
export SAST_AI_MODEL_SIZE=base
```

#### GPU Issues
```bash
# Check CUDA installation
nvidia-smi

# Install CPU-only version
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
```

### Getting Help

#### Check Logs
```bash
# Enable debug logging
export SAST_DEBUG=true
export SAST_LOG_LEVEL=DEBUG

# Run scan and check logs
python sast_scanner_cli.py scan file app.py
tail -f logs/sast_scanner_*.log
```

#### Run Diagnostics
```bash
# Run system check
python sast_scanner_cli.py diagnose

# Check dependencies
python sast_scanner_cli.py check-deps
```

#### Contact Support
- **GitHub Issues**: [Report bugs](https://github.com/your-repo/issues)
- **Discord**: [Join community](https://discord.gg/your-server)
- **Email**: sast-scanner@example.com

## Next Steps

After successful installation:

1. **Read the [Usage Guide](USAGE.md)** for basic usage instructions
2. **Check the [API Reference](API_REFERENCE.md)** for advanced features
3. **Review the [Vulnerability Database](VULNERABILITIES.md)** for supported vulnerabilities
4. **Run the quick start example**:
   ```bash
   python quick_start.py
   ```

## Uninstallation

### Remove Python Package
```bash
# Remove from pip
pip uninstall sast-scanner

# Remove virtual environment
rm -rf sast-env/
```

### Remove Docker Images
```bash
# Remove Docker image
docker rmi sast-scanner

# Remove all related images
docker images | grep sast-scanner | awk '{print $3}' | xargs docker rmi
```

### Clean Up Files
```bash
# Remove cloned repository
rm -rf sast-scanner/

# Remove configuration files
rm -f ~/.sast_scanner_config.json
rm -f .env
``` 