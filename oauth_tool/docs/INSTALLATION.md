# OAuth/OIDC Security Testing Tool - Installation Guide

This guide provides step-by-step instructions for installing and setting up the OAuth/OIDC Security Testing Tool.

## Prerequisites

### System Requirements
- **Python 3.7 or higher**
- **pip** (Python package installer)
- **Internet connection** for downloading dependencies and testing OAuth providers
- **Git** (optional, for cloning the repository)

### Operating System Support
- ✅ Windows 10/11
- ✅ macOS 10.14+
- ✅ Linux (Ubuntu 18.04+, CentOS 7+, etc.)

## Installation Methods

### Method 1: Direct Installation (Recommended)

#### Step 1: Download the Tool
```bash
# Navigate to your desired directory
cd /path/to/your/workspace

# The tool should already be in the oauth_tool/ directory
ls oauth_tool/
```

#### Step 2: Install Python Dependencies
```bash
# Navigate to the oauth_tool directory
cd oauth_tool

# Install required packages
pip install -r requirements.txt
```

#### Step 3: Verify Installation
```bash
# Test the installation
python src/oauth_oidc_tester.py --help
```

You should see the help output with all available options.

### Method 2: Virtual Environment Installation (Recommended for Production)

#### Step 1: Create Virtual Environment
```bash
# Navigate to oauth_tool directory
cd oauth_tool

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

#### Step 2: Install Dependencies
```bash
# Install packages in virtual environment
pip install -r requirements.txt
```

#### Step 3: Verify Installation
```bash
# Test the tool
python src/oauth_oidc_tester.py --help
```

### Method 3: Docker Installation (Advanced)

#### Step 1: Create Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT ["python", "src/oauth_oidc_tester.py"]
```

#### Step 2: Build and Run
```bash
# Build Docker image
docker build -t oauth-security-tester .

# Run the tool
docker run oauth-security-tester --help
```

## Dependencies

### Core Dependencies
- **requests (2.31.0)**: HTTP library for API calls
- **PyJWT (2.8.0)**: JWT token handling
- **cryptography (41.0.7)**: Cryptographic operations
- **Flask (3.0.2)**: Web framework (for future local server features)
- **rich (13.7.0)**: Rich text and formatting for CLI

### Optional Dependencies
- **colorama**: Better color support on Windows
- **urllib3**: HTTP client (included with requests)

## Configuration

### Environment Variables (Optional)
```bash
# Set these environment variables for convenience
export OAUTH_ISSUER="https://your-oauth-provider.com"
export OAUTH_CLIENT_ID="your_client_id"
export OAUTH_CLIENT_SECRET="your_client_secret"
export OAUTH_REDIRECT_URI="http://localhost:8080/callback"
```

### Configuration File (Future Feature)
Create a `config.json` file for persistent settings:
```json
{
  "default_issuer": "https://your-oauth-provider.com",
  "default_client_id": "your_client_id",
  "default_redirect_uri": "http://localhost:8080/callback",
  "default_scope": "openid profile email",
  "timeout": 10,
  "max_retries": 3
}
```

## Verification Steps

### Step 1: Basic Functionality Test
```bash
# Test help command
python src/oauth_oidc_tester.py --help

# Expected output: Shows all available options and commands
```

### Step 2: Discovery Test
```bash
# Test OIDC discovery (replace with a real OAuth provider)
python src/oauth_oidc_tester.py --issuer https://accounts.google.com --client-id test --redirect-uri http://localhost:8080/callback

# Expected output: Should show OIDC metadata discovery results
```

### Step 3: Example Scenario Test
```bash
# Run an example scenario
cd examples
python test_scenarios.py

# Expected output: Shows available test scenarios
```

## Troubleshooting

### Common Installation Issues

#### Issue 1: Python Version
```bash
# Check Python version
python --version

# If version is < 3.7, upgrade Python
# Windows: Download from python.org
# macOS: brew install python@3.9
# Linux: sudo apt-get install python3.9
```

#### Issue 2: pip Not Found
```bash
# Install pip
python -m ensurepip --upgrade

# Or on Ubuntu/Debian:
sudo apt-get install python3-pip
```

#### Issue 3: Permission Errors
```bash
# Use --user flag for user installation
pip install --user -r requirements.txt

# Or use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

#### Issue 4: SSL Certificate Errors
```bash
# Update certificates
pip install --upgrade certifi

# Or use trusted hosts
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
```

#### Issue 5: Missing Dependencies
```bash
# Force reinstall all dependencies
pip install --force-reinstall -r requirements.txt

# Or install individually
pip install requests PyJWT cryptography Flask rich
```

### Platform-Specific Issues

#### Windows
```bash
# Install Visual C++ Build Tools (if needed)
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Use Windows Subsystem for Linux (WSL) for better compatibility
wsl
```

#### macOS
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Use Homebrew for Python
brew install python@3.9
```

#### Linux
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3-dev python3-pip python3-venv

# Or on CentOS/RHEL:
sudo yum install python3-devel python3-pip
```

## Security Considerations

### Installation Security
- ✅ Install from trusted sources only
- ✅ Use virtual environments to isolate dependencies
- ✅ Keep Python and pip updated
- ✅ Verify package signatures when possible

### Runtime Security
- ⚠️ Only test OAuth implementations you own or have permission to test
- ⚠️ Be aware that some tests may trigger security alerts
- ⚠️ Follow responsible disclosure practices
- ⚠️ Use in controlled environments

## Next Steps

After successful installation:

1. **Read the Usage Guide**: See `docs/USAGE.md`
2. **Review Examples**: Check `examples/test_scenarios.py`
3. **Configure OAuth Provider**: Set up your OAuth application
4. **Run First Test**: Try a basic discovery test
5. **Generate Report**: Run comprehensive security audit

## Support

If you encounter issues:

1. Check this troubleshooting guide
2. Review the error messages carefully
3. Ensure all prerequisites are met
4. Try the virtual environment approach
5. Check Python and pip versions

For additional help, refer to the main README.md file or the examples directory. 