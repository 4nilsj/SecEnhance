# 🍎 Jira Tool - Mac User Guide

## Overview

The Jira Tool is a comprehensive automation suite for Jira operations, designed to work seamlessly on macOS. This guide provides everything you need to get started on your Mac.

## 🚀 Quick Start (Mac)

### Option 1: Automated Setup (Recommended)
```bash
# Download and run the automated setup script
curl -O https://raw.githubusercontent.com/4nilsj/SecEnhance/main/jira_tool/mac_quick_setup.sh
chmod +x mac_quick_setup.sh
./mac_quick_setup.sh
```

### Option 2: Manual Setup
```bash
# 1. Clone the repository
git clone https://github.com/4nilsj/SecEnhance.git
cd SecEnhance/jira_tool

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Configure the tool
python3 config/config_manager.py

# 4. Start the web interface
python3 -m streamlit run web/app.py
```

## 📋 Prerequisites

### Required Software
- **Python 3.7+** (usually pre-installed on Mac)
- **pip3** (Python package manager)
- **Git** (for cloning the repository)

### Optional but Recommended
- **Homebrew** (for easy package management)
- **iTerm2** (enhanced terminal experience)

## 🔧 Installation

### Step 1: Check Your System
```bash
# Check Python version
python3 --version

# Check pip version
pip3 --version

# Check Git version
git --version
```

### Step 2: Install Missing Dependencies
If any of the above commands fail, install the missing components:

**Python 3:**
```bash
# Using Homebrew (recommended)
brew install python

# Or download from https://www.python.org/downloads/
```

**Git:**
```bash
# Using Homebrew
brew install git

# Or download from https://git-scm.com/download/mac
```

### Step 3: Clone and Setup
```bash
# Clone the repository
git clone https://github.com/4nilsj/SecEnhance.git
cd SecEnhance/jira_tool

# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x scripts/**/*.py
chmod +x web/*.py
chmod +x *.py
```

## ⚙️ Configuration

### Option 1: Interactive Configuration
```bash
python3 config/config_manager.py
```

### Option 2: Environment Variables
```bash
export JIRA_URL="https://your-jira-instance.com"
export JIRA_TOKEN="your-bearer-token"
export JIRA_PROJECT_KEY="YOUR_PROJECT"
```

### Option 3: Direct Configuration
Edit `config/settings.py` with your Jira details.

## 🎯 Usage

### Web Interface (Recommended)
```bash
# Start the web interface
python3 -m streamlit run web/app.py

# Access at: http://localhost:8501
```

### Command Line Operations

**Create Tickets:**
```bash
python3 scripts/bulk_operations/create/bulk_create_true_positive.py \
  --excel data.xlsx \
  --url https://jira.company.com \
  --token your_token
```

**Remove Labels:**
```bash
python3 scripts/bulk_operations/update/bulk_remove_labels_sync_fixed.py \
  --excel data.xlsx \
  --url https://jira.company.com \
  --token your_token \
  --labels "label1,label2"
```

**Upload POC Files:**
```bash
python3 scripts/attachments/bulk_poc_upload.py \
  --excel data.xlsx \
  --dir ./poc_files \
  --url https://jira.company.com \
  --token your_token
```

**Workflow Transitions:**
```bash
# Security workflow
python3 scripts/bulk_operations/transition/bulk_transition_security_workflow.py \
  --excel data.xlsx \
  --url https://jira.company.com \
  --token your_token

# Dev workflow
python3 scripts/bulk_operations/transition/bulk_transition_dev_workflow.py \
  --excel data.xlsx \
  --url https://jira.company.com \
  --token your_token
```

## 🧪 Testing

### Run Compatibility Test
```bash
python3 mac_compatibility_test.py
```

### Test Individual Components
```bash
# Test core modules
python3 -c "import core.headers, core.urls, config.settings; print('✅ Core modules working')"

# Test web app
python3 -c "import web.app; print('✅ Web app working')"

# Test scripts
python3 -c "import scripts.bulk_operations.create.bulk_create_true_positive; print('✅ Scripts working')"
```

## 🔧 Troubleshooting

### Common Issues on Mac

**1. Permission Denied**
```bash
# Fix permissions
chmod +x scripts/*.py
chmod +x web/*.py
chmod +x *.py
```

**2. Python Path Issues**
```bash
# Use python3 explicitly
python3 script.py

# Or create alias in ~/.zshrc or ~/.bash_profile
alias python=python3
```

**3. Package Installation Issues**
```bash
# Upgrade pip
pip3 install --upgrade pip

# Install with user flag
pip3 install --user -r requirements.txt

# Clear pip cache
pip3 cache purge
```

**4. Streamlit Issues**
```bash
# Clear streamlit cache
streamlit cache clear

# Run with specific port
streamlit run web/app.py --server.port 8501

# Run with debug mode
streamlit run web/app.py --logger.level debug
```

**5. Network Issues**
```bash
# Check network connectivity
python3 -c "import requests; print(requests.get('https://httpbin.org/get').status_code)"
```

### Performance Optimization

**1. Use Virtual Environment**
```bash
# Create virtual environment
python3 -m venv jira_tool_env

# Activate it
source jira_tool_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**2. Optimize for Large Files**
```bash
# Set environment variables
export PYTHONOPTIMIZE=1
export PYTHONUNBUFFERED=1
```

## 🔒 Security

### Secure Token Storage
```bash
# Use keychain for token storage
security add-generic-password -a $USER -s jira-tool -w "your-token"

# Retrieve token
security find-generic-password -a $USER -s jira-tool -w
```

### File Permissions
```bash
# Secure sensitive files
chmod 600 config/settings.py
chmod 600 *.xlsx
```

## 📚 Additional Resources

### Documentation
- **Main Guide**: `README.md`
- **Mac Setup**: `mac_setup_guide.md`
- **Configuration**: `config/README.md`
- **Scripts**: `scripts/README.md`

### Tools and Scripts
- **Compatibility Test**: `mac_compatibility_test.py`
- **Quick Setup**: `mac_quick_setup.sh`
- **Configuration Manager**: `config/config_manager.py`

### Useful Mac Commands
```bash
# View directory structure
tree -I '__pycache__'

# Monitor system resources
top -pid $(pgrep -f streamlit)

# Check open ports
lsof -i :8501

# View logs
tail -f ~/.streamlit/logs/streamlit.log
```

## 🆘 Support

### Getting Help
1. **Check the logs**: Look for error messages in terminal output
2. **Run compatibility test**: `python3 mac_compatibility_test.py`
3. **Check dependencies**: `pip3 list`
4. **Verify configuration**: `python3 config/config_manager.py`

### Common Solutions
- **Restart Terminal**: Close and reopen Terminal/iTerm2
- **Clear Cache**: `streamlit cache clear`
- **Reinstall Dependencies**: `pip3 install --force-reinstall -r requirements.txt`
- **Check Permissions**: Ensure scripts are executable

## 🎉 Success Indicators

You'll know everything is working when you see:
- ✅ All compatibility tests pass
- ✅ Web interface loads at http://localhost:8501
- ✅ Command line scripts run without errors
- ✅ Jira API calls succeed
- ✅ Excel files are read/written correctly

## 🚀 Next Steps

1. **Configure your Jira settings**
2. **Prepare your Excel data file**
3. **Test with a small dataset first**
4. **Scale up to your full workflow**

---

**🎉 Welcome to the Jira Tool on Mac! You're ready to automate your Jira workflows! 🍎** 