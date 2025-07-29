# 🍎 Mac Setup Guide for Jira Tool

## Prerequisites

### 1. Check Python Installation
```bash
python3 --version
# Should show Python 3.7 or higher
```

### 2. Check pip Installation
```bash
pip3 --version
# Should show pip version
```

### 3. Install Git (if not already installed)
```bash
# Using Homebrew (recommended)
brew install git

# Or download from https://git-scm.com/download/mac
```

## Installation Steps

### Step 1: Clone Repository
```bash
git clone https://github.com/4nilsj/SecEnhance.git
cd SecEnhance/jira_tool
```

### Step 2: Install Dependencies
```bash
# Install all requirements
pip3 install -r requirements.txt

# Alternative: Install individually
pip3 install requests pandas openpyxl streamlit
```

### Step 3: Verify Installation
```bash
# Test core modules
python3 -c "import core.headers, core.urls, config.settings; print('✅ Core modules working')"

# Test web app
python3 -c "import web.app; print('✅ Web app working')"
```

## Configuration

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

## Running the Tool

### Web Interface (Recommended)
```bash
# Start the web interface
python3 -m streamlit run web/app.py

# Access at: http://localhost:8501
```

### Command Line Operations
```bash
# Create tickets
python3 scripts/bulk_operations/create/bulk_create_true_positive.py \
  --excel data.xlsx \
  --url https://jira.company.com \
  --token your_token

# Remove labels
python3 scripts/bulk_operations/update/bulk_remove_labels_sync_fixed.py \
  --excel data.xlsx \
  --url https://jira.company.com \
  --token your_token \
  --labels "label1,label2"

# Upload POC files
python3 scripts/attachments/bulk_poc_upload.py \
  --excel data.xlsx \
  --dir ./poc_files \
  --url https://jira.company.com \
  --token your_token
```

## Troubleshooting

### Common Issues on Mac

1. **Permission Denied**
```bash
# Fix permissions
chmod +x scripts/*.py
chmod +x web/*.py
```

2. **Python Path Issues**
```bash
# Use python3 explicitly
python3 script.py

# Or create alias
alias python=python3
```

3. **Package Installation Issues**
```bash
# Upgrade pip
pip3 install --upgrade pip

# Install with user flag
pip3 install --user -r requirements.txt
```

4. **Streamlit Issues**
```bash
# Clear streamlit cache
streamlit cache clear

# Run with specific port
streamlit run web/app.py --server.port 8501
```

## Mac-Specific Tips

### 1. Use Homebrew for Additional Tools
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install useful tools
brew install jq  # JSON processor
brew install tree # Directory tree viewer
```

### 2. Terminal Customization
```bash
# Add to ~/.zshrc or ~/.bash_profile
export PATH="/usr/local/bin:$PATH"
alias ll='ls -la'
alias python=python3
```

### 3. File Permissions
```bash
# Make scripts executable
chmod +x *.py
chmod +x scripts/**/*.py
chmod +x web/*.py
```

## Performance Optimization

### 1. Use Virtual Environment
```bash
# Create virtual environment
python3 -m venv jira_tool_env

# Activate it
source jira_tool_env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Optimize for Large Files
```bash
# Set environment variables for better performance
export PYTHONOPTIMIZE=1
export PYTHONUNBUFFERED=1
```

## Security Considerations

### 1. Secure Token Storage
```bash
# Use keychain for token storage
security add-generic-password -a $USER -s jira-tool -w "your-token"

# Retrieve token
security find-generic-password -a $USER -s jira-tool -w
```

### 2. File Permissions
```bash
# Secure sensitive files
chmod 600 config/settings.py
chmod 600 *.xlsx
```

## Support

If you encounter issues on Mac:

1. **Check Python Version**: Ensure you're using Python 3.7+
2. **Verify Dependencies**: Run `pip3 list` to see installed packages
3. **Check Permissions**: Ensure scripts are executable
4. **Review Logs**: Check for error messages in terminal output

## Quick Start Commands

```bash
# Complete setup in one go
git clone https://github.com/4nilsj/SecEnhance.git
cd SecEnhance/jira_tool
pip3 install -r requirements.txt
python3 config/config_manager.py
python3 -m streamlit run web/app.py
```

🎉 **Your Jira Tool is now ready to use on Mac!** 🍎 