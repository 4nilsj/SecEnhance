# Jira Bearer Token Management Guide

## Overview

This guide explains how to update and manage your Jira bearer token across all scripts in the Jira tool.

## Where to Update the Bearer Token

### 1. **Command Line (Current Method)**
Pass the token as a parameter when running scripts:

```bash
python bulk_create.py --url "https://your-jira.com" --token "your_bearer_token" --excel data.xlsx --project PROJ
```

### 2. **Environment Variables (Recommended)**
Set environment variables to avoid passing tokens in command line:

#### Windows (PowerShell):
```powershell
$env:JIRA_BASE_URL="https://your-jira.com"
$env:JIRA_TOKEN="your_bearer_token_here"
```

#### Windows (Command Prompt):
```cmd
set JIRA_BASE_URL=https://your-jira.com
set JIRA_TOKEN=your_bearer_token_here
```

#### Linux/Mac:
```bash
export JIRA_BASE_URL="https://your-jira.com"
export JIRA_TOKEN="your_bearer_token_here"
```

### 3. **Configuration File (Easy Setup)**
Use the provided configuration system:

```bash
python update_token.py
```

Then choose option 2 to update the default token in `config.py`.

### 4. **Direct File Edit**
Edit `config.py` and update the `DEFAULT_JIRA_TOKEN` variable:

```python
DEFAULT_JIRA_TOKEN = "your_actual_bearer_token_here"
```

## Quick Setup

### Option A: Interactive Setup (Recommended)
```bash
cd jira_tool
python update_token.py
```

### Option B: Environment Variables (Most Secure)
```bash
# Set environment variables
$env:JIRA_TOKEN="your_bearer_token_here"  # Windows PowerShell
export JIRA_TOKEN="your_bearer_token_here"  # Linux/Mac

# Then run scripts without --token parameter
python bulk_create.py --excel data.xlsx --project PROJ
```

### Option C: Direct Configuration
Edit `config.py` and change:
```python
DEFAULT_JIRA_TOKEN = "your_actual_bearer_token_here"
```

## Token Security Best Practices

### ✅ Recommended
- Use environment variables for production
- Store tokens in secure credential managers
- Rotate tokens regularly
- Use least-privilege tokens

### ❌ Avoid
- Hardcoding tokens in scripts
- Committing tokens to version control
- Sharing tokens in plain text
- Using admin tokens for regular operations

## Getting Your Jira Bearer Token

### For Jira Cloud:
1. Go to your Jira instance
2. Click on your profile picture → Settings
3. Go to Security → API tokens
4. Create a new API token
5. Copy the token (it won't be shown again)

### For Jira Server:
1. Go to your Jira instance
2. Click on your profile picture → Settings
3. Go to Personal access tokens
4. Create a new token
5. Copy the token

## Testing Your Token

### Method 1: Use the Update Script
```bash
python update_token.py
# Choose option 4 to test configuration
```

### Method 2: Test with a Simple Script
```bash
python bulk_status.py --url "https://your-jira.com" --token "your_token" --excel test.xlsx
```

### Method 3: Check Environment Variables
```bash
echo $env:JIRA_TOKEN  # Windows PowerShell
echo $JIRA_TOKEN      # Linux/Mac
```

## Troubleshooting

### Token Not Working
1. Verify the token is correct
2. Check if the token has expired
3. Ensure the token has proper permissions
4. Verify the Jira URL is correct

### Environment Variables Not Working
1. Restart your terminal/IDE after setting variables
2. Check variable names (case-sensitive on Linux/Mac)
3. Verify the variables are set: `echo $env:JIRA_TOKEN`

### Scripts Still Asking for Token
1. Make sure you're using the `--token` parameter
2. Or set environment variables and restart terminal
3. Check if the config.py file is being read correctly

## File Locations

### Configuration Files
- `config.py` - Main configuration file
- `update_token.py` - Interactive token update tool

### Scripts That Use Tokens
All scripts in `scripts/` directory use the token parameter:
- `bulk_create.py`
- `bulk_update.py`
- `bulk_comment.py`
- `bulk_status.py`
- `bulk_transition.py`
- `bulk_attachment.py`
- And all other bulk operation scripts

## Examples

### Running with Command Line Token
```bash
python bulk_create.py --url "https://company.atlassian.net" --token "ATATT3xFfGF0..." --excel tickets.xlsx --project PROJ
```

### Running with Environment Variables
```bash
# Set variables
$env:JIRA_BASE_URL="https://company.atlassian.net"
$env:JIRA_TOKEN="ATATT3xFfGF0..."

# Run script (no --token needed)
python bulk_create.py --excel tickets.xlsx --project PROJ
```

### Running with Configuration File
```bash
# After updating config.py
python bulk_create.py --excel tickets.xlsx --project PROJ
```

## Security Notes

- Never commit tokens to version control
- Use environment variables in production
- Rotate tokens regularly
- Use tokens with minimal required permissions
- Consider using Jira's OAuth for better security

## Support

If you have issues with token management:
1. Check the troubleshooting section above
2. Run `python update_token.py` for interactive help
3. Verify your Jira instance and permissions
4. Test with a simple API call first 