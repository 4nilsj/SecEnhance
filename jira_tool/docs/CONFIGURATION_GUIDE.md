# Jira Tool Configuration Guide

## Overview

The Jira Tool now supports centralized configuration management including project keys, custom fields, and column mappings. This guide explains how to configure and use these features.

## Configuration Components

### 1. **Jira Connection Settings**
- **Base URL**: Your Jira instance URL
- **API Token**: Your Jira API bearer token
- **Project Key**: Default project key for operations

### 2. **Custom Fields**
- **Security Ticket**: Custom field for Security Ticket IDs
- **Finding Type**: Custom field for finding classification
- **Risk Level**: Custom field for risk assessment
- **Compliance**: Custom field for compliance tracking
- **Environment**: Custom field for environment specification

### 3. **Column Mappings**
- **status**: Excel column containing status values
- **security_ticket**: Excel column for Security Ticket IDs
- **summary**: Excel column for ticket summaries
- **description**: Excel column for ticket descriptions
- **priority**: Excel column for priority values
- **assignee**: Excel column for assignee usernames
- **issue_type**: Excel column for issue types

## Configuration Methods

### Method 1: Environment Variables (Recommended)

Set environment variables for persistent configuration:

```bash
# Windows (PowerShell)
$env:JIRA_BASE_URL="https://your-jira.com"
$env:JIRA_TOKEN="your_bearer_token"
$env:JIRA_PROJECT_KEY="PROJ"

# Linux/Mac
export JIRA_BASE_URL="https://your-jira.com"
export JIRA_TOKEN="your_bearer_token"
export JIRA_PROJECT_KEY="PROJ"

# Custom Fields (JSON format)
export JIRA_CUSTOM_FIELDS='{"Security Ticket": "customfield_10001", "Risk Level": "customfield_10002"}'

# Column Mappings (JSON format)
export JIRA_COLUMN_MAPPINGS='{"status": "finding_status", "security_ticket": "jira_ticket"}'
```

### Method 2: Configuration Manager

Use the interactive configuration manager:

```bash
python config/config_manager.py
```

This provides a menu-driven interface for:
- Viewing current configuration
- Setting Jira connection parameters
- Configuring custom fields
- Configuring column mappings
- Exporting/importing configuration
- Testing configuration

### Method 3: Web Interface

Use the web interface configuration tab:
1. Open web interface: `python web/app.py`
2. Go to "⚙️ Config" tab
3. Set URL, token, and project key
4. Click "💾 Save Configuration"

### Method 4: Direct File Editing

Edit the configuration file directly:

```python
# config/settings.py
DEFAULT_JIRA_BASE_URL = "https://your-jira.com"
DEFAULT_JIRA_TOKEN = "your_bearer_token"
DEFAULT_JIRA_PROJECT_KEY = "PROJ"

DEFAULT_CUSTOM_FIELDS = {
    "Security Ticket": "customfield_10001",
    "Finding Type": "customfield_10002",
    "Risk Level": "customfield_10003"
}

DEFAULT_COLUMN_MAPPINGS = {
    "status": "finding_status",
    "security_ticket": "jira_ticket",
    "summary": "title",
    "description": "details"
}
```

## Usage Examples

### Basic Configuration

```python
from config.settings import get_jira_config, get_custom_fields, get_column_mappings

# Get Jira connection
config = get_jira_config()
url = config['base_url']
token = config['token']
project = config['project_key']

# Get custom fields
custom_fields = get_custom_fields()
security_ticket_field = custom_fields.get("Security Ticket")

# Get column mappings
column_mappings = get_column_mappings()
status_column = column_mappings.get("status", "status")
```

### Using Configuration in Scripts

```python
# In your scripts, use configuration defaults
from config.settings import get_jira_config, get_column_mappings

config = get_jira_config()
column_mappings = get_column_mappings()

# Use configured values
project_key = args.project or config.get("project_key")
status_col = args.status_col or column_mappings.get("status", "status")
```

### Command Line with Configuration

```bash
# Use configuration defaults
python scripts/bulk_operations/create/bulk_create_true_positive.py \
    --excel findings.xlsx \
    --use-config

# Override specific values
python scripts/bulk_operations/create/bulk_create_true_positive.py \
    --excel findings.xlsx \
    --project SEC \
    --status-col "finding_status"
```

## Custom Fields Configuration

### Finding Custom Field IDs

1. **Via Jira API:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     "https://your-jira.com/rest/api/latest/field"
```

2. **Via Jira Web Interface:**
   - Go to Administration → Issues → Custom fields
   - Note the custom field IDs (e.g., customfield_10001)

### Example Custom Fields

```json
{
    "Security Ticket": "customfield_10001",
    "Finding Type": "customfield_10002",
    "Risk Level": "customfield_10003",
    "Compliance": "customfield_10004",
    "Environment": "customfield_10005",
    "Severity": "customfield_10006",
    "CVSS Score": "customfield_10007"
}
```

## Column Mappings Configuration

### Default Mappings

```json
{
    "status": "status",
    "security_ticket": "Security Ticket",
    "summary": "summary",
    "description": "description",
    "priority": "priority",
    "assignee": "assignee",
    "issue_type": "issue_type"
}
```

### Custom Mappings Example

```json
{
    "status": "finding_status",
    "security_ticket": "jira_ticket",
    "summary": "title",
    "description": "details",
    "priority": "risk_level",
    "assignee": "owner",
    "issue_type": "type"
}
```

## Configuration Validation

### Test Configuration

```bash
# Using configuration manager
python config/config_manager.py
# Choose option 8: Test Configuration

# Or test manually
python -c "
from config.settings import get_jira_config
import requests
from core.headers import get_jira_headers

config = get_jira_config()
headers = get_jira_headers(config['token'])
response = requests.get(f'{config[\"base_url\"]}/rest/api/latest/myself', headers=headers, verify=False)
print(f'Connection: {\"✅ Success\" if response.status_code == 200 else \"❌ Failed\"}')
"
```

### Validation Checklist

- [ ] Jira URL is accessible
- [ ] API token is valid
- [ ] Project key exists and is accessible
- [ ] Custom field IDs are correct
- [ ] Column mappings match Excel file structure

## Environment-Specific Configuration

### Development Environment

```bash
export JIRA_BASE_URL="https://dev-jira.company.com"
export JIRA_PROJECT_KEY="DEV"
export JIRA_CUSTOM_FIELDS='{"Security Ticket": "customfield_10001"}'
```

### Production Environment

```bash
export JIRA_BASE_URL="https://jira.company.com"
export JIRA_PROJECT_KEY="PROD"
export JIRA_CUSTOM_FIELDS='{"Security Ticket": "customfield_20001"}'
```

### Testing Environment

```bash
export JIRA_BASE_URL="https://test-jira.company.com"
export JIRA_PROJECT_KEY="TEST"
export JIRA_CUSTOM_FIELDS='{"Security Ticket": "customfield_30001"}'
```

## Troubleshooting

### Common Issues

1. **Configuration Not Found**
   ```bash
   # Check environment variables
   echo $JIRA_BASE_URL
   echo $JIRA_TOKEN
   echo $JIRA_PROJECT_KEY
   ```

2. **Invalid Custom Field IDs**
   ```bash
   # Test custom field access
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        "https://your-jira.com/rest/api/latest/field/customfield_10001"
   ```

3. **Column Mapping Errors**
   ```python
   # Check Excel file columns
   import pandas as pd
   df = pd.read_excel("your_file.xlsx")
   print(df.columns.tolist())
   ```

### Debug Mode

Enable debug output to see configuration details:

```bash
python scripts/bulk_operations/create/bulk_create_true_positive.py \
    --excel findings.xlsx \
    --debug \
    --use-config
```

## Best Practices

### Security
- Use environment variables for sensitive data (tokens)
- Don't commit tokens to version control
- Use different tokens for different environments

### Organization
- Use consistent naming conventions
- Document custom field purposes
- Maintain mapping documentation

### Maintenance
- Regularly test configuration
- Update custom field IDs when Jira changes
- Version control configuration templates

## Migration Guide

### From Hardcoded Values

1. **Identify hardcoded values in scripts**
2. **Replace with configuration calls**
3. **Set up environment variables**
4. **Test with new configuration**

### Example Migration

**Before:**
```python
url = "https://jira.company.com"
token = "your_token"
project = "PROJ"
status_col = "status"
```

**After:**
```python
from config.settings import get_jira_config, get_column_mappings

config = get_jira_config()
column_mappings = get_column_mappings()

url = config['base_url']
token = config['token']
project = config['project_key']
status_col = column_mappings.get("status", "status")
```

This configuration system provides flexibility, security, and maintainability for your Jira Tool setup. 