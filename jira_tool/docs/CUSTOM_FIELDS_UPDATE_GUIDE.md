# Custom Fields Update Guide

## Overview

The Custom Fields Update feature allows you to update custom fields for Jira tickets using ticket URLs from the "Security Ticket" column in your Excel file. This is particularly useful for bulk updating custom fields like Risk Level, Environment, Compliance, etc.

## Features

- **Bulk Custom Field Updates**: Update multiple custom fields for multiple tickets at once
- **Excel Integration**: Reads ticket IDs from "Security Ticket" column
- **Database Sync**: Optionally syncs with SQLite database (sync version)
- **Dry Run Mode**: Preview what would be updated without actually updating
- **Flexible Mapping**: Map Excel columns to custom field IDs
- **Web Interface**: Available through the Streamlit web interface

## Usage

### Command Line

#### Basic Usage
```bash
# Update custom fields with default mappings
python scripts/bulk_operations/update/bulk_update_custom_fields.py \
    --excel tickets.xlsx \
    --url https://jira.company.com \
    --token your_token
```

#### With Custom Field Mappings
```bash
python scripts/bulk_operations/update/bulk_update_custom_fields.py \
    --excel tickets.xlsx \
    --custom-fields "Risk Level:customfield_10002,Environment:customfield_10003" \
    --url https://jira.company.com \
    --token your_token
```

#### Dry Run (Preview Only)
```bash
python scripts/bulk_operations/update/bulk_update_custom_fields.py \
    --excel tickets.xlsx \
    --dry-run \
    --url https://jira.company.com \
    --token your_token
```

#### With Database Sync
```bash
python scripts/bulk_operations/update/bulk_update_custom_fields_sync.py \
    --excel tickets.xlsx \
    --db tickets.db \
    --url https://jira.company.com \
    --token your_token
```

### Web Interface

1. Open the web interface: `python web/app.py`
2. Go to "Bulk Operations" tab
3. Select "Update Custom Fields" from the operation dropdown
4. Upload your Excel file
5. Configure parameters:
   - **Security Ticket Column**: Column containing Security Ticket IDs (default: "Security Ticket")
   - **Custom Fields Mapping**: Map Excel columns to custom field IDs
   - **Dry Run**: Preview without updating
6. Click "Execute Operation"

### Main Script

```bash
# Using the main script
python main.py custom-fields --excel tickets.xlsx
```

## Excel File Format

Your Excel file should contain the following columns:

| Column | Description | Required | Default |
|--------|-------------|----------|---------|
| `Security Ticket` | Security Ticket ID | Yes | "Security Ticket" |
| `Risk Level` | Risk level value | No | (mapped to custom field) |
| `Environment` | Environment value | No | (mapped to custom field) |
| `Compliance` | Compliance value | No | (mapped to custom field) |

### Example Excel Structure

| Security Ticket | Risk Level | Environment | Compliance | summary |
|----------------|------------|-------------|------------|---------|
| SEC-123 | High | Production | PCI | SQL Injection vulnerability |
| SEC-124 | Medium | Development | SOX | XSS alert |
| SEC-125 | Critical | Staging | GDPR | CSRF vulnerability |
| SEC-126 | Low | Testing | HIPAA | Weak password policy |

## Custom Field Mappings

### Default Mappings (from config)

The script uses default custom field mappings from the configuration:

```json
{
    "Security Ticket": "customfield_10001",
    "Finding Type": "customfield_10002",
    "Risk Level": "customfield_10003",
    "Compliance": "customfield_10004",
    "Environment": "customfield_10005"
}
```

### Custom Mappings

You can specify custom mappings using the `--custom-fields` parameter:

```bash
--custom-fields "Risk Level:customfield_10002,Environment:customfield_10003,Severity:customfield_10006"
```

Format: `excel_column:custom_field_id,excel_column2:custom_field_id2`

## Parameters

### Required Parameters

- `--excel`: Excel file with ticket data
- `--url`: Jira base URL
- `--token`: Jira API token

### Optional Parameters

- `--sheet`: Sheet name or index (default: 0)
- `--security-ticket-col`: Column name for Security Ticket IDs (default: "Security Ticket")
- `--custom-fields`: Custom field mappings in format 'excel_col:field_id,excel_col2:field_id2'
- `--dry-run`: Show what would be updated without actually updating
- `--debug`: Enable debug output

### Sync Version Additional Parameters

- `--db`: SQLite database file for sync (optional)
- `--table`: Database table name (default: "tickets")
- `--no-sync`: Skip database synchronization

## Output

### Console Output

The script provides detailed console output showing:

- Number of tickets with Security Ticket IDs
- Custom field mappings being used
- Progress for each ticket update
- Success/failure status for each update
- Summary of results

### Excel Updates

The script updates the Excel file with:

- **custom_field_status**: Status of custom field update ("Updated: X fields", "Failed to update", "Skipped - No valid values", etc.)
- **updated_fields**: List of fields that were updated
- **update_date**: Timestamp of when the update was processed

### Database Updates (Sync Version)

If using the sync version with a database:

- Updates the database table with custom field information
- Adds new columns if they don't exist
- Maintains data consistency between Excel and database

## Logic Flow

1. **Read Excel File**: Load the Excel file and validate required columns
2. **Get Custom Field Mappings**: Use provided mappings or default from config
3. **Filter Data**: Find rows where Security Ticket column is not empty
4. **Process Tickets**: For each matching row:
   - Extract custom field values from Excel columns
   - Update Jira ticket with custom field values
   - Record update status
5. **Update Files**: Write updated data back to Excel (and database if sync version)
6. **Report Results**: Display summary of operations

## Error Handling

The script handles various error scenarios:

- **Missing Excel File**: Displays error and exits
- **Missing Required Columns**: Lists missing columns and available columns
- **Invalid Jira Credentials**: Shows authentication error
- **API Errors**: Displays specific error messages from Jira API
- **Invalid Custom Field IDs**: Shows errors for invalid custom field mappings
- **File Write Errors**: Handles Excel file update failures

## Use Cases

### Risk Management

1. **Risk Assessment**: Update risk levels for security findings
2. **Compliance Tracking**: Update compliance requirements
3. **Environment Classification**: Update environment information
4. **Severity Updates**: Update severity levels based on analysis

### Project Management

1. **Status Tracking**: Update custom status fields
2. **Priority Management**: Update priority custom fields
3. **Assignment Updates**: Update assignee custom fields
4. **Category Classification**: Update category custom fields

### Compliance and Audit

1. **Compliance Updates**: Update compliance-related custom fields
2. **Audit Trail**: Maintain audit trail of field updates
3. **Reporting**: Use custom fields for reporting and metrics
4. **Documentation**: Update documentation-related fields

## Best Practices

### Excel File Preparation

1. **Valid Ticket IDs**: Ensure Security Ticket column contains valid Jira ticket IDs
2. **Consistent Values**: Use consistent values for custom fields
3. **Data Validation**: Verify that custom field values are valid
4. **Backup**: Keep backups of Excel files before running

### Custom Field Configuration

1. **Find Custom Field IDs**: Use Jira API or web interface to find custom field IDs
2. **Test Mappings**: Test custom field mappings with sample data
3. **Document Mappings**: Document custom field mappings for your organization
4. **Validate Values**: Ensure custom field values are valid for your Jira instance

### Workflow Integration

1. **Regular Updates**: Run the script regularly to process updates
2. **Dry Run First**: Always run with `--dry-run` first to preview changes
3. **Monitor Output**: Review console output for any errors or warnings
4. **Data Synchronization**: Ensure data is synchronized between systems

## Troubleshooting

### Common Issues

1. **No Updates Performed**: Check that Security Ticket column contains valid IDs and custom field columns have values
2. **Authentication Errors**: Verify Jira URL and token are correct
3. **Permission Errors**: Ensure API token has permission to update custom fields
4. **Invalid Custom Field IDs**: Verify custom field IDs are correct for your Jira instance
5. **Column Not Found**: Verify column names match exactly (case-sensitive)

### Debug Mode

Use `--debug` flag for detailed error information:

```bash
python scripts/bulk_operations/update/bulk_update_custom_fields.py \
    --excel tickets.xlsx \
    --debug \
    --url https://jira.company.com \
    --token your_token
```

## Integration with Other Features

This feature integrates with other Jira Tool features:

- **Status Tracking**: Use status tracking to monitor custom field updates
- **Bulk Updates**: Use bulk updates for standard fields
- **Comments**: Add comments about custom field changes
- **Reporting**: Use custom field data for reporting and analytics

## Examples

### Example 1: Basic Custom Field Update

```bash
# Update risk levels and environments
python scripts/bulk_operations/update/bulk_update_custom_fields.py \
    --excel security_tickets.xlsx \
    --custom-fields "Risk Level:customfield_10002,Environment:customfield_10003" \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 2: Compliance Updates

```bash
# Update compliance and severity fields
python scripts/bulk_operations/update/bulk_update_custom_fields_sync.py \
    --excel compliance_tickets.xlsx \
    --custom-fields "Compliance:customfield_10004,Severity:customfield_10006" \
    --db compliance.db \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 3: Web Interface Workflow

1. Upload `custom_fields_tickets.xlsx` to web interface
2. Select "Update Custom Fields"
3. Configure parameters:
   - Security Ticket Column: "jira_ticket"
   - Custom Fields Mapping: "Risk Level:customfield_10002,Environment:customfield_10003"
4. Enable "Dry Run" to preview
5. Execute operation
6. Download updated Excel file with update status

This feature provides efficient bulk updating of custom fields, improving data consistency and workflow efficiency. 