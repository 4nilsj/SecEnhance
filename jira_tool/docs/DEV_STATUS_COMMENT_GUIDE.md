# Dev Status Comment Guide

## Overview

The Dev Status Comment feature automatically adds comments to Jira tickets based on the "dev ticket status" column in your Excel file. When the status is "Acceptance", it adds the comment "QE Testing in Dev Completed" to the corresponding ticket.

## Features

- **Conditional Commenting**: Only adds comments when dev status is "Acceptance"
- **Excel Integration**: Reads ticket IDs from "Security Ticket" column
- **Database Sync**: Optionally syncs with SQLite database (sync version)
- **Dry Run Mode**: Preview what would be done without actually doing it
- **Flexible Configuration**: Customizable column names
- **Web Interface**: Available through the Streamlit web interface

## Usage

### Command Line

#### Basic Usage
```bash
# Add comments for Acceptance status
python scripts/bulk_operations/comment/bulk_comment_dev_status.py \
    --excel tickets.xlsx \
    --url https://jira.company.com \
    --token your_token
```

#### With Custom Column Names
```bash
python scripts/bulk_operations/comment/bulk_comment_dev_status.py \
    --excel tickets.xlsx \
    --security-ticket-col "Jira_Ticket" \
    --dev-status-col "dev_status" \
    --url https://jira.company.com \
    --token your_token
```

#### Dry Run (Preview Only)
```bash
python scripts/bulk_operations/comment/bulk_comment_dev_status.py \
    --excel tickets.xlsx \
    --dry-run \
    --url https://jira.company.com \
    --token your_token
```

#### With Database Sync
```bash
python scripts/bulk_operations/comment/bulk_comment_dev_status_sync.py \
    --excel tickets.xlsx \
    --db tickets.db \
    --url https://jira.company.com \
    --token your_token
```

### Web Interface

1. Open the web interface: `python web/app.py`
2. Go to "Bulk Operations" tab
3. Select "Add Dev Status Comments" from the operation dropdown
4. Upload your Excel file
5. Configure parameters:
   - **Security Ticket Column**: Column containing Security Ticket IDs (default: "Security Ticket")
   - **Dev Status Column**: Column containing dev ticket status (default: "dev ticket status")
   - **Dry Run**: Preview without adding comments
6. Click "Execute Operation"

### Main Script

```bash
# Using the main script
python main.py dev-status-comment --excel tickets.xlsx
```

## Excel File Format

Your Excel file should contain the following columns:

| Column | Description | Required | Default |
|--------|-------------|----------|---------|
| `Security Ticket` | Security Ticket ID | Yes | "Security Ticket" |
| `dev ticket status` | Dev ticket status | Yes | "dev ticket status" |

### Example Excel Structure

| Security Ticket | dev ticket status | summary | description |
|----------------|------------------|---------|-------------|
| SEC-123 | Acceptance | SQL Injection | Critical vulnerability found... |
| SEC-124 | In Progress | XSS Alert | Cross-site scripting issue... |
| SEC-125 | Acceptance | CSRF Vulnerability | CSRF token missing... |
| SEC-126 | Review | Weak Password | Password policy issue... |

## Parameters

### Required Parameters

- `--excel`: Excel file with ticket data
- `--url`: Jira base URL
- `--token`: Jira API token

### Optional Parameters

- `--sheet`: Sheet name or index (default: 0)
- `--security-ticket-col`: Column name for Security Ticket IDs (default: "Security Ticket")
- `--dev-status-col`: Column name for dev ticket status (default: "dev ticket status")
- `--dry-run`: Show what would be done without actually doing it
- `--debug`: Enable debug output

### Sync Version Additional Parameters

- `--db`: SQLite database file for sync (optional)
- `--table`: Database table name (default: "tickets")
- `--no-sync`: Skip database synchronization

## Output

### Console Output

The script provides detailed console output showing:

- Number of tickets with Security Ticket IDs and dev status
- Progress for each ticket processing
- Success/failure status for each comment
- Summary of results

### Excel Updates

The script updates the Excel file with:

- **comment_status**: Status of comment addition ("Added: QE Testing in Dev Completed", "Failed to add comment", "Skipped - Status: In Progress", etc.)
- **comment_text**: The comment text that was added (or empty if skipped)
- **comment_date**: Timestamp of when the comment was processed

### Database Updates (Sync Version)

If using the sync version with a database:

- Updates the database table with comment information
- Adds new columns if they don't exist
- Maintains data consistency between Excel and database

## Logic Flow

1. **Read Excel File**: Load the Excel file and validate required columns
2. **Filter Data**: Find rows where:
   - Security Ticket column is not empty
   - Dev status column is not empty
3. **Process Tickets**: For each matching row:
   - Check if dev status is "Acceptance" (case-insensitive)
   - If yes, add comment "QE Testing in Dev Completed"
   - If no, skip the ticket
4. **Update Files**: Write updated data back to Excel (and database if sync version)
5. **Report Results**: Display summary of operations

## Error Handling

The script handles various error scenarios:

- **Missing Excel File**: Displays error and exits
- **Missing Required Columns**: Lists missing columns and available columns
- **Invalid Jira Credentials**: Shows authentication error
- **API Errors**: Displays specific error messages from Jira API
- **File Write Errors**: Handles Excel file update failures

## Use Cases

### Quality Assurance Workflow

1. **Development**: Developers work on tickets
2. **Testing**: QA team tests in development environment
3. **Status Update**: Dev ticket status is updated to "Acceptance"
4. **Comment Addition**: Script automatically adds "QE Testing in Dev Completed" comment
5. **Tracking**: Comments provide audit trail of testing completion

### DevOps Pipeline

1. **Automated Testing**: CI/CD pipeline runs tests
2. **Status Updates**: Pipeline updates dev ticket status
3. **Comment Automation**: Script adds comments for completed testing
4. **Audit Trail**: Comments document testing completion

### Project Management

1. **Status Tracking**: Track development progress
2. **Automated Documentation**: Comments provide automatic documentation
3. **Compliance**: Maintain audit trail for compliance requirements
4. **Reporting**: Use comments for reporting and metrics

## Best Practices

### Excel File Preparation

1. **Consistent Status Values**: Use "Acceptance" (case-insensitive) for status
2. **Valid Ticket IDs**: Ensure Security Ticket column contains valid Jira ticket IDs
3. **Data Validation**: Verify that required columns exist and contain data
4. **Backup**: Keep backups of Excel files before running

### Workflow Integration

1. **Regular Updates**: Run the script regularly to process status changes
2. **Dry Run First**: Always run with `--dry-run` first to preview changes
3. **Monitor Output**: Review console output for any errors or warnings
4. **Status Synchronization**: Ensure dev status is updated before running script

### Configuration Management

1. **Environment Variables**: Use environment variables for sensitive data (URL, token)
2. **Column Mapping**: Document custom column names for your organization
3. **Status Values**: Define status values appropriate for your workflow
4. **Testing**: Test with sample data before running on production data

## Troubleshooting

### Common Issues

1. **No Comments Added**: Check that dev status column contains "Acceptance" and Security Ticket column is not empty
2. **Authentication Errors**: Verify Jira URL and token are correct
3. **Permission Errors**: Ensure API token has permission to add comments to tickets
4. **Column Not Found**: Verify column names match exactly (case-sensitive)

### Debug Mode

Use `--debug` flag for detailed error information:

```bash
python scripts/bulk_operations/comment/bulk_comment_dev_status.py \
    --excel tickets.xlsx \
    --debug \
    --url https://jira.company.com \
    --token your_token
```

## Integration with Other Features

This feature integrates with other Jira Tool features:

- **Status Tracking**: Use status tracking to monitor dev progress
- **Bulk Updates**: Update dev status using bulk update feature
- **Comments**: Add additional comments using bulk comment feature
- **Reporting**: Use comment data for reporting and analytics

## Examples

### Example 1: Basic Dev Status Comment

```bash
# Process dev status comments
python scripts/bulk_operations/comment/bulk_comment_dev_status.py \
    --excel dev_tickets.xlsx \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 2: Custom Column Names

```bash
# Process with custom column names
python scripts/bulk_operations/comment/bulk_comment_dev_status_sync.py \
    --excel dev_tickets.xlsx \
    --security-ticket-col "jira_ticket" \
    --dev-status-col "dev_status" \
    --db dev_tickets.db \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 3: Web Interface Workflow

1. Upload `dev_tickets.xlsx` to web interface
2. Select "Add Dev Status Comments"
3. Configure parameters:
   - Security Ticket Column: "jira_ticket"
   - Dev Status Column: "dev_status"
4. Enable "Dry Run" to preview
5. Execute operation
6. Download updated Excel file with comment status

This feature provides automated comment management based on development status, improving workflow efficiency and maintaining clear audit trails. 