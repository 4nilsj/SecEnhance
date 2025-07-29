# Linked Tickets Fetch Guide

## Overview

The Linked Tickets Fetch feature allows you to fetch linked tickets and their status using ticket URLs from the "Security Ticket" column in your Excel file. This is particularly useful for finding development tickets linked to security tickets and tracking their status.

## Features

- **Bulk Linked Ticket Fetching**: Fetch linked tickets for multiple security tickets at once
- **Dev Ticket Identification**: Automatically identify development tickets using configurable keywords
- **Excel Integration**: Reads ticket IDs from "Security Ticket" column
- **Database Sync**: Optionally syncs with SQLite database (sync version)
- **Dry Run Mode**: Preview what would be fetched without actually fetching
- **Smart Scoring**: Uses intelligent scoring to identify the most relevant dev ticket
- **Web Interface**: Available through the Streamlit web interface

## Usage

### Command Line

#### Basic Usage
```bash
# Fetch linked tickets with default settings
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets.py \
    --excel tickets.xlsx \
    --url https://jira.company.com \
    --token your_token
```

#### With Custom Dev Keywords
```bash
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets.py \
    --excel tickets.xlsx \
    --dev-keywords "dev,fix,implementation,bug" \
    --url https://jira.company.com \
    --token your_token
```

#### Dry Run (Preview Only)
```bash
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets.py \
    --excel tickets.xlsx \
    --dry-run \
    --url https://jira.company.com \
    --token your_token
```

#### With Database Sync
```bash
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets_sync.py \
    --excel tickets.xlsx \
    --db tickets.db \
    --url https://jira.company.com \
    --token your_token
```

### Web Interface

1. Open the web interface: `python web/app.py`
2. Go to "Bulk Operations" tab
3. Select "Fetch Linked Tickets" from the operation dropdown
4. Upload your Excel file
5. Configure parameters:
   - **Security Ticket Column**: Column containing Security Ticket IDs (default: "Security Ticket")
   - **Dev Ticket Column**: Column for storing dev ticket IDs (default: "dev ticket")
   - **Dev Status Column**: Column for storing dev ticket status (default: "dev ticket status")
   - **Dev Keywords**: Comma-separated keywords to identify dev tickets
   - **Dry Run**: Preview without fetching
6. Click "Execute Operation"

### Main Script

```bash
# Using the main script
python main.py fetch-linked-tickets --excel tickets.xlsx
```

## Excel File Format

Your Excel file should contain the following columns:

| Column | Description | Required | Default |
|--------|-------------|----------|---------|
| `Security Ticket` | Security Ticket ID | Yes | "Security Ticket" |
| `dev ticket` | Dev ticket ID (will be populated) | No | "dev ticket" |
| `dev ticket status` | Dev ticket status (will be populated) | No | "dev ticket status" |

### Example Excel Structure

| Security Ticket | summary | priority | dev ticket | dev ticket status |
|----------------|---------|----------|------------|-------------------|
| SEC-123 | SQL Injection vulnerability | High | DEV-456 | In Progress |
| SEC-124 | XSS alert | Medium | DEV-457 | Done |
| SEC-125 | CSRF vulnerability | Critical | DEV-458 | To Do |
| SEC-126 | Weak password policy | Low | DEV-459 | In Review |

## Dev Ticket Identification

### Default Keywords

The script uses default keywords to identify development tickets:

```
dev, development, implementation, fix, bug, task, story
```

### Scoring Algorithm

The script uses an intelligent scoring system to identify the most relevant dev ticket:

1. **Key Patterns**: +10 points for keywords in ticket key
2. **Summary Keywords**: +5 points for keywords in summary
3. **Link Type**: +3 points for keywords in link type
4. **Direction**: +2 points for outward links (security ticket links to dev ticket)
5. **Dev Key**: +5 points for "dev" in ticket key

### Custom Keywords

You can specify custom keywords using the `--dev-keywords` parameter:

```bash
--dev-keywords "dev,fix,implementation,bug,story,task"
```

## Parameters

### Required Parameters

- `--excel`: Excel file with ticket data
- `--url`: Jira base URL
- `--token`: Jira API token

### Optional Parameters

- `--sheet`: Sheet name or index (default: 0)
- `--security-ticket-col`: Column name for Security Ticket IDs (default: "Security Ticket")
- `--dev-ticket-col`: Column name for dev ticket IDs (default: "dev ticket")
- `--dev-status-col`: Column name for dev ticket status (default: "dev ticket status")
- `--dev-keywords`: Comma-separated keywords to identify dev tickets
- `--dry-run`: Show what would be fetched without actually fetching
- `--debug`: Enable debug output

### Sync Version Additional Parameters

- `--db`: SQLite database file for sync (optional)
- `--table`: Database table name (default: "tickets")
- `--no-sync`: Skip database synchronization

## Output

### Console Output

The script provides detailed console output showing:

- Number of tickets with Security Ticket IDs
- Dev keywords being used
- Progress for each ticket fetch
- Linked issues found for each ticket
- Dev ticket identification results
- Summary of results

### Excel Updates

The script updates the Excel file with:

- **dev ticket**: ID of the identified dev ticket
- **dev ticket status**: Status of the identified dev ticket
- **linked_tickets_found**: Number of linked tickets found
- **dev_ticket_summary**: Summary of the dev ticket
- **dev_ticket_link_type**: Type of link to the dev ticket
- **fetch_date**: Timestamp of when the fetch was processed

### Database Updates (Sync Version)

If using the sync version with a database:

- Updates the database table with linked ticket information
- Adds new columns if they don't exist
- Maintains data consistency between Excel and database

## Logic Flow

1. **Read Excel File**: Load the Excel file and validate required columns
2. **Filter Data**: Find rows where Security Ticket column is not empty
3. **Process Tickets**: For each matching row:
   - Fetch linked issues from Jira API
   - Score linked issues based on dev keywords
   - Identify the most relevant dev ticket
   - Record dev ticket information
4. **Update Files**: Write updated data back to Excel (and database if sync version)
5. **Report Results**: Display summary of operations

## Link Types

The script handles various types of Jira links:

### Outward Links
- Security ticket links to other tickets
- Example: "is implemented by", "relates to", "duplicates"

### Inward Links
- Other tickets link to security ticket
- Example: "implements", "relates to", "duplicates"

### Link Type Scoring
- Links with dev-related keywords get higher scores
- Outward links are preferred (security ticket → dev ticket)
- Links with "dev" in the type get bonus points

## Error Handling

The script handles various error scenarios:

- **Missing Excel File**: Displays error and exits
- **Missing Required Columns**: Lists missing columns and available columns
- **Invalid Jira Credentials**: Shows authentication error
- **API Errors**: Displays specific error messages from Jira API
- **No Linked Issues**: Handles tickets with no linked issues gracefully
- **No Dev Ticket Found**: Records when no suitable dev ticket is identified
- **File Write Errors**: Handles Excel file update failures

## Use Cases

### Security Ticket Management

1. **Dev Ticket Tracking**: Find development tickets linked to security findings
2. **Status Monitoring**: Track status of development work on security issues
3. **Progress Reporting**: Generate reports on security issue resolution progress
4. **Workflow Integration**: Integrate security and development workflows

### Project Management

1. **Cross-Team Coordination**: Link security and development teams
2. **Progress Tracking**: Monitor development progress on security issues
3. **Resource Allocation**: Identify which dev tickets need attention
4. **Reporting**: Generate reports for stakeholders

### Compliance and Audit

1. **Audit Trail**: Maintain audit trail of security issue resolution
2. **Compliance Reporting**: Track security issue resolution for compliance
3. **Documentation**: Link security findings to implementation work
4. **Risk Management**: Monitor risk mitigation progress

## Best Practices

### Excel File Preparation

1. **Valid Ticket IDs**: Ensure Security Ticket column contains valid Jira ticket IDs
2. **Consistent Format**: Use consistent ticket ID format
3. **Data Validation**: Verify that ticket IDs are accessible
4. **Backup**: Keep backups of Excel files before running

### Dev Keywords Configuration

1. **Organization-Specific**: Configure keywords based on your organization's naming conventions
2. **Test Keywords**: Test keywords with sample data
3. **Document Keywords**: Document keywords for your organization
4. **Regular Updates**: Update keywords as naming conventions change

### Workflow Integration

1. **Regular Fetching**: Run the script regularly to keep data current
2. **Dry Run First**: Always run with `--dry-run` first to preview results
3. **Monitor Output**: Review console output for any errors or warnings
4. **Data Synchronization**: Ensure data is synchronized between systems

## Troubleshooting

### Common Issues

1. **No Dev Tickets Found**: Check that dev keywords match your organization's naming conventions
2. **Authentication Errors**: Verify Jira URL and token are correct
3. **Permission Errors**: Ensure API token has permission to read issue links
4. **No Linked Issues**: Some tickets may not have linked issues
5. **Column Not Found**: Verify column names match exactly (case-sensitive)

### Debug Mode

Use `--debug` flag for detailed error information:

```bash
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets.py \
    --excel tickets.xlsx \
    --debug \
    --url https://jira.company.com \
    --token your_token
```

## Integration with Other Features

This feature integrates with other Jira Tool features:

- **Status Tracking**: Use status tracking to monitor dev ticket status changes
- **Custom Fields**: Update custom fields on dev tickets
- **Comments**: Add comments about linked ticket relationships
- **Reporting**: Use linked ticket data for reporting and analytics

## Examples

### Example 1: Basic Linked Ticket Fetch

```bash
# Fetch linked tickets with default settings
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets.py \
    --excel security_tickets.xlsx \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 2: Custom Dev Keywords

```bash
# Fetch with custom dev keywords
python scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets.py \
    --excel security_tickets.xlsx \
    --dev-keywords "dev,fix,implementation,bug,story" \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 3: Web Interface Workflow

1. Upload `security_tickets.xlsx` to web interface
2. Select "Fetch Linked Tickets"
3. Configure parameters:
   - Security Ticket Column: "jira_ticket"
   - Dev Ticket Column: "dev_ticket"
   - Dev Status Column: "dev_status"
   - Dev Keywords: "dev,fix,implementation"
4. Enable "Dry Run" to preview
5. Execute operation
6. Download updated Excel file with linked ticket information

This feature provides efficient linked ticket discovery and tracking, improving coordination between security and development teams. 