# Transition Workflow Guide

## Overview

The Transition Workflow feature provides two specialized transition scripts for managing security and development workflows in Jira. These scripts automatically transition tickets through predefined workflow paths with validation checks.

## Features

### Security Workflow Transition
- **Path**: New → Analysing → Refining → Refined Backlog → Inprogress
- **Purpose**: Manages security ticket progression through analysis and refinement phases
- **Validation**: No special validation required
- **Excel Integration**: Uses "Security Ticket" column for ticket IDs

### Dev Workflow Transition
- **Path**: Inprogress → Review → Acceptance → Done
- **Purpose**: Manages development ticket progression through review and acceptance phases
- **Validation**: Requires QE comment and QE-Evidence attachments for Acceptance/Done transitions
- **Excel Integration**: Uses "Security Ticket" column for ticket IDs

## Usage

### Command Line

#### Security Workflow Transition
```bash
# Basic security workflow transition
python scripts/bulk_operations/transition/bulk_transition_security_workflow.py \
    --excel tickets.xlsx \
    --url https://jira.company.com \
    --token your_token

# With database sync
python scripts/bulk_operations/transition/bulk_transition_security_workflow_sync.py \
    --excel tickets.xlsx \
    --db tickets.db \
    --url https://jira.company.com \
    --token your_token

# Dry run
python scripts/bulk_operations/transition/bulk_transition_security_workflow.py \
    --excel tickets.xlsx \
    --dry-run \
    --url https://jira.company.com \
    --token your_token
```

#### Dev Workflow Transition
```bash
# Basic dev workflow transition (with validation)
python scripts/bulk_operations/transition/bulk_transition_dev_workflow.py \
    --excel tickets.xlsx \
    --url https://jira.company.com \
    --token your_token

# With database sync
python scripts/bulk_operations/transition/bulk_transition_dev_workflow_sync.py \
    --excel tickets.xlsx \
    --db tickets.db \
    --url https://jira.company.com \
    --token your_token

# Dry run
python scripts/bulk_operations/transition/bulk_transition_dev_workflow.py \
    --excel tickets.xlsx \
    --dry-run \
    --url https://jira.company.com \
    --token your_token
```

### Web Interface

1. Open the web interface: `python web/app.py`
2. Go to "Bulk Operations" tab
3. Select either:
   - **Security Workflow Transition**: For security ticket progression
   - **Dev Workflow Transition**: For development ticket progression
4. Upload your Excel file
5. Configure parameters (dry run option)
6. Click "Execute Operation"

### Main Script

```bash
# Security workflow transition
python main.py security-workflow --excel tickets.xlsx

# Dev workflow transition
python main.py dev-workflow --excel tickets.xlsx
```

## Excel File Format

Your Excel file should contain the following columns:

| Column | Description | Required | Default |
|--------|-------------|----------|---------|
| `Security Ticket` | Security Ticket ID | Yes | "Security Ticket" |
| `current_status` | Current status (will be populated) | No | (auto-generated) |
| `next_status` | Next status (will be populated) | No | (auto-generated) |
| `transition_status` | Transition result (will be populated) | No | (auto-generated) |
| `transition_date` | Transition timestamp (will be populated) | No | (auto-generated) |
| `validation_status` | Validation result (dev workflow only) | No | (auto-generated) |

### Example Excel Structure

| Security Ticket | summary | priority | current_status | next_status | transition_status |
|----------------|---------|----------|----------------|-------------|-------------------|
| SEC-123 | SQL Injection vulnerability | High | New | Analysing | Success |
| SEC-124 | XSS alert | Medium | Analysing | Refining | Success |
| SEC-125 | CSRF vulnerability | Critical | Refining | Refined Backlog | Success |
| SEC-126 | Weak password policy | Low | Refined Backlog | Inprogress | Success |

## Workflow Paths

### Security Workflow
```
New → Analysing → Refining → Refined Backlog → Inprogress
```

**Status Descriptions:**
- **New**: Initial security finding created
- **Analysing**: Security team analyzing the finding
- **Refining**: Finding being refined and prioritized
- **Refined Backlog**: Ready for development planning
- **Inprogress**: Development work has started

### Dev Workflow
```
Inprogress → Review → Acceptance → Done
```

**Status Descriptions:**
- **Inprogress**: Development work in progress
- **Review**: Code review and testing phase
- **Acceptance**: QE testing completed, ready for acceptance
- **Done**: Work completed and accepted

## Validation Requirements

### Security Workflow
- **No special validation required**
- Transitions proceed automatically based on current status

### Dev Workflow
- **For Acceptance/Done transitions**: Requires validation
  - **QE Comment**: Must have "QE Testing in Dev Completed" comment
  - **QE-Evidence**: Must have QE-Evidence attachments (filename contains "QE-Evidence-")

**Validation Logic:**
1. Check if target status is "Acceptance" or "Done"
2. Verify QE comment exists on the ticket
3. Verify QE-Evidence attachments exist
4. Only proceed with transition if all requirements are met

## Parameters

### Required Parameters

- `--excel`: Excel file with ticket data
- `--url`: Jira base URL
- `--token`: Jira API token

### Optional Parameters

- `--sheet`: Sheet name or index (default: 0)
- `--security-ticket-col`: Column name for Security Ticket IDs (default: "Security Ticket")
- `--dry-run`: Show what would be transitioned without actually transitioning
- `--debug`: Enable debug output

### Sync Version Additional Parameters

- `--db`: SQLite database file for sync (optional)
- `--table`: Database table name (default: "tickets")
- `--no-sync`: Skip database synchronization

## Output

### Console Output

The scripts provide detailed console output showing:

- Number of tickets with Security Ticket IDs
- Current status of each ticket
- Target status for transition
- Validation results (for dev workflow)
- Transition success/failure status
- Summary of results

### Excel Updates

The scripts update the Excel file with:

- **current_status**: Current status of the ticket
- **next_status**: Target status for transition
- **transition_status**: Result of transition attempt ("Success", "Failed", "Validation failed", etc.)
- **transition_date**: Timestamp of when transition was processed
- **validation_status**: Validation result (dev workflow only)

### Database Updates (Sync Version)

If using the sync version with a database:

- Updates the database table with transition information
- Adds new columns if they don't exist
- Maintains data consistency between Excel and database

## Logic Flow

### Security Workflow
1. **Read Excel File**: Load the Excel file and validate required columns
2. **Filter Data**: Find rows where Security Ticket column is not empty
3. **Process Tickets**: For each matching row:
   - Get current status from Jira
   - Determine next status in workflow
   - Perform transition if not at end of workflow
   - Record transition status
4. **Update Files**: Write updated data back to Excel (and database if sync version)
5. **Report Results**: Display summary of operations

### Dev Workflow
1. **Read Excel File**: Load the Excel file and validate required columns
2. **Filter Data**: Find rows where Security Ticket column is not empty
3. **Process Tickets**: For each matching row:
   - Get current status from Jira
   - Determine next status in workflow
   - Validate requirements for transition (if needed)
   - Perform transition if validation passes
   - Record transition status
4. **Update Files**: Write updated data back to Excel (and database if sync version)
5. **Report Results**: Display summary of operations

## Error Handling

The scripts handle various error scenarios:

- **Missing Excel File**: Displays error and exits
- **Missing Required Columns**: Lists missing columns and available columns
- **Invalid Jira Credentials**: Shows authentication error
- **API Errors**: Displays specific error messages from Jira API
- **No Transitions Available**: Shows when no transitions are available for a ticket
- **Validation Failures**: Records validation failures with specific reasons
- **File Write Errors**: Handles Excel file update failures

## Use Cases

### Security Workflow Use Cases

1. **Security Finding Management**: Automate progression of security findings through analysis phases
2. **Team Coordination**: Ensure security findings follow proper workflow
3. **Process Standardization**: Standardize security ticket progression
4. **Reporting**: Track security finding progression for reporting

### Dev Workflow Use Cases

1. **Development Process Management**: Automate development ticket progression
2. **Quality Assurance**: Ensure proper validation before acceptance
3. **Process Compliance**: Enforce QE testing and evidence requirements
4. **Workflow Automation**: Reduce manual transition work

## Best Practices

### Excel File Preparation

1. **Valid Ticket IDs**: Ensure Security Ticket column contains valid Jira ticket IDs
2. **Consistent Format**: Use consistent ticket ID format
3. **Data Validation**: Verify that ticket IDs are accessible
4. **Backup**: Keep backups of Excel files before running

### Workflow Management

1. **Regular Transitions**: Run the scripts regularly to keep workflows current
2. **Dry Run First**: Always run with `--dry-run` first to preview transitions
3. **Monitor Output**: Review console output for any errors or warnings
4. **Validation Compliance**: Ensure dev tickets meet validation requirements before transitioning

### Integration

1. **Team Coordination**: Coordinate with security and development teams
2. **Process Alignment**: Align with organizational workflow processes
3. **Documentation**: Document workflow processes and requirements
4. **Training**: Train teams on workflow requirements and validation

## Troubleshooting

### Common Issues

1. **No Transitions Available**: Check that tickets are in the correct workflow states
2. **Authentication Errors**: Verify Jira URL and token are correct
3. **Permission Errors**: Ensure API token has permission to transition tickets
4. **Validation Failures**: Check that QE comments and evidence are properly added
5. **Workflow Mismatch**: Verify that ticket statuses match expected workflow states

### Debug Mode

Use `--debug` flag for detailed error information:

```bash
python scripts/bulk_operations/transition/bulk_transition_security_workflow.py \
    --excel tickets.xlsx \
    --debug \
    --url https://jira.company.com \
    --token your_token
```

## Integration with Other Features

These transition workflows integrate with other Jira Tool features:

- **Status Tracking**: Use status tracking to monitor transition progress
- **Custom Fields**: Update custom fields during transitions
- **Comments**: Add comments about transition reasons
- **Attachments**: Ensure required attachments are present for validation
- **Reporting**: Use transition data for workflow reporting and analytics

## Examples

### Example 1: Security Workflow Transition

```bash
# Transition security tickets through workflow
python scripts/bulk_operations/transition/bulk_transition_security_workflow_sync.py \
    --excel security_tickets.xlsx \
    --db security.db \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 2: Dev Workflow Transition

```bash
# Transition dev tickets with validation
python scripts/bulk_operations/transition/bulk_transition_dev_workflow_sync.py \
    --excel dev_tickets.xlsx \
    --db dev.db \
    --url https://company.atlassian.net \
    --token $JIRA_TOKEN
```

### Example 3: Web Interface Workflow

1. Upload `workflow_tickets.xlsx` to web interface
2. Select "Security Workflow Transition" or "Dev Workflow Transition"
3. Configure parameters (dry run option)
4. Execute operation
5. Download updated Excel file with transition status

These transition workflows provide efficient automation of ticket progression through security and development processes, ensuring proper workflow compliance and validation. 