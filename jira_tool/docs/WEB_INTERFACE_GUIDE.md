# Jira Tool Web Interface Guide

## Overview

The Jira Tool Web Interface provides a comprehensive, user-friendly way to access all Jira tool features through a modern web application built with Streamlit. This interface makes it easy to perform both bulk operations and single ticket operations without needing to use command-line tools.

## 🚀 Quick Start

### Running the Web Interface

```bash
# Navigate to the jira_tool directory
cd jira_tool

# Install dependencies (if not already installed)
pip install -r requirements.txt

# Run the web interface
streamlit run web/app.py
```

The web interface will open in your browser at `http://localhost:8501`.

## 📋 Features Overview

### 1. **Configuration Management** ⚙️
- **Jira Connection Setup**: Configure your Jira URL and API token
- **Connection Testing**: Test your connection to Jira
- **Configuration Persistence**: Save your settings for future use

### 2. **Bulk Operations** 📊
- **Create Tickets**: Bulk create tickets from Excel data
- **Update Tickets**: Bulk update ticket fields
- **Add Comments**: Add comments to multiple tickets
- **Fetch Status**: Get status information for multiple tickets
- **Transition Status**: Change status of multiple tickets
- **Upload Attachments**: Upload files to multiple tickets
- **Delete Tickets**: Bulk delete tickets
- **Linked Status Analysis**: Analyze linked ticket statuses

### 3. **Single Operations** 🎯
- **Create Single Ticket**: Create individual tickets
- **Update Single Ticket**: Update individual ticket fields
- **Add Comment**: Add comments to individual tickets
- **Upload Attachment**: Upload files to individual tickets
- **Get Status**: Retrieve ticket information

### 4. **File Management** 📁
- **Multi-file Upload**: Upload multiple files at once
- **File Preview**: Preview uploaded Excel files
- **Attachment Management**: Manage file attachments to tickets

### 5. **Status & Reports** 📈
- **Connection Status**: Monitor Jira connection
- **User Information**: Display current user details
- **Operation History**: Track recent operations

## 🔧 Configuration

### Setting Up Jira Connection

1. **Navigate to the Configuration Tab** in the sidebar
2. **Enter your Jira URL** (e.g., `https://company.atlassian.net`)
3. **Enter your API Token** (get this from your Jira account settings)
4. **Click "Save Configuration"** to store your settings
5. **Test your connection** using the "Test Connection" button

### Environment Variables

You can also set environment variables for automatic configuration:

```bash
# Windows (PowerShell)
$env:JIRA_BASE_URL="https://your-jira.com"
$env:JIRA_TOKEN="your_bearer_token"

# Linux/Mac
export JIRA_BASE_URL="https://your-jira.com"
export JIRA_TOKEN="your_bearer_token"
```

## 📊 Bulk Operations

### Create Tickets

1. **Select "Create Tickets"** from the bulk operations dropdown
2. **Upload an Excel file** with your ticket data
3. **Configure parameters**:
   - **Project Key**: The Jira project key (e.g., "PROJ")
   - **Sheet Name**: Excel sheet name (default: "Sheet1")
   - **Summary Column**: Column containing ticket summaries
   - **Description Column**: Column containing ticket descriptions
   - **Issue Type**: Type of issue to create (Task, Bug, Story, Epic)
4. **Click "Execute Create Tickets"** to run the operation

### Update Tickets

1. **Select "Update Tickets"** from the bulk operations dropdown
2. **Upload an Excel file** with ticket IDs and data to update
3. **Select fields to update**:
   - Summary
   - Description
   - Priority
   - Assignee
   - Labels
4. **Click "Execute Update Tickets"** to run the operation

### Add Comments

1. **Select "Add Comments"** from the bulk operations dropdown
2. **Upload an Excel file** with ticket IDs
3. **Enter comment text** in the text area
4. **Click "Execute Add Comments"** to run the operation

### Fetch Status

1. **Select "Fetch Status"** from the bulk operations dropdown
2. **Upload an Excel file** with ticket IDs
3. **Click "Execute Fetch Status"** to retrieve status information

### Transition Status

1. **Select "Transition Status"** from the bulk operations dropdown
2. **Upload an Excel file** with ticket IDs
3. **Enter target status** (e.g., "In Progress", "Done")
4. **Click "Execute Transition Status"** to run the operation

### Upload Attachments

1. **Select "Upload Attachments"** from the bulk operations dropdown
2. **Upload an Excel file** with ticket IDs
3. **Configure attachment parameters**:
   - **Attachment Directory**: Path to directory containing files
   - **File Pattern**: Regex pattern to extract ticket ID from filename
4. **Click "Execute Upload Attachments"** to run the operation

## 🎯 Single Operations

### Create Single Ticket

1. **Select "Create Single Ticket"** from the single operations dropdown
2. **Fill in ticket details**:
   - **Project Key**: The Jira project key
   - **Summary**: Ticket summary
   - **Description**: Ticket description
   - **Issue Type**: Type of issue
   - **Priority**: Ticket priority
   - **Assignee**: Username of assignee
3. **Click "Execute Single Operation"** to create the ticket

### Update Single Ticket

1. **Select "Update Single Ticket"** from the single operations dropdown
2. **Enter the ticket ID** (e.g., "PROJ-123")
3. **Fill in the fields you want to update**
4. **Click "Execute Single Operation"** to update the ticket

### Add Comment

1. **Select "Add Comment"** from the single operations dropdown
2. **Enter the ticket ID** (e.g., "PROJ-123")
3. **Enter your comment text**
4. **Click "Execute Single Operation"** to add the comment

### Get Status

1. **Select "Get Status"** from the single operations dropdown
2. **Enter the ticket ID** (e.g., "PROJ-123")
3. **Click "Execute Single Operation"** to retrieve ticket information

## 📁 File Management

### Upload Attachments

1. **Navigate to the "File Management" tab**
2. **Select files to upload** (supports multiple file types)
3. **Enter the target ticket ID** (e.g., "PROJ-123")
4. **Click "Upload Attachments"** to attach files to the ticket

### Supported File Types

- **Documents**: PDF, DOC, DOCX
- **Spreadsheets**: XLS, XLSX
- **Text Files**: TXT
- **Images**: PNG, JPG, JPEG

## 📈 Status & Reports

### Connection Status

The Status & Reports tab shows:
- **Connection Status**: Whether you're connected to Jira
- **User Information**: Your Jira user details
- **Account Information**: Your account ID and email

### Operation History

Future versions will include:
- **Recent Operations**: List of recently performed operations
- **Success/Failure Rates**: Statistics on operation success
- **Performance Metrics**: Operation timing and efficiency

## 📋 Excel File Format

### For Create Operations

Your Excel file should contain columns like:
```
| summary | description | priority | assignee |
|---------|-------------|----------|----------|
| Fix login bug | User cannot log in | High | john.doe |
| Update docs | Update API docs | Medium | jane.smith |
```

### For Update Operations

Your Excel file should contain:
```
| ticket_id | summary | description | priority |
|-----------|---------|-------------|----------|
| PROJ-123  | Updated summary | New description | High |
| PROJ-124  | Another update | More details | Medium |
```

### For Comment Operations

Your Excel file should contain:
```
| ticket_id |
|-----------|
| PROJ-123  |
| PROJ-124  |
```

## 🔧 Advanced Features

### Custom Parameters

Many operations support custom parameters:
- **Sheet Names**: Specify which Excel sheet to use
- **Column Mappings**: Map Excel columns to Jira fields
- **File Patterns**: Use regex patterns for file matching
- **Status Transitions**: Specify target status names

### Error Handling

The web interface provides:
- **Real-time Feedback**: Success/error messages for each operation
- **Detailed Error Information**: Specific error messages and suggestions
- **Operation Logs**: Detailed logs for troubleshooting

### Security Features

- **Token Protection**: API tokens are masked in the interface
- **Secure Storage**: Configuration is stored securely
- **Connection Validation**: Automatic connection testing

## 🚨 Troubleshooting

### Common Issues

1. **Connection Failed**
   - Check your Jira URL format
   - Verify your API token is correct
   - Ensure your Jira instance is accessible

2. **Operation Failed**
   - Check the error messages in the output
   - Verify your Excel file format
   - Ensure you have permissions for the operations

3. **File Upload Issues**
   - Check file size limits
   - Verify file format is supported
   - Ensure you have write permissions

### Getting Help

1. **Check the logs** displayed in the interface
2. **Review the documentation** in the sidebar
3. **Test with a simple operation** first
4. **Verify your Jira permissions** for the operations

## 📚 Additional Resources

- **Token Management Guide**: See `docs/TOKEN_MANAGEMENT_GUIDE.md`
- **Headers Migration Summary**: See `docs/HEADERS_MIGRATION_SUMMARY.md`
- **URLs Migration Summary**: See `docs/URLS_MIGRATION_SUMMARY.md`
- **New Structure Guide**: See `README_NEW_STRUCTURE.md`

## 🎯 Best Practices

1. **Test with Small Data**: Start with a few records to test operations
2. **Backup Your Data**: Always backup your Excel files before bulk operations
3. **Verify Permissions**: Ensure you have the necessary Jira permissions
4. **Use Descriptive Names**: Use clear, descriptive names for your operations
5. **Monitor Results**: Always check the results of bulk operations

The web interface provides a powerful, user-friendly way to manage all your Jira operations without needing to use command-line tools! 