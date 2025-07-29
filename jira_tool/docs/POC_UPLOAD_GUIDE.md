# POC Upload Guide

## Overview

The POC (Proof of Concept) Upload functionality allows you to upload POC files to Jira tickets based on the "Security Ticket" column in an Excel sheet. This is specifically designed for security teams who need to attach POC files to security tickets.

**Important**: The script checks for existing "QE-Evidence-{Ticket ID}" files before uploading. If such files already exist, the upload will be skipped to prevent duplicates.

## 🚀 Quick Start

### Command Line Usage

```bash
# Basic POC upload
python scripts/attachments/bulk_poc_upload.py --excel security_tickets.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token

# With database sync
python scripts/attachments/bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --db tickets.db --url https://jira.company.com --token your_token

# With custom file extensions
python scripts/attachments/bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --extensions pdf doc zip --url https://jira.company.com --token your_token
```

### Web Interface Usage

1. **Launch the web interface**:
   ```bash
   python launch_web.py
   ```

2. **Navigate to Bulk Operations** tab

3. **Select "Upload POC Files"** from the dropdown

4. **Upload your Excel file** with Security Ticket column

5. **Configure parameters**:
   - **POC Directory**: Path to directory containing POC files
   - **Security Ticket Column**: Column name containing ticket IDs (default: "Security Ticket")
   - **File Extensions**: Select which file types to include
   - **Check for existing QE-Evidence files**: Enable/disable duplicate check

6. **Click "Execute Upload POC Files"** to run the operation

## 📋 Excel File Format

Your Excel file should contain a "Security Ticket" column with ticket IDs:

| Security Ticket | Summary | Description | Priority | Status |
|-----------------|---------|-------------|----------|--------|
| SEC-123 | SQL Injection Vulnerability | Found SQL injection in login form | High | Open |
| SEC-456 | XSS in Search | Cross-site scripting in search functionality | Medium | In Progress |
| SEC-789 | File Upload Vulnerability | Unrestricted file upload allows malicious files | Critical | Open |

## 📁 POC File Naming Convention

POC files should be named to include the ticket ID. The script will match files containing the ticket ID in the filename.

### Examples of Valid POC File Names:
- `SEC-123_poc_report.pdf`
- `SEC-123_vulnerability_proof.docx`
- `SEC-123_screenshots.zip`
- `SEC-123_exploit_code.txt`
- `SEC-123_demo_video.mp4`

### Examples of Invalid POC File Names:
- `poc_report.pdf` (no ticket ID)
- `security_report.pdf` (no ticket ID)
- `SEC-123` (no file extension)

## 🔧 Script Options

### Basic Options
- `--excel`: Excel file with Security Ticket column
- `--poc-dir`: Directory containing POC files
- `--url`: Jira base URL
- `--token`: Jira API token

### Advanced Options
- `--sheet`: Excel sheet name or index (default: 0)
- `--security-ticket-col`: Column name containing ticket IDs (default: "Security Ticket")
- `--extensions`: File extensions to include (default: pdf, doc, docx, txt, png, jpg, jpeg, zip, rar)
- `--pattern`: Regex pattern to extract ticket ID from filename
- `--no-check-existing`: Skip checking for existing QE-Evidence files
- `--dry-run`: Show what would be uploaded without actually uploading
- `--debug`: Enable debug output

### Sync Options (for sync version)
- `--db`: SQLite database file for sync
- `--table`: Database table name (default: tickets)

## 📊 Output and Results

### Excel File Updates

After running the script, your Excel file will be updated with additional columns:

| Security Ticket | Summary | poc_files_found | poc_files_uploaded | poc_upload_status | poc_files_list | qe_evidence_exists | existing_qe_evidence |
|-----------------|---------|-----------------|-------------------|-------------------|----------------|-------------------|-------------------|
| SEC-123 | SQL Injection Vulnerability | 3 | 3 | Uploaded 3/3 files | SEC-123_poc_report.pdf, SEC-123_vulnerability_proof.docx, SEC-123_screenshots.zip | False | |
| SEC-456 | XSS in Search | 0 | 0 | Skipped - QE-Evidence exists: QE-Evidence-SEC-456.pdf | | True | QE-Evidence-SEC-456.pdf |
| SEC-789 | File Upload Vulnerability | 0 | 0 | No files found | | False | |

### Database Sync (if using sync version)

If you specify a database file, the results will also be synced to SQLite:

```sql
-- Example database table structure
CREATE TABLE tickets (
    Security_Ticket TEXT,
    Summary TEXT,
    Description TEXT,
    Priority TEXT,
    Status TEXT,
    poc_files_found INTEGER,
    poc_files_uploaded INTEGER,
    poc_upload_status TEXT,
    poc_files_list TEXT,
    poc_failed_files TEXT,
    qe_evidence_exists BOOLEAN,
    existing_qe_evidence TEXT
);
```

## 🎯 Use Cases

### Security Teams
- Upload vulnerability POC files to security tickets
- Attach exploit code and screenshots
- Link demonstration videos to tickets
- Track POC file uploads in Excel/database

### Compliance Teams
- Upload evidence files to compliance tickets
- Attach audit reports and findings
- Link supporting documentation

### Development Teams
- Upload bug reproduction steps
- Attach error logs and screenshots
- Link test cases and examples

## 🔍 File Matching Logic

The script uses the following logic to match POC files to tickets:

1. **QE-Evidence Check**: First checks if "QE-Evidence-{Ticket ID}" files already exist
2. **File Extension Check**: Only files with specified extensions are considered
3. **Ticket ID Matching**: Files must contain the ticket ID in the filename
4. **Case Insensitive**: Matching is case-insensitive
5. **Partial Matching**: Ticket ID can be anywhere in the filename

### Example Matching:
- Ticket ID: `SEC-123`
- Valid files: `SEC-123_report.pdf`, `report_SEC-123.docx`, `SEC-123_v2.zip`
- Invalid files: `SEC-124_report.pdf`, `report.pdf`, `SEC-123` (no extension)

## 🚨 Error Handling

### Common Issues and Solutions

1. **No POC files found for ticket**
   - Check that POC files contain the ticket ID in the filename
   - Verify file extensions are in the allowed list
   - Ensure files are in the specified directory

2. **Upload skipped due to existing QE-Evidence**
   - Check if "QE-Evidence-{Ticket ID}" files already exist
   - Use `--no-check-existing` to skip this check
   - Review existing attachments in Jira

3. **Upload failed**
   - Check Jira API token permissions
   - Verify ticket ID exists in Jira
   - Check file size limits (Jira has attachment size limits)

4. **Column not found**
   - Ensure "Security Ticket" column exists in Excel file
   - Check column name spelling and case

5. **Directory not found**
   - Verify POC directory path is correct
   - Check directory permissions

## 📈 Performance Tips

### For Large Numbers of Files
- Use specific file extensions to reduce search time
- Organize POC files in subdirectories by ticket ID
- Use dry-run mode to test before actual upload

### For Large Numbers of Tickets
- Process in batches if you have many tickets
- Use database sync for better performance with large datasets
- Monitor upload progress and logs

## 🔐 Security Considerations

### File Type Restrictions
- Only upload files from trusted sources
- Be cautious with executable files
- Consider file size limits for your Jira instance

### Access Control
- Ensure only authorized users have access to POC files
- Use secure file storage for sensitive POC files
- Consider encrypting sensitive POC files before upload

## 📚 Integration with Other Features

### Combined with Other Operations
You can combine POC uploads with other operations:

1. **Create tickets** with security findings
2. **Upload POC files** to those tickets
3. **Add comments** with additional context
4. **Update status** to reflect POC review

### Workflow Example
```bash
# 1. Create security tickets
python scripts/bulk_operations/create/bulk_create_sync.py --excel security_findings.xlsx --project SEC --url https://jira.company.com --token your_token

# 2. Upload POC files to created tickets
python scripts/attachments/bulk_poc_upload_sync.py --excel security_findings.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token

# 3. Add comments with context
python scripts/bulk_operations/comment/bulk_comment_sync.py --excel security_findings.xlsx --comment "POC files uploaded for verification" --url https://jira.company.com --token your_token
```

## 🎯 Best Practices

1. **File Organization**
   - Use consistent naming conventions
   - Include ticket ID in all POC file names
   - Organize files by ticket ID or date

2. **Documentation**
   - Include clear descriptions in POC files
   - Document steps to reproduce issues
   - Add context about the security impact

3. **Testing**
   - Use dry-run mode to test before actual upload
   - Verify file permissions and access
   - Test with a small subset first

4. **Monitoring**
   - Check upload logs for errors
   - Verify files are attached correctly in Jira
   - Monitor disk space and file sizes

The POC upload functionality provides a powerful way to manage security-related file attachments in Jira, making it easy to link evidence and proof-of-concept files to security tickets! 