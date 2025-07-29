# QE-Evidence Check Feature

## Overview

The QE-Evidence check feature prevents duplicate uploads by checking for existing "QE-Evidence-{Ticket ID}" files before uploading POC files. This ensures that only new POC files are uploaded and prevents overwriting existing evidence.

## 🔍 How It Works

### Check Process
1. **Before uploading** any POC files, the script checks the ticket's attachments
2. **Looks for files** that start with "QE-Evidence-{Ticket ID}"
3. **If found**: Skips the upload and logs the existing files
4. **If not found**: Proceeds with POC file upload

### Example Scenarios

#### Scenario 1: No QE-Evidence Files Exist
- **Ticket**: SEC-123
- **Check**: No "QE-Evidence-SEC-123" files found
- **Result**: POC files are uploaded normally
- **Status**: "Uploaded 3/3 files"

#### Scenario 2: QE-Evidence Files Already Exist
- **Ticket**: SEC-456
- **Check**: Found "QE-Evidence-SEC-456.pdf" and "QE-Evidence-SEC-456.docx"
- **Result**: Upload is skipped
- **Status**: "Skipped - QE-Evidence exists: QE-Evidence-SEC-456.pdf, QE-Evidence-SEC-456.docx"

## 🚀 Usage

### Command Line

#### Basic Usage (with QE-Evidence check)
```bash
python scripts/attachments/bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token
```

#### Skip QE-Evidence Check
```bash
python scripts/attachments/bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --no-check-existing --url https://jira.company.com --token your_token
```

### Web Interface

1. **Launch web interface**:
   ```bash
   python launch_web.py
   ```

2. **Select "Upload POC Files"** from bulk operations

3. **Configure parameters**:
   - **POC Directory**: Path to POC files
   - **Security Ticket Column**: Column with ticket IDs
   - **File Extensions**: Select file types
   - **Check for existing QE-Evidence files**: ✅ Enable (default) or ❌ Disable

4. **Click "Execute"** to run the operation

## 📊 Output and Results

### Excel File Updates

The script adds new columns to track QE-Evidence status:

| Security Ticket | Summary | poc_upload_status | qe_evidence_exists | existing_qe_evidence |
|-----------------|---------|-------------------|-------------------|---------------------|
| SEC-123 | SQL Injection | Uploaded 3/3 files | False | |
| SEC-456 | XSS in Search | Skipped - QE-Evidence exists: QE-Evidence-SEC-456.pdf | True | QE-Evidence-SEC-456.pdf |
| SEC-789 | File Upload | No files found | False | |

### Database Sync

If using database sync, the results include:

```sql
-- Additional columns in database
qe_evidence_exists BOOLEAN,      -- Whether QE-Evidence files exist
existing_qe_evidence TEXT        -- List of existing QE-Evidence files
```

### Console Output

```
🔧 Bulk POC Upload Sync Tool
==================================================
Check existing QE-Evidence: True
==================================================

📖 Reading Excel file: security_tickets.xlsx
📋 Found 3 tickets with Security Ticket IDs

🔍 Processing ticket: SEC-123
📁 Found 3 POC file(s) for ticket SEC-123
✅ Successfully uploaded SEC-123_poc_report.pdf to SEC-123
✅ Successfully uploaded SEC-123_vulnerability_proof.docx to SEC-123
✅ Successfully uploaded SEC-123_screenshots.zip to SEC-123

🔍 Processing ticket: SEC-456
⚠️  Skipping SEC-456 - QE-Evidence files already exist: QE-Evidence-SEC-456.pdf

🔍 Processing ticket: SEC-789
⚠️  No POC files found for ticket SEC-789

==================================================
📊 UPLOAD SUMMARY
==================================================
Total tickets processed: 3
Tickets skipped (existing QE-Evidence): 1
Tickets processed: 2
Total files found: 3
Successful uploads: 3
Failed uploads: 0
✅ Upload complete! 3/3 files uploaded successfully
```

## 🎯 Benefits

### Prevents Duplicate Uploads
- ✅ **No overwrites**: Existing QE-Evidence files are preserved
- ✅ **Data integrity**: Prevents accidental file replacement
- ✅ **Audit trail**: Clear tracking of what was uploaded vs skipped

### Improves Workflow Efficiency
- ✅ **Faster processing**: Skips tickets that already have evidence
- ✅ **Clear feedback**: Shows exactly why uploads were skipped
- ✅ **Batch processing**: Handles multiple tickets efficiently

### Enhanced Reporting
- ✅ **Detailed tracking**: Records which tickets were skipped and why
- ✅ **Excel integration**: Updates Excel with skip reasons
- ✅ **Database sync**: Syncs skip information to database

## 🔧 Configuration Options

### Enable QE-Evidence Check (Default)
```bash
# Command line (default behavior)
python bulk_poc_upload_sync.py --excel tickets.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token

# Web interface: Check "Check for existing QE-Evidence files"
```

### Disable QE-Evidence Check
```bash
# Command line
python bulk_poc_upload_sync.py --excel tickets.xlsx --poc-dir ./poc_files --no-check-existing --url https://jira.company.com --token your_token

# Web interface: Uncheck "Check for existing QE-Evidence files"
```

## 🚨 Error Handling

### Common Scenarios

1. **QE-Evidence files exist**
   - **Action**: Upload is skipped
   - **Log**: "Skipped - QE-Evidence exists: [file list]"
   - **Excel**: Status shows skip reason

2. **No QE-Evidence files found**
   - **Action**: POC files are uploaded normally
   - **Log**: "Successfully uploaded [filename] to [ticket]"
   - **Excel**: Status shows upload results

3. **Error checking attachments**
   - **Action**: Proceeds with upload (fails safe)
   - **Log**: "Error checking attachments for [ticket]"
   - **Excel**: Status shows upload attempt

### Troubleshooting

#### Upload Skipped Unexpectedly
1. **Check existing attachments** in Jira for the ticket
2. **Look for files** starting with "QE-Evidence-{Ticket ID}"
3. **Use `--no-check-existing`** to force upload if needed

#### Upload Failed After Check
1. **Verify ticket ID** exists in Jira
2. **Check API permissions** for the token
3. **Review file size** limits for your Jira instance

## 📈 Performance Impact

### With QE-Evidence Check
- **Additional API calls**: One GET request per ticket to check attachments
- **Processing time**: Slightly longer due to attachment checks
- **Network usage**: Minimal additional traffic

### Without QE-Evidence Check
- **Faster processing**: No additional API calls
- **Risk**: May overwrite existing QE-Evidence files
- **Use case**: When you want to force upload regardless of existing files

## 🎯 Best Practices

### When to Use QE-Evidence Check
- ✅ **Production environments**: Prevent accidental overwrites
- ✅ **Batch processing**: Ensure data integrity
- ✅ **Audit requirements**: Maintain clear upload history

### When to Skip QE-Evidence Check
- ✅ **Testing environments**: Allow overwrites for testing
- ✅ **Force uploads**: When you need to replace existing files
- ✅ **Performance critical**: When speed is more important than safety

### File Naming Conventions
- ✅ **QE-Evidence files**: Use "QE-Evidence-{Ticket ID}" prefix
- ✅ **POC files**: Include ticket ID in filename
- ✅ **Consistent naming**: Use same pattern across all files

## 🔄 Integration with Other Features

### Combined with Bulk Operations
```bash
# 1. Create security tickets
python scripts/bulk_operations/create/bulk_create_sync.py --excel security_findings.xlsx --project SEC --url https://jira.company.com --token your_token

# 2. Upload POC files (with QE-Evidence check)
python scripts/attachments/bulk_poc_upload_sync.py --excel security_findings.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token

# 3. Add comments about upload results
python scripts/bulk_operations/comment/bulk_comment_sync.py --excel security_findings.xlsx --comment "POC files uploaded with QE-Evidence check" --url https://jira.company.com --token your_token
```

### Web Interface Workflow
1. **Create tickets** using web interface
2. **Upload POC files** with QE-Evidence check enabled
3. **Review results** in Excel file with skip information
4. **Add comments** based on upload status

The QE-Evidence check feature provides a robust way to prevent duplicate uploads while maintaining clear audit trails and improving workflow efficiency! 