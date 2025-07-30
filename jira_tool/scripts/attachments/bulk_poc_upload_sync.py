#!/usr/bin/env python3
"""
Bulk POC Upload Sync Script
Upload POC files to Jira tickets based on "Security Ticket" column in Excel sheet with sync capabilities.
Checks for existing "QE-Evidence-{Ticket ID}" files before uploading.
"""

import argparse
import pandas as pd
import requests
import os
import re
import sys
from pathlib import Path

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from core.headers import get_jira_headers, get_jira_attachment_headers
from core.urls import get_issue_attachments_url
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, add_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log


def extract_ticket_id_from_filename(filename, pattern=r"([A-Z]+-\d+)"):
    """
    Extract ticket ID from filename using regex pattern.
    
    Args:
        filename (str): Name of the file
        pattern (str): Regex pattern to extract ticket ID
        
    Returns:
        str: Extracted ticket ID or None if not found
    """
    match = re.search(pattern, filename)
    return match.group(1) if match else None


def check_existing_qe_evidence(url, token, ticket_id):
    """
    Check if there are existing "QE-Evidence-{Ticket ID}" files attached to the ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Jira ticket ID
        
    Returns:
        list: List of existing QE-Evidence files
    """
    try:
        api_url = get_issue_attachments_url(url, ticket_id)
        headers = get_jira_headers(token)
        
        response = requests.get(api_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            attachments = response.json()
            qe_evidence_files = []
            
            for attachment in attachments:
                filename = attachment.get('filename', '')
                if filename.startswith(f"QE-Evidence-{ticket_id}"):
                    qe_evidence_files.append(filename)
            
            return qe_evidence_files
        else:
            error_log(f"Failed to get attachments for {ticket_id}: {response.status_code} {response.text}")
            return []
            
    except Exception as e:
        error_log(f"Error checking attachments for {ticket_id}: {str(e)}")
        return []


def upload_poc_to_ticket(url, token, ticket_id, file_path, check_existing=True):
    """
    Upload a POC file to a specific Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Jira ticket ID
        file_path (str): Path to the POC file
        check_existing (bool): Whether to check for existing QE-Evidence files
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Check for existing QE-Evidence files if requested
        if check_existing:
            existing_files = check_existing_qe_evidence(url, token, ticket_id)
            if existing_files:
                info_log(f"Skipping upload for {ticket_id} - QE-Evidence files already exist: {', '.join(existing_files)}")
                return False
        
        api_url = get_issue_attachments_url(url, ticket_id)
        headers = get_jira_attachment_headers(token)
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            response = requests.post(api_url, headers=headers, files=files, verify=False)
            
        if response.status_code in [200, 201]:
            info_log(f"Successfully uploaded {os.path.basename(file_path)} to {ticket_id}")
            return True
        else:
            error_log(f"Failed to upload {os.path.basename(file_path)} to {ticket_id}: {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        error_log(f"Error uploading {os.path.basename(file_path)} to {ticket_id}: {str(e)}")
        return False


def find_poc_files(directory, ticket_id, file_extensions=None):
    """
    Find POC files in directory that match the ticket ID.
    
    Args:
        directory (str): Directory to search for files
        ticket_id (str): Ticket ID to match
        file_extensions (list): List of file extensions to include
        
    Returns:
        list: List of matching file paths
    """
    if file_extensions is None:
        file_extensions = ['.pdf', '.doc', '.docx', '.txt', '.png', '.jpg', '.jpeg', '.zip', '.rar']
    
    matching_files = []
    
    try:
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path):
                # Check if file extension is in allowed list
                if any(file.lower().endswith(ext) for ext in file_extensions):
                    # Check if ticket ID is in filename
                    if ticket_id in file:
                        matching_files.append(file_path)
                        debug_log(f"Found POC file: {file}")
    except Exception as e:
        error_log(f"Error searching directory {directory}: {str(e)}")
    
    return matching_files


def process_poc_uploads(df, url, token, poc_dir, security_ticket_col, file_extensions, pattern, dry_run=False, check_existing=True):
    """
    Process POC uploads for all tickets in the dataframe.
    
    Args:
        df (DataFrame): DataFrame containing ticket information
        url (str): Jira base URL
        token (str): Jira API token
        poc_dir (str): Directory containing POC files
        security_ticket_col (str): Column name containing ticket IDs
        file_extensions (list): List of file extensions to include
        pattern (str): Regex pattern for ticket ID extraction
        dry_run (bool): If True, only show what would be uploaded
        check_existing (bool): Whether to check for existing QE-Evidence files
        
    Returns:
        tuple: (success_count, total_files, updated_df)
    """
    success_count = 0
    total_files = 0
    skipped_count = 0
    updated_rows = []
    
    # Filter out empty ticket IDs
    df_filtered = df[df[security_ticket_col].notna()]
    df_filtered = df_filtered[df_filtered[security_ticket_col].astype(str).str.strip() != '']
    
    info_log(f"Processing {len(df_filtered)} tickets with Security Ticket IDs")
    
    for idx, row in df_filtered.iterrows():
        ticket_id = str(row[security_ticket_col]).strip()
        debug_log(f"Processing ticket: {ticket_id}")
        
        # Check for existing QE-Evidence files
        existing_files = []
        if check_existing:
            existing_files = check_existing_qe_evidence(url, token, ticket_id)
            if existing_files:
                info_log(f"Skipping {ticket_id} - QE-Evidence files already exist: {', '.join(existing_files)}")
                skipped_count += 1
                # Add row with skip information
                row_dict = row.to_dict()
                row_dict['poc_files_found'] = 0
                row_dict['poc_files_uploaded'] = 0
                row_dict['poc_upload_status'] = f"Skipped - QE-Evidence exists: {', '.join(existing_files)}"
                row_dict['poc_files_list'] = ''
                row_dict['poc_failed_files'] = ''
                row_dict['qe_evidence_exists'] = True
                row_dict['existing_qe_evidence'] = ', '.join(existing_files)
                updated_rows.append(row_dict)
                continue
        
        # Find POC files for this ticket
        poc_files = find_poc_files(poc_dir, ticket_id, file_extensions)
        
        if not poc_files:
            debug_log(f"No POC files found for ticket {ticket_id}")
            # Add row with no files found
            row_dict = row.to_dict()
            row_dict['poc_files_found'] = 0
            row_dict['poc_files_uploaded'] = 0
            row_dict['poc_upload_status'] = 'No files found'
            row_dict['poc_files_list'] = ''
            row_dict['poc_failed_files'] = ''
            row_dict['qe_evidence_exists'] = False
            row_dict['existing_qe_evidence'] = ''
            updated_rows.append(row_dict)
            continue
        
        info_log(f"Found {len(poc_files)} POC file(s) for ticket {ticket_id}")
        
        uploaded_files = []
        failed_files = []
        
        # Upload each POC file
        for file_path in poc_files:
            total_files += 1
            
            if dry_run:
                debug_log(f"[DRY RUN] Would upload: {os.path.basename(file_path)} to {ticket_id}")
                uploaded_files.append(os.path.basename(file_path))
                success_count += 1
            else:
                if upload_poc_to_ticket(url, token, ticket_id, file_path, check_existing):
                    uploaded_files.append(os.path.basename(file_path))
                    success_count += 1
                else:
                    failed_files.append(os.path.basename(file_path))
        
        # Update row with upload results
        row_dict = row.to_dict()
        row_dict['poc_files_found'] = len(poc_files)
        row_dict['poc_files_uploaded'] = len(uploaded_files)
        row_dict['poc_files_failed'] = len(failed_files)
        row_dict['poc_upload_status'] = f"Uploaded {len(uploaded_files)}/{len(poc_files)} files"
        row_dict['poc_files_list'] = ', '.join(uploaded_files) if uploaded_files else ''
        row_dict['poc_failed_files'] = ', '.join(failed_files) if failed_files else ''
        row_dict['qe_evidence_exists'] = False
        row_dict['existing_qe_evidence'] = ''
        updated_rows.append(row_dict)
    
    # Create updated dataframe
    updated_df = pd.DataFrame(updated_rows)
    
    return success_count, total_files, updated_df, skipped_count


def main():
    """Main function to handle bulk POC uploads with sync capabilities."""
    
    parser = argparse.ArgumentParser(
        description="Upload POC files to Jira tickets based on 'Security Ticket' column in Excel sheet with sync capabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload POC files from directory to tickets listed in Excel
  python bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token
  
  # Upload with database sync
  python bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --db tickets.db --url https://jira.company.com --token your_token
  
  # Upload with custom file extensions
  python bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --extensions pdf doc zip --url https://jira.company.com --token your_token
  
  # Skip existing QE-Evidence check
  python bulk_poc_upload_sync.py --excel security_tickets.xlsx --poc-dir ./poc_files --no-check-existing --url https://jira.company.com --token your_token
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with Security Ticket column")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--poc-dir", required=True, help="Directory containing POC files")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--db", help="SQLite database file for sync")
    parser.add_argument("--table", default="tickets", help="Database table name (default: tickets)")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name containing ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--pattern", default=r"([A-Z]+-\d+)", help="Regex pattern to extract ticket ID from filename")
    parser.add_argument("--extensions", nargs="+", default=["pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "zip", "rar"], 
                       help="File extensions to include (default: pdf doc docx txt png jpg jpeg zip rar)")
    parser.add_argument("--no-check-existing", action="store_true", help="Skip checking for existing QE-Evidence files")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded without actually uploading")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    # Set debug mode
    if args.debug:
        set_debug(True)
    
    # Validate inputs
    if not os.path.exists(args.excel):
        error_log(f"Excel file not found: {args.excel}")
        return
    
    if not os.path.exists(args.poc_dir):
        error_log(f"POC directory not found: {args.poc_dir}")
        return
    
    info_log("🔧 Bulk POC Upload Sync Tool")
    info_log("=" * 50)
    info_log(f"Excel file: {args.excel}")
    info_log(f"POC directory: {args.poc_dir}")
    info_log(f"Security Ticket column: {args.security_ticket_col}")
    info_log(f"File extensions: {', '.join(args.extensions)}")
    info_log(f"Pattern: {args.pattern}")
    info_log(f"Check existing QE-Evidence: {not args.no_check_existing}")
    info_log(f"Dry run: {args.dry_run}")
    if args.db:
        info_log(f"Database: {args.db}")
        info_log(f"Table: {args.table}")
    info_log("=" * 50)
    
    try:
        # Read Excel file
        info_log(f"Reading Excel file: {args.excel}")
        df = read_excel(args.excel, args.sheet)
        
        if args.security_ticket_col not in df.columns:
            error_log(f"Column '{args.security_ticket_col}' not found in Excel file")
            info_log(f"Available columns: {list(df.columns)}")
            return
        
        # Process POC uploads
        success_count, total_files, updated_df, skipped_count = process_poc_uploads(
            df, args.url, args.token, args.poc_dir, args.security_ticket_col, 
            args.extensions, args.pattern, args.dry_run, not args.no_check_existing
        )
        
        # Write updated data back to Excel
        info_log(f"Writing updated data to Excel file")
        write_excel(args.excel, args.sheet, updated_df)
        
        # Sync with database if provided
        if args.db:
            info_log(f"Syncing with database: {args.db}")
            write_sqlite(args.db, args.table, updated_df)
        
        # Summary
        info_log("\n" + "=" * 50)
        info_log("📊 UPLOAD SUMMARY")
        info_log("=" * 50)
        info_log(f"Total tickets processed: {len(updated_df)}")
        info_log(f"Tickets skipped (existing QE-Evidence): {skipped_count}")
        info_log(f"Tickets processed: {len(updated_df) - skipped_count}")
        info_log(f"Total files found: {total_files}")
        info_log(f"Successful uploads: {success_count}")
        info_log(f"Failed uploads: {total_files - success_count}")
        
        if args.dry_run:
            info_log("🔍 This was a dry run - no files were actually uploaded")
        else:
            info_log(f"✅ Upload complete! {success_count}/{total_files} files uploaded successfully")
            info_log(f"📊 Updated Excel file with upload results")
            if args.db:
                info_log(f"📊 Synced results to database: {args.db}")
        
    except Exception as e:
        error_log(f"Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 