#!/usr/bin/env python3
"""
Bulk POC Upload Script
Upload POC files to Jira tickets based on "Security Ticket" column in Excel sheet.
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
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from core.headers import get_jira_attachment_headers
from core.urls import get_issue_attachments_url


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
        headers = get_jira_attachment_headers(token)
        
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
            print(f"❌ Failed to get attachments for {ticket_id}: {response.status_code} {response.text}")
            return []
            
    except Exception as e:
        print(f"❌ Error checking attachments for {ticket_id}: {str(e)}")
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
                print(f"⚠️  Skipping upload for {ticket_id} - QE-Evidence files already exist: {', '.join(existing_files)}")
                return False
        
        api_url = get_issue_attachments_url(url, ticket_id)
        headers = get_jira_attachment_headers(token)
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            response = requests.post(api_url, headers=headers, files=files, verify=False)
            
        if response.status_code in [200, 201]:
            print(f"✅ Successfully uploaded {os.path.basename(file_path)} to {ticket_id}")
            return True
        else:
            print(f"❌ Failed to upload {os.path.basename(file_path)} to {ticket_id}: {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error uploading {os.path.basename(file_path)} to {ticket_id}: {str(e)}")
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
                        print(f"📁 Found POC file: {file}")
    except Exception as e:
        print(f"❌ Error searching directory {directory}: {str(e)}")
    
    return matching_files


def main():
    """Main function to handle bulk POC uploads."""
    
    parser = argparse.ArgumentParser(
        description="Upload POC files to Jira tickets based on 'Security Ticket' column in Excel sheet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Upload POC files from directory to tickets listed in Excel
  python bulk_poc_upload.py --excel security_tickets.xlsx --poc-dir ./poc_files --url https://jira.company.com --token your_token
  
  # Upload with custom file pattern
  python bulk_poc_upload.py --excel security_tickets.xlsx --poc-dir ./poc_files --pattern "SEC-\\d+" --url https://jira.company.com --token your_token
  
  # Upload specific file types only
  python bulk_poc_upload.py --excel security_tickets.xlsx --poc-dir ./poc_files --extensions pdf doc zip --url https://jira.company.com --token your_token
  
  # Skip existing QE-Evidence check
  python bulk_poc_upload.py --excel security_tickets.xlsx --poc-dir ./poc_files --no-check-existing --url https://jira.company.com --token your_token
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with Security Ticket column")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--poc-dir", required=True, help="Directory containing POC files")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name containing ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--pattern", default=r"([A-Z]+-\d+)", help="Regex pattern to extract ticket ID from filename")
    parser.add_argument("--extensions", nargs="+", default=["pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "zip", "rar"], 
                       help="File extensions to include (default: pdf doc docx txt png jpg jpeg zip rar)")
    parser.add_argument("--no-check-existing", action="store_true", help="Skip checking for existing QE-Evidence files")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded without actually uploading")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.excel):
        print(f"❌ Excel file not found: {args.excel}")
        return
    
    if not os.path.exists(args.poc_dir):
        print(f"❌ POC directory not found: {args.poc_dir}")
        return
    
    print("🔧 Bulk POC Upload Tool")
    print("=" * 50)
    print(f"Excel file: {args.excel}")
    print(f"POC directory: {args.poc_dir}")
    print(f"Security Ticket column: {args.security_ticket_col}")
    print(f"File extensions: {', '.join(args.extensions)}")
    print(f"Pattern: {args.pattern}")
    print(f"Check existing QE-Evidence: {not args.no_check_existing}")
    print(f"Dry run: {args.dry_run}")
    print("=" * 50)
    
    try:
        # Read Excel file
        print(f"📖 Reading Excel file: {args.excel}")
        df = pd.read_excel(args.excel, sheet_name=args.sheet)
        
        if args.security_ticket_col not in df.columns:
            print(f"❌ Column '{args.security_ticket_col}' not found in Excel file")
            print(f"Available columns: {list(df.columns)}")
            return
        
        # Filter out empty ticket IDs
        df = df[df[args.security_ticket_col].notna()]
        df = df[df[args.security_ticket_col].astype(str).str.strip() != '']
        
        print(f"📋 Found {len(df)} tickets with Security Ticket IDs")
        
        if args.debug:
            print("Ticket IDs found:")
            for ticket_id in df[args.security_ticket_col]:
                print(f"  - {ticket_id}")
        
        # Process each ticket
        success_count = 0
        total_files = 0
        skipped_count = 0
        
        for idx, row in df.iterrows():
            ticket_id = str(row[args.security_ticket_col]).strip()
            
            if args.debug:
                print(f"\n🔍 Processing ticket: {ticket_id}")
            
            # Check for existing QE-Evidence files
            if not args.no_check_existing:
                existing_files = check_existing_qe_evidence(args.url, args.token, ticket_id)
                if existing_files:
                    print(f"⚠️  Skipping {ticket_id} - QE-Evidence files already exist: {', '.join(existing_files)}")
                    skipped_count += 1
                    continue
            
            # Find POC files for this ticket
            poc_files = find_poc_files(args.poc_dir, ticket_id, args.extensions)
            
            if not poc_files:
                print(f"⚠️  No POC files found for ticket {ticket_id}")
                continue
            
            print(f"📁 Found {len(poc_files)} POC file(s) for ticket {ticket_id}")
            
            # Upload each POC file
            for file_path in poc_files:
                total_files += 1
                
                if args.dry_run:
                    print(f"🔍 [DRY RUN] Would upload: {os.path.basename(file_path)} to {ticket_id}")
                    success_count += 1
                else:
                    if upload_poc_to_ticket(args.url, args.token, ticket_id, file_path, not args.no_check_existing):
                        success_count += 1
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 UPLOAD SUMMARY")
        print("=" * 50)
        print(f"Total tickets processed: {len(df)}")
        print(f"Tickets skipped (existing QE-Evidence): {skipped_count}")
        print(f"Tickets processed: {len(df) - skipped_count}")
        print(f"Total files found: {total_files}")
        print(f"Successful uploads: {success_count}")
        print(f"Failed uploads: {total_files - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no files were actually uploaded")
        else:
            print(f"✅ Upload complete! {success_count}/{total_files} files uploaded successfully")
        
    except Exception as e:
        print(f"❌ Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 