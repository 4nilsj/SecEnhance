#!/usr/bin/env python3
"""
Bulk Remove Labels from Jira Tickets (Sync Version)
Removes labels from tickets using URLs from the "dev ticket" column of Excel sheet.
Includes database synchronization for tracking changes.
"""

import os
import sys
import pandas as pd
import requests
import argparse
from urllib.parse import quote
from datetime import datetime

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))))
sys.path.append(parent_dir)
from core.headers import get_jira_headers
from core.urls import get_issue_url
from config.settings import get_jira_config, get_column_mappings
from utils.data_sync_utils import sync_excel_to_db, sync_db_to_excel


def get_ticket_key_from_url(ticket_url):
    """
    Extract ticket key from Jira URL.
    
    Args:
        ticket_url (str): Full Jira ticket URL
        
    Returns:
        str: Ticket key (e.g., 'DEV-123')
    """
    try:
        # Extract the last part of the URL which should be the ticket key
        parts = ticket_url.strip('/').split('/')
        ticket_key = parts[-1]
        return ticket_key
    except Exception as e:
        print(f"❌ Error extracting ticket key from URL {ticket_url}: {str(e)}")
        return None


def get_ticket_labels(url, token, ticket_key):
    """
    Get current labels from a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_key (str): Ticket key (e.g., 'DEV-123')
        
    Returns:
        list: Current labels or None if error
    """
    try:
        api_url = get_issue_url(url, ticket_key)
        headers = get_jira_headers(token)
        
        response = requests.get(api_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            ticket_data = response.json()
            labels = ticket_data.get('fields', {}).get('labels', [])
            return labels
        else:
            print(f"❌ Failed to get ticket {ticket_key}: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error getting labels for ticket {ticket_key}: {str(e)}")
        return None


def remove_labels_from_ticket(url, token, ticket_key, labels_to_remove):
    """
    Remove specific labels from a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_key (str): Ticket key (e.g., 'DEV-123')
        labels_to_remove (list): List of labels to remove
        
    Returns:
        dict: Result with success status and details
    """
    try:
        # First get current labels
        current_labels = get_ticket_labels(url, token, ticket_key)
        if current_labels is None:
            return {"success": False, "error": "Failed to get current labels"}
        
        # Remove specified labels
        updated_labels = [label for label in current_labels if label not in labels_to_remove]
        
        # If no changes, skip update
        if len(updated_labels) == len(current_labels):
            return {
                "success": True, 
                "skipped": True, 
                "message": f"No labels to remove for ticket {ticket_key}",
                "removed_labels": [],
                "remaining_labels": current_labels
            }
        
        # Update ticket with new labels
        api_url = get_issue_url(url, ticket_key)
        headers = get_jira_headers(token)
        
        data = {
            "fields": {
                "labels": updated_labels
            }
        }
        
        response = requests.put(api_url, json=data, headers=headers, verify=False)
        
        if response.status_code == 204:
            removed_labels = [label for label in current_labels if label in labels_to_remove]
            return {
                "success": True,
                "skipped": False,
                "message": f"Successfully removed labels from ticket {ticket_key}",
                "removed_labels": removed_labels,
                "remaining_labels": updated_labels
            }
        else:
            return {
                "success": False,
                "error": f"Failed to remove labels from ticket {ticket_key}: {response.status_code} {response.text}"
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Error removing labels from ticket {ticket_key}: {str(e)}"
        }


def process_remove_labels_sync(excel_file, sheet_name, dev_ticket_col, labels_to_remove, url, token):
    """
    Process label removal for tickets from Excel file with database sync.
    
    Args:
        excel_file (str): Path to Excel file
        sheet_name (str): Sheet name
        dev_ticket_col (str): Column name containing dev ticket URLs
        labels_to_remove (list): List of labels to remove
        url (str): Jira base URL
        token (str): Jira API token
        
    Returns:
        dict: Processing results
    """
    try:
        # Sync Excel to database first
        print("🔄 Syncing Excel to database...")
        sync_result = sync_excel_to_db(excel_file, sheet_name)
        if not sync_result["success"]:
            print(f"❌ Failed to sync Excel to database: {sync_result['error']}")
            return {"success": False, "processed": 0, "successful": 0, "failed": 0}
        
        # Read Excel file
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        
        if dev_ticket_col not in df.columns:
            print(f"❌ Column '{dev_ticket_col}' not found in Excel file")
            return {"success": False, "processed": 0, "successful": 0, "failed": 0}
        
        # Filter rows with dev ticket URLs
        df_filtered = df[df[dev_ticket_col].notna() & (df[dev_ticket_col] != "")]
        
        if df_filtered.empty:
            print("ℹ️  No dev ticket URLs found in the Excel file")
            return {"success": True, "processed": 0, "successful": 0, "failed": 0}
        
        print(f"📋 Processing {len(df_filtered)} tickets for label removal...")
        print(f"🗑️  Labels to remove: {labels_to_remove}")
        print("-" * 60)
        
        successful = 0
        failed = 0
        skipped = 0
        
        # Track changes for database update
        changes = []
        
        for index, row in df_filtered.iterrows():
            ticket_url = str(row[dev_ticket_col]).strip()
            
            if not ticket_url or ticket_url.lower() in ['nan', 'none', '']:
                continue
            
            print(f"\n🔗 Processing ticket URL: {ticket_url}")
            
            # Extract ticket key from URL
            ticket_key = get_ticket_key_from_url(ticket_url)
            if not ticket_key:
                failed += 1
                continue
            
            # Remove labels
            result = remove_labels_from_ticket(url, token, ticket_key, labels_to_remove)
            
            if result["success"]:
                if result.get("skipped", False):
                    print(f"ℹ️  {result['message']}")
                    skipped += 1
                else:
                    print(f"✅ {result['message']}")
                    print(f"   Removed labels: {result['removed_labels']}")
                    print(f"   Remaining labels: {result['remaining_labels']}")
                    successful += 1
                
                # Track change for database update
                changes.append({
                    "index": index,
                    "ticket_key": ticket_key,
                    "action": "remove_labels",
                    "labels_removed": result.get("removed_labels", []),
                    "labels_remaining": result.get("remaining_labels", []),
                    "timestamp": datetime.now().isoformat()
                })
            else:
                print(f"❌ {result['error']}")
                failed += 1
        
        # Update Excel file with results
        if changes:
            print("\n🔄 Updating Excel file with results...")
            for change in changes:
                row_index = change["index"]
                if row_index < len(df):
                    # Add or update columns for tracking
                    df.at[row_index, "label_removal_status"] = "Completed"
                    df.at[row_index, "labels_removed"] = ", ".join(change["labels_removed"])
                    df.at[row_index, "labels_remaining"] = ", ".join(change["labels_remaining"])
                    df.at[row_index, "label_removal_date"] = change["timestamp"]
            
            # Save updated Excel file
            try:
                with pd.ExcelWriter(excel_file, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                print("✅ Excel file updated with results")
            except Exception as e:
                print(f"⚠️  Warning: Could not update Excel file: {str(e)}")
        
        # Sync database to Excel
        print("🔄 Syncing database to Excel...")
        sync_result = sync_db_to_excel(excel_file, sheet_name)
        if not sync_result["success"]:
            print(f"⚠️  Warning: Failed to sync database to Excel: {sync_result['error']}")
        
        print("\n" + "=" * 60)
        print(f"📊 Processing Summary:")
        print(f"   Total tickets processed: {len(df_filtered)}")
        print(f"   Successful: {successful}")
        print(f"   Skipped: {skipped}")
        print(f"   Failed: {failed}")
        
        return {
            "success": True,
            "processed": len(df_filtered),
            "successful": successful,
            "skipped": skipped,
            "failed": failed
        }
        
    except Exception as e:
        print(f"❌ Error processing Excel file: {str(e)}")
        return {"success": False, "processed": 0, "successful": 0, "failed": 0}


def main():
    """Main function for bulk label removal with sync."""
    parser = argparse.ArgumentParser(description="Remove labels from Jira tickets using Excel data (with sync)")
    
    parser.add_argument("--excel-file", required=True, help="Path to Excel file")
    parser.add_argument("--sheet", default="Sheet1", help="Sheet name (default: Sheet1)")
    parser.add_argument("--dev-ticket-col", help="Column name containing dev ticket URLs")
    parser.add_argument("--labels", required=True, help="Comma-separated list of labels to remove")
    parser.add_argument("--url", help="Jira base URL")
    parser.add_argument("--token", help="Jira API token")
    parser.add_argument("--use-config", action="store_true", help="Use configuration from settings")
    
    args = parser.parse_args()
    
    # Get configuration defaults
    config = get_jira_config()
    column_mappings = get_column_mappings()
    
    # Use config defaults if --use-config is specified or if parameters are missing
    if args.use_config or not args.url:
        args.url = args.url or config.get("base_url")
    if args.use_config or not args.token:
        args.token = args.token or config.get("token")
    if args.use_config or not args.dev_ticket_col:
        args.dev_ticket_col = args.dev_ticket_col or column_mappings.get("dev_ticket", "dev ticket")
    
    # Parse labels
    labels_to_remove = [label.strip() for label in args.labels.split(",") if label.strip()]
    
    if not labels_to_remove:
        print("❌ No labels specified to remove")
        return
    
    print("🗑️  Bulk Label Removal Tool (Sync Version)")
    print("=" * 50)
    print(f"📁 Excel File: {args.excel_file}")
    print(f"📋 Sheet: {args.sheet}")
    print(f"🔗 Dev Ticket Column: {args.dev_ticket_col}")
    print(f"🏷️  Labels to Remove: {labels_to_remove}")
    print(f"🌐 Jira URL: {args.url}")
    print("-" * 50)
    
    # Process label removal
    result = process_remove_labels_sync(
        args.excel_file,
        args.sheet,
        args.dev_ticket_col,
        labels_to_remove,
        args.url,
        args.token
    )
    
    if result["success"]:
        print(f"\n✅ Label removal completed!")
        print(f"   Processed: {result['processed']} tickets")
        print(f"   Successful: {result['successful']}")
        print(f"   Skipped: {result.get('skipped', 0)}")
        print(f"   Failed: {result['failed']}")
    else:
        print(f"\n❌ Label removal failed!")
        sys.exit(1)


if __name__ == "__main__":
    main() 