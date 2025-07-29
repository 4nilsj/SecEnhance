#!/usr/bin/env python3
"""
Bulk Comment Dev Status Script (Sync Version)
Fetch ticket URLs from "Security Ticket" column and update comments based on "dev ticket status" column.
If "dev ticket status" is "Acceptance", adds comment "QE Testing in Dev Completed".
Updates both Excel file and SQLite database with comment status.
"""

import argparse
import pandas as pd
import requests
import os
import sys
import sqlite3
from pathlib import Path
from datetime import datetime

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))))
sys.path.append(parent_dir)
from core.headers import get_jira_headers
from core.urls import get_issue_comment_url
from utils.data_sync_utils import sync_excel_to_db, sync_db_to_excel, get_db_connection, error_log, info_log, success_log
from config.settings import get_jira_config, get_column_mappings


def add_jira_comment(url, token, ticket_id, comment):
    """
    Add a comment to a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Ticket ID
        comment (str): Comment text
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        api_url = get_issue_comment_url(url, ticket_id)
        headers = get_jira_headers(token)
        data = {"body": comment}
        
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        
        if response.status_code == 201:
            success_log(f"Successfully added comment to {ticket_id}")
            return True
        else:
            error_log(f"Failed to add comment to {ticket_id}: {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        error_log(f"Error adding comment to {ticket_id}: {str(e)}")
        return False


def process_dev_status_comments(df, url, token, security_ticket_col="Security Ticket", 
                              dev_status_col="dev ticket status", dry_run=False):
    """
    Process Excel rows and add comments based on dev ticket status.
    
    Args:
        df (DataFrame): DataFrame containing ticket information
        url (str): Jira base URL
        token (str): Jira API token
        security_ticket_col (str): Column name containing Security Ticket IDs
        dev_status_col (str): Column name containing dev ticket status
        dry_run (bool): If True, only show what would be done
        
    Returns:
        tuple: (success_count, total_processed, updated_df)
    """
    success_count = 0
    total_processed = 0
    updated_rows = []
    
    # Filter for rows with Security Ticket IDs and dev status
    has_security_ticket = df[security_ticket_col].notna() & (df[security_ticket_col].astype(str).str.strip() != "")
    has_dev_status = df[dev_status_col].notna() & (df[dev_status_col].astype(str).str.strip() != "")
    
    filtered_df = df[has_security_ticket & has_dev_status].copy()
    
    info_log(f"Found {len(filtered_df)} tickets with Security Ticket IDs and dev status")
    
    if len(filtered_df) == 0:
        info_log("No tickets to process - no rows with both Security Ticket and dev status")
        return 0, 0, df
    
    for idx, row in filtered_df.iterrows():
        total_processed += 1
        
        # Get ticket details
        ticket_id = str(row[security_ticket_col]).strip()
        dev_status = str(row[dev_status_col]).strip()
        
        info_log(f"Processing row {idx + 2}: {ticket_id} - Status: {dev_status}")
        
        # Check if status is "Acceptance"
        if dev_status.lower() == "acceptance":
            comment = "QE Testing in Dev Completed"
            
            if dry_run:
                info_log(f"[DRY RUN] Would add comment to {ticket_id}: '{comment}'")
                success_count += 1
                # Add row with dry run info
                row_dict = row.to_dict()
                row_dict['comment_status'] = 'Dry Run - Would Add Comment'
                row_dict['comment_text'] = comment
                row_dict['comment_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
            else:
                # Add the comment
                success = add_jira_comment(url, token, ticket_id, comment)
                
                if success:
                    success_count += 1
                    # Update row with comment info
                    row_dict = row.to_dict()
                    row_dict['comment_status'] = f'Added: {comment}'
                    row_dict['comment_text'] = comment
                    row_dict['comment_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    updated_rows.append(row_dict)
                else:
                    # Keep original row if comment failed
                    row_dict = row.to_dict()
                    row_dict['comment_status'] = 'Failed to add comment'
                    row_dict['comment_text'] = comment
                    row_dict['comment_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    updated_rows.append(row_dict)
        else:
            info_log(f"Skipping {ticket_id} - Status '{dev_status}' is not 'Acceptance'")
            # Add row with skip info
            row_dict = row.to_dict()
            row_dict['comment_status'] = f'Skipped - Status: {dev_status}'
            row_dict['comment_text'] = ''
            row_dict['comment_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_rows.append(row_dict)
    
    # Create updated dataframe
    updated_df = df.copy()
    
    # Update only the processed rows
    for row_dict in updated_rows:
        original_idx = None
        for idx, row in df.iterrows():
            if all(row[col] == row_dict[col] for col in df.columns if col in row_dict):
                original_idx = idx
                break
        
        if original_idx is not None:
            for col, value in row_dict.items():
                if col in updated_df.columns:
                    updated_df.at[original_idx, col] = value
                else:
                    # Add new column if it doesn't exist
                    updated_df[col] = value
    
    return success_count, total_processed, updated_df


def update_database_with_comments(df, db_path, table_name="tickets"):
    """
    Update SQLite database with comment status results.
    
    Args:
        df (DataFrame): Updated DataFrame with comment status
        db_path (str): Path to SQLite database
        table_name (str): Table name in database
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        conn = get_db_connection(db_path)
        cursor = conn.cursor()
        
        # Get existing table structure
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        # Add new columns if they don't exist
        new_columns = ['comment_status', 'comment_text', 'comment_date']
        for col in new_columns:
            if col not in existing_columns:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col} TEXT")
                info_log(f"Added column '{col}' to database table")
        
        # Update database with comment information
        for idx, row in df.iterrows():
            # Create a dictionary of values to update
            update_data = {}
            for col in df.columns:
                if col in existing_columns:
                    update_data[col] = row[col]
            
            # Build UPDATE query
            set_clause = ", ".join([f"{col} = ?" for col in update_data.keys()])
            where_clause = " AND ".join([f"{col} = ?" for col in df.columns if col in existing_columns])
            
            # Get values for SET clause
            set_values = list(update_data.values())
            # Get values for WHERE clause (use original row data for matching)
            where_values = [row[col] for col in df.columns if col in existing_columns]
            
            query = f"UPDATE {table_name} SET {set_clause} WHERE {where_clause}"
            cursor.execute(query, set_values + where_values)
        
        conn.commit()
        conn.close()
        success_log("Database updated successfully with comment information")
        return True
        
    except Exception as e:
        error_log(f"Error updating database: {str(e)}")
        return False


def main():
    """Main function to handle bulk comment updates based on dev status with sync."""
    
    parser = argparse.ArgumentParser(
        description="Add comments to Jira tickets based on dev ticket status (with Excel/DB sync)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Add comments for Acceptance status with sync
  python bulk_comment_dev_status_sync.py --excel tickets.xlsx --url https://jira.company.com --token your_token --db tickets.db
  
  # Use custom column names with sync
  python bulk_comment_dev_status_sync.py --excel tickets.xlsx --security-ticket-col "Jira_Ticket" --dev-status-col "dev_status" --url https://jira.company.com --token your_token --db tickets.db
  
  # Dry run to see what would be done
  python bulk_comment_dev_status_sync.py --excel tickets.xlsx --dry-run --url https://jira.company.com --token your_token --db tickets.db
  
  # Use configuration defaults
  python bulk_comment_dev_status_sync.py --excel tickets.xlsx --use-config --db tickets.db
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with ticket data")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--url", help="Jira base URL (defaults to config)")
    parser.add_argument("--token", help="Jira API token (defaults to config)")
    parser.add_argument("--db", help="SQLite database file for sync (optional)")
    parser.add_argument("--table", default="tickets", help="Database table name (default: tickets)")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name for Security Ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--dev-status-col", default="dev ticket status", help="Column name for dev ticket status (default: 'dev ticket status')")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without actually doing it")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--use-config", action="store_true", help="Use configuration defaults for missing parameters")
    parser.add_argument("--no-sync", action="store_true", help="Skip database synchronization")
    
    args = parser.parse_args()
    
    # Get configuration defaults
    config = get_jira_config()
    column_mappings = get_column_mappings()
    
    # Use config defaults if --use-config is specified or if parameters are missing
    if args.use_config or not args.url:
        args.url = args.url or config.get("base_url")
    if args.use_config or not args.token:
        args.token = args.token or config.get("token")
    if args.use_config or not args.security_ticket_col:
        args.security_ticket_col = args.security_ticket_col or column_mappings.get("security_ticket", "Security Ticket")
    
    # Validate required parameters
    if not args.url:
        error_log("Jira URL is required. Use --url or set JIRA_BASE_URL environment variable.")
        return
    if not args.token:
        error_log("Jira token is required. Use --token or set JIRA_TOKEN environment variable.")
        return
    
    # Validate inputs
    if not os.path.exists(args.excel):
        error_log(f"Excel file not found: {args.excel}")
        return
    
    if args.db and not os.path.exists(args.db):
        info_log(f"Database file not found: {args.db} - will create new database")
    
    print("🔧 Bulk Comment Dev Status Tool (Sync Version)")
    print("=" * 60)
    print(f"Excel file: {args.excel}")
    print(f"Security Ticket column: {args.security_ticket_col}")
    print(f"Dev Status column: {args.dev_status_col}")
    if args.db:
        print(f"Database: {args.db}")
        print(f"Table: {args.table}")
    print(f"Dry run: {args.dry_run}")
    print(f"Sync enabled: {not args.no_sync}")
    print("=" * 60)
    
    try:
        # Read Excel file
        info_log(f"Reading Excel file: {args.excel}")
        df = pd.read_excel(args.excel, sheet_name=args.sheet)
        
        # Validate required columns
        required_columns = [args.security_ticket_col, args.dev_status_col]
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            error_log(f"Missing required columns: {missing_columns}")
            print(f"Available columns: {list(df.columns)}")
            return
        
        info_log(f"Found {len(df)} total rows in Excel file")
        
        # Check for tickets with Security Ticket IDs and dev status
        has_security_ticket_count = len(df[df[args.security_ticket_col].notna() & (df[args.security_ticket_col].astype(str).str.strip() != "")])
        has_dev_status_count = len(df[df[args.dev_status_col].notna() & (df[args.dev_status_col].astype(str).str.strip() != "")])
        acceptance_count = len(df[df[args.dev_status_col].str.lower().str.strip() == "acceptance"])
        
        print(f"📊 Analysis:")
        print(f"   - Rows with Security Ticket IDs: {has_security_ticket_count}")
        print(f"   - Rows with dev status: {has_dev_status_count}")
        print(f"   - Rows with 'Acceptance' status: {acceptance_count}")
        
        if args.debug:
            print("\n🔍 Sample data:")
            print(df[[args.security_ticket_col, args.dev_status_col]].head())
        
        # Sync Excel to database if database is provided
        if args.db and not args.no_sync:
            info_log("Syncing Excel data to database...")
            sync_excel_to_db(df, args.db, args.table)
        
        # Process dev status comments
        success_count, total_processed, updated_df = process_dev_status_comments(
            df, args.url, args.token, args.security_ticket_col, args.dev_status_col, args.dry_run
        )
        
        # Write updated data back to Excel
        info_log("Writing updated data to Excel file")
        updated_df.to_excel(args.excel, sheet_name=args.sheet, index=False)
        
        # Update database with comment information
        if args.db and not args.no_sync:
            info_log("Updating database with comment information...")
            update_database_with_comments(updated_df, args.db, args.table)
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 COMMENT SUMMARY")
        print("=" * 60)
        print(f"Total rows processed: {total_processed}")
        print(f"Comments added successfully: {success_count}")
        print(f"Comments failed to add: {total_processed - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no comments were actually added")
        else:
            print(f"✅ Comment update complete! {success_count}/{total_processed} comments added successfully")
            print(f"📊 Updated Excel file with comment status")
            if args.db and not args.no_sync:
                print(f"💾 Updated database with comment information")
        
    except Exception as e:
        error_log(f"Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 