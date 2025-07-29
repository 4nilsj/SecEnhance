#!/usr/bin/env python3
"""
Bulk Update Custom Fields Script (Sync Version)
Update custom fields for Jira tickets using ticket URLs from "Security Ticket" column of Excel.
Supports updating multiple custom fields based on Excel column data.
Updates both Excel file and SQLite database with update status.
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
from core.urls import get_issue_url
from utils.data_sync_utils import sync_excel_to_db, sync_db_to_excel, get_db_connection, error_log, info_log, success_log
from config.settings import get_jira_config, get_custom_fields, get_column_mappings


def update_jira_custom_fields(url, token, ticket_id, custom_field_updates):
    """
    Update custom fields for a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Ticket ID
        custom_field_updates (dict): Dictionary of custom field updates {field_id: value}
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        api_url = get_issue_url(url, ticket_id)
        headers = get_jira_headers(token)
        
        # Prepare the update data
        data = {"fields": {}}
        
        for field_id, value in custom_field_updates.items():
            if value is not None and str(value).strip() != "":
                data["fields"][field_id] = value
        
        if not data["fields"]:
            info_log(f"No valid custom field values to update for {ticket_id}")
            return True
        
        response = requests.put(api_url, json=data, headers=headers, verify=False)
        
        if response.status_code == 204:
            success_log(f"Successfully updated custom fields for {ticket_id}")
            return True
        else:
            error_log(f"Failed to update custom fields for {ticket_id}: {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        error_log(f"Error updating custom fields for {ticket_id}: {str(e)}")
        return False


def process_custom_field_updates(df, url, token, security_ticket_col="Security Ticket", 
                               custom_field_mappings=None, dry_run=False):
    """
    Process Excel rows and update custom fields for tickets.
    
    Args:
        df (DataFrame): DataFrame containing ticket information
        url (str): Jira base URL
        token (str): Jira API token
        security_ticket_col (str): Column name containing Security Ticket IDs
        custom_field_mappings (dict): Mapping of Excel columns to custom field IDs
        dry_run (bool): If True, only show what would be done
        
    Returns:
        tuple: (success_count, total_processed, updated_df)
    """
    success_count = 0
    total_processed = 0
    updated_rows = []
    
    # Filter for rows with Security Ticket IDs
    has_security_ticket = df[security_ticket_col].notna() & (df[security_ticket_col].astype(str).str.strip() != "")
    filtered_df = df[has_security_ticket].copy()
    
    info_log(f"Found {len(filtered_df)} tickets with Security Ticket IDs")
    
    if len(filtered_df) == 0:
        info_log("No tickets to process - no rows with Security Ticket IDs")
        return 0, 0, df
    
    if not custom_field_mappings:
        info_log("No custom field mappings provided - nothing to update")
        return 0, 0, df
    
    for idx, row in filtered_df.iterrows():
        total_processed += 1
        
        # Get ticket ID
        ticket_id = str(row[security_ticket_col]).strip()
        
        info_log(f"Processing row {idx + 2}: {ticket_id}")
        
        # Prepare custom field updates
        custom_field_updates = {}
        updated_fields = []
        
        for excel_column, custom_field_id in custom_field_mappings.items():
            if excel_column in row and pd.notna(row[excel_column]):
                value = row[excel_column]
                if str(value).strip() != "":
                    custom_field_updates[custom_field_id] = value
                    updated_fields.append(f"{excel_column}: {value}")
        
        if not custom_field_updates:
            info_log(f"Skipping {ticket_id} - no valid custom field values")
            # Add row with skip info
            row_dict = row.to_dict()
            row_dict['custom_field_status'] = 'Skipped - No valid values'
            row_dict['updated_fields'] = ''
            row_dict['update_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_rows.append(row_dict)
            continue
        
        if dry_run:
            info_log(f"[DRY RUN] Would update custom fields for {ticket_id}:")
            for field in updated_fields:
                info_log(f"   - {field}")
            success_count += 1
            # Add row with dry run info
            row_dict = row.to_dict()
            row_dict['custom_field_status'] = 'Dry Run - Would Update'
            row_dict['updated_fields'] = ', '.join(updated_fields)
            row_dict['update_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_rows.append(row_dict)
        else:
            # Update the custom fields
            success = update_jira_custom_fields(url, token, ticket_id, custom_field_updates)
            
            if success:
                success_count += 1
                # Update row with success info
                row_dict = row.to_dict()
                row_dict['custom_field_status'] = f'Updated: {len(updated_fields)} fields'
                row_dict['updated_fields'] = ', '.join(updated_fields)
                row_dict['update_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
            else:
                # Keep original row if update failed
                row_dict = row.to_dict()
                row_dict['custom_field_status'] = 'Failed to update'
                row_dict['updated_fields'] = ', '.join(updated_fields)
                row_dict['update_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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


def update_database_with_custom_fields(df, db_path, table_name="tickets"):
    """
    Update SQLite database with custom field update results.
    
    Args:
        df (DataFrame): Updated DataFrame with custom field status
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
        new_columns = ['custom_field_status', 'updated_fields', 'update_date']
        for col in new_columns:
            if col not in existing_columns:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col} TEXT")
                info_log(f"Added column '{col}' to database table")
        
        # Update database with custom field information
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
        success_log("Database updated successfully with custom field information")
        return True
        
    except Exception as e:
        error_log(f"Error updating database: {str(e)}")
        return False


def parse_custom_field_mappings(mapping_string):
    """
    Parse custom field mappings from string format.
    
    Args:
        mapping_string (str): String in format "excel_col:field_id,excel_col2:field_id2"
        
    Returns:
        dict: Mapping of Excel columns to custom field IDs
    """
    if not mapping_string:
        return {}
    
    mappings = {}
    for mapping in mapping_string.split(','):
        if ':' in mapping:
            excel_col, field_id = mapping.split(':', 1)
            mappings[excel_col.strip()] = field_id.strip()
    
    return mappings


def main():
    """Main function to handle bulk custom field updates with sync."""
    
    parser = argparse.ArgumentParser(
        description="Update custom fields for Jira tickets using Security Ticket column (with Excel/DB sync)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update custom fields with default mappings and sync
  python bulk_update_custom_fields_sync.py --excel tickets.xlsx --url https://jira.company.com --token your_token --db tickets.db
  
  # Update custom fields with custom mappings and sync
  python bulk_update_custom_fields_sync.py --excel tickets.xlsx --custom-fields "Risk Level:customfield_10002,Environment:customfield_10003" --url https://jira.company.com --token your_token --db tickets.db
  
  # Dry run to see what would be updated
  python bulk_update_custom_fields_sync.py --excel tickets.xlsx --dry-run --url https://jira.company.com --token your_token --db tickets.db
  
  # Use configuration defaults
  python bulk_update_custom_fields_sync.py --excel tickets.xlsx --use-config --db tickets.db
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with ticket data")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--url", help="Jira base URL (defaults to config)")
    parser.add_argument("--token", help="Jira API token (defaults to config)")
    parser.add_argument("--db", help="SQLite database file for sync (optional)")
    parser.add_argument("--table", default="tickets", help="Database table name (default: tickets)")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name for Security Ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--custom-fields", help="Custom field mappings in format 'excel_col:field_id,excel_col2:field_id2'")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be updated without actually updating")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--use-config", action="store_true", help="Use configuration defaults for missing parameters")
    parser.add_argument("--no-sync", action="store_true", help="Skip database synchronization")
    
    args = parser.parse_args()
    
    # Get configuration defaults
    config = get_jira_config()
    column_mappings = get_column_mappings()
    default_custom_fields = get_custom_fields()
    
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
    
    print("🔧 Bulk Update Custom Fields Tool (Sync Version)")
    print("=" * 60)
    print(f"Excel file: {args.excel}")
    print(f"Security Ticket column: {args.security_ticket_col}")
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
        required_columns = [args.security_ticket_col]
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            error_log(f"Missing required columns: {missing_columns}")
            print(f"Available columns: {list(df.columns)}")
            return
        
        info_log(f"Found {len(df)} total rows in Excel file")
        
        # Get custom field mappings
        custom_field_mappings = {}
        if args.custom_fields:
            custom_field_mappings = parse_custom_field_mappings(args.custom_fields)
        else:
            # Use default custom fields from config
            custom_field_mappings = default_custom_fields
        
        if not custom_field_mappings:
            error_log("No custom field mappings provided. Use --custom-fields or configure default mappings.")
            return
        
        print(f"📊 Custom field mappings:")
        for excel_col, field_id in custom_field_mappings.items():
            print(f"   {excel_col} -> {field_id}")
        
        # Check for tickets with Security Ticket IDs
        has_security_ticket_count = len(df[df[args.security_ticket_col].notna() & (df[args.security_ticket_col].astype(str).str.strip() != "")])
        
        print(f"📊 Analysis:")
        print(f"   - Rows with Security Ticket IDs: {has_security_ticket_count}")
        print(f"   - Custom field mappings: {len(custom_field_mappings)}")
        
        if args.debug:
            print("\n🔍 Sample data:")
            print(df[[args.security_ticket_col] + list(custom_field_mappings.keys())].head())
        
        # Sync Excel to database if database is provided
        if args.db and not args.no_sync:
            info_log("Syncing Excel data to database...")
            sync_excel_to_db(df, args.db, args.table)
        
        # Process custom field updates
        success_count, total_processed, updated_df = process_custom_field_updates(
            df, args.url, args.token, args.security_ticket_col, custom_field_mappings, args.dry_run
        )
        
        # Write updated data back to Excel
        info_log("Writing updated data to Excel file")
        updated_df.to_excel(args.excel, sheet_name=args.sheet, index=False)
        
        # Update database with custom field information
        if args.db and not args.no_sync:
            info_log("Updating database with custom field information...")
            update_database_with_custom_fields(updated_df, args.db, args.table)
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 UPDATE SUMMARY")
        print("=" * 60)
        print(f"Total rows processed: {total_processed}")
        print(f"Custom fields updated successfully: {success_count}")
        print(f"Updates failed: {total_processed - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no custom fields were actually updated")
        else:
            print(f"✅ Custom field update complete! {success_count}/{total_processed} updates successful")
            print(f"📊 Updated Excel file with update status")
            if args.db and not args.no_sync:
                print(f"💾 Updated database with custom field information")
        
    except Exception as e:
        error_log(f"Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 