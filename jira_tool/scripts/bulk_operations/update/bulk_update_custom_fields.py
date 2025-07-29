#!/usr/bin/env python3
"""
Bulk Update Custom Fields Script
Update custom fields for Jira tickets using ticket URLs from "Security Ticket" column of Excel.
Supports updating multiple custom fields based on Excel column data.
"""

import argparse
import pandas as pd
import requests
import os
import sys
from pathlib import Path

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))))
sys.path.append(parent_dir)
from core.headers import get_jira_headers
from core.urls import get_issue_url
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
            print(f"⚠️  No valid custom field values to update for {ticket_id}")
            return True
        
        response = requests.put(api_url, json=data, headers=headers, verify=False)
        
        if response.status_code == 204:
            print(f"✅ Successfully updated custom fields for {ticket_id}")
            return True
        else:
            print(f"❌ Failed to update custom fields for {ticket_id}: {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error updating custom fields for {ticket_id}: {str(e)}")
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
    
    print(f"📋 Found {len(filtered_df)} tickets with Security Ticket IDs")
    
    if len(filtered_df) == 0:
        print("ℹ️  No tickets to process - no rows with Security Ticket IDs")
        return 0, 0, df
    
    if not custom_field_mappings:
        print("⚠️  No custom field mappings provided - nothing to update")
        return 0, 0, df
    
    for idx, row in filtered_df.iterrows():
        total_processed += 1
        
        # Get ticket ID
        ticket_id = str(row[security_ticket_col]).strip()
        
        print(f"\n🔍 Processing row {idx + 2}: {ticket_id}")
        
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
            print(f"ℹ️  Skipping {ticket_id} - no valid custom field values")
            # Add row with skip info
            row_dict = row.to_dict()
            row_dict['custom_field_status'] = 'Skipped - No valid values'
            row_dict['updated_fields'] = ''
            row_dict['update_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_rows.append(row_dict)
            continue
        
        if dry_run:
            print(f"🔍 [DRY RUN] Would update custom fields for {ticket_id}:")
            for field in updated_fields:
                print(f"   - {field}")
            success_count += 1
            # Add row with dry run info
            row_dict = row.to_dict()
            row_dict['custom_field_status'] = 'Dry Run - Would Update'
            row_dict['updated_fields'] = ', '.join(updated_fields)
            row_dict['update_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
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
                row_dict['update_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
            else:
                # Keep original row if update failed
                row_dict = row.to_dict()
                row_dict['custom_field_status'] = 'Failed to update'
                row_dict['updated_fields'] = ', '.join(updated_fields)
                row_dict['update_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
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
    """Main function to handle bulk custom field updates."""
    
    parser = argparse.ArgumentParser(
        description="Update custom fields for Jira tickets using Security Ticket column",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update custom fields with default mappings
  python bulk_update_custom_fields.py --excel tickets.xlsx --url https://jira.company.com --token your_token
  
  # Update custom fields with custom mappings
  python bulk_update_custom_fields.py --excel tickets.xlsx --custom-fields "Risk Level:customfield_10002,Environment:customfield_10003" --url https://jira.company.com --token your_token
  
  # Dry run to see what would be updated
  python bulk_update_custom_fields.py --excel tickets.xlsx --dry-run --url https://jira.company.com --token your_token
  
  # Use configuration defaults
  python bulk_update_custom_fields.py --excel tickets.xlsx --use-config
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with ticket data")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--url", help="Jira base URL (defaults to config)")
    parser.add_argument("--token", help="Jira API token (defaults to config)")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name for Security Ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--custom-fields", help="Custom field mappings in format 'excel_col:field_id,excel_col2:field_id2'")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be updated without actually updating")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--use-config", action="store_true", help="Use configuration defaults for missing parameters")
    
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
        print("❌ Jira URL is required. Use --url or set JIRA_BASE_URL environment variable.")
        return
    if not args.token:
        print("❌ Jira token is required. Use --token or set JIRA_TOKEN environment variable.")
        return
    
    # Validate inputs
    if not os.path.exists(args.excel):
        print(f"❌ Excel file not found: {args.excel}")
        return
    
    print("🔧 Bulk Update Custom Fields Tool")
    print("=" * 50)
    print(f"Excel file: {args.excel}")
    print(f"Security Ticket column: {args.security_ticket_col}")
    print(f"Dry run: {args.dry_run}")
    print("=" * 50)
    
    try:
        # Read Excel file
        print(f"📖 Reading Excel file: {args.excel}")
        df = pd.read_excel(args.excel, sheet_name=args.sheet)
        
        # Validate required columns
        required_columns = [args.security_ticket_col]
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            print(f"❌ Missing required columns: {missing_columns}")
            print(f"Available columns: {list(df.columns)}")
            return
        
        print(f"📋 Found {len(df)} total rows in Excel file")
        
        # Get custom field mappings
        custom_field_mappings = {}
        if args.custom_fields:
            custom_field_mappings = parse_custom_field_mappings(args.custom_fields)
        else:
            # Use default custom fields from config
            custom_field_mappings = default_custom_fields
        
        if not custom_field_mappings:
            print("❌ No custom field mappings provided. Use --custom-fields or configure default mappings.")
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
        
        # Process custom field updates
        success_count, total_processed, updated_df = process_custom_field_updates(
            df, args.url, args.token, args.security_ticket_col, custom_field_mappings, args.dry_run
        )
        
        # Write updated data back to Excel
        print(f"\n💾 Writing updated data to Excel file")
        updated_df.to_excel(args.excel, sheet_name=args.sheet, index=False)
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 UPDATE SUMMARY")
        print("=" * 50)
        print(f"Total rows processed: {total_processed}")
        print(f"Custom fields updated successfully: {success_count}")
        print(f"Updates failed: {total_processed - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no custom fields were actually updated")
        else:
            print(f"✅ Custom field update complete! {success_count}/{total_processed} updates successful")
            print(f"📊 Updated Excel file with update status")
        
    except Exception as e:
        print(f"❌ Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 