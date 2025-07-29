#!/usr/bin/env python3
"""
Bulk Transition Security Workflow Script (Sync Version)
Transition tickets through the security workflow: New->Analysing->Refining->Refined Backlog->Inprogress
Uses ticket URLs from "Security Ticket" column of Excel.
Updates both Excel file and SQLite database with transition status.
"""

import argparse
import pandas as pd
import requests
import os
import sys
import json
import sqlite3
from pathlib import Path
from datetime import datetime

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))))
sys.path.append(parent_dir)
from core.headers import get_jira_headers
from core.urls import get_issue_url, get_issue_transitions_url
from utils.data_sync_utils import sync_excel_to_db, sync_db_to_excel, get_db_connection, error_log, info_log, success_log
from config.settings import get_jira_config, get_column_mappings


def get_available_transitions(url, token, ticket_id):
    """
    Get available transitions for a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Ticket ID
        
    Returns:
        list: List of available transitions
    """
    try:
        api_url = get_issue_transitions_url(url, ticket_id)
        headers = get_jira_headers(token)
        
        response = requests.get(api_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            transitions = []
            
            for transition in data.get('transitions', []):
                transitions.append({
                    'id': transition['id'],
                    'name': transition['name'],
                    'to': transition['to']['name']
                })
            
            return transitions
        else:
            error_log(f"Failed to get transitions for {ticket_id}: {response.status_code} {response.text}")
            return []
            
    except Exception as e:
        error_log(f"Error getting transitions for {ticket_id}: {str(e)}")
        return []


def transition_ticket(url, token, ticket_id, target_status):
    """
    Transition a Jira ticket to a specific status.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Ticket ID
        target_status (str): Target status name
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get available transitions
        transitions = get_available_transitions(url, token, ticket_id)
        
        if not transitions:
            info_log(f"No transitions available for {ticket_id}")
            return False
        
        # Find the transition that leads to target status
        target_transition = None
        for transition in transitions:
            if transition['to'].lower() == target_status.lower():
                target_transition = transition
                break
        
        if not target_transition:
            info_log(f"No transition found to '{target_status}' for {ticket_id}")
            info_log(f"Available transitions: {[t['to'] for t in transitions]}")
            return False
        
        # Perform the transition
        api_url = get_issue_transitions_url(url, ticket_id)
        headers = get_jira_headers(token)
        
        data = {
            "transition": {
                "id": target_transition['id']
            }
        }
        
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        
        if response.status_code == 204:
            success_log(f"Successfully transitioned {ticket_id} to '{target_status}'")
            return True
        else:
            error_log(f"Failed to transition {ticket_id} to '{target_status}': {response.status_code} {response.text}")
            return False
            
    except Exception as e:
        error_log(f"Error transitioning {ticket_id}: {str(e)}")
        return False


def get_ticket_status(url, token, ticket_id):
    """
    Get current status of a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Ticket ID
        
    Returns:
        str: Current status or None if error
    """
    try:
        api_url = get_issue_url(url, ticket_id)
        headers = get_jira_headers(token)
        
        response = requests.get(api_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            return data['fields']['status']['name']
        else:
            error_log(f"Failed to get status for {ticket_id}: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        error_log(f"Error getting status for {ticket_id}: {str(e)}")
        return None


def determine_next_status(current_status):
    """
    Determine the next status in the security workflow.
    
    Args:
        current_status (str): Current status
        
    Returns:
        str: Next status in workflow or None if at end
    """
    workflow = ["New", "Analysing", "Refining", "Refined Backlog", "Inprogress"]
    
    try:
        current_index = workflow.index(current_status)
        if current_index < len(workflow) - 1:
            return workflow[current_index + 1]
        else:
            return None
    except ValueError:
        # If current status is not in workflow, start from beginning
        return workflow[0]


def process_security_transitions(df, url, token, security_ticket_col="Security Ticket", 
                               dry_run=False):
    """
    Process Excel rows and transition security tickets through workflow.
    
    Args:
        df (DataFrame): DataFrame containing ticket information
        url (str): Jira base URL
        token (str): Jira API token
        security_ticket_col (str): Column name containing Security Ticket IDs
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
    
    for idx, row in filtered_df.iterrows():
        total_processed += 1
        
        # Get ticket ID
        ticket_id = str(row[security_ticket_col]).strip()
        
        info_log(f"Processing row {idx + 2}: {ticket_id}")
        
        if dry_run:
            info_log(f"[DRY RUN] Would check and transition {ticket_id}")
            success_count += 1
            # Add row with dry run info
            row_dict = row.to_dict()
            row_dict['current_status'] = 'DRY_RUN'
            row_dict['next_status'] = 'DRY_RUN'
            row_dict['transition_status'] = 'DRY_RUN'
            row_dict['transition_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_rows.append(row_dict)
        else:
            # Get current status
            current_status = get_ticket_status(url, token, ticket_id)
            
            if current_status is None:
                error_log(f"Could not get status for {ticket_id}")
                # Add row with error info
                row_dict = row.to_dict()
                row_dict['current_status'] = 'Error getting status'
                row_dict['next_status'] = 'N/A'
                row_dict['transition_status'] = 'Failed'
                row_dict['transition_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
                continue
            
            info_log(f"Current status: {current_status}")
            
            # Determine next status
            next_status = determine_next_status(current_status)
            
            if next_status is None:
                info_log(f"{ticket_id} is already at the end of workflow ({current_status})")
                # Add row with end of workflow info
                row_dict = row.to_dict()
                row_dict['current_status'] = current_status
                row_dict['next_status'] = 'End of workflow'
                row_dict['transition_status'] = 'No transition needed'
                row_dict['transition_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
                continue
            
            info_log(f"Target status: {next_status}")
            
            # Perform transition
            success = transition_ticket(url, token, ticket_id, next_status)
            
            if success:
                success_count += 1
                # Add row with success info
                row_dict = row.to_dict()
                row_dict['current_status'] = current_status
                row_dict['next_status'] = next_status
                row_dict['transition_status'] = 'Success'
                row_dict['transition_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
            else:
                # Add row with failure info
                row_dict = row.to_dict()
                row_dict['current_status'] = current_status
                row_dict['next_status'] = next_status
                row_dict['transition_status'] = 'Failed'
                row_dict['transition_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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


def update_database_with_transitions(df, db_path, table_name="tickets"):
    """
    Update SQLite database with transition information.
    
    Args:
        df (DataFrame): Updated DataFrame with transition information
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
        new_columns = ['current_status', 'next_status', 'transition_status', 'transition_date']
        for col in new_columns:
            if col not in existing_columns:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col} TEXT")
                info_log(f"Added column '{col}' to database table")
        
        # Update database with transition information
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
        success_log("Database updated successfully with transition information")
        return True
        
    except Exception as e:
        error_log(f"Error updating database: {str(e)}")
        return False


def main():
    """Main function to handle bulk security workflow transitions with sync."""
    
    parser = argparse.ArgumentParser(
        description="Transition security tickets through workflow: New->Analysing->Refining->Refined Backlog->Inprogress (with Excel/DB sync)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Transition security tickets with sync
  python bulk_transition_security_workflow_sync.py --excel tickets.xlsx --url https://jira.company.com --token your_token --db tickets.db
  
  # Dry run to see what would be transitioned
  python bulk_transition_security_workflow_sync.py --excel tickets.xlsx --dry-run --url https://jira.company.com --token your_token --db tickets.db
  
  # Use configuration defaults
  python bulk_transition_security_workflow_sync.py --excel tickets.xlsx --use-config --db tickets.db
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with ticket data")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--url", help="Jira base URL (defaults to config)")
    parser.add_argument("--token", help="Jira API token (defaults to config)")
    parser.add_argument("--db", help="SQLite database file for sync (optional)")
    parser.add_argument("--table", default="tickets", help="Database table name (default: tickets)")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name for Security Ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be transitioned without actually transitioning")
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
    
    print("🔧 Bulk Security Workflow Transition Tool (Sync Version)")
    print("=" * 70)
    print(f"Excel file: {args.excel}")
    print(f"Security Ticket column: {args.security_ticket_col}")
    print(f"Workflow: New -> Analysing -> Refining -> Refined Backlog -> Inprogress")
    if args.db:
        print(f"Database: {args.db}")
        print(f"Table: {args.table}")
    print(f"Dry run: {args.dry_run}")
    print(f"Sync enabled: {not args.no_sync}")
    print("=" * 70)
    
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
        
        # Check for tickets with Security Ticket IDs
        has_security_ticket_count = len(df[df[args.security_ticket_col].notna() & (df[args.security_ticket_col].astype(str).str.strip() != "")])
        
        print(f"📊 Analysis:")
        print(f"   - Rows with Security Ticket IDs: {has_security_ticket_count}")
        
        if args.debug:
            print("\n🔍 Sample data:")
            print(df[[args.security_ticket_col]].head())
        
        # Sync Excel to database if database is provided
        if args.db and not args.no_sync:
            info_log("Syncing Excel data to database...")
            sync_excel_to_db(df, args.db, args.table)
        
        # Process security transitions
        success_count, total_processed, updated_df = process_security_transitions(
            df, args.url, args.token, args.security_ticket_col, args.dry_run
        )
        
        # Write updated data back to Excel
        info_log("Writing updated data to Excel file")
        updated_df.to_excel(args.excel, sheet_name=args.sheet, index=False)
        
        # Update database with transition information
        if args.db and not args.no_sync:
            info_log("Updating database with transition information...")
            update_database_with_transitions(updated_df, args.db, args.table)
        
        # Summary
        print("\n" + "=" * 70)
        print("📊 TRANSITION SUMMARY")
        print("=" * 70)
        print(f"Total rows processed: {total_processed}")
        print(f"Transitions successful: {success_count}")
        print(f"Transitions failed: {total_processed - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no transitions were actually performed")
        else:
            print(f"✅ Security workflow transitions complete! {success_count}/{total_processed} transitions successful")
            print(f"📊 Updated Excel file with transition status")
            if args.db and not args.no_sync:
                print(f"💾 Updated database with transition information")
        
    except Exception as e:
        error_log(f"Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 