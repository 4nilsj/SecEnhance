#!/usr/bin/env python3
"""
Bulk Create True Positive Tickets Script (Sync Version)
Create Jira tickets only for rows where status is "true positive" and Security Ticket column is empty.
Updates the Excel file and SQLite database with newly created ticket IDs.
"""

import argparse
import pandas as pd
import requests
import os
import sys
import urllib.parse
import sqlite3
from pathlib import Path

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))))
sys.path.append(parent_dir)
from core.headers import get_jira_headers
from core.urls import get_create_issue_url
from config.settings import (
    get_jira_config, get_custom_fields, get_column_mappings,
    get_issue_type_config, get_priority_config, get_labels_config, 
    get_custom_field_12200_config, get_ticket_creation_config
)
from utils.data_sync_utils import sync_excel_to_db, sync_db_to_excel


def get_db_connection(db_path):
    """
    Get a connection to the SQLite database.
    
    Args:
        db_path (str): Path to the SQLite database
        
    Returns:
        sqlite3.Connection: Database connection
    """
    try:
        conn = sqlite3.connect(db_path)
        return conn
    except Exception as e:
        print(f"❌ Error connecting to database: {str(e)}")
        raise


def info_log(message):
    """Log informational message."""
    print(f"ℹ️  {message}")


def success_log(message):
    """Log success message."""
    print(f"✅ {message}")


def error_log(message):
    """Log error message."""
    print(f"❌ {message}")


def url_encode_text(text):
    """
    URL encode text for safe transmission.
    
    Args:
        text (str): Text to encode
        
    Returns:
        str: URL encoded text
    """
    if not text or pd.isna(text):
        return ""
    return urllib.parse.quote(str(text).strip(), safe='')


def create_formatted_description(row):
    """
    Create a formatted description from Excel row data.
    
    Args:
        row: Pandas Series containing the row data
        
    Returns:
        str: URL encoded formatted description
    """
    try:
        # Get column mappings
        column_mappings = get_column_mappings()
        
        # Extract values with fallbacks
        description_value = str(row.get(column_mappings.get("description", "Description"), ""))
        file_name = str(row.get(column_mappings.get("file_name_fullpath", "File Name (FullPath)"), ""))
        line_numbers = str(row.get(column_mappings.get("line_numbers", "Line Number(s)"), ""))
        severity = str(row.get(column_mappings.get("severity", "Severity"), ""))
        impact = str(row.get(column_mappings.get("impact", "Impact"), ""))
        code_snippet = str(row.get(column_mappings.get("vulnerable_code_snippet", "Vulnerable Code Snippet"), ""))
        fix = str(row.get(column_mappings.get("potential_fix", "Potential Fix(Text+Code)"), ""))
        more_info = str(row.get(column_mappings.get("more_info", "More Info"), ""))
        
        # Create formatted description
        description_parts = [
            f"{description_value}",
            "",
            f"**File Name:** {file_name}",
            "",
            f"**Line Numbers:** {line_numbers}",
            "",
            f"**Severity:** {severity}",
            "",
            f"**Impact:** {impact}",
            "",
            f"**Code Snippet:** {code_snippet}",
            "",
            f"**Fix:** {fix}",
            "",
            f"**More Info:** {more_info}"
        ]
        
        # Join with three newlines between each section
        formatted_description = "\n\n\n".join(description_parts)
        
        # URL encode the entire description
        return url_encode_text(formatted_description)
        
    except Exception as e:
        print(f"❌ Error formatting description: {str(e)}")
        return url_encode_text("Error formatting description")


def create_jira_ticket(url, token, project_key, summary, description, issue_type=None, priority=None, assignee=None, labels=None):
    """
    Create a Jira ticket with the given parameters.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        project_key (str): Jira project key
        summary (str): Ticket summary (URL encoded)
        description (str): Ticket description (formatted with URL encoded values)
        issue_type (str): Type of issue (defaults to config)
        priority (str): Priority level (defaults to config)
        assignee (str): Username of assignee (optional)
        labels (list): List of labels to add (defaults to config)
        
    Returns:
        dict: Response data if successful, None if failed
    """
    try:
        api_url = get_create_issue_url(url)
        headers = get_jira_headers(token)
        
        # Get configuration values
        config = get_ticket_creation_config()
        issue_type_config = config["issue_type"]
        priority_config = config["priority"]
        labels_config = config["labels"]
        custom_field_value = config["custom_field_12200"]
        
        # Use provided values or defaults from config
        issue_type = issue_type or issue_type_config["name"]
        priority = priority or priority_config
        labels = labels or labels_config
        
        data = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
                "labels": labels,
                "customfield_12200": {"value": custom_field_value}  # Mandatory custom field
            }
        }
        
        if assignee:
            data["fields"]["assignee"] = {"name": assignee}
        
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        
        if response.status_code == 201:
            ticket_data = response.json()
            print(f"✅ Successfully created ticket: {ticket_data['key']}")
            print(f"   Labels: {labels}")
            print(f"   Priority: {priority}")
            print(f"   Issue Type: {issue_type}")
            print(f"   Custom Field: {custom_field_value}")
            return ticket_data
        else:
            print(f"❌ Failed to create ticket: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Error creating ticket: {str(e)}")
        return None


def process_true_positive_tickets(df, url, token, project_key, status_col="status", security_ticket_col="Security Ticket", 
                                vulnerability_name_col="Vulnerability Name", issue_type="Bug", 
                                priority="High", assignee_col=None, labels=None, dry_run=False):
    """
    Process Excel rows and create tickets only for true positive findings with empty Security Ticket.
    
    Args:
        df (DataFrame): DataFrame containing ticket information
        url (str): Jira base URL
        token (str): Jira API token
        project_key (str): Jira project key
        status_col (str): Column name containing status
        security_ticket_col (str): Column name for Security Ticket IDs
        vulnerability_name_col (str): Column name for Vulnerability Name (used for summary)
        issue_type (str): Default issue type
        priority (str): Default priority
        assignee_col (str): Column name for assignee (optional)
        labels (list): List of labels to add to tickets (optional)
        dry_run (bool): If True, only show what would be created
        
    Returns:
        tuple: (success_count, total_processed, updated_df)
    """
    success_count = 0
    total_processed = 0
    updated_rows = []
    
    # Filter for true positive findings with empty Security Ticket
    true_positive_mask = df[status_col].str.lower().str.strip() == "true positive"
    empty_security_mask = df[security_ticket_col].isna() | (df[security_ticket_col].astype(str).str.strip() == "")
    
    filtered_df = df[true_positive_mask & empty_security_mask].copy()
    
    print(f"📋 Found {len(filtered_df)} true positive findings with empty Security Ticket")
    
    if len(filtered_df) == 0:
        print("ℹ️  No tickets to create - all true positive findings already have Security Ticket IDs")
        return 0, 0, df
    
    for idx, row in filtered_df.iterrows():
        total_processed += 1
        
        # Get vulnerability name for summary (URL encoded)
        vulnerability_name = str(row.get(vulnerability_name_col, "True Positive Finding")).strip()
        summary = url_encode_text(vulnerability_name)
        
        # Create formatted description with URL encoded values
        description = create_formatted_description(row)
        
        priority = str(row.get("priority", priority)).strip()
        issue_type = str(row.get("issue_type", issue_type)).strip()
        assignee = str(row.get(assignee_col, "")).strip() if assignee_col and assignee_col in row else None
        
        # Get labels from row or use defaults
        row_labels = labels or ["security", "vulnerability", "true-positive"]
        if "labels" in row and not pd.isna(row["labels"]) and str(row["labels"]).strip():
            # If labels column exists and has value, use it
            row_labels = str(row["labels"]).strip().split(",")
            row_labels = [label.strip() for label in row_labels if label.strip()]
        
        print(f"\n🔍 Processing row {idx + 2}: {vulnerability_name[:50]}...")
        print(f"   Summary (URL encoded): {summary}")
        print(f"   Description length: {len(description)} characters")
        print(f"   Labels: {row_labels}")
        
        if dry_run:
            print(f"🔍 [DRY RUN] Would create ticket:")
            print(f"   Summary: {summary}")
            print(f"   Description: {description[:200]}...")
            print(f"   Priority: {priority}")
            print(f"   Type: {issue_type}")
            print(f"   Labels: {row_labels}")
            if assignee:
                print(f"   Assignee: {assignee}")
            success_count += 1
            # Add row with dry run info
            row_dict = row.to_dict()
            row_dict[security_ticket_col] = f"[DRY RUN] Would create ticket"
            row_dict['ticket_creation_status'] = 'Dry Run - Would Create'
            updated_rows.append(row_dict)
        else:
            # Create the ticket
            ticket_data = create_jira_ticket(
                url, token, project_key, summary, description, 
                issue_type, priority, assignee, row_labels
            )
            
            if ticket_data:
                ticket_id = ticket_data['key']
                success_count += 1
                
                # Update row with ticket ID
                row_dict = row.to_dict()
                row_dict[security_ticket_col] = ticket_id
                row_dict['ticket_creation_status'] = f'Created: {ticket_id}'
                row_dict['ticket_creation_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
                updated_rows.append(row_dict)
            else:
                # Keep original row if creation failed
                row_dict = row.to_dict()
                row_dict['ticket_creation_status'] = 'Failed to create'
                row_dict['ticket_creation_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
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


def update_database_with_tickets(df, db_path, table_name="findings"):
    """
    Update SQLite database with ticket creation results.
    
    Args:
        df (DataFrame): Updated DataFrame with ticket IDs
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
        new_columns = ['ticket_creation_status', 'ticket_creation_date']
        for col in new_columns:
            if col not in existing_columns:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {col} TEXT")
                info_log(f"Added column '{col}' to database table")
        
        # Update database with ticket information
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
        success_log("Database updated successfully with ticket information")
        return True
        
    except Exception as e:
        error_log(f"Error updating database: {str(e)}")
        return False


def main():
    """Main function to handle bulk creation of true positive tickets with sync."""
    
    parser = argparse.ArgumentParser(
        description="Create Jira tickets only for true positive findings with empty Security Ticket column (with Excel/DB sync)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create tickets for true positive findings with sync
  python bulk_create_true_positive_sync.py --excel findings.xlsx --project SEC --url https://jira.company.com --token your_token
  
  # Create tickets with custom column names and sync
  python bulk_create_true_positive_sync.py --excel findings.xlsx --project SEC --status-col "finding_status" --security-ticket-col "Jira_Ticket" --url https://jira.company.com --token your_token
  
  # Dry run to see what would be created
  python bulk_create_true_positive_sync.py --excel findings.xlsx --project SEC --dry-run --url https://jira.company.com --token your_token
  
  # Create tickets with specific issue type and priority
  python bulk_create_true_positive_sync.py --excel findings.xlsx --project SEC --issue-type "Bug" --priority "High" --url https://jira.company.com --token your_token
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with findings data")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--project", help="Jira project key (defaults to config)")
    parser.add_argument("--url", help="Jira base URL (defaults to config)")
    parser.add_argument("--token", help="Jira API token (defaults to config)")
    parser.add_argument("--status-col", help="Column name containing status (defaults to config)")
    parser.add_argument("--security-ticket-col", help="Column name for Security Ticket IDs (defaults to config)")
    parser.add_argument("--vulnerability-name-col", help="Column name for Vulnerability Name (defaults to config)")
    parser.add_argument("--assignee-col", help="Column name for assignee (optional)")
    parser.add_argument("--issue-type", default="Bug", help="Default issue type (default: Bug)")
    parser.add_argument("--priority", default="High", help="Default priority (default: High)")
    parser.add_argument("--labels", help="Comma-separated labels to add to tickets (default: security,vulnerability,true-positive)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be created without actually creating")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--use-config", action="store_true", help="Use configuration defaults for missing parameters")
    parser.add_argument("--db-path", help="SQLite database path (defaults to config)")
    parser.add_argument("--table-name", default="findings", help="Database table name (default: findings)")
    parser.add_argument("--no-sync", action="store_true", help="Skip Excel/DB synchronization")
    
    args = parser.parse_args()
    
    # Get configuration defaults
    config = get_jira_config()
    column_mappings = get_column_mappings()
    custom_fields = get_custom_fields()
    
    # Use config defaults if --use-config is specified or if parameters are missing
    if args.use_config or not args.url:
        args.url = args.url or config.get("base_url")
    if args.use_config or not args.token:
        args.token = args.token or config.get("token")
    if args.use_config or not args.project:
        args.project = args.project or config.get("project_key")
    if args.use_config or not args.status_col:
        args.status_col = args.status_col or column_mappings.get("status", "status")
    if args.use_config or not args.security_ticket_col:
        args.security_ticket_col = args.security_ticket_col or column_mappings.get("security_ticket", "Security Ticket")
    if args.use_config or not args.vulnerability_name_col:
        args.vulnerability_name_col = args.vulnerability_name_col or column_mappings.get("vulnerability_name", "Vulnerability Name")
    
    # Parse labels
    labels = None
    if args.labels:
        labels = [label.strip() for label in args.labels.split(",") if label.strip()]
    else:
        labels = ["security", "vulnerability", "true-positive"]
    
    # Validate required parameters
    if not args.url:
        print("❌ Jira URL is required. Use --url or set JIRA_BASE_URL environment variable.")
        return
    if not args.token:
        print("❌ Jira token is required. Use --token or set JIRA_TOKEN environment variable.")
        return
    if not args.project:
        print("❌ Project key is required. Use --project or set JIRA_PROJECT_KEY environment variable.")
        return
    
    # Validate inputs
    if not os.path.exists(args.excel):
        print(f"❌ Excel file not found: {args.excel}")
        return
    
    print("🔧 Bulk Create True Positive Tickets Tool (Sync Version)")
    print("=" * 60)
    print(f"Excel file: {args.excel}")
    print(f"Project key: {args.project}")
    print(f"Status column: {args.status_col}")
    print(f"Security Ticket column: {args.security_ticket_col}")
    print(f"Vulnerability Name column: {args.vulnerability_name_col}")
    if args.assignee_col:
        print(f"Assignee column: {args.assignee_col}")
    print(f"Issue type: {args.issue_type}")
    print(f"Priority: {args.priority}")
    print(f"Labels: {labels}")
    print(f"Dry run: {args.dry_run}")
    print(f"Sync enabled: {not args.no_sync}")
    print("=" * 60)
    
    try:
        # Read Excel file
        print(f"📖 Reading Excel file: {args.excel}")
        df = pd.read_excel(args.excel, sheet_name=args.sheet)
        
        # Validate required columns
        required_columns = [args.status_col, args.security_ticket_col, args.vulnerability_name_col]
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            print(f"❌ Missing required columns: {missing_columns}")
            print(f"Available columns: {list(df.columns)}")
            return
        
        if args.assignee_col and args.assignee_col not in df.columns:
            print(f"⚠️  Assignee column '{args.assignee_col}' not found, will not assign tickets")
            args.assignee_col = None
        
        print(f"📋 Found {len(df)} total rows in Excel file")
        
        # Check for true positive findings
        true_positive_count = len(df[df[args.status_col].str.lower().str.strip() == "true positive"])
        empty_security_count = len(df[df[args.security_ticket_col].isna() | (df[args.security_ticket_col].astype(str).str.strip() == "")])
        
        print(f"📊 Analysis:")
        print(f"   - True positive findings: {true_positive_count}")
        print(f"   - Rows with empty Security Ticket: {empty_security_count}")
        
        if args.debug:
            print("\n🔍 Sample data:")
            print(df[[args.status_col, args.security_ticket_col, args.vulnerability_name_col]].head())
        
        # Process true positive tickets
        success_count, total_processed, updated_df = process_true_positive_tickets(
            df, args.url, args.token, args.project, args.status_col, args.security_ticket_col,
            args.vulnerability_name_col, args.issue_type, args.priority, 
            args.assignee_col, labels, args.dry_run
        )
        
        # Sync with database if enabled
        if not args.no_sync and args.db_path:
            print(f"\n🔄 Syncing with database: {args.db_path}")
            try:
                # Sync Excel to database
                sync_excel_to_db(args.excel, args.db_path, args.table_name)
                print("✅ Excel data synced to database")
                
                # Update database with ticket information
                update_database_with_tickets(updated_df, args.db_path, args.table_name)
                
                # Sync database back to Excel
                sync_db_to_excel(args.db_path, args.excel, args.table_name)
                print("✅ Database synced back to Excel")
                
            except Exception as e:
                print(f"⚠️  Database sync failed: {str(e)}")
                print("📊 Continuing with Excel-only update...")
        
        # Write updated data back to Excel
        print(f"\n💾 Writing updated data to Excel file")
        updated_df.to_excel(args.excel, sheet_name=args.sheet, index=False)
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 CREATION SUMMARY")
        print("=" * 60)
        print(f"Total rows processed: {total_processed}")
        print(f"Tickets created successfully: {success_count}")
        print(f"Tickets failed to create: {total_processed - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no tickets were actually created")
        else:
            print(f"✅ Creation complete! {success_count}/{total_processed} tickets created successfully")
            print(f"📊 Updated Excel file with new ticket IDs")
            if not args.no_sync and args.db_path:
                print(f"🔄 Database synchronized successfully")
        
    except Exception as e:
        print(f"❌ Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 