#!/usr/bin/env python3
"""
Bulk Fetch Linked Tickets Script
Fetch linked tickets and their status using ticket URLs from "Security Ticket" column of Excel.
Updates Excel with linked ticket IDs in "dev ticket" column and status in "dev ticket status" column.
"""

import argparse
import pandas as pd
import requests
import os
import sys
import json
from pathlib import Path

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))))
sys.path.append(parent_dir)
from core.headers import get_jira_headers
from core.urls import get_issue_url
from config.settings import get_jira_config, get_column_mappings


def get_linked_issues(url, token, ticket_id):
    """
    Get linked issues for a Jira ticket.
    
    Args:
        url (str): Jira base URL
        token (str): Jira API token
        ticket_id (str): Ticket ID
        
    Returns:
        list: List of linked issues with their details
    """
    try:
        api_url = get_issue_url(url, ticket_id)
        headers = get_jira_headers(token)
        
        # Add expand parameter to get issue links
        api_url += "?expand=issuelinks"
        
        response = requests.get(api_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            linked_issues = []
            
            # Process outward links (this ticket links to others)
            if 'issuelinks' in data:
                for link in data['issuelinks']:
                    if 'outwardIssue' in link:
                        linked_issue = link['outwardIssue']
                        linked_issues.append({
                            'id': linked_issue['id'],
                            'key': linked_issue['key'],
                            'status': linked_issue['fields']['status']['name'],
                            'summary': linked_issue['fields']['summary'],
                            'link_type': link['type']['outward'],
                            'direction': 'outward'
                        })
            
            # Process inward links (other tickets link to this one)
            if 'issuelinks' in data:
                for link in data['issuelinks']:
                    if 'inwardIssue' in link:
                        linked_issue = link['inwardIssue']
                        linked_issues.append({
                            'id': linked_issue['id'],
                            'key': linked_issue['key'],
                            'status': linked_issue['fields']['status']['name'],
                            'summary': linked_issue['fields']['summary'],
                            'link_type': link['type']['inward'],
                            'direction': 'inward'
                        })
            
            return linked_issues
        else:
            print(f"❌ Failed to get linked issues for {ticket_id}: {response.status_code} {response.text}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting linked issues for {ticket_id}: {str(e)}")
        return []


def find_dev_ticket(linked_issues, dev_keywords=None):
    """
    Find the most likely dev ticket from linked issues.
    
    Args:
        linked_issues (list): List of linked issues
        dev_keywords (list): Keywords to identify dev tickets
        
    Returns:
        dict: Best matching dev ticket or None
    """
    if not linked_issues:
        return None
    
    # Default keywords for identifying dev tickets
    if dev_keywords is None:
        dev_keywords = ['dev', 'development', 'implementation', 'fix', 'bug', 'task', 'story']
    
    # Score each linked issue based on relevance
    scored_issues = []
    
    for issue in linked_issues:
        score = 0
        key_lower = issue['key'].lower()
        summary_lower = issue['summary'].lower()
        link_type_lower = issue['link_type'].lower()
        
        # Score based on key patterns
        if any(keyword in key_lower for keyword in dev_keywords):
            score += 10
        
        # Score based on summary keywords
        if any(keyword in summary_lower for keyword in dev_keywords):
            score += 5
        
        # Score based on link type
        if any(keyword in link_type_lower for keyword in dev_keywords):
            score += 3
        
        # Prefer outward links (this ticket links to dev ticket)
        if issue['direction'] == 'outward':
            score += 2
        
        # Prefer tickets with "dev" in the key
        if 'dev' in key_lower:
            score += 5
        
        scored_issues.append((score, issue))
    
    # Sort by score (highest first) and return the best match
    scored_issues.sort(key=lambda x: x[0], reverse=True)
    
    if scored_issues and scored_issues[0][0] > 0:
        return scored_issues[0][1]
    
    # If no clear dev ticket found, return the first linked issue
    return linked_issues[0] if linked_issues else None


def process_linked_tickets(df, url, token, security_ticket_col="Security Ticket", 
                          dev_ticket_col="dev ticket", dev_status_col="dev ticket status",
                          dev_keywords=None, dry_run=False):
    """
    Process Excel rows and fetch linked tickets for Security Tickets.
    
    Args:
        df (DataFrame): DataFrame containing ticket information
        url (str): Jira base URL
        token (str): Jira API token
        security_ticket_col (str): Column name containing Security Ticket IDs
        dev_ticket_col (str): Column name for dev ticket IDs
        dev_status_col (str): Column name for dev ticket status
        dev_keywords (list): Keywords to identify dev tickets
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
    
    for idx, row in filtered_df.iterrows():
        total_processed += 1
        
        # Get ticket ID
        ticket_id = str(row[security_ticket_col]).strip()
        
        print(f"\n🔍 Processing row {idx + 2}: {ticket_id}")
        
        if dry_run:
            print(f"🔍 [DRY RUN] Would fetch linked tickets for {ticket_id}")
            success_count += 1
            # Add row with dry run info
            row_dict = row.to_dict()
            row_dict[dev_ticket_col] = 'DRY_RUN'
            row_dict[dev_status_col] = 'DRY_RUN'
            row_dict['linked_tickets_found'] = 'DRY_RUN'
            row_dict['fetch_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
            updated_rows.append(row_dict)
        else:
            # Get linked issues
            linked_issues = get_linked_issues(url, token, ticket_id)
            
            if linked_issues:
                print(f"📎 Found {len(linked_issues)} linked issues for {ticket_id}")
                
                # Find the most likely dev ticket
                dev_ticket = find_dev_ticket(linked_issues, dev_keywords)
                
                if dev_ticket:
                    print(f"✅ Found dev ticket: {dev_ticket['key']} (Status: {dev_ticket['status']})")
                    
                    # Update row with dev ticket info
                    row_dict = row.to_dict()
                    row_dict[dev_ticket_col] = dev_ticket['key']
                    row_dict[dev_status_col] = dev_ticket['status']
                    row_dict['linked_tickets_found'] = len(linked_issues)
                    row_dict['dev_ticket_summary'] = dev_ticket['summary']
                    row_dict['dev_ticket_link_type'] = dev_ticket['link_type']
                    row_dict['fetch_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
                    updated_rows.append(row_dict)
                    
                    success_count += 1
                else:
                    print(f"⚠️  No suitable dev ticket found for {ticket_id}")
                    # Update row with no dev ticket info
                    row_dict = row.to_dict()
                    row_dict[dev_ticket_col] = 'No dev ticket found'
                    row_dict[dev_status_col] = 'N/A'
                    row_dict['linked_tickets_found'] = len(linked_issues)
                    row_dict['dev_ticket_summary'] = ''
                    row_dict['dev_ticket_link_type'] = ''
                    row_dict['fetch_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
                    updated_rows.append(row_dict)
            else:
                print(f"ℹ️  No linked issues found for {ticket_id}")
                # Update row with no linked issues info
                row_dict = row.to_dict()
                row_dict[dev_ticket_col] = 'No linked tickets'
                row_dict[dev_status_col] = 'N/A'
                row_dict['linked_tickets_found'] = 0
                row_dict['dev_ticket_summary'] = ''
                row_dict['dev_ticket_link_type'] = ''
                row_dict['fetch_date'] = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
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


def main():
    """Main function to handle bulk linked ticket fetching."""
    
    parser = argparse.ArgumentParser(
        description="Fetch linked tickets and their status using Security Ticket column",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch linked tickets with default settings
  python bulk_fetch_linked_tickets.py --excel tickets.xlsx --url https://jira.company.com --token your_token
  
  # Fetch with custom dev keywords
  python bulk_fetch_linked_tickets.py --excel tickets.xlsx --dev-keywords "dev,fix,implementation" --url https://jira.company.com --token your_token
  
  # Dry run to see what would be fetched
  python bulk_fetch_linked_tickets.py --excel tickets.xlsx --dry-run --url https://jira.company.com --token your_token
  
  # Use configuration defaults
  python bulk_fetch_linked_tickets.py --excel tickets.xlsx --use-config
        """
    )
    
    parser.add_argument("--excel", required=True, help="Excel file with ticket data")
    parser.add_argument("--sheet", default=0, help="Sheet name or index (default: 0)")
    parser.add_argument("--url", help="Jira base URL (defaults to config)")
    parser.add_argument("--token", help="Jira API token (defaults to config)")
    parser.add_argument("--security-ticket-col", default="Security Ticket", help="Column name for Security Ticket IDs (default: 'Security Ticket')")
    parser.add_argument("--dev-ticket-col", default="dev ticket", help="Column name for dev ticket IDs (default: 'dev ticket')")
    parser.add_argument("--dev-status-col", default="dev ticket status", help="Column name for dev ticket status (default: 'dev ticket status')")
    parser.add_argument("--dev-keywords", help="Comma-separated keywords to identify dev tickets (default: 'dev,development,implementation,fix,bug,task,story')")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be fetched without actually fetching")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--use-config", action="store_true", help="Use configuration defaults for missing parameters")
    
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
    if args.use_config or not args.dev_ticket_col:
        args.dev_ticket_col = args.dev_ticket_col or column_mappings.get("dev_ticket", "dev ticket")
    if args.use_config or not args.dev_status_col:
        args.dev_status_col = args.dev_status_col or column_mappings.get("dev_status", "dev ticket status")
    
    # Parse dev keywords
    dev_keywords = None
    if args.dev_keywords:
        dev_keywords = [kw.strip() for kw in args.dev_keywords.split(',')]
    else:
        dev_keywords = ['dev', 'development', 'implementation', 'fix', 'bug', 'task', 'story']
    
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
    
    print("🔧 Bulk Fetch Linked Tickets Tool")
    print("=" * 50)
    print(f"Excel file: {args.excel}")
    print(f"Security Ticket column: {args.security_ticket_col}")
    print(f"Dev ticket column: {args.dev_ticket_col}")
    print(f"Dev status column: {args.dev_status_col}")
    print(f"Dev keywords: {', '.join(dev_keywords)}")
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
        
        # Check for tickets with Security Ticket IDs
        has_security_ticket_count = len(df[df[args.security_ticket_col].notna() & (df[args.security_ticket_col].astype(str).str.strip() != "")])
        
        print(f"📊 Analysis:")
        print(f"   - Rows with Security Ticket IDs: {has_security_ticket_count}")
        print(f"   - Dev keywords: {len(dev_keywords)}")
        
        if args.debug:
            print("\n🔍 Sample data:")
            print(df[[args.security_ticket_col]].head())
        
        # Process linked ticket fetching
        success_count, total_processed, updated_df = process_linked_tickets(
            df, args.url, args.token, args.security_ticket_col, 
            args.dev_ticket_col, args.dev_status_col, dev_keywords, args.dry_run
        )
        
        # Write updated data back to Excel
        print(f"\n💾 Writing updated data to Excel file")
        updated_df.to_excel(args.excel, sheet_name=args.sheet, index=False)
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 FETCH SUMMARY")
        print("=" * 50)
        print(f"Total rows processed: {total_processed}")
        print(f"Dev tickets found: {success_count}")
        print(f"No dev tickets found: {total_processed - success_count}")
        
        if args.dry_run:
            print("🔍 This was a dry run - no linked tickets were actually fetched")
        else:
            print(f"✅ Linked ticket fetch complete! {success_count}/{total_processed} dev tickets found")
            print(f"📊 Updated Excel file with dev ticket information")
        
    except Exception as e:
        print(f"❌ Error processing Excel file: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main() 