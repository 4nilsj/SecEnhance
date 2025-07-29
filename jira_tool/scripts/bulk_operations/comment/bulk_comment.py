import argparse
import pandas as pd
import requests
import sys
import os

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.headers import get_jira_headers
from core.urls import get_issue_comment_url


def add_jira_comment(url, token, ticket_id, comment):
    api_url = get_issue_comment_url(url, ticket_id)
    headers = get_jira_headers(token)
    data = {"body": comment}
    response = requests.post(api_url, json=data, headers=headers, verify=False)
    if response.status_code == 201:
        return True
    else:
        print(f"Failed to comment on {ticket_id}: {response.status_code} {response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk add comments to Jira tickets from Excel.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--comment_col", default="comment", help="Column with comments")
    args = parser.parse_args()

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    for idx, row in df.iterrows():
        ticket_id = row[args.id_col]
        comment = row[args.comment_col]
        add_jira_comment(args.url, args.token, ticket_id, comment)
    print(f"Added comments to {len(df)} tickets.")

if __name__ == "__main__":
    main() 