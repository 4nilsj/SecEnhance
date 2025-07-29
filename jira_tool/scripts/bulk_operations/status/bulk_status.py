import argparse
import pandas as pd
import requests
import sys
import os

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.headers import get_jira_headers
from core.urls import get_issue_url


def get_jira_status(url, token, ticket_id):
    api_url = get_issue_url(url, ticket_id)
    headers = get_jira_headers(token)
    response = requests.get(api_url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        return data["fields"]["status"]["name"]
    else:
        print(f"Failed to get status for {ticket_id}: {response.status_code} {response.text}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Bulk get Jira ticket status from Excel.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--status_col", default="status", help="Column to write status")
    args = parser.parse_args()

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    statuses = []
    for idx, row in df.iterrows():
        ticket_id = row[args.id_col]
        status = get_jira_status(args.url, args.token, ticket_id)
        statuses.append(status)
    df[args.status_col] = statuses
    df.to_excel(args.excel, sheet_name=args.sheet, index=False)
    print(f"Fetched status for {len(statuses)} tickets. Status written to column '{args.status_col}'.")

if __name__ == "__main__":
    main() 