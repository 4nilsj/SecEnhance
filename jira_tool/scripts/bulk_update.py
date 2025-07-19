import argparse
import pandas as pd
import requests


def update_jira_ticket(url, token, ticket_id, fields):
    api_url = f"{url}/rest/api/2/issue/{ticket_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {"fields": fields}
    response = requests.put(api_url, json=data, headers=headers, verify=False)
    if response.status_code == 204:
        return True
    else:
        print(f"Failed to update {ticket_id}: {response.status_code} {response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk update Jira tickets from Excel.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--fields", nargs='+', required=True, help="Columns to update in Jira")
    args = parser.parse_args()

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    for idx, row in df.iterrows():
        ticket_id = row[args.id_col]
        fields = {field: row[field] for field in args.fields}
        update_jira_ticket(args.url, args.token, ticket_id, fields)
    print(f"Updated {len(df)} tickets.")

if __name__ == "__main__":
    main() 