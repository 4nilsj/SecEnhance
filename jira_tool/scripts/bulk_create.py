import argparse
import pandas as pd
import requests


def create_jira_ticket(url, token, project_key, summary, description):
    api_url = f"{url}/rest/api/2/issue"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"}
        }
    }
    response = requests.post(api_url, json=data, headers=headers, verify=False)
    if response.status_code == 201:
        return response.json()["key"]
    else:
        print(f"Failed to create ticket: {response.status_code} {response.text}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Bulk create Jira tickets from Excel.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--project", required=True, help="Jira project key")
    parser.add_argument("--summary_col", default="summary", help="Column for summary")
    parser.add_argument("--desc_col", default="description", help="Column for description")
    parser.add_argument("--id_col", default="ticket_id", help="Column to write ticket IDs")
    args = parser.parse_args()

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    ticket_ids = []
    for idx, row in df.iterrows():
        summary = row[args.summary_col]
        description = row[args.desc_col]
        ticket_id = create_jira_ticket(args.url, args.token, args.project, summary, description)
        ticket_ids.append(ticket_id)
    df[args.id_col] = ticket_ids
    df.to_excel(args.excel, sheet_name=args.sheet, index=False)
    print(f"Created {len(ticket_ids)} tickets. Ticket IDs written to column '{args.id_col}'.")

if __name__ == "__main__":
    main() 