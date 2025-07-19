import argparse
import pandas as pd
import requests


def get_jira_linked_status(url, token, ticket_id):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.get(api_url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        links = data["fields"].get("issuelinks", [])
        linked_ids = []
        linked_statuses = []
        for link in links:
            if "outwardIssue" in link:
                linked = link["outwardIssue"]
            elif "inwardIssue" in link:
                linked = link["inwardIssue"]
            else:
                continue
            linked_id = linked["key"]
            linked_ids.append(linked_id)
            # Fetch status of linked ticket
            status = get_jira_status(url, token, linked_id)
            linked_statuses.append(f"{linked_id}:{status}")
        return ",".join(linked_ids), ",".join(linked_statuses)
    else:
        print(f"Failed to get links for {ticket_id}: {response.status_code} {response.text}")
        return None, None

def get_jira_status(url, token, ticket_id):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.get(api_url, headers=headers, verify=False)
    if response.status_code == 200:
        data = response.json()
        return data["fields"]["status"]["name"]
    else:
        return None

def main():
    parser = argparse.ArgumentParser(description="Bulk get linked Jira tickets and their status from Excel.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--linked_col", default="linked_tickets", help="Column to write linked ticket IDs")
    parser.add_argument("--linked_status_col", default="linked_statuses", help="Column to write linked ticket statuses")
    args = parser.parse_args()

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    linked_ids_list = []
    linked_statuses_list = []
    for idx, row in df.iterrows():
        ticket_id = row[args.id_col]
        linked_ids, linked_statuses = get_jira_linked_status(args.url, args.token, ticket_id)
        linked_ids_list.append(linked_ids)
        linked_statuses_list.append(linked_statuses)
    df[args.linked_col] = linked_ids_list
    df[args.linked_status_col] = linked_statuses_list
    df.to_excel(args.excel, sheet_name=args.sheet, index=False)
    print(f"Fetched linked tickets and statuses for {len(df)} tickets. Results written to columns '{args.linked_col}' and '{args.linked_status_col}'.")

if __name__ == "__main__":
    main() 