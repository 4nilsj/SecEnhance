import argparse
import pandas as pd
import requests


def get_transition_id(url, token, ticket_id, target_status):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}/transitions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.get(api_url, headers=headers, verify=False)
    if response.status_code == 200:
        transitions = response.json().get("transitions", [])
        for t in transitions:
            if t["to"]["name"].lower() == target_status.lower():
                return t["id"]
    else:
        print(f"Failed to get transitions for {ticket_id}: {response.status_code} {response.text}")
    return None

def transition_ticket(url, token, ticket_id, transition_id):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}/transitions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {"transition": {"id": transition_id}}
    response = requests.post(api_url, json=data, headers=headers, verify=False)
    if response.status_code == 204:
        return True
    else:
        print(f"Failed to transition {ticket_id}: {response.status_code} {response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk update Jira ticket status from Excel.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--status_col", default="new_status", help="Column with desired status")
    args = parser.parse_args()

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    results = []
    for idx, row in df.iterrows():
        ticket_id = row[args.id_col]
        target_status = row[args.status_col]
        transition_id = get_transition_id(args.url, args.token, ticket_id, target_status)
        if transition_id:
            success = transition_ticket(args.url, args.token, ticket_id, transition_id)
            results.append("Success" if success else "Failed")
        else:
            print(f"No valid transition found for {ticket_id} to status '{target_status}'")
            results.append("No transition")
    df["transition_result"] = results
    df.to_excel(args.excel, sheet_name=args.sheet, index=False)
    print(f"Attempted status update for {len(df)} tickets. Results written to 'transition_result' column.")

if __name__ == "__main__":
    main() 