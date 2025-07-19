import argparse
import pandas as pd
import requests
import os
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, update_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log

def get_transition_id(url, token, ticket_id, target_status):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}/transitions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(api_url, headers=headers, verify=False)
        debug_log(f"Jira transitions response for {ticket_id}: {response.status_code} {response.text}")
        if response.status_code == 200:
            transitions = response.json().get("transitions", [])
            for t in transitions:
                if t["to"]["name"].lower() == target_status.lower():
                    return t["id"]
        else:
            error_log(f"Failed to get transitions for {ticket_id}: {response.status_code} {response.text}")
    except Exception as e:
        error_log(f"Exception during Jira transition fetch for {ticket_id}", e)
    return None

def transition_ticket(url, token, ticket_id, transition_id):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}/transitions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {"transition": {"id": transition_id}}
    try:
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        debug_log(f"Jira transition response for {ticket_id}: {response.status_code} {response.text}")
        if response.status_code == 204:
            return True
        else:
            error_log(f"Failed to transition {ticket_id}: {response.status_code} {response.text}")
            return False
    except Exception as e:
        error_log(f"Exception during Jira transition for {ticket_id}", e)
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk update Jira ticket status from Excel and sync with SQLite.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--status_col", default="new_status", help="Column with desired status")
    parser.add_argument("--db", default="tickets.db", help="SQLite DB file path")
    parser.add_argument("--table", default="tickets", help="Table name in SQLite DB")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    set_debug(args.debug)

    try:
        df_excel = read_excel(args.excel, args.sheet)
        if os.path.exists(args.db):
            try:
                df_db = read_sqlite(args.db, args.table)
            except Exception:
                df_db = pd.DataFrame(columns=df_excel.columns)
        else:
            df_db = pd.DataFrame(columns=df_excel.columns)

        results = []
        for idx, row in df_excel.iterrows():
            ticket_id = row[args.id_col]
            target_status = row[args.status_col]
            transition_id = get_transition_id(args.url, args.token, ticket_id, target_status)
            if transition_id:
                success = transition_ticket(args.url, args.token, ticket_id, transition_id)
                result = "Success" if success else "Failed"
                df_db = update_row(df_db, args.id_col, ticket_id, {args.status_col: target_status, "transition_result": result})
                df_excel = update_row(df_excel, args.id_col, ticket_id, {args.status_col: target_status, "transition_result": result})
            else:
                error_log(f"No valid transition found for {ticket_id} to status '{target_status}'")
                df_db = update_row(df_db, args.id_col, ticket_id, {"transition_result": "No transition"})
                df_excel = update_row(df_excel, args.id_col, ticket_id, {"transition_result": "No transition"})
            results.append(df_excel.loc[idx, "transition_result"])
        sync_resources(df_excel, args.excel, args.db, args.table, args.sheet)
        print(f"Attempted status update for {len(df_excel)} tickets. Results written to 'transition_result' column and synced with DB.")
    except Exception as e:
        error_log("Exception in bulk_transition_sync main", e)

if __name__ == "__main__":
    main() 