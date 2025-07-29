import argparse
import pandas as pd
import requests
import os
import sys

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, update_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log
from core.headers import get_jira_headers
from core.urls import get_issue_url

def get_jira_status(url, token, ticket_id):
    api_url = get_issue_url(url, ticket_id)
    headers = get_jira_headers(token)
    try:
        response = requests.get(api_url, headers=headers, verify=False)
        debug_log(f"Jira status response for {ticket_id}: {response.status_code} {response.text}")
        if response.status_code == 200:
            data = response.json()
            return data["fields"]["status"]["name"]
        else:
            error_log(f"Failed to get status for {ticket_id}: {response.status_code} {response.text}")
            return None
    except Exception as e:
        error_log(f"Exception during Jira status fetch for {ticket_id}", e)
        return None

def main():
    parser = argparse.ArgumentParser(description="Bulk get Jira ticket status from Excel and sync with SQLite.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--status_col", default="status", help="Column to write status")
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

        statuses = []
        for idx, row in df_excel.iterrows():
            ticket_id = row[args.id_col]
            status = get_jira_status(args.url, args.token, ticket_id)
            statuses.append(status)
            df_db = update_row(df_db, args.id_col, ticket_id, {args.status_col: status})
            df_excel = update_row(df_excel, args.id_col, ticket_id, {args.status_col: status})
        df_excel[args.status_col] = statuses
        sync_resources(df_excel, args.excel, args.db, args.table, args.sheet)
        print(f"Fetched status for {len(statuses)} tickets. Status written to column '{args.status_col}' and synced with DB.")
    except Exception as e:
        error_log("Exception in bulk_status_sync main", e)

if __name__ == "__main__":
    main() 