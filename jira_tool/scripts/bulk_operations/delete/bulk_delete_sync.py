import argparse
import pandas as pd
import requests
import os
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, delete_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log
from core.headers import get_jira_headers
from core.urls import get_issue_url

def delete_jira_ticket(url, token, ticket_id):
    api_url = get_issue_url(url, ticket_id)
    headers = get_jira_headers(token)
    try:
        response = requests.delete(api_url, headers=headers, verify=False)
        debug_log(f"Jira delete response for {ticket_id}: {response.status_code} {response.text}")
        if response.status_code == 204:
            return True
        else:
            error_log(f"Failed to delete {ticket_id}: {response.status_code} {response.text}")
            return False
    except Exception as e:
        error_log(f"Exception during Jira ticket delete for {ticket_id}", e)
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk delete Jira tickets and sync with Excel and SQLite.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
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

        to_delete = []
        for idx, row in df_excel.iterrows():
            ticket_id = row[args.id_col]
            success = delete_jira_ticket(args.url, args.token, ticket_id)
            if success:
                to_delete.append(ticket_id)
        for ticket_id in to_delete:
            df_excel = delete_row(df_excel, args.id_col, ticket_id)
            df_db = delete_row(df_db, args.id_col, ticket_id)
        sync_resources(df_excel, args.excel, args.db, args.table, args.sheet)
        print(f"Deleted {len(to_delete)} tickets from Jira, Excel, and DB.")
    except Exception as e:
        error_log("Exception in bulk_delete_sync main", e)

if __name__ == "__main__":
    main() 