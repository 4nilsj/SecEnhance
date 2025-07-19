import argparse
import pandas as pd
import requests
import os
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, update_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log

def add_jira_comment(url, token, ticket_id, comment):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}/comment"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {"body": comment}
    try:
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        debug_log(f"Jira comment response for {ticket_id}: {response.status_code} {response.text}")
        if response.status_code == 201:
            return True
        else:
            error_log(f"Failed to comment on {ticket_id}: {response.status_code} {response.text}")
            return False
    except Exception as e:
        error_log(f"Exception during Jira comment for {ticket_id}", e)
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk add comments to Jira tickets from Excel and sync with SQLite.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs")
    parser.add_argument("--comment_col", default="comment", help="Column with comments")
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

        for idx, row in df_excel.iterrows():
            ticket_id = row[args.id_col]
            comment = row[args.comment_col]
            success = add_jira_comment(args.url, args.token, ticket_id, comment)
            if success:
                df_db = update_row(df_db, args.id_col, ticket_id, {args.comment_col: comment})
                df_excel = update_row(df_excel, args.id_col, ticket_id, {args.comment_col: comment})
        sync_resources(df_excel, args.excel, args.db, args.table, args.sheet)
        print(f"Added comments and synced with DB.")
    except Exception as e:
        error_log("Exception in bulk_comment_sync main", e)

if __name__ == "__main__":
    main() 