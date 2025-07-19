import argparse
import pandas as pd
import requests
import os
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, add_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log


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
    try:
        response = requests.post(api_url, json=data, headers=headers, verify=False)
        debug_log(f"Jira create response: {response.status_code} {response.text}")
        if response.status_code == 201:
            return response.json()["key"]
        else:
            error_log(f"Failed to create ticket: {response.status_code} {response.text}")
            return None
    except Exception as e:
        error_log("Exception during Jira ticket creation", e)
        return None

def main():
    parser = argparse.ArgumentParser(description="Bulk create Jira tickets from Excel and sync with SQLite.")
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--project", required=True, help="Jira project key")
    parser.add_argument("--summary_col", default="summary", help="Column for summary")
    parser.add_argument("--desc_col", default="description", help="Column for description")
    parser.add_argument("--id_col", default="ticket_id", help="Column to write ticket IDs")
    parser.add_argument("--db", default="tickets.db", help="SQLite DB file path")
    parser.add_argument("--table", default="tickets", help="Table name in SQLite DB")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    set_debug(args.debug)
    info_log("Started bulk_create_sync script")

    try:
        info_log(f"Reading Excel: {args.excel}, sheet: {args.sheet}")
        df_excel = read_excel(args.excel, args.sheet)
        if os.path.exists(args.db):
            try:
                info_log(f"Reading SQLite DB: {args.db}, table: {args.table}")
                df_db = read_sqlite(args.db, args.table)
            except Exception:
                df_db = pd.DataFrame(columns=df_excel.columns)
        else:
            df_db = pd.DataFrame(columns=df_excel.columns)

        ticket_ids = []
        for idx, row in df_excel.iterrows():
            summary = row[args.summary_col]
            description = row[args.desc_col]
            info_log(f"Creating Jira ticket for row {idx+1}")
            ticket_id = create_jira_ticket(args.url, args.token, args.project, summary, description)
            ticket_ids.append(ticket_id)
            if ticket_id and (ticket_id not in df_db[args.id_col].values):
                row_dict = row.to_dict()
                row_dict[args.id_col] = ticket_id
                df_db = add_row(df_db, row_dict)
        df_excel[args.id_col] = ticket_ids
        info_log("Syncing resources (Excel and SQLite)")
        sync_resources(df_excel, args.excel, args.db, args.table, args.sheet)
        info_log("Completed bulk_create_sync script")
        print(f"Created {len(ticket_ids)} tickets. Ticket IDs written to column '{args.id_col}' and synced with DB.")
    except Exception as e:
        error_log("Exception in bulk_create_sync main", e)

if __name__ == "__main__":
    main() 