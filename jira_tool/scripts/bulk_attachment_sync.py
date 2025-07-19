import argparse
import os
import re
import pandas as pd
import requests
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite, update_row, sync_resources
from utils.debug_utils import set_debug, debug_log, error_log, safe_run, info_log

def extract_ticket_id(filename, pattern):
    match = re.search(pattern, filename)
    if match:
        return match.group(1)
    return None

def upload_attachment(url, token, ticket_id, file_path):
    api_url = f"{url}/rest/api/2/issue/{ticket_id}/attachments"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Atlassian-Token": "no-check"
    }
    try:
        files = {'file': open(file_path, 'rb')}
        response = requests.post(api_url, headers=headers, files=files, verify=False)
        files['file'].close()
        debug_log(f"Jira attachment response for {ticket_id}: {response.status_code} {response.text}")
        if response.status_code == 200 or response.status_code == 201:
            return True
        else:
            error_log(f"Failed to upload {os.path.basename(file_path)} to {ticket_id}: {response.status_code} {response.text}")
            return False
    except Exception as e:
        error_log(f"Exception during Jira attachment for {ticket_id}", e)
        return False

def main():
    parser = argparse.ArgumentParser(description="Upload attachments to Jira tickets, update Excel and SQLite.")
    parser.add_argument("--dir", required=True, help="Directory containing files to upload")
    parser.add_argument("--excel", required=True, help="Excel file with ticket IDs")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs in Excel")
    parser.add_argument("--evidence_col", default="Evidence", help="Column to write Evidence status")
    parser.add_argument("--pattern", default=r"([A-Z]+-\d+)$", help="Regex pattern to extract ticket ID from file name (default: Jira key at end)")
    parser.add_argument("--db", default="tickets.db", help="SQLite DB file path")
    parser.add_argument("--table", default="tickets", help="Table name in SQLite DB")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    set_debug(args.debug)

    try:
        ticket_file_map = {}
        for fname in os.listdir(args.dir):
            fpath = os.path.join(args.dir, fname)
            if os.path.isfile(fpath):
                ticket_id = extract_ticket_id(fname, args.pattern)
                if ticket_id:
                    ticket_file_map[ticket_id] = fpath

        df_excel = read_excel(args.excel, args.sheet)
        if os.path.exists(args.db):
            try:
                df_db = read_sqlite(args.db, args.table)
            except Exception:
                df_db = pd.DataFrame(columns=df_excel.columns)
        else:
            df_db = pd.DataFrame(columns=df_excel.columns)

        evidence = []
        for idx, row in df_excel.iterrows():
            ticket_id = str(row[args.id_col])
            file_path = ticket_file_map.get(ticket_id)
            if file_path:
                success = upload_attachment(args.url, args.token, ticket_id, file_path)
                ev = "Yes" if success else "No"
                df_db = update_row(df_db, args.id_col, ticket_id, {args.evidence_col: ev})
                df_excel = update_row(df_excel, args.id_col, ticket_id, {args.evidence_col: ev})
                evidence.append(ev)
            else:
                df_db = update_row(df_db, args.id_col, ticket_id, {args.evidence_col: "No"})
                df_excel = update_row(df_excel, args.id_col, ticket_id, {args.evidence_col: "No"})
                evidence.append("No")
        df_excel[args.evidence_col] = evidence
        sync_resources(df_excel, args.excel, args.db, args.table, args.sheet)
        print(f"Updated '{args.evidence_col}' column in {args.excel} and synced with DB for {len(df_excel)} tickets.")
    except Exception as e:
        error_log("Exception in bulk_attachment_sync main", e)

if __name__ == "__main__":
    main() 