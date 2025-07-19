import argparse
import os
import re
import pandas as pd
import requests
import sqlite3
from datetime import datetime


def extract_ticket_id(filename, pattern):
    match = re.search(pattern, filename)
    if match:
        return match.group(1)
    return None

def upload_attachment(url, token, ticket_id, file_path):
    api_url = f"{url}/rest/api/latest/issue/{ticket_id}/attachments"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Atlassian-Token": "no-check"
    }
    files = {'file': open(file_path, 'rb')}
    response = requests.post(api_url, headers=headers, files=files, verify=False)
    files['file'].close()
    if response.status_code == 200 or response.status_code == 201:
        return True
    else:
        return False

def log_to_db(db_path, ticket_id, file_name, evidence, timestamp):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attachment_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT,
                    file_name TEXT,
                    evidence TEXT,
                    timestamp TEXT
                )''')
    c.execute('''INSERT INTO attachment_log (ticket_id, file_name, evidence, timestamp)
                 VALUES (?, ?, ?, ?)''', (ticket_id, file_name, evidence, timestamp))
    conn.commit()
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Upload attachments to Jira tickets, update Excel, and log to SQLite DB.")
    parser.add_argument("--dir", required=True, help="Directory containing files to upload")
    parser.add_argument("--excel", required=True, help="Excel file with ticket IDs")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--id_col", default="ticket_id", help="Column with ticket IDs in Excel")
    parser.add_argument("--evidence_col", default="Evidence", help="Column to write Evidence status")
    parser.add_argument("--pattern", default=r"([A-Z]+-\d+)$", help="Regex pattern to extract ticket ID from file name (default: Jira key at end)")
    parser.add_argument("--db", default="attachment_log.db", help="SQLite DB file path")
    args = parser.parse_args()

    # Map ticket_id to file path
    ticket_file_map = {}
    for fname in os.listdir(args.dir):
        fpath = os.path.join(args.dir, fname)
        if os.path.isfile(fpath):
            ticket_id = extract_ticket_id(fname, args.pattern)
            if ticket_id:
                ticket_file_map[ticket_id] = fpath

    df = pd.read_excel(args.excel, sheet_name=args.sheet)
    evidence = []
    for idx, row in df.iterrows():
        ticket_id = str(row[args.id_col])
        file_path = ticket_file_map.get(ticket_id)
        now = datetime.now().isoformat()
        if file_path:
            success = upload_attachment(args.url, args.token, ticket_id, file_path)
            ev = "Yes" if success else "No"
            log_to_db(args.db, ticket_id, os.path.basename(file_path), ev, now)
            evidence.append(ev)
        else:
            log_to_db(args.db, ticket_id, None, "No", now)
            evidence.append("No")
    df[args.evidence_col] = evidence
    df.to_excel(args.excel, sheet_name=args.sheet, index=False)
    print(f"Updated '{args.evidence_col}' column in {args.excel} and logged to {args.db} for {len(df)} tickets.")

if __name__ == "__main__":
    main() 