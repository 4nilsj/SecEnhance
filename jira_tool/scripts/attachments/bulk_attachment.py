import argparse
import os
import re
import requests
import sys

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.headers import get_jira_attachment_headers
from core.urls import get_issue_attachments_url


def extract_ticket_id(filename, pattern):
    match = re.search(pattern, filename)
    if match:
        return match.group(1)
    return None

def upload_attachment(url, token, ticket_id, file_path):
    api_url = get_issue_attachments_url(url, ticket_id)
    headers = get_jira_attachment_headers(token)
    files = {'file': open(file_path, 'rb')}
    response = requests.post(api_url, headers=headers, files=files, verify=False)
    files['file'].close()
    if response.status_code == 200 or response.status_code == 201:
        print(f"Uploaded {os.path.basename(file_path)} to {ticket_id}")
        return True
    else:
        print(f"Failed to upload {os.path.basename(file_path)} to {ticket_id}: {response.status_code} {response.text}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Bulk upload attachments to Jira tickets based on file name suffix.")
    parser.add_argument("--dir", required=True, help="Directory containing files to upload")
    parser.add_argument("--url", required=True, help="Jira base URL")
    parser.add_argument("--token", required=True, help="Jira API token")
    parser.add_argument("--pattern", default=r"([A-Z]+-\d+)$", help="Regex pattern to extract ticket ID from file name (default: Jira key at end)")
    args = parser.parse_args()

    for fname in os.listdir(args.dir):
        fpath = os.path.join(args.dir, fname)
        if os.path.isfile(fpath):
            ticket_id = extract_ticket_id(fname, args.pattern)
            if ticket_id:
                upload_attachment(args.url, args.token, ticket_id, fpath)
            else:
                print(f"No ticket ID found in file name: {fname}")

if __name__ == "__main__":
    main() 