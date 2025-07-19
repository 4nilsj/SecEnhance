# Jira Tool

This tool provides scripts for bulk creating, updating, commenting, transitioning, and attaching files to Jira tickets using data from Excel files, with full sync to a SQLite database for backup and recovery.

## Folder Structure

```
jira_tool/
│
├── scripts/                # All main CLI scripts (create, update, comment, etc.)
│   ├── bulk_create_sync.py
│   ├── bulk_update_sync.py
│   ├── bulk_comment_sync.py
│   ├── bulk_status_sync.py
│   ├── bulk_transition_sync.py
│   ├── bulk_attachment_sync.py
│   ├── bulk_delete_sync.py
│   ├── excel_to_sqlite.py
│   └── sync_excel_sqlite.py
│
├── utils/                  # All utility modules
│   ├── data_sync_utils.py
│   └── debug_utils.py
│
├── logs/                   # All log files
│   └── error.log
│
├── requirements.txt
├── README.md
└── sample_input.xlsx
```

## Quickstart

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Prepare your Excel file:**
   - Use `sample_input.xlsx` as a template.
   - Ensure columns like `summary`, `description`, and (for updates) `ticket_id` are present.

3. **Import Excel data into SQLite (optional, for backup/sync):**
   ```bash
   python scripts/excel_to_sqlite.py --excel sample_input.xlsx --sheet Sheet1 --db tickets.db --table tickets
   ```

4. **Run a script (example: bulk create):**
   ```bash
   python scripts/bulk_create_sync.py --excel sample_input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --project <PROJECT_KEY> --db tickets.db
   ```

5. **Check logs:**
   - All info, debug, and error logs are written to `logs/error.log`.
   - Use the `--debug` flag for verbose output and stack traces.

6. **Sync Excel and SQLite at any time:**
   ```bash
   python scripts/sync_excel_sqlite.py --excel sample_input.xlsx --sheet Sheet1 --db tickets.db --table tickets --direction sqlite_to_excel
   ```

## Usage Tips

- **Always back up your Excel and DB files** before running bulk operations.
- **Use the `--debug` flag** for troubleshooting; it provides detailed logs and stack traces.
- **Check `logs/error.log`** for a persistent record of all actions and errors.
- **Column names in Excel must match the script arguments** (e.g., `summary`, `description`, `ticket_id`).
- **For attachments,** ensure file names contain the ticket ID as a suffix (e.g., `QE-Evidence-ABC-123`).
- **If you add new columns to Excel,** they will be automatically handled and synced with SQLite.
- **Restore Excel from SQLite** if your Excel file is lost or corrupted using the sync script.
- **Review the README table** for script-specific usage examples and arguments.

---

## Features
- Bulk create Jira tickets from Excel
- Write created ticket IDs back to Excel and SQLite
- Bulk update ticket fields from Excel
- Bulk add comments to tickets from Excel
- Bulk fetch and update ticket status
- Bulk change ticket status (transition)
- Bulk upload attachments and update Evidence column
- Bulk delete tickets
- Full two-way sync between Excel and SQLite (backup/restore)
- All logs (info, debug, error) are written to `logs/error.log`

## Requirements
- Python 3.7+
- requests
- pandas
- openpyxl

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 📋 Script Summary Table

| Script Name                | Purpose                                                      | Key Arguments / Usage Example                                                                                   |
|----------------------------|--------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| **scripts/excel_to_sqlite.py**     | Import all Excel data into SQLite (initial setup)            | `python scripts/excel_to_sqlite.py --excel input.xlsx --sheet Sheet1 --db tickets.db --table tickets`            |
| **scripts/bulk_create_sync.py**    | Bulk create tickets, sync to Excel & SQLite                  | `python scripts/bulk_create_sync.py --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --project <KEY> --db tickets.db`         |
| **scripts/bulk_update_sync.py**    | Bulk update ticket fields, sync to Excel & SQLite            | `python scripts/bulk_update_sync.py --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --fields summary description ... --db tickets.db` |
| **scripts/bulk_comment_sync.py**   | Bulk add comments, sync to Excel & SQLite                    | `python scripts/bulk_comment_sync.py --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --comment_col comment --db tickets.db`   |
| **scripts/bulk_status_sync.py**    | Fetch ticket status, sync to Excel & SQLite                  | `python scripts/bulk_status_sync.py --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --status_col status --db tickets.db`     |
| **scripts/bulk_transition_sync.py**| Change ticket status, sync to Excel & SQLite                 | `python scripts/bulk_transition_sync.py --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --status_col new_status --db tickets.db` |
| **scripts/bulk_attachment_sync.py**| Upload attachments, update Evidence column, sync to both      | `python scripts/bulk_attachment_sync.py --dir ./attachments --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --db tickets.db`     |
| **scripts/bulk_delete_sync.py**    | Delete tickets in Jira, Excel, and SQLite                    | `python scripts/bulk_delete_sync.py --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --db tickets.db`                         |
| **scripts/sync_excel_sqlite.py**   | Restore/sync Excel from SQLite or vice versa                 | `python scripts/sync_excel_sqlite.py --excel input.xlsx --sheet Sheet1 --db tickets.db --table tickets --direction excel_to_sqlite`<br>or<br>`--direction sqlite_to_excel` |

--- 