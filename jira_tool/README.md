# Jira Tool

This tool provides scripts and a web interface for bulk creating, updating, commenting, transitioning, and attaching files to Jira tickets using data from Excel files, with full sync to a SQLite database for backup and recovery.

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
├── jira_tool.py            # Unified CLI entry point (Typer-based)
├── web_app.py              # Streamlit web interface
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

4. **Run operations via the unified CLI:**
   ```bash
   python jira_tool.py create --excel sample_input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --project <PROJECT_KEY> --db tickets.db
   python jira_tool.py update --excel sample_input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --fields summary description --db tickets.db
   # ... and so on for other subcommands (see below)
   ```

5. **Or use the web interface:**
   ```bash
   # Easy launcher
   python launch_web.py
   
   # Or directly with streamlit
   streamlit run web/app.py
   ```
   - Upload your Excel file, select operation, enter parameters, and view logs/results in the browser.
   - The web interface provides access to ALL features including bulk operations, single operations, file management, and status monitoring.

6. **Check logs:**
   - All info, debug, and error logs are written to `logs/error.log`.
   - Use the `--debug` flag for verbose output and stack traces.

7. **Sync Excel and SQLite at any time:**
   ```bash
   python jira_tool.py sync --excel sample_input.xlsx --sheet Sheet1 --db tickets.db --table tickets --direction sqlite_to_excel
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
- **All scripts are accessible via the unified CLI (`jira_tool.py`) or the web UI (`web_app.py`).**

---

## 📋 Script Summary Table

| CLI Command / Script                | Purpose                                                      | Key Arguments / Usage Example                                                                                   |
|-------------------------------------|--------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| **jira_tool.py create**             | Bulk create tickets, sync to Excel & SQLite                  | `python jira_tool.py create --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --project <KEY> --db tickets.db`         |
| **jira_tool.py true-positive**      | Create tickets only for true positive findings with empty Security Ticket | `python jira_tool.py true-positive --excel findings.xlsx --project SEC --status-col status --security-ticket-col "Security Ticket" --url <JIRA_URL> --token <API_TOKEN>` |
| **jira_tool.py update**             | Bulk update ticket fields, sync to Excel & SQLite            | `python jira_tool.py update --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --fields summary description ... --db tickets.db` |
| **jira_tool.py custom-fields**      | Update custom fields for tickets using Security Ticket column | `python jira_tool.py custom-fields --excel tickets.xlsx --custom-fields "Risk Level:customfield_10002,Environment:customfield_10003" --url <JIRA_URL> --token <API_TOKEN>` |
| **jira_tool.py comment**            | Bulk add comments, sync to Excel & SQLite                    | `python jira_tool.py comment --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --comment_col comment --db tickets.db`   |
| **jira_tool.py dev-status-comment** | Add comments based on dev ticket status (Acceptance = "QE Testing in Dev Completed") | `python jira_tool.py dev-status-comment --excel tickets.xlsx --security-ticket-col "Security Ticket" --dev-status-col "dev ticket status" --url <JIRA_URL> --token <API_TOKEN>` |
| **jira_tool.py status**              | Bulk fetch ticket status, sync to Excel & SQLite              | `python jira_tool.py status --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --status-columns status priority --db tickets.db` |
| **jira_tool.py fetch-linked-tickets** | Fetch linked tickets and their status using Security Ticket column | `python jira_tool.py fetch-linked-tickets --excel tickets.xlsx --dev-keywords "dev,fix,implementation" --url <JIRA_URL> --token <API_TOKEN>` |
| **jira_tool.py transition**            | Bulk transition ticket status, sync to Excel & SQLite              | `python jira_tool.py transition --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --status "In Progress" --db tickets.db` |
| **jira_tool.py security-workflow**     | Transition security tickets: New→Analysing→Refining→Refined Backlog→Inprogress | `python jira_tool.py security-workflow --excel tickets.xlsx --url <JIRA_URL> --token <API_TOKEN>` |
| **jira_tool.py dev-workflow**          | Transition dev tickets: Inprogress→Review→Acceptance→Done (with validation) | `python jira_tool.py dev-workflow --excel tickets.xlsx --url <JIRA_URL> --token <API_TOKEN>` |
| **jira_tool.py attach**                | Upload attachments, update Evidence column, sync to both      | `python jira_tool.py attach --dir ./attachments --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --db tickets.db`     |
| **jira_tool.py poc-upload**         | Upload POC files based on Security Ticket column              | `python jira_tool.py poc-upload --excel security_tickets.xlsx --poc-dir ./poc_files --url <JIRA_URL> --token <API_TOKEN> --db tickets.db` |
| **jira_tool.py delete**             | Delete tickets in Jira, Excel, and SQLite                    | `python jira_tool.py delete --excel input.xlsx --sheet Sheet1 --url <JIRA_URL> --token <API_TOKEN> --db tickets.db`                         |
| **jira_tool.py sync**               | Restore/sync Excel from SQLite or vice versa                 | `python jira_tool.py sync --excel input.xlsx --sheet Sheet1 --db tickets.db --table tickets --direction excel_to_sqlite`<br>or<br>`--direction sqlite_to_excel` |
| **web/app.py**                      | Complete web interface for all operations                   | `python launch_web.py` or `streamlit run web/app.py` (use browser UI)                                          |

---

## GitHub & Branch Info

- This project is versioned with Git and pushed to GitHub.
- Main development is on the `security-tools` branch. To merge to `main`, open a pull request or merge locally and push.
- To push changes:
  ```bash
  git add jira_tool
  git commit -m "Describe your change"
  git push origin security-tools
  ```

--- 