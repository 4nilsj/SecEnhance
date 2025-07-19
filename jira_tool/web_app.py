import streamlit as st
import subprocess
from pathlib import Path
import os

st.set_page_config(page_title="Jira Tool Web UI", layout="wide")

SCRIPTS_DIR = Path(__file__).parent / "scripts"
LOG_FILE = Path(__file__).parent / "logs" / "error.log"

st.title("Jira Tool Web Interface")

# Sidebar: Operation selection and parameters
st.sidebar.header("Bulk Operation")
operation = st.sidebar.selectbox(
    "Select Operation",
    [
        "Create Tickets",
        "Update Tickets",
        "Add Comments",
        "Fetch Status",
        "Transition Status",
        "Attach Files",
        "Delete Tickets",
        "Sync Excel/DB"
    ]
)

st.sidebar.header("Jira Connection")
jira_url = st.sidebar.text_input("Jira URL", "http://your-jira-server")
jira_token = st.sidebar.text_input("Jira API Token", type="password")
project_key = st.sidebar.text_input("Project Key (for create)")

st.sidebar.header("Excel File")
uploaded_file = st.sidebar.file_uploader("Upload Excel file", type=["xlsx"])
sheet_name = st.sidebar.text_input("Sheet Name", "Sheet1")

# Additional parameters
st.sidebar.header("Other Parameters")
db_file = st.sidebar.text_input("SQLite DB File", "tickets.db")

# File upload handling
excel_path = None
if uploaded_file:
    excel_path = Path("uploaded_" + uploaded_file.name)
    with open(excel_path, "wb") as f:
        f.write(uploaded_file.read())
    st.success(f"Uploaded file saved as {excel_path}")

# Operation argument builder
def build_args():
    args = []
    if excel_path:
        args += ["--excel", str(excel_path)]
    if sheet_name:
        args += ["--sheet", sheet_name]
    if jira_url:
        args += ["--url", jira_url]
    if jira_token:
        args += ["--token", jira_token]
    if db_file:
        args += ["--db", db_file]
    if project_key and operation == "Create Tickets":
        args += ["--project", project_key]
    return args

# Main operation trigger
if st.sidebar.button("Run Operation"):
    if not excel_path:
        st.error("Please upload an Excel file.")
    else:
        op_map = {
            "Create Tickets": "bulk_create_sync.py",
            "Update Tickets": "bulk_update_sync.py",
            "Add Comments": "bulk_comment_sync.py",
            "Fetch Status": "bulk_status_sync.py",
            "Transition Status": "bulk_transition_sync.py",
            "Attach Files": "bulk_attachment_sync.py",
            "Delete Tickets": "bulk_delete_sync.py",
            "Sync Excel/DB": "sync_excel_sqlite.py"
        }
        script = op_map[operation]
        args = build_args()
        cmd = ["python", str(SCRIPTS_DIR / script)] + args
        st.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        st.code(result.stdout)
        if result.stderr:
            st.error(result.stderr)
        # Show log file
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8") as logf:
                logs = logf.read()
            st.subheader("Log Output (error.log)")
            st.text_area("Logs", logs, height=200)

# Manual ticket management (future: forms for single create/update/comment/attach)
st.header("Manual Ticket Management (Coming Soon)")
st.info("This section will allow you to create, update, comment, or attach files to individual tickets via forms.") 