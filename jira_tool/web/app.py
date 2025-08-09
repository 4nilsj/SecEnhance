import streamlit as st
import subprocess
import sys
import os
from pathlib import Path
import pandas as pd
import tempfile
import json

# Python version check - ensure Python 3.8+
def check_python_version():
    """Check if running on Python 3.8 or higher."""
    if sys.version_info < (3, 8):
        st.error("❌ This application requires Python 3.8 or higher!")
        st.error(f"Current version: {sys.version}")
        st.error("Please upgrade your Python installation.")
        st.stop()
    else:
        st.success(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected")

# Check Python version on startup
check_python_version()

# Generic import setup - works on any system
def setup_imports():
    """Set up import paths for the current script."""
    current_script = Path(__file__).resolve()
    project_root = find_project_root(current_script)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root

def find_project_root(start_path):
    """Find the project root by looking for jira_tool.py."""
    current_dir = start_path.parent
    while current_dir != current_dir.parent:  # Stop at root
        if (current_dir / "jira_tool.py").exists():
            return str(current_dir)
        current_dir = current_dir.parent
    return str(start_path.parent.parent)

setup_imports()

from core.headers import get_jira_headers, get_jira_attachment_headers
from core.urls import get_create_issue_url, get_issue_url, get_issue_comment_url, get_issue_transitions_url, get_issue_attachments_url
from config.settings import get_jira_config

st.set_page_config(
    page_title="Jira Tool - Complete Web Interface",
    page_icon="🔧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .feature-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown('<h1 class="main-header">🔧 Jira Tool - Complete Web Interface</h1>', unsafe_allow_html=True)

# Sidebar configuration
st.sidebar.header("🔧 Configuration")

# Configuration tabs
config_tab, bulk_tab, single_tab, docs_tab = st.sidebar.tabs(["⚙️ Config", "📊 Bulk Ops", "🎯 Single Ops", "📚 Docs"])

with config_tab:
    st.subheader("Jira Connection")
    
    # Get current config
    config = get_jira_config()
    
    jira_url = st.text_input(
        "Jira Base URL",
        value=config.get("base_url", "https://www.examplejira.com"),
        help="Your Jira instance URL (e.g., https://company.atlassian.net)"
    )
    
    jira_token = st.text_input(
        "Jira API Token",
        value=config.get("token", ""),
        type="password",
        help="Your Jira API token"
    )
    
    jira_project = st.text_input(
        "Jira Project Key",
        value=config.get("project_key", "PROJ"),
        help="Default Jira project key for operations"
    )
    
    if st.button("💾 Save Configuration"):
        # Update environment variables
        os.environ["JIRA_BASE_URL"] = jira_url
        os.environ["JIRA_TOKEN"] = jira_token
        os.environ["JIRA_PROJECT_KEY"] = jira_project
        st.success("Configuration saved!")
    
    st.subheader("Test Connection")
    if st.button("🔍 Test Connection"):
        if jira_token and jira_url:
            try:
                import requests
                headers = get_jira_headers(jira_token)
                response = requests.get(f"{jira_url}/rest/api/latest/myself", headers=headers, verify=False)
                if response.status_code == 200:
                    user_info = response.json()
                    st.success(f"✅ Connected as: {user_info.get('displayName', 'Unknown')}")
                else:
                    st.error(f"❌ Connection failed: {response.status_code}")
            except Exception as e:
                st.error(f"❌ Connection error: {str(e)}")
        else:
            st.error("Please provide both URL and token")

# Unified Excel file configuration
st.sidebar.header("📊 Unified Excel Configuration")

# Get unified Excel config
try:
    from config.settings import get_unified_excel_file, get_unified_excel_sheet
    unified_excel_file = get_unified_excel_file()
    unified_excel_sheet = get_unified_excel_sheet()
    
    st.sidebar.info(f"**Default Unified File:** {unified_excel_file}")
    st.sidebar.info(f"**Default Sheet:** {unified_excel_sheet}")
    
    # Option to use unified Excel file
    use_unified_excel = st.sidebar.checkbox(
        "Use Unified Excel File", 
        value=True, 
        help="Use the configured unified Excel file for all operations"
    )
    
    if use_unified_excel:
        st.sidebar.success("✅ Using unified Excel file for all operations")
        # Set the Excel path to unified file
        # This part of the logic needs to be integrated into the main_tab1 section
        # For now, we'll assume excel_path is set correctly if use_unified_excel is True
    else:
        st.sidebar.warning("⚠️ Using uploaded Excel file")
        
except ImportError:
    st.sidebar.warning("⚠️ Unified Excel configuration not available")
    use_unified_excel = False

# Main content area
main_tab1, main_tab2, main_tab3, main_tab4 = st.tabs([
    "📊 Bulk Operations", 
    "🎯 Single Operations", 
    "📁 File Management", 
    "📈 Status & Reports"
])

with main_tab1:
    st.header("📊 Bulk Operations")
    
    # Bulk operations
    operation = st.selectbox(
        "Select Bulk Operation",
        [
            "Create Tickets",
            "Create True Positive Tickets", 
            "Update Tickets",
            "Update Custom Fields",
            "Add Comments",
            "Add Dev Status Comments",
            "Fetch Status",
            "Fetch Linked Tickets",
            "Transition Status",
            "Security Workflow Transition",
            "Dev Workflow Transition",
            "Upload Attachments",
            "Upload POC Files",
            "Remove Labels",
            "Delete Tickets",
            "Linked Status Analysis"
        ]
    )
    
    # File upload
    uploaded_file = st.file_uploader(
        "Upload Excel File",
        type=["xlsx", "xls"],
        help="Upload an Excel file with your data"
    )
    
    if uploaded_file:
        # Save uploaded file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            excel_path = tmp_file.name
        
        st.success(f"✅ File uploaded: {uploaded_file.name}")
        
        # Show preview
        try:
            df = pd.read_excel(excel_path)
            st.subheader("📋 Data Preview")
            st.dataframe(df.head(), use_container_width=True)
            st.info(f"Total rows: {len(df)}")
        except Exception as e:
            st.error(f"Error reading file: {str(e)}")
        
        # Operation-specific parameters
        col1, col2 = st.columns(2)
        
        with col1:
            sheet_name = st.text_input("Sheet Name", value="Sheet1")
            project_key = st.text_input("Project Key", value=config.get("project_key", "PROJ"), help="Required for create operations")
            
        with col2:
            id_column = st.text_input("ID Column", value="ticket_id", help="Column containing ticket IDs")
            summary_column = st.text_input("Summary Column", value="summary")
        
        # Additional parameters based on operation
        if operation == "Create Tickets":
            st.subheader("Create Parameters")
            col1, col2 = st.columns(2)
            with col1:
                desc_column = st.text_input("Description Column", value="description")
            with col2:
                issue_type = st.selectbox("Issue Type", ["Task", "Bug", "Story", "Epic"])
        
        elif operation == "Create True Positive Tickets":
            st.subheader("True Positive Create Parameters")
            col1, col2 = st.columns(2)
            with col1:
                status_col = st.text_input("Status Column", value="status", help="Column containing status values")
                security_ticket_col = st.text_input("Security Ticket Column", value="Security Ticket", help="Column for Security Ticket IDs")
            with col2:
                desc_column = st.text_input("Description Column", value="description")
                issue_type = st.selectbox("Issue Type", ["Task", "Bug", "Story", "Epic"])
            
            col3, col4 = st.columns(2)
            with col3:
                priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"], index=1)
                assignee_col = st.text_input("Assignee Column", help="Column containing assignee usernames (optional)")
            with col4:
                dry_run = st.checkbox("Dry Run", value=False, help="Show what would be created without actually creating")
        
        elif operation == "Update Tickets":
            st.subheader("Update Parameters")
            update_fields = st.multiselect(
                "Fields to Update",
                ["summary", "description", "priority", "assignee", "labels"],
                default=["summary", "description"]
            )
        
        elif operation == "Update Custom Fields":
            st.subheader("Custom Fields Update Parameters")
            col1, col2 = st.columns(2)
            with col1:
                security_ticket_col = st.text_input("Security Ticket Column", value="Security Ticket", help="Column containing Security Ticket IDs")
                custom_fields_mapping = st.text_area("Custom Fields Mapping", height=100, help="Format: excel_col:field_id,excel_col2:field_id2\nExample: Risk Level:customfield_10002,Environment:customfield_10003")
            with col2:
                dry_run = st.checkbox("Dry Run", value=False, help="Show what would be updated without actually updating")
        
        elif operation == "Add Comments":
            st.subheader("Comment Parameters")
            comment_text = st.text_area("Comment Text", height=100)
        
        elif operation == "Add Dev Status Comments":
            st.subheader("Dev Status Comment Parameters")
            col1, col2 = st.columns(2)
            with col1:
                security_ticket_col = st.text_input("Security Ticket Column", value="Security Ticket", help="Column containing Security Ticket IDs")
                dev_status_col = st.text_input("Dev Status Column", value="dev ticket status", help="Column containing dev ticket status")
            with col2:
                dry_run = st.checkbox("Dry Run", value=False, help="Show what would be done without actually doing it")
        
        elif operation == "Fetch Status":
            st.subheader("Status Fetch Parameters")
            col1, col2 = st.columns(2)
            with col1:
                status_columns = st.multiselect(
                    "Status Fields to Fetch",
                    ["status", "priority", "assignee", "reporter", "created", "updated"],
                    default=["status", "priority"]
                )
            with col2:
                dry_run = st.checkbox("Dry Run", value=False, help="Show what would be fetched without actually fetching")
        
        elif operation == "Fetch Linked Tickets":
            st.subheader("Linked Tickets Fetch Parameters")
            col1, col2 = st.columns(2)
            with col1:
                security_ticket_col = st.text_input("Security Ticket Column", value="Security Ticket", help="Column containing Security Ticket IDs")
                dev_ticket_col = st.text_input("Dev Ticket Column", value="dev ticket", help="Column for storing dev ticket IDs")
                dev_status_col = st.text_input("Dev Status Column", value="dev ticket status", help="Column for storing dev ticket status")
            with col2:
                dev_keywords = st.text_input("Dev Keywords", value="dev,development,implementation,fix,bug,task,story", help="Comma-separated keywords to identify dev tickets")
                dry_run = st.checkbox("Dry Run", value=False, help="Show what would be fetched without actually fetching")
        
        elif operation == "Transition Status":
            st.subheader("Transition Parameters")
            target_status = st.text_input("Target Status", help="e.g., 'In Progress', 'Done'")
        
        elif operation == "Security Workflow Transition":
            st.subheader("Security Workflow Transition Parameters")
            st.info("Workflow: New -> Analysing -> Refining -> Refined Backlog -> Inprogress")
            dry_run = st.checkbox("Dry Run", value=False, help="Show what would be transitioned without actually transitioning")
        
        elif operation == "Dev Workflow Transition":
            st.subheader("Dev Workflow Transition Parameters")
            st.info("Workflow: Inprogress -> Review -> Acceptance -> Done")
            st.warning("Validation: QE comment and QE-Evidence attachments required for Acceptance/Done")
            dry_run = st.checkbox("Dry Run", value=False, help="Show what would be transitioned without actually transitioning")
        
        elif operation == "Upload Attachments":
            st.subheader("Attachment Parameters")
            attachment_dir = st.text_input("Attachment Directory", help="Path to directory containing files")
            file_pattern = st.text_input("File Pattern", value=r"([A-Z]+-\d+)$", help="Regex pattern to extract ticket ID from filename")
        
        elif operation == "Upload POC Files":
            st.subheader("POC Upload Parameters")
            poc_dir = st.text_input("POC Directory", help="Path to directory containing POC files")
            security_ticket_col = st.text_input("Security Ticket Column", value="Security Ticket", help="Column name containing ticket IDs")
            file_extensions = st.multiselect(
                "File Extensions",
                ["pdf", "doc", "docx", "txt", "png", "jpg", "jpeg", "zip", "rar"],
                default=["pdf", "doc", "docx", "zip"],
                help="File extensions to include"
            )
            check_existing = st.checkbox(
                "Check for existing QE-Evidence files", 
                value=True, 
                help="Skip upload if QE-Evidence-{Ticket ID} files already exist"
            )
        
        elif operation == "Remove Labels":
            st.subheader("Label Removal Parameters")
            col1, col2 = st.columns(2)
            with col1:
                dev_ticket_col = st.text_input("Dev Ticket Column", value="dev ticket", help="Column containing dev ticket URLs")
                labels_to_remove = st.text_input("Labels to Remove", help="Comma-separated list of labels to remove (e.g., old-label,deprecated-label)")
            with col2:
                dry_run = st.checkbox("Dry Run", value=False, help="Show what would be removed without actually removing")
        
        # Execute operation
        if st.button(f"🚀 Execute {operation}", type="primary"):
            if not excel_path:
                st.error("Please upload an Excel file first.")
            else:
                with st.spinner(f"Executing {operation}..."):
                    try:
                        # Build command based on operation
                        script_map = {
                            "Create Tickets": "scripts/bulk_operations/create/bulk_create_sync.py",
                            "Create True Positive Tickets": "scripts/bulk_operations/create/bulk_create_true_positive_sync.py",
                            "Update Tickets": "scripts/bulk_operations/update/bulk_update_sync.py",
                            "Update Custom Fields": "scripts/bulk_operations/update/bulk_update_custom_fields_sync.py",
                            "Add Comments": "scripts/bulk_operations/comment/bulk_comment_sync.py",
                            "Add Dev Status Comments": "scripts/bulk_operations/comment/bulk_comment_dev_status_sync.py",
                            "Fetch Status": "scripts/bulk_operations/status/bulk_status_sync.py",
                            "Fetch Linked Tickets": "scripts/bulk_operations/linked_status/bulk_fetch_linked_tickets_sync.py",
                            "Transition Status": "scripts/bulk_operations/transition/bulk_transition_sync.py",
                            "Security Workflow Transition": "scripts/bulk_operations/transition/bulk_transition_security_workflow_sync.py",
                            "Dev Workflow Transition": "scripts/bulk_operations/transition/bulk_transition_dev_workflow_sync.py",
                            "Upload Attachments": "scripts/attachments/bulk_attachment_sync.py",
                            "Upload POC Files": "scripts/attachments/bulk_poc_upload_sync.py",
                            "Remove Labels": "scripts/bulk_operations/update/bulk_remove_labels_sync.py",
                            "Delete Tickets": "scripts/bulk_operations/delete/bulk_delete_sync.py",
                            "Linked Status Analysis": "scripts/bulk_operations/linked_status/bulk_linked_status.py"
                        }
                        
                        script_path = script_map.get(operation)
                        if not script_path:
                            st.error(f"Script not found for operation: {operation}")
                            st.stop()
                        
                        # Build command arguments
                        cmd = ["python3", script_path, "--excel", excel_path]
                        
                        if jira_url:
                            cmd.extend(["--url", jira_url])
                        if jira_token:
                            cmd.extend(["--token", jira_token])
                        if project_key:
                            cmd.extend(["--project", project_key])
                        if sheet_name:
                            cmd.extend(["--sheet", sheet_name])
                        
                        # Operation-specific arguments
                        if operation == "Update Tickets" and update_fields:
                            cmd.extend(["--fields"] + update_fields)
                        elif operation == "Update Custom Fields":
                            cmd.extend(["--security-ticket-col", security_ticket_col])
                            if custom_fields_mapping:
                                cmd.extend(["--custom-fields", custom_fields_mapping])
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Add Comments" and comment_text:
                            cmd.extend(["--comment", comment_text])
                        elif operation == "Add Dev Status Comments":
                            cmd.extend(["--security-ticket-col", security_ticket_col, "--dev-status-col", dev_status_col])
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Fetch Status":
                            cmd.extend(["--status-columns"] + status_columns)
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Fetch Linked Tickets":
                            cmd.extend(["--security-ticket-col", security_ticket_col, "--dev-ticket-col", dev_ticket_col, "--dev-status-col", dev_status_col, "--dev-keywords", dev_keywords])
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Transition Status" and target_status:
                            cmd.extend(["--status", target_status])
                        elif operation == "Security Workflow Transition":
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Dev Workflow Transition":
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Upload Attachments" and attachment_dir:
                            cmd.extend(["--dir", attachment_dir, "--pattern", file_pattern])
                        elif operation == "Create True Positive Tickets":
                            cmd.extend(["--status-col", status_col, "--security-ticket-col", security_ticket_col])
                            if desc_column:
                                cmd.extend(["--description-col", desc_column])
                            if assignee_col:
                                cmd.extend(["--assignee-col", assignee_col])
                            cmd.extend(["--issue-type", issue_type, "--priority", priority])
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        elif operation == "Upload POC Files" and poc_dir:
                            cmd.extend(["--poc-dir", poc_dir, "--security-ticket-col", security_ticket_col])
                            if file_extensions:
                                cmd.extend(["--extensions"] + file_extensions)
                            if not check_existing:
                                cmd.extend(["--no-check-existing"])
                        elif operation == "Remove Labels":
                            cmd.extend(["--dev-ticket-col", dev_ticket_col, "--labels", labels_to_remove])
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        
                        st.info(f"Running: {' '.join(cmd)}")
                        
                        # Execute command
                        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                        
                        if result.returncode == 0:
                            st.success("✅ Operation completed successfully!")
                            if result.stdout:
                                st.text("Output:")
                                st.code(result.stdout)
                        else:
                            st.error("❌ Operation failed!")
                            st.text("Error:")
                            st.code(result.stderr)
                            
                    except Exception as e:
                        st.error(f"❌ Error executing operation: {str(e)}")

with main_tab2:
    st.header("🎯 Single Operations")
    
    # Single ticket operations
    single_op = st.selectbox(
        "Select Single Operation",
        ["Create Single Ticket", "Update Single Ticket", "Add Comment", "Upload Attachment", "Get Status", "Remove Labels"]
    )
    
    col1, col2 = st.columns(2)
    
    with col1:
        ticket_id = st.text_input("Ticket ID (e.g., PROJ-123)", help="Leave empty for create operations")
        project_key = st.text_input("Project Key", help="Required for create operations")
        summary = st.text_input("Summary", help="Ticket summary")
        description = st.text_area("Description", height=100)
    
    with col2:
        issue_type = st.selectbox("Issue Type", ["Task", "Bug", "Story", "Epic"])
        priority = st.selectbox("Priority", ["Low", "Medium", "High", "Critical"])
        assignee = st.text_input("Assignee", help="Username of assignee")
    
    if st.button("🚀 Execute Single Operation", type="primary"):
        if not jira_url or not jira_token:
            st.error("Please configure Jira connection first.")
        else:
            with st.spinner("Executing operation..."):
                try:
                    import requests
                    headers = get_jira_headers(jira_token)
                    
                    if single_op == "Create Single Ticket":
                        url = get_create_issue_url(jira_url)
                        data = {
                            "fields": {
                                "project": {"key": project_key},
                                "summary": summary,
                                "description": description,
                                "issuetype": {"name": issue_type},
                                "priority": {"name": priority}
                            }
                        }
                        if assignee:
                            data["fields"]["assignee"] = {"name": assignee}
                        
                        response = requests.post(url, json=data, headers=headers, verify=False)
                        
                        if response.status_code == 201:
                            created_ticket = response.json()
                            st.success(f"✅ Ticket created: {created_ticket['key']}")
                        else:
                            st.error(f"❌ Failed to create ticket: {response.text}")
                    
                    elif single_op == "Update Single Ticket":
                        if not ticket_id:
                            st.error("Please provide a ticket ID")
                            st.stop()
                        
                        url = get_issue_url(jira_url, ticket_id)
                        data = {"fields": {}}
                        
                        if summary:
                            data["fields"]["summary"] = summary
                        if description:
                            data["fields"]["description"] = description
                        if priority:
                            data["fields"]["priority"] = {"name": priority}
                        if assignee:
                            data["fields"]["assignee"] = {"name": assignee}
                        
                        response = requests.put(url, json=data, headers=headers, verify=False)
                        
                        if response.status_code == 204:
                            st.success("✅ Ticket updated successfully!")
                        else:
                            st.error(f"❌ Failed to update ticket: {response.text}")
                    
                    elif single_op == "Add Comment":
                        if not ticket_id:
                            st.error("Please provide a ticket ID")
                            st.stop()
                        
                        comment_text = st.text_area("Comment Text", height=100)
                        if comment_text:
                            url = get_issue_comment_url(jira_url, ticket_id)
                            data = {"body": comment_text}
                            
                            response = requests.post(url, json=data, headers=headers, verify=False)
                            
                            if response.status_code == 201:
                                st.success("✅ Comment added successfully!")
                            else:
                                st.error(f"❌ Failed to add comment: {response.text}")
                    
                    elif single_op == "Get Status":
                        if not ticket_id:
                            st.error("Please provide a ticket ID")
                            st.stop()
                        
                        url = get_issue_url(jira_url, ticket_id)
                        response = requests.get(url, headers=headers, verify=False)
                        
                        if response.status_code == 200:
                            ticket_data = response.json()
                            st.success("✅ Ticket information retrieved!")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Key:** {ticket_data['key']}")
                                st.write(f"**Status:** {ticket_data['fields']['status']['name']}")
                                st.write(f"**Summary:** {ticket_data['fields']['summary']}")
                            with col2:
                                st.write(f"**Type:** {ticket_data['fields']['issuetype']['name']}")
                                st.write(f"**Priority:** {ticket_data['fields']['priority']['name']}")
                                st.write(f"**Assignee:** {ticket_data['fields'].get('assignee', {}).get('displayName', 'Unassigned')}")
                        else:
                            st.error(f"❌ Failed to get ticket: {response.text}")
                    
                    elif single_op == "Remove Labels":
                        if not ticket_id:
                            st.error("Please provide a ticket ID")
                            st.stop()
                        
                        labels_to_remove = st.text_input("Labels to Remove", help="Comma-separated list of labels to remove")
                        
                        if labels_to_remove:
                            # Get current labels
                            url = get_issue_url(jira_url, ticket_id)
                            response = requests.get(url, headers=headers, verify=False)
                            
                            if response.status_code == 200:
                                ticket_data = response.json()
                                current_labels = ticket_data['fields'].get('labels', [])
                                
                                # Parse labels to remove
                                labels_to_remove_list = [label.strip() for label in labels_to_remove.split(",") if label.strip()]
                                
                                # Remove specified labels
                                updated_labels = [label for label in current_labels if label not in labels_to_remove_list]
                                
                                # Update ticket
                                data = {"fields": {"labels": updated_labels}}
                                update_response = requests.put(url, json=data, headers=headers, verify=False)
                                
                                if update_response.status_code == 204:
                                    removed_labels = [label for label in current_labels if label in labels_to_remove_list]
                                    st.success(f"✅ Successfully removed labels from {ticket_id}")
                                    st.write(f"**Removed labels:** {removed_labels}")
                                    st.write(f"**Remaining labels:** {updated_labels}")
                                else:
                                    st.error(f"❌ Failed to remove labels: {update_response.text}")
                            else:
                                st.error(f"❌ Failed to get ticket: {response.text}")
                        else:
                            st.error("Please provide labels to remove")
                    
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")

with main_tab3:
    st.header("📁 File Management")
    
    # File upload for attachments
    st.subheader("Upload Attachments")
    
    uploaded_files = st.file_uploader(
        "Select Files to Upload",
        type=["pdf", "doc", "docx", "xls", "xlsx", "txt", "png", "jpg", "jpeg"],
        accept_multiple_files=True
    )
    
    if uploaded_files:
        st.write(f"Selected {len(uploaded_files)} files:")
        for file in uploaded_files:
            st.write(f"- {file.name} ({file.size} bytes)")
        
        ticket_id = st.text_input("Target Ticket ID", help="Ticket ID to attach files to")
        
        if st.button("📎 Upload Attachments", type="primary"):
            if not ticket_id:
                st.error("Please provide a ticket ID")
            elif not jira_url or not jira_token:
                st.error("Please configure Jira connection first")
            else:
                with st.spinner("Uploading attachments..."):
                    try:
                        import requests
                        headers = get_jira_attachment_headers(jira_token)
                        url = get_issue_attachments_url(jira_url, ticket_id)
                        
                        success_count = 0
                        for file in uploaded_files:
                            files = {'file': (file.name, file.getvalue(), file.type)}
                            response = requests.post(url, headers=headers, files=files, verify=False)
                            
                            if response.status_code in [200, 201]:
                                success_count += 1
                                st.success(f"✅ {file.name} uploaded successfully")
                            else:
                                st.error(f"❌ Failed to upload {file.name}: {response.text}")
                        
                        st.success(f"✅ Uploaded {success_count}/{len(uploaded_files)} files successfully!")
                        
                    except Exception as e:
                        st.error(f"❌ Error uploading files: {str(e)}")

with main_tab4:
    st.header("📈 Status & Reports")
    
    # Status dashboard
    st.subheader("Connection Status")
    
    if jira_url and jira_token:
        try:
            import requests
            headers = get_jira_headers(jira_token)
            response = requests.get(f"{jira_url}/rest/api/latest/myself", headers=headers, verify=False)
            
            if response.status_code == 200:
                user_info = response.json()
                st.success("✅ Connected to Jira")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("User", user_info.get('displayName', 'Unknown'))
                with col2:
                    st.metric("Email", user_info.get('emailAddress', 'Unknown'))
                with col3:
                    st.metric("Account ID", user_info.get('accountId', 'Unknown')[:10] + "...")
            else:
                st.error("❌ Connection failed")
        except Exception as e:
            st.error(f"❌ Connection error: {str(e)}")
    else:
        st.warning("⚠️ Please configure Jira connection")
    
    # Recent operations log
    st.subheader("Recent Operations")
    st.info("Operation history will be displayed here in future versions")

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>🔧 Jira Tool - Complete Web Interface | Built with Streamlit</p>
        <p>For more information, check the documentation in the sidebar.</p>
    </div>
    """,
    unsafe_allow_html=True
) 