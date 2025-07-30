import streamlit as st
import subprocess
import sys
import os
from pathlib import Path
import pandas as pd
import tempfile
import json
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from collections import defaultdict
import threading
import time

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
from utils.excel_metrics import display_unified_excel_metrics, UnifiedExcelMetrics

# Enhanced page configuration
st.set_page_config(
    page_title="Jira Tool - Enhanced Web Interface",
    page_icon="🔧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #1f77b4, #ff7f0e);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .feature-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        border-left: 4px solid #1f77b4;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #28a745;
    }
    .error-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #dc3545;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #ffc107;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .operation-status {
        padding: 0.5rem;
        border-radius: 0.25rem;
        margin: 0.25rem 0;
    }
    .status-running { background-color: #fff3cd; }
    .status-success { background-color: #d4edda; }
    .status-error { background-color: #f8d7da; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'operation_history' not in st.session_state:
    st.session_state.operation_history = []
if 'pending_operations' not in st.session_state:
    st.session_state.pending_operations = []
if 'config_profiles' not in st.session_state:
    st.session_state.config_profiles = {
        "Default": {"timeout": 60, "retries": 3, "debug": False},
        "Development": {"timeout": 120, "retries": 5, "debug": True},
        "Production": {"timeout": 30, "retries": 2, "debug": False}
    }

# Main header with enhanced styling
st.markdown('<h1 class="main-header">🔧 Jira Tool - Enhanced Web Interface</h1>', unsafe_allow_html=True)

# Enhanced sidebar with better organization
st.sidebar.header("🔧 Configuration")

# Configuration tabs with enhanced features
config_tab, bulk_tab, single_tab, docs_tab, analytics_tab = st.sidebar.tabs([
    "⚙️ Config", "📊 Bulk Ops", "🎯 Single Ops", "📚 Docs", "📈 Analytics"
])

with config_tab:
    st.subheader("Jira Connection")
    
    # Get current config
    config = get_jira_config()
    
    # Enhanced configuration with profiles
    config_profile = st.selectbox(
        "Configuration Profile",
        list(st.session_state.config_profiles.keys()) + ["Custom"],
        help="Choose a predefined configuration profile"
    )
    
    if config_profile == "Custom":
        st.session_state.config_profiles["Custom"] = {
            "timeout": st.number_input("Timeout (seconds)", min_value=30, max_value=300, value=60),
            "retries": st.number_input("Retry attempts", min_value=1, max_value=5, value=3),
            "debug": st.checkbox("Enable debug mode"),
            "detailed_logging": st.checkbox("Enable detailed logging")
        }
    
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
    
    # Enhanced configuration management
    col1, col2 = st.columns(2)
    with col1:
        if st.button("💾 Save Configuration"):
            # Update environment variables
            os.environ["JIRA_BASE_URL"] = jira_url
            os.environ["JIRA_TOKEN"] = jira_token
            os.environ["JIRA_PROJECT_KEY"] = jira_project
            st.success("Configuration saved!")
    
    with col2:
        if st.button("📥 Export Config"):
            config_data = {
                "url": jira_url,
                "token": jira_token,
                "project": jira_project,
                "profile": config_profile
            }
            st.download_button(
                "📥 Download Config",
                json.dumps(config_data, indent=2),
                file_name="jira_config.json",
                mime="application/json"
            )
    
    # Enhanced connection testing
    st.subheader("Test Connection")
    if st.button("🔍 Test Connection"):
        if jira_token and jira_url:
            with st.spinner("Testing connection..."):
                try:
                    import requests
                    headers = get_jira_headers(jira_token)
                    response = requests.get(f"{jira_url}/rest/api/latest/myself", headers=headers, verify=False)
                    if response.status_code == 200:
                        user_info = response.json()
                        st.success(f"✅ Connected as: {user_info.get('displayName', 'Unknown')}")
                        
                        # Show connection metrics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Response Time", f"{response.elapsed.total_seconds():.2f}s")
                        with col2:
                            st.metric("Status Code", response.status_code)
                        with col3:
                            st.metric("User", user_info.get('displayName', 'Unknown'))
                    else:
                        st.error(f"❌ Connection failed: {response.status_code}")
                except Exception as e:
                    st.error(f"❌ Connection error: {str(e)}")
        else:
            st.error("Please provide both URL and token")

# Enhanced unified Excel configuration
st.sidebar.header("📊 Unified Excel Configuration")

try:
    from config.settings import get_unified_excel_file, get_unified_excel_file
    unified_excel_file = get_unified_excel_file()
    unified_excel_sheet = get_unified_excel_file()
    
    st.sidebar.info(f"**Default Unified File:** {unified_excel_file}")
    st.sidebar.info(f"**Default Sheet:** {unified_excel_sheet}")
    
    use_unified_excel = st.sidebar.checkbox(
        "Use Unified Excel File", 
        value=True, 
        help="Use the configured unified Excel file for all operations"
    )
    
    if use_unified_excel:
        st.sidebar.success("✅ Using unified Excel file for all operations")
    else:
        st.sidebar.warning("⚠️ Using uploaded Excel file")
        
except ImportError:
    st.sidebar.warning("⚠️ Unified Excel configuration not available")
    use_unified_excel = False

# Enhanced main content area with analytics
main_tab1, main_tab2, main_tab3, main_tab4, main_tab5, main_tab6 = st.tabs([
    "📊 Bulk Operations", 
    "🎯 Single Operations", 
    "📁 File Management", 
    "📈 Status & Reports",
    "📊 Analytics Dashboard",
    "📊 Unified Excel Metrics"
])

with main_tab1:
    st.header("📊 Bulk Operations")
    
    # Enhanced operation selection with descriptions
    operation_descriptions = {
        "Create Tickets": "Create new Jira tickets from Excel data",
        "Create True Positive Tickets": "Create tickets for true positive findings",
        "Update Tickets": "Update existing tickets with new data",
        "Update Custom Fields": "Update custom fields on tickets",
        "Add Comments": "Add comments to tickets",
        "Add Dev Status Comments": "Add development status comments",
        "Fetch Status": "Fetch current status of tickets",
        "Fetch Linked Tickets": "Fetch linked tickets and their status",
        "Transition Status": "Transition tickets to new status",
        "Security Workflow Transition": "Execute security workflow transitions",
        "Dev Workflow Transition": "Execute development workflow transitions",
        "Upload Attachments": "Upload files to tickets",
        "Upload POC Files": "Upload proof of concept files",
        "Remove Labels": "Remove labels from tickets",
        "Delete Tickets": "Delete tickets (use with caution)",
        "Linked Status Analysis": "Analyze linked ticket status"
    }
    
    operation = st.selectbox(
        "Select Bulk Operation",
        list(operation_descriptions.keys())
    )
    
    # Show operation description
    if operation in operation_descriptions:
        st.info(f"📝 **{operation}**: {operation_descriptions[operation]}")
    
    # Enhanced file upload with validation
    uploaded_file = st.file_uploader(
        "Upload Excel File",
        type=["xlsx", "xls"],
        help="Upload an Excel file with your data"
    )
    
    if uploaded_file:
        # Enhanced file validation
        file_size_mb = uploaded_file.size / (1024 * 1024)
        if file_size_mb > 10:
            st.warning(f"⚠️ File size ({file_size_mb:.1f}MB) is large. Processing may take longer.")
        
        # Save uploaded file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            excel_path = tmp_file.name
        
        st.success(f"✅ File uploaded: {uploaded_file.name}")
        
        # Enhanced data preview with validation
        try:
            df = pd.read_excel(excel_path)
            
            # Data quality analysis
            st.subheader("📋 Data Quality Analysis")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Rows", len(df))
            with col2:
                st.metric("Total Columns", len(df.columns))
            with col3:
                st.metric("Missing Values", df.isnull().sum().sum())
            with col4:
                st.metric("Memory Usage", f"{df.memory_usage(deep=True).sum() / 1024:.1f} KB")
            
            # Show data preview with enhanced styling
            st.subheader("📊 Data Preview")
            st.dataframe(df.head(), use_container_width=True)
            
            # Data quality warnings
            missing_data = df.isnull().sum()
            if missing_data.sum() > 0:
                st.warning(f"⚠️ {missing_data.sum()} missing values detected")
                
                # Show missing data chart
                missing_chart = px.bar(
                    x=missing_data.index,
                    y=missing_data.values,
                    title="Missing Values by Column"
                )
                st.plotly_chart(missing_chart, use_container_width=True)
            
            # Column analysis
            with st.expander("📋 Column Analysis"):
                for col in df.columns:
                    col_info = f"**{col}:** {df[col].dtype} - {df[col].nunique()} unique values"
                    if df[col].dtype == 'object':
                        col_info += f" (Sample: {df[col].dropna().iloc[0] if len(df[col].dropna()) > 0 else 'N/A'})"
                    st.write(col_info)
                    
        except Exception as e:
            st.error(f"Error reading file: {str(e)}")
        
        # Enhanced operation parameters with better organization
        st.subheader("⚙️ Operation Parameters")
        
        col1, col2 = st.columns(2)
        
        with col1:
            sheet_name = st.text_input("Sheet Name", value="Sheet1")
            project_key = st.text_input("Project Key", value=config.get("project_key", "PROJ"), help="Required for create operations")
            
        with col2:
            id_column = st.text_input("ID Column", value="ticket_id", help="Column containing ticket IDs")
            summary_column = st.text_input("Summary Column", value="summary")
        
        # Operation-specific parameters with enhanced UI
        if operation == "Create True Positive Tickets":
            st.subheader("🎯 True Positive Create Parameters")
            
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
                
                # Add batch processing options
                batch_size = st.number_input("Batch Size", min_value=1, max_value=100, value=10, help="Process tickets in batches")
        
        # Enhanced execution with progress tracking
        if st.button(f"🚀 Execute {operation}", type="primary"):
            if not excel_path:
                st.error("Please upload an Excel file first.")
            else:
                # Add operation to pending queue
                operation_id = f"{operation}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                st.session_state.pending_operations.append({
                    "id": operation_id,
                    "operation": operation,
                    "status": "running",
                    "start_time": datetime.now(),
                    "file": uploaded_file.name
                })
                
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
                        cmd = ["python", script_path, "--excel", excel_path]
                        
                        if jira_url:
                            cmd.extend(["--url", jira_url])
                        if jira_token:
                            cmd.extend(["--token", jira_token])
                        if project_key:
                            cmd.extend(["--project", project_key])
                        if sheet_name:
                            cmd.extend(["--sheet", sheet_name])
                        
                        # Operation-specific arguments
                        if operation == "Create True Positive Tickets":
                            cmd.extend(["--status-col", status_col, "--security-ticket-col", security_ticket_col])
                            if desc_column:
                                cmd.extend(["--description-col", desc_column])
                            if assignee_col:
                                cmd.extend(["--assignee-col", assignee_col])
                            cmd.extend(["--issue-type", issue_type, "--priority", priority])
                            if dry_run:
                                cmd.extend(["--dry-run"])
                        
                        st.info(f"Running: {' '.join(cmd)}")
                        
                        # Execute command with enhanced error handling
                        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                        
                        # Update operation status
                        for op in st.session_state.pending_operations:
                            if op["id"] == operation_id:
                                op["status"] = "success" if result.returncode == 0 else "error"
                                op["end_time"] = datetime.now()
                                op["duration"] = (op["end_time"] - op["start_time"]).total_seconds()
                                break
                        
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
                        
                        # Update operation status to error
                        for op in st.session_state.pending_operations:
                            if op["id"] == operation_id:
                                op["status"] = "error"
                                op["end_time"] = datetime.now()
                                op["duration"] = (op["end_time"] - op["start_time"]).total_seconds()
                                break

# Enhanced single operations tab
with main_tab2:
    st.header("🎯 Single Operations")
    
    # Enhanced single ticket operations
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
                    
                    elif single_op == "Get Status":
                        if not ticket_id:
                            st.error("Please provide a ticket ID")
                            st.stop()
                        
                        url = get_issue_url(jira_url, ticket_id)
                        response = requests.get(url, headers=headers, verify=False)
                        
                        if response.status_code == 200:
                            ticket_data = response.json()
                            st.success("✅ Ticket information retrieved!")
                            
                            # Enhanced ticket display
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Key", ticket_data['key'])
                                st.metric("Status", ticket_data['fields']['status']['name'])
                                st.metric("Type", ticket_data['fields']['issuetype']['name'])
                            with col2:
                                st.metric("Priority", ticket_data['fields']['priority']['name'])
                                st.metric("Assignee", ticket_data['fields'].get('assignee', {}).get('displayName', 'Unassigned'))
                                st.metric("Reporter", ticket_data['fields']['reporter']['displayName'])
                            
                            # Show ticket details
                            with st.expander("📋 Ticket Details"):
                                st.write(f"**Summary:** {ticket_data['fields']['summary']}")
                                st.write(f"**Description:** {ticket_data['fields'].get('description', 'No description')}")
                                st.write(f"**Created:** {ticket_data['fields']['created']}")
                                st.write(f"**Updated:** {ticket_data['fields']['updated']}")
                        else:
                            st.error(f"❌ Failed to get ticket: {response.text}")
                    
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")

# Enhanced file management tab
with main_tab3:
    st.header("📁 File Management")
    
    # Enhanced file upload with drag-and-drop support
    st.subheader("Upload Attachments")
    
    uploaded_files = st.file_uploader(
        "Select Files to Upload",
        type=["pdf", "doc", "docx", "xls", "xlsx", "txt", "png", "jpg", "jpeg", "zip"],
        accept_multiple_files=True,
        help="Drag and drop files here or click to browse"
    )
    
    if uploaded_files:
        # Enhanced file display
        st.write(f"Selected {len(uploaded_files)} files:")
        
        total_size = sum(file.size for file in uploaded_files)
        st.info(f"Total size: {total_size / (1024*1024):.2f} MB")
        
        for file in uploaded_files:
            file_size_mb = file.size / (1024*1024)
            if file_size_mb > 5:
                st.warning(f"⚠️ {file.name} is large ({file_size_mb:.1f}MB)")
            else:
                st.write(f"✅ {file.name} ({file.size} bytes)")
        
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
                        progress_bar = st.progress(0)
                        
                        for i, file in enumerate(uploaded_files):
                            files = {'file': (file.name, file.getvalue(), file.type)}
                            response = requests.post(url, headers=headers, files=files, verify=False)
                            
                            if response.status_code in [200, 201]:
                                success_count += 1
                                st.success(f"✅ {file.name} uploaded successfully")
                            else:
                                st.error(f"❌ Failed to upload {file.name}: {response.text}")
                            
                            # Update progress bar
                            progress_bar.progress((i + 1) / len(uploaded_files))
                        
                        st.success(f"✅ Uploaded {success_count}/{len(uploaded_files)} files successfully!")
                        
                    except Exception as e:
                        st.error(f"❌ Error uploading files: {str(e)}")

# Enhanced status and reports tab
with main_tab4:
    st.header("📈 Status & Reports")
    
    # Enhanced connection status
    st.subheader("🔗 Connection Status")
    
    if jira_url and jira_token:
        try:
            import requests
            headers = get_jira_headers(jira_token)
            response = requests.get(f"{jira_url}/rest/api/latest/myself", headers=headers, verify=False)
            
            if response.status_code == 200:
                user_info = response.json()
                st.success("✅ Connected to Jira")
                
                # Enhanced metrics display
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("User", user_info.get('displayName', 'Unknown'))
                with col2:
                    st.metric("Email", user_info.get('emailAddress', 'Unknown'))
                with col3:
                    st.metric("Response Time", f"{response.elapsed.total_seconds():.2f}s")
                with col4:
                    st.metric("Status", "Connected")
            else:
                st.error("❌ Connection failed")
        except Exception as e:
            st.error(f"❌ Connection error: {str(e)}")
    else:
        st.warning("⚠️ Please configure Jira connection")
    
    # Enhanced operation history
    st.subheader("📋 Operation History")
    
    if st.session_state.operation_history:
        # Create operation history chart
        history_data = []
        for op in st.session_state.operation_history:
            history_data.append({
                "operation": op["operation"],
                "status": op["status"],
                "duration": op.get("duration", 0),
                "timestamp": op["start_time"]
            })
        
        if history_data:
            df_history = pd.DataFrame(history_data)
            
            # Success rate chart
            success_rate = df_history[df_history["status"] == "success"].shape[0] / len(df_history) * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
            
            # Operation duration chart
            if "duration" in df_history.columns:
                fig = px.histogram(df_history, x="duration", title="Operation Duration Distribution")
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No operation history yet. Run some operations to see analytics here.")
    
    # Pending operations
    st.subheader("⏳ Pending Operations")
    
    if st.session_state.pending_operations:
        for op in st.session_state.pending_operations:
            status_color = {
                "running": "🔄",
                "success": "✅",
                "error": "❌"
            }.get(op["status"], "⏳")
            
            st.write(f"{status_color} {op['operation']} - {op['status']}")
            if "duration" in op:
                st.write(f"   Duration: {op['duration']:.2f}s")
    else:
        st.info("No pending operations")

# New analytics dashboard tab
with main_tab5:
    st.header("📊 Analytics Dashboard")
    
    # Operation analytics
    st.subheader("📈 Operation Analytics")
    
    if st.session_state.operation_history:
        df_analytics = pd.DataFrame(st.session_state.operation_history)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_ops = len(df_analytics)
            st.metric("Total Operations", total_ops)
        
        with col2:
            success_ops = len(df_analytics[df_analytics["status"] == "success"])
            st.metric("Successful Operations", success_ops)
        
        with col3:
            if total_ops > 0:
                success_rate = (success_ops / total_ops) * 100
                st.metric("Success Rate", f"{success_rate:.1f}%")
        
        # Operation type distribution
        if "operation" in df_analytics.columns:
            op_counts = df_analytics["operation"].value_counts()
            fig = px.pie(values=op_counts.values, names=op_counts.index, title="Operations by Type")
            st.plotly_chart(fig, use_container_width=True)
        
        # Timeline of operations
        if "start_time" in df_analytics.columns:
            df_analytics["date"] = pd.to_datetime(df_analytics["start_time"]).dt.date
            daily_ops = df_analytics.groupby("date").size().reset_index(name="count")
            
            fig = px.line(daily_ops, x="date", y="count", title="Operations Over Time")
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Run some operations to see analytics here")
    
    # Performance metrics
    st.subheader("⚡ Performance Metrics")
    
    if st.session_state.operation_history:
        df_perf = pd.DataFrame(st.session_state.operation_history)
        
        if "duration" in df_perf.columns:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                avg_duration = df_perf["duration"].mean()
                st.metric("Average Duration", f"{avg_duration:.2f}s")
            
            with col2:
                max_duration = df_perf["duration"].max()
                st.metric("Longest Operation", f"{max_duration:.2f}s")
            
            with col3:
                min_duration = df_perf["duration"].min()
                st.metric("Fastest Operation", f"{min_duration:.2f}s")

# Unified Excel Metrics Tab
with main_tab6:
    st.header("📊 Unified Excel Metrics Dashboard")
    st.subheader("Focusing on First 15 Vulnerability-Specific Columns")
    
    # File upload for metrics analysis
    metrics_file = st.file_uploader(
        "Upload Excel File for Metrics Analysis",
        type=["xlsx", "xls"],
        help="Upload your unified Excel file to analyze the first 15 vulnerability-specific columns"
    )
    
    if metrics_file:
        # Save uploaded file for metrics analysis
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
            tmp_file.write(metrics_file.getvalue())
            metrics_excel_path = tmp_file.name
        
        st.success(f"✅ File uploaded for metrics analysis: {metrics_file.name}")
        
        # Display unified Excel metrics
        display_unified_excel_metrics(metrics_excel_path, "Sheet1")
    else:
        st.info("📊 Upload an Excel file to analyze the first 15 vulnerability-specific columns")
        st.markdown("""
        ### 📋 First 15 Columns Analyzed:
        1. **File Name (FullPath)** - File path analysis
        2. **Vulnerability Name** - Vulnerability type patterns
        3. **Line Number(s)** - Code location analysis
        4. **Severity** - Risk level distribution
        5. **Description** - Content completeness
        6. **Impact** - Impact assessment
        7. **Vulnerable Code Snippet** - Code analysis
        8. **Potential Fix(Text+Code)** - Fix availability
        9. **More Info** - Additional information
        10. **True Positive (%)** - Confidence analysis
        11. **Exploitable(%)** - Risk assessment
        12. **Status** - Current status distribution
        13. **Security Ticket** - Ticket creation metrics
        14. **Security Ticket Status** - Ticket workflow analysis
        15. **dev ticket** - Development ticket linking
        
        ### 📊 Metrics Provided:
        - **Severity Distribution** - Risk level analysis
        - **True Positive vs Exploitable** - Confidence vs risk correlation
        - **File Extension Analysis** - Technology stack insights
        - **Line Number Patterns** - Code location trends
        - **Ticket Completion Rates** - Workflow efficiency
        - **Data Completeness** - Quality assessment
        - **Vulnerability Type Patterns** - Security focus areas
        """)

# Enhanced footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>🔧 Jira Tool - Enhanced Web Interface | Built with Streamlit</p>
        <p>For more information, check the documentation in the sidebar.</p>
        <p>Last updated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    </div>
    """,
    unsafe_allow_html=True
) 