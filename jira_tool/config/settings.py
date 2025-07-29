"""
Jira Configuration Settings
Centralized configuration for Jira API settings.
"""

import os
from typing import Optional, Dict, Any
import pandas as pd # Added for unified Excel template creation

# Default Jira configuration
DEFAULT_JIRA_BASE_URL = "https://www.examplejira.com"
DEFAULT_JIRA_TOKEN = ""
DEFAULT_JIRA_PROJECT_KEY = "SEC"

# Default ticket creation configuration
DEFAULT_ISSUE_TYPE_ID = "10001"  # Bug issue type ID
DEFAULT_ISSUE_TYPE_NAME = "Bug"
DEFAULT_PRIORITY_NAME = "High"
DEFAULT_LABELS = ["security", "vulnerability", "true-positive"]
DEFAULT_CUSTOM_FIELD_12200_VALUE = "Security Finding"

# Default Custom Fields Configuration
DEFAULT_CUSTOM_FIELDS = {
    "Security Ticket": "customfield_10001",  # Example custom field ID
    "Finding Type": "customfield_10002",
    "Risk Level": "customfield_10003",
    "Compliance": "customfield_10004",
    "Environment": "customfield_10005"
}

# Default Column Mappings for True Positive Creation
DEFAULT_COLUMN_MAPPINGS = {
    "status": "status",
    "security_ticket": "Security Ticket",
    "summary": "summary",
    "description": "description",
    "priority": "priority",
    "assignee": "assignee",
    "issue_type": "issue_type"
}

# Default unified Excel file configuration
DEFAULT_UNIFIED_EXCEL_FILE = "jira_tool_data.xlsx"
DEFAULT_UNIFIED_SHEET = "Tickets"

# Unified Excel column structure
UNIFIED_EXCEL_COLUMNS = {
    # Vulnerability-specific information (first)
    "file_name_fullpath": "File Name (FullPath)",
    "vulnerability_name": "Vulnerability Name",
    "line_numbers": "Line Number(s)",
    "severity": "Severity",
    "description": "Description",
    "impact": "Impact",
    "vulnerable_code_snippet": "Vulnerable Code Snippet",
    "potential_fix": "Potential Fix(Text+Code)",
    "more_info": "More Info",
    "true_positive_percentage": "True Positive (%)",
    "exploitable_percentage": "Exploitable(%)",
    "status": "Status",
    "security_ticket": "Security Ticket",
    "security_ticket_status": "Security Ticket Status",
    "dev_ticket": "dev ticket",
    "dev_ticket_status": "dev ticket status",
    
    # Core ticket information
    "summary": "summary",
    "priority": "priority",
    "assignee": "assignee",
    "reporter": "reporter",
    "issue_type": "issue_type",
    "project_key": "project_key",
    
    # Status and workflow
    "current_status": "current_status",
    "next_status": "next_status",
    "transition_status": "transition_status",
    "transition_date": "transition_date",
    "validation_status": "validation_status",
    
    # Dev ticket information (from linked tickets)
    "dev_ticket_summary": "dev_ticket_summary",
    "dev_ticket_link_type": "dev_ticket_link_type",
    "linked_tickets_found": "linked_tickets_found",
    "fetch_date": "fetch_date",
    
    # Comments
    "comment_text": "comment_text",
    "comment_status": "comment_status",
    "comment_date": "comment_date",
    
    # Custom fields
    "custom_field_status": "custom_field_status",
    "updated_fields": "updated_fields",
    "update_date": "update_date",
    
    # Attachments and POC
    "attachment_status": "attachment_status",
    "attachment_count": "attachment_count",
    "poc_status": "poc_status",
    "poc_files": "poc_files",
    "qe_evidence_exists": "qe_evidence_exists",
    "existing_qe_evidence": "existing_qe_evidence",
    
    # Creation and tracking
    "created_date": "created_date",
    "updated_date": "updated_date",
    "last_processed": "last_processed",
    "processing_status": "processing_status"
}

# Unified Excel file template structure
UNIFIED_EXCEL_TEMPLATE = {
    "columns": [
        # Vulnerability-specific columns (first)
        "File Name (FullPath)",
        "Vulnerability Name", 
        "Line Number(s)",
        "Severity",
        "Description",
        "Impact",
        "Vulnerable Code Snippet",
        "Potential Fix(Text+Code)",
        "More Info",
        "True Positive (%)",
        "Exploitable(%)",
        "Status",
        "Security Ticket",
        "Security Ticket Status",
        "dev ticket",
        "dev ticket status",
        
        # Core ticket information
        "summary", 
        "description",
        "priority",
        "assignee",
        "reporter",
        "issue_type",
        "project_key",
        
        # Status and workflow
        "current_status",
        "next_status", 
        "transition_status",
        "transition_date",
        "validation_status",
        
        # Dev ticket information (from linked tickets)
        "dev_ticket_summary",
        "dev_ticket_link_type",
        "linked_tickets_found",
        "fetch_date",
        
        # Comments
        "comment_text",
        "comment_status",
        "comment_date",
        
        # Custom fields
        "custom_field_status",
        "updated_fields",
        "update_date",
        
        # Attachments and POC
        "attachment_status",
        "attachment_count",
        "poc_status",
        "poc_files",
        "qe_evidence_exists",
        "existing_qe_evidence",
        
        # Creation and tracking
        "created_date",
        "updated_date",
        "last_processed",
        "processing_status"
    ],
    "sample_data": [
        ["/src/auth/login.php", "SQL Injection", "45-47", "High", "High severity finding in login form", "Data breach, unauthorized access", "SELECT * FROM users WHERE id = $_GET['id']", "Use prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');", "CWE-89: SQL Injection", "95", "85", "New", "SEC-123", "Open", "DEV-456", "In Progress", "SQL Injection vulnerability", "High severity finding in login form", "High", "security-team", "scanner", "Bug", "SEC", "New", "Analysing", "Success", "2024-01-15 10:30:00", "No special requirements", "Fix implementation", "implements", 2, "2024-01-15 11:00:00", "QE Testing in Dev Completed", "Added", "2024-01-15 12:00:00", "Updated: 3 fields", "Risk Level: High, Environment: Production", "2024-01-15 13:00:00", "Uploaded", 2, "Uploaded", "poc1.pdf,poc2.zip", "Yes", "QE-Evidence-SEC-123.pdf", "2024-01-15 09:00:00", "2024-01-15 13:00:00", "2024-01-15 13:00:00", "Complete"],
        ["/src/search/search.php", "Cross-Site Scripting", "23-25", "Medium", "Medium severity finding in search form", "Session hijacking, data theft", "echo $_GET['query'];", "Use htmlspecialchars(): echo htmlspecialchars($_GET['query'], ENT_QUOTES, 'UTF-8');", "CWE-79: XSS", "90", "70", "Analysing", "SEC-124", "In Progress", "DEV-457", "Review", "XSS vulnerability", "Medium severity finding in search form", "Medium", "security-team", "scanner", "Bug", "SEC", "Analysing", "Refining", "Success", "2024-01-15 10:35:00", "No special requirements", "Patch implementation", "implements", 1, "2024-01-15 11:05:00", "", "Pending", "", "Updated: 2 fields", "Risk Level: Medium, Environment: Development", "2024-01-15 13:05:00", "Uploaded", 1, "Uploaded", "poc3.pdf", "No", "", "2024-01-15 09:05:00", "2024-01-15 13:05:00", "2024-01-15 13:05:00", "Complete"],
        ["/src/admin/update.php", "Cross-Site Request Forgery", "12-15", "Critical", "Critical severity finding in form submission", "Unauthorized actions, data modification", "if ($_POST['action']) { updateUser($_POST['id']); }", "Add CSRF token: if (hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) { updateUser($_POST['id']); }", "CWE-352: CSRF", "98", "95", "Refining", "SEC-125", "In Progress", "DEV-458", "Done", "CSRF vulnerability", "Critical severity finding in form submission", "Critical", "security-team", "scanner", "Bug", "SEC", "Refining", "Refined Backlog", "Success", "2024-01-15 10:40:00", "No special requirements", "Security fix completed", "implements", 1, "2024-01-15 11:10:00", "QE Testing in Dev Completed", "Added", "2024-01-15 12:10:00", "Updated: 4 fields", "Risk Level: Critical, Environment: Production, Compliance: PCI", "2024-01-15 13:10:00", "Uploaded", 3, "Uploaded", "poc4.pdf,poc5.zip,poc6.doc", "Yes", "QE-Evidence-SEC-125.pdf", "2024-01-15 09:10:00", "2024-01-15 13:10:00", "2024-01-15 13:10:00", "Complete"]
    ]
}


def get_jira_config():
    """
    Get Jira configuration from environment variables or defaults.
    
    Returns:
        dict: Configuration dictionary with base_url, token, and project_key
    """
    return {
        "base_url": os.getenv("JIRA_BASE_URL", DEFAULT_JIRA_BASE_URL),
        "token": os.getenv("JIRA_TOKEN", DEFAULT_JIRA_TOKEN),
        "project_key": os.getenv("JIRA_PROJECT_KEY", DEFAULT_JIRA_PROJECT_KEY)
    }


def get_jira_base_url() -> str:
    """
    Get Jira base URL from environment or default.
    
    Returns:
        str: Jira base URL
    """
    return os.getenv("JIRA_BASE_URL", DEFAULT_JIRA_BASE_URL)


def get_jira_token() -> str:
    """
    Get Jira bearer token from environment or default.
    
    Returns:
        str: Jira bearer token
    """
    return os.getenv("JIRA_TOKEN", DEFAULT_JIRA_TOKEN)


def get_jira_project_key() -> str:
    """
    Get Jira project key from environment or default.
    
    Returns:
        str: Jira project key
    """
    return os.getenv("JIRA_PROJECT_KEY", DEFAULT_JIRA_PROJECT_KEY)


def get_custom_fields() -> Dict[str, str]:
    """
    Get custom fields configuration from environment or defaults.
    
    Returns:
        dict: Custom fields mapping
    """
    # Try to get from environment variable (JSON string)
    custom_fields_env = os.getenv("JIRA_CUSTOM_FIELDS")
    if custom_fields_env:
        try:
            import json
            return json.loads(custom_fields_env)
        except (json.JSONDecodeError, ImportError):
            pass
    
    return DEFAULT_CUSTOM_FIELDS.copy()


def get_column_mappings() -> Dict[str, str]:
    """
    Get column mappings configuration from environment or defaults.
    
    Returns:
        dict: Column mappings
    """
    # Try to get from environment variable (JSON string)
    column_mappings_env = os.getenv("JIRA_COLUMN_MAPPINGS")
    if column_mappings_env:
        try:
            import json
            return json.loads(column_mappings_env)
        except (json.JSONDecodeError, ImportError):
            pass
    
    return DEFAULT_COLUMN_MAPPINGS.copy()


def set_jira_config(base_url: Optional[str] = None, token: Optional[str] = None, project_key: Optional[str] = None):
    """
    Set Jira configuration values.
    
    Args:
        base_url (str, optional): Jira base URL
        token (str, optional): Jira bearer token
        project_key (str, optional): Jira project key
    """
    if base_url:
        os.environ["JIRA_BASE_URL"] = base_url
    if token:
        os.environ["JIRA_TOKEN"] = token
    if project_key:
        os.environ["JIRA_PROJECT_KEY"] = project_key


def set_custom_fields(custom_fields: Dict[str, str]):
    """
    Set custom fields configuration.
    
    Args:
        custom_fields (dict): Custom fields mapping
    """
    import json
    os.environ["JIRA_CUSTOM_FIELDS"] = json.dumps(custom_fields)


def set_column_mappings(column_mappings: Dict[str, str]):
    """
    Set column mappings configuration.
    
    Args:
        column_mappings (dict): Column mappings
    """
    import json
    os.environ["JIRA_COLUMN_MAPPINGS"] = json.dumps(column_mappings)


def update_default_token(new_token: str):
    """
    Update the default token in this configuration file.
    Note: This modifies the source code - use environment variables for production.
    
    Args:
        new_token (str): New bearer token
    """
    global DEFAULT_JIRA_TOKEN
    DEFAULT_JIRA_TOKEN = new_token
    print(f"Default token updated to: {new_token[:10]}...")


def update_default_project_key(new_project_key: str):
    """
    Update the default project key in this configuration file.
    Note: This modifies the source code - use environment variables for production.
    
    Args:
        new_project_key (str): New project key
    """
    global DEFAULT_JIRA_PROJECT_KEY
    DEFAULT_JIRA_PROJECT_KEY = new_project_key
    print(f"Default project key updated to: {new_project_key}")


def print_current_config():
    """
    Print current Jira configuration.
    """
    config = get_jira_config()
    custom_fields = get_custom_fields()
    column_mappings = get_column_mappings()
    
    print("Current Jira Configuration:")
    print(f"  Base URL: {config['base_url']}")
    print(f"  Token: {config['token'][:10]}..." if len(config['token']) > 10 else f"  Token: {config['token']}")
    print(f"  Project Key: {config['project_key']}")
    print(f"  Custom Fields: {len(custom_fields)} configured")
    print(f"  Column Mappings: {len(column_mappings)} configured")


def get_full_config() -> Dict[str, Any]:
    """
    Get complete configuration including custom fields and column mappings.
    
    Returns:
        dict: Complete configuration dictionary
    """
    return {
        **get_jira_config(),
        "custom_fields": get_custom_fields(),
        "column_mappings": get_column_mappings()
    }


def get_unified_excel_config():
    """
    Get unified Excel file configuration.
    
    Returns:
        dict: Unified Excel configuration
    """
    return {
        "file": os.getenv("UNIFIED_EXCEL_FILE", DEFAULT_UNIFIED_EXCEL_FILE),
        "sheet": os.getenv("UNIFIED_EXCEL_SHEET", DEFAULT_UNIFIED_SHEET),
        "columns": UNIFIED_EXCEL_COLUMNS,
        "template": UNIFIED_EXCEL_TEMPLATE
    }


def get_unified_excel_file():
    """
    Get unified Excel file path.
    
    Returns:
        str: Path to unified Excel file
    """
    return os.getenv("UNIFIED_EXCEL_FILE", DEFAULT_UNIFIED_EXCEL_FILE)


def get_unified_excel_sheet():
    """
    Get unified Excel sheet name.
    
    Returns:
        str: Sheet name
    """
    return os.getenv("UNIFIED_EXCEL_SHEET", DEFAULT_UNIFIED_SHEET)


def get_unified_excel_columns():
    """
    Get unified Excel column mappings.
    
    Returns:
        dict: Column mappings
    """
    return UNIFIED_EXCEL_COLUMNS


def get_unified_excel_template():
    """
    Get unified Excel template structure.
    
    Returns:
        dict: Template structure with columns and sample data
    """
    return UNIFIED_EXCEL_TEMPLATE


def set_unified_excel_config(file_path=None, sheet_name=None):
    """
    Set unified Excel configuration.
    
    Args:
        file_path (str): Path to unified Excel file
        sheet_name (str): Sheet name
    """
    if file_path:
        os.environ["UNIFIED_EXCEL_FILE"] = file_path
    if sheet_name:
        os.environ["UNIFIED_EXCEL_SHEET"] = sheet_name


def create_unified_excel_template(file_path=None):
    """
    Create a unified Excel template file.
    
    Args:
        file_path (str): Path to create the template file (optional)
        
    Returns:
        str: Path to created template file
    """
    if not file_path:
        file_path = get_unified_excel_file()
    
    template = get_unified_excel_template()
    
    # Create DataFrame with template structure
    df = pd.DataFrame(template["sample_data"], columns=template["columns"])
    
    # Write to Excel
    df.to_excel(file_path, sheet_name=get_unified_excel_sheet(), index=False)
    
    print(f"✅ Created unified Excel template: {file_path}")
    print(f"📊 Template includes {len(template['columns'])} columns")
    print(f"📋 Sample data with {len(template['sample_data'])} rows")
    
    return file_path


def get_issue_type_config():
    """
    Get issue type configuration.
    
    Returns:
        dict: Issue type configuration with ID and name
    """
    return {
        "id": os.getenv("JIRA_ISSUE_TYPE_ID", DEFAULT_ISSUE_TYPE_ID),
        "name": os.getenv("JIRA_ISSUE_TYPE_NAME", DEFAULT_ISSUE_TYPE_NAME)
    }


def get_priority_config():
    """
    Get priority configuration.
    
    Returns:
        str: Priority name
    """
    return os.getenv("JIRA_PRIORITY_NAME", DEFAULT_PRIORITY_NAME)


def get_labels_config():
    """
    Get labels configuration.
    
    Returns:
        list: List of labels
    """
    labels_env = os.getenv("JIRA_LABELS", "")
    if labels_env:
        return [label.strip() for label in labels_env.split(",") if label.strip()]
    return DEFAULT_LABELS


def get_custom_field_12200_config():
    """
    Get custom field 12200 configuration.
    
    Returns:
        str: Custom field value
    """
    return os.getenv("JIRA_CUSTOM_FIELD_12200_VALUE", DEFAULT_CUSTOM_FIELD_12200_VALUE)


def set_issue_type_config(issue_type_id=None, issue_type_name=None):
    """
    Set issue type configuration.
    
    Args:
        issue_type_id (str): Issue type ID
        issue_type_name (str): Issue type name
    """
    if issue_type_id:
        os.environ["JIRA_ISSUE_TYPE_ID"] = issue_type_id
    if issue_type_name:
        os.environ["JIRA_ISSUE_TYPE_NAME"] = issue_type_name


def set_priority_config(priority_name):
    """
    Set priority configuration.
    
    Args:
        priority_name (str): Priority name
    """
    os.environ["JIRA_PRIORITY_NAME"] = priority_name


def set_labels_config(labels):
    """
    Set labels configuration.
    
    Args:
        labels (list): List of labels
    """
    if isinstance(labels, list):
        labels_str = ",".join(labels)
        os.environ["JIRA_LABELS"] = labels_str
    else:
        os.environ["JIRA_LABELS"] = str(labels)


def set_custom_field_12200_config(value):
    """
    Set custom field 12200 configuration.
    
    Args:
        value (str): Custom field value
    """
    os.environ["JIRA_CUSTOM_FIELD_12200_VALUE"] = value


def get_ticket_creation_config():
    """
    Get complete ticket creation configuration.
    
    Returns:
        dict: Complete ticket creation configuration
    """
    return {
        "issue_type": get_issue_type_config(),
        "priority": get_priority_config(),
        "labels": get_labels_config(),
        "custom_field_12200": get_custom_field_12200_config(),
        "project_key": get_jira_config().get("project_key")
    }


if __name__ == "__main__":
    # Interactive configuration setup
    print("Jira Configuration Setup")
    print("=" * 30)
    
    current_config = get_jira_config()
    print(f"Current base URL: {current_config['base_url']}")
    print(f"Current token: {current_config['token'][:10]}..." if len(current_config['token']) > 10 else f"Current token: {current_config['token']}")
    print(f"Current project key: {current_config['project_key']}")
    
    print("\nOptions:")
    print("1. Set environment variables (recommended)")
    print("2. Update default values in this file")
    print("3. View current configuration")
    print("4. Configure custom fields")
    print("5. Configure column mappings")
    
    choice = input("\nEnter your choice (1-5): ")
    
    if choice == "1":
        print("\nSet these environment variables:")
        print("Windows (PowerShell):")
        print('$env:JIRA_BASE_URL="https://your-jira.com"')
        print('$env:JIRA_TOKEN="your_bearer_token"')
        print('$env:JIRA_PROJECT_KEY="PROJ"')
        print("\nLinux/Mac:")
        print('export JIRA_BASE_URL="https://your-jira.com"')
        print('export JIRA_TOKEN="your_bearer_token"')
        print('export JIRA_PROJECT_KEY="PROJ"')
    
    elif choice == "2":
        new_url = input("Enter new base URL (or press Enter to keep current): ").strip()
        new_token = input("Enter new bearer token (or press Enter to keep current): ").strip()
        new_project = input("Enter new project key (or press Enter to keep current): ").strip()
        
        if new_url:
            DEFAULT_JIRA_BASE_URL = new_url
        if new_token:
            update_default_token(new_token)
        if new_project:
            update_default_project_key(new_project)
        
        print("Configuration updated!")
    
    elif choice == "3":
        print_current_config()
    
    elif choice == "4":
        print("\nCurrent custom fields:")
        custom_fields = get_custom_fields()
        for field_name, field_id in custom_fields.items():
            print(f"  {field_name}: {field_id}")
        
        print("\nTo update custom fields, set the JIRA_CUSTOM_FIELDS environment variable:")
        print('export JIRA_CUSTOM_FIELDS=\'{"Security Ticket": "customfield_10001", "Risk Level": "customfield_10002"}\'')
    
    elif choice == "5":
        print("\nCurrent column mappings:")
        column_mappings = get_column_mappings()
        for config_key, excel_column in column_mappings.items():
            print(f"  {config_key}: {excel_column}")
        
        print("\nTo update column mappings, set the JIRA_COLUMN_MAPPINGS environment variable:")
        print('export JIRA_COLUMN_MAPPINGS=\'{"status": "finding_status", "security_ticket": "jira_ticket"}\'')
    
    else:
        print("Invalid choice.") 