"""
Jira API URL Configuration
Centralized URL configuration for all Jira API endpoints.
"""

from typing import Optional


# Default Jira base URL
DEFAULT_JIRA_BASE_URL = "https://www.examplejira.com"


def get_jira_base_url(custom_url: Optional[str] = None) -> str:
    """
    Get the Jira base URL.
    
    Args:
        custom_url (str, optional): Custom Jira URL. If None, uses default.
    
    Returns:
        str: Jira base URL
    """
    return custom_url if custom_url else DEFAULT_JIRA_BASE_URL


def build_jira_api_url(base_url: str, endpoint: str) -> str:
    """
    Build a complete Jira API URL.
    
    Args:
        base_url (str): Jira base URL
        endpoint (str): API endpoint path
    
    Returns:
        str: Complete Jira API URL
    """
    # Ensure base_url doesn't end with slash
    base_url = base_url.rstrip('/')
    # Ensure endpoint starts with slash
    if not endpoint.startswith('/'):
        endpoint = '/' + endpoint
    
    return f"{base_url}{endpoint}"


def get_issue_url(base_url: str, issue_key: str) -> str:
    """
    Get URL for a specific Jira issue.
    
    Args:
        base_url (str): Jira base URL
        issue_key (str): Jira issue key (e.g., "PROJ-123")
    
    Returns:
        str: Complete URL for the issue
    """
    return build_jira_api_url(base_url, f"/rest/api/latest/issue/{issue_key}")


def get_create_issue_url(base_url: str) -> str:
    """
    Get URL for creating new Jira issues.
    
    Args:
        base_url (str): Jira base URL
    
    Returns:
        str: Complete URL for creating issues
    """
    return build_jira_api_url(base_url, "/rest/api/latest/issue")


def get_issue_comment_url(base_url: str, issue_key: str) -> str:
    """
    Get URL for adding comments to a Jira issue.
    
    Args:
        base_url (str): Jira base URL
        issue_key (str): Jira issue key
    
    Returns:
        str: Complete URL for issue comments
    """
    return build_jira_api_url(base_url, f"/rest/api/latest/issue/{issue_key}/comment")


def get_issue_transitions_url(base_url: str, issue_key: str) -> str:
    """
    Get URL for Jira issue transitions.
    
    Args:
        base_url (str): Jira base URL
        issue_key (str): Jira issue key
    
    Returns:
        str: Complete URL for issue transitions
    """
    return build_jira_api_url(base_url, f"/rest/api/latest/issue/{issue_key}/transitions")


def get_issue_attachments_url(base_url: str, issue_key: str) -> str:
    """
    Get URL for uploading attachments to a Jira issue.
    
    Args:
        base_url (str): Jira base URL
        issue_key (str): Jira issue key
    
    Returns:
        str: Complete URL for issue attachments
    """
    return build_jira_api_url(base_url, f"/rest/api/latest/issue/{issue_key}/attachments")


def get_project_url(base_url: str, project_key: str) -> str:
    """
    Get URL for a specific Jira project.
    
    Args:
        base_url (str): Jira base URL
        project_key (str): Jira project key
    
    Returns:
        str: Complete URL for the project
    """
    return build_jira_api_url(base_url, f"/rest/api/latest/project/{project_key}")


def get_projects_url(base_url: str) -> str:
    """
    Get URL for listing all Jira projects.
    
    Args:
        base_url (str): Jira base URL
    
    Returns:
        str: Complete URL for projects list
    """
    return build_jira_api_url(base_url, "/rest/api/latest/project") 