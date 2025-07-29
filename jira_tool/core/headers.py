"""
Jira API Headers Configuration
Centralized headers configuration for all Jira API requests.
"""

from typing import Dict, Optional


def get_jira_headers(token: str, content_type: str = "application/json") -> Dict[str, str]:
    """
    Get standard Jira API headers.
    
    Args:
        token (str): Jira API token
        content_type (str): Content-Type header value, defaults to "application/json"
    
    Returns:
        Dict[str, str]: Headers dictionary for Jira API requests
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": content_type
    }
    return headers


def get_jira_attachment_headers(token: str) -> Dict[str, str]:
    """
    Get headers for Jira attachment uploads.
    
    Args:
        token (str): Jira API token
    
    Returns:
        Dict[str, str]: Headers dictionary for Jira attachment requests
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Atlassian-Token": "no-check"
    }
    return headers


def get_jira_headers_with_custom_content_type(token: str, content_type: str) -> Dict[str, str]:
    """
    Get Jira headers with custom content type.
    
    Args:
        token (str): Jira API token
        content_type (str): Custom content type
    
    Returns:
        Dict[str, str]: Headers dictionary with custom content type
    """
    return get_jira_headers(token, content_type) 