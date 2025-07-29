# Jira API URL Configuration

This document describes the centralized URL configuration system for Jira API endpoints.

## Overview

The `jira_urls.py` module provides centralized URL configuration for all Jira API endpoints across the codebase. This eliminates code duplication and ensures consistency in API endpoint construction.

## Files

- `utils/jira_urls.py` - Main URL configuration module
- `test_urls.py` - Test script to verify URL functionality

## Configuration

### Default Base URL
The default Jira base URL is set to: `https://www.examplejira.com`

This can be customized by passing a custom URL to the functions.

## Functions

### `get_jira_base_url(custom_url=None)`

Returns the Jira base URL.

**Parameters:**
- `custom_url` (str, optional): Custom Jira URL. If None, uses default.

**Returns:**
- `str`: Jira base URL

**Example:**
```python
base_url = get_jira_base_url()
# Returns: "https://www.examplejira.com"

custom_base = get_jira_base_url("https://mycompany.jira.com")
# Returns: "https://mycompany.jira.com"
```

### `build_jira_api_url(base_url, endpoint)`

Builds a complete Jira API URL.

**Parameters:**
- `base_url` (str): Jira base URL
- `endpoint` (str): API endpoint path

**Returns:**
- `str`: Complete Jira API URL

**Example:**
```python
url = build_jira_api_url("https://jira.com", "/rest/api/latest/issue")
# Returns: "https://jira.com/rest/api/latest/issue"
```

### `get_issue_url(base_url, issue_key)`

Gets URL for a specific Jira issue.

**Parameters:**
- `base_url` (str): Jira base URL
- `issue_key` (str): Jira issue key (e.g., "PROJ-123")

**Returns:**
- `str`: Complete URL for the issue

**Example:**
```python
url = get_issue_url("https://jira.com", "PROJ-123")
# Returns: "https://jira.com/rest/api/latest/issue/PROJ-123"
```

### `get_create_issue_url(base_url)`

Gets URL for creating new Jira issues.

**Parameters:**
- `base_url` (str): Jira base URL

**Returns:**
- `str`: Complete URL for creating issues

**Example:**
```python
url = get_create_issue_url("https://jira.com")
# Returns: "https://jira.com/rest/api/latest/issue"
```

### `get_issue_comment_url(base_url, issue_key)`

Gets URL for adding comments to a Jira issue.

**Parameters:**
- `base_url` (str): Jira base URL
- `issue_key` (str): Jira issue key

**Returns:**
- `str`: Complete URL for issue comments

**Example:**
```python
url = get_issue_comment_url("https://jira.com", "PROJ-123")
# Returns: "https://jira.com/rest/api/latest/issue/PROJ-123/comment"
```

### `get_issue_transitions_url(base_url, issue_key)`

Gets URL for Jira issue transitions.

**Parameters:**
- `base_url` (str): Jira base URL
- `issue_key` (str): Jira issue key

**Returns:**
- `str`: Complete URL for issue transitions

**Example:**
```python
url = get_issue_transitions_url("https://jira.com", "PROJ-123")
# Returns: "https://jira.com/rest/api/latest/issue/PROJ-123/transitions"
```

### `get_issue_attachments_url(base_url, issue_key)`

Gets URL for uploading attachments to a Jira issue.

**Parameters:**
- `base_url` (str): Jira base URL
- `issue_key` (str): Jira issue key

**Returns:**
- `str`: Complete URL for issue attachments

**Example:**
```python
url = get_issue_attachments_url("https://jira.com", "PROJ-123")
# Returns: "https://jira.com/rest/api/latest/issue/PROJ-123/attachments"
```

### `get_project_url(base_url, project_key)`

Gets URL for a specific Jira project.

**Parameters:**
- `base_url` (str): Jira base URL
- `project_key` (str): Jira project key

**Returns:**
- `str`: Complete URL for the project

**Example:**
```python
url = get_project_url("https://jira.com", "PROJ")
# Returns: "https://jira.com/rest/api/latest/project/PROJ"
```

### `get_projects_url(base_url)`

Gets URL for listing all Jira projects.

**Parameters:**
- `base_url` (str): Jira base URL

**Returns:**
- `str`: Complete URL for projects list

**Example:**
```python
url = get_projects_url("https://jira.com")
# Returns: "https://jira.com/rest/api/latest/project"
```

## Usage in Scripts

### Before (Old Way)
```python
api_url = f"{url}/rest/api/latest/issue/{ticket_id}"
```

### After (New Way)
```python
from utils.jira_urls import get_issue_url

api_url = get_issue_url(url, ticket_id)
```

### For Different Endpoints
```python
from utils.jira_urls import (
    get_create_issue_url,
    get_issue_comment_url,
    get_issue_transitions_url,
    get_issue_attachments_url
)

# Create issue
create_url = get_create_issue_url(url)

# Add comment
comment_url = get_issue_comment_url(url, ticket_id)

# Get transitions
transitions_url = get_issue_transitions_url(url, ticket_id)

# Upload attachment
attachment_url = get_issue_attachments_url(url, ticket_id)
```

## Updated Scripts

The following scripts have been updated to use the centralized URLs:

### Standard API Request Scripts
- `bulk_create.py` ✅
- `bulk_create_sync.py` ✅
- `bulk_update.py` ✅
- `bulk_update_sync.py` ✅
- `bulk_comment.py` ✅
- `bulk_comment_sync.py` ✅
- `bulk_status.py` ✅
- `bulk_status_sync.py` ✅
- `bulk_transition.py` ✅
- `bulk_transition_sync.py` ✅
- `bulk_delete_sync.py` ✅
- `bulk_linked_status.py` ✅

### Attachment Scripts
- `bulk_attachment.py` ✅
- `bulk_attachment_sync.py` ✅
- `bulk_attachment_excel.py` ✅
- `bulk_attachment_excel_db.py` ✅

## Benefits

1. **Consistency**: All scripts use the same URL construction logic
2. **Maintainability**: URL changes only need to be made in one place
3. **Reduced Code Duplication**: Eliminates repeated URL construction
4. **Type Safety**: Proper type hints for better IDE support
5. **Flexibility**: Easy to add new endpoints or modify existing ones
6. **Default Configuration**: Centralized default base URL

## Testing

Run the test script to verify URL configuration:

```bash
cd jira_tool
python test_urls.py
```

## Migration Guide

If you have existing scripts that need to be updated:

1. Add the import statement:
   ```python
   from utils.jira_urls import get_issue_url  # or appropriate function
   ```

2. Replace hardcoded URLs with function calls:
   ```python
   # Old
   api_url = f"{url}/rest/api/latest/issue/{ticket_id}"
   
   # New
   api_url = get_issue_url(url, ticket_id)
   ```

3. For different endpoints, use the appropriate function:
   ```python
   # Comments
   api_url = get_issue_comment_url(url, ticket_id)
   
   # Transitions
   api_url = get_issue_transitions_url(url, ticket_id)
   
   # Attachments
   api_url = get_issue_attachments_url(url, ticket_id)
   ```

## Future Enhancements

- Add support for different Jira API versions
- Add URL validation
- Add support for custom endpoints
- Add URL caching for performance
- Add support for different Jira instances (Cloud vs Server) 