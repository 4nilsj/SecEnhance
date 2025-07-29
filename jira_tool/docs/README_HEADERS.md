# Jira API Headers Configuration

This document describes the centralized headers configuration system for Jira API requests.

## Overview

The `jira_headers.py` module provides centralized header configuration for all Jira API requests across the codebase. This eliminates code duplication and ensures consistency in API authentication and content type handling.

## Files

- `utils/jira_headers.py` - Main headers configuration module
- `test_headers.py` - Test script to verify headers functionality

## Functions

### `get_jira_headers(token, content_type="application/json")`

Returns standard Jira API headers for GET, POST, PUT, and DELETE requests.

**Parameters:**
- `token` (str): Jira API token
- `content_type` (str): Content-Type header value (default: "application/json")

**Returns:**
- `Dict[str, str]`: Headers dictionary with Authorization and Content-Type

**Example:**
```python
headers = get_jira_headers("your_api_token")
# Returns: {"Authorization": "Bearer your_api_token", "Content-Type": "application/json"}
```

### `get_jira_attachment_headers(token)`

Returns headers specifically for Jira attachment uploads.

**Parameters:**
- `token` (str): Jira API token

**Returns:**
- `Dict[str, str]`: Headers dictionary with Authorization and X-Atlassian-Token

**Example:**
```python
headers = get_jira_attachment_headers("your_api_token")
# Returns: {"Authorization": "Bearer your_api_token", "X-Atlassian-Token": "no-check"}
```

### `get_jira_headers_with_custom_content_type(token, content_type)`

Returns Jira headers with a custom content type.

**Parameters:**
- `token` (str): Jira API token
- `content_type` (str): Custom content type

**Returns:**
- `Dict[str, str]`: Headers dictionary with custom content type

## Usage in Scripts

### Before (Old Way)
```python
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}
```

### After (New Way)
```python
from utils.jira_headers import get_jira_headers

headers = get_jira_headers(token)
```

### For Attachments
```python
from utils.jira_headers import get_jira_attachment_headers

headers = get_jira_attachment_headers(token)
```

## Updated Scripts

The following scripts have been updated to use the centralized headers:

### Standard API Requests
- `bulk_create.py`
- `bulk_create_sync.py`
- `bulk_update.py`
- `bulk_update_sync.py`
- `bulk_comment.py`
- `bulk_comment_sync.py`
- `bulk_status.py`
- `bulk_status_sync.py`
- `bulk_transition.py`
- `bulk_transition_sync.py`
- `bulk_delete_sync.py`
- `bulk_linked_status.py`

### Attachment Requests
- `bulk_attachment.py`
- `bulk_attachment_sync.py`
- `bulk_attachment_excel.py`
- `bulk_attachment_excel_db.py`

## Benefits

1. **Consistency**: All scripts use the same header format
2. **Maintainability**: Header changes only need to be made in one place
3. **Reduced Code Duplication**: Eliminates repeated header definitions
4. **Type Safety**: Proper type hints for better IDE support
5. **Flexibility**: Easy to add new header types or modify existing ones

## Testing

Run the test script to verify headers configuration:

```bash
cd jira_tool
python test_headers.py
```

## Migration Guide

If you have existing scripts that need to be updated:

1. Add the import statement:
   ```python
   import sys
   import os
   sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
   from utils.jira_headers import get_jira_headers
   ```

2. Replace hardcoded headers with function calls:
   ```python
   # Old
   headers = {
       "Authorization": f"Bearer {token}",
       "Content-Type": "application/json"
   }
   
   # New
   headers = get_jira_headers(token)
   ```

3. For attachment scripts, use:
   ```python
   from utils.jira_headers import get_jira_attachment_headers
   headers = get_jira_attachment_headers(token)
   ```

## Future Enhancements

- Add support for different authentication methods (Basic Auth, OAuth)
- Add header validation
- Add support for custom headers
- Add header caching for performance 