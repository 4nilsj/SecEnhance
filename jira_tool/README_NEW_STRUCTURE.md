# Jira Tool - Restructured Package

## Overview

The Jira Tool has been restructured for better organization, maintainability, and scalability. This new structure provides clear separation of concerns and makes it easier to find and modify specific functionality.

## New Folder Structure

```
jira_tool/
├── README.md                          # Main documentation
├── requirements.txt                    # Dependencies
├── setup.py                          # Package setup
├── main.py                           # Main entry point
├── config/
│   ├── __init__.py
│   ├── settings.py                   # Main configuration
│   └── token_manager.py              # Token management
├── core/
│   ├── __init__.py
│   ├── headers.py                   # Headers configuration
│   └── urls.py                      # URL configuration
├── scripts/
│   ├── __init__.py
│   ├── bulk_operations/
│   │   ├── __init__.py
│   │   ├── create/
│   │   │   ├── __init__.py
│   │   │   ├── bulk_create.py
│   │   │   └── bulk_create_sync.py
│   │   ├── update/
│   │   │   ├── __init__.py
│   │   │   ├── bulk_update.py
│   │   │   └── bulk_update_sync.py
│   │   ├── comment/
│   │   │   ├── __init__.py
│   │   │   ├── bulk_comment.py
│   │   │   └── bulk_comment_sync.py
│   │   ├── status/
│   │   │   ├── __init__.py
│   │   │   ├── bulk_status.py
│   │   │   └── bulk_status_sync.py
│   │   ├── transition/
│   │   │   ├── __init__.py
│   │   │   ├── bulk_transition.py
│   │   │   └── bulk_transition_sync.py
│   │   ├── delete/
│   │   │   ├── __init__.py
│   │   │   └── bulk_delete_sync.py
│   │   └── linked_status/
│   │       ├── __init__.py
│   │       └── bulk_linked_status.py
│   ├── attachments/
│   │   ├── __init__.py
│   │   ├── bulk_attachment.py
│   │   ├── bulk_attachment_sync.py
│   │   ├── bulk_attachment_excel.py
│   │   └── bulk_attachment_excel_db.py
│   └── data_sync/
│       ├── __init__.py
│       ├── sync_excel_sqlite.py
│       └── excel_to_sqlite.py
├── utils/
│   ├── __init__.py
│   ├── debug_utils.py
│   └── data_sync_utils.py
├── web/
│   ├── __init__.py
│   └── app.py
├── docs/
│   ├── README.md
│   ├── TOKEN_MANAGEMENT_GUIDE.md
│   ├── HEADERS_MIGRATION_SUMMARY.md
│   ├── URLS_MIGRATION_SUMMARY.md
│   ├── README_HEADERS.md
│   └── README_URLS.md
├── examples/
│   ├── sample_input.xlsx
│   └── sample_scripts/
├── logs/
│   └── .gitkeep
└── tests/
    ├── __init__.py
    ├── test_headers.py
    ├── test_urls.py
    └── test_config.py
```

## Key Improvements

### 1. **Clear Separation of Concerns**
- **`config/`** - Configuration management and token handling
- **`core/`** - Core Jira functionality (headers, URLs)
- **`scripts/`** - Bulk operation scripts organized by functionality
- **`web/`** - Web interface components
- **`docs/`** - All documentation in one place
- **`utils/`** - Utility functions and helpers
- **`tests/`** - Test files
- **`examples/`** - Sample data and scripts

### 2. **Organized Scripts**
Scripts are now organized by functionality:
- **`bulk_operations/create/`** - Create ticket operations
- **`bulk_operations/update/`** - Update ticket operations
- **`bulk_operations/comment/`** - Comment operations
- **`bulk_operations/status/`** - Status operations
- **`bulk_operations/transition/`** - Transition operations
- **`bulk_operations/delete/`** - Delete operations
- **`bulk_operations/linked_status/`** - Linked status operations
- **`attachments/`** - File attachment operations
- **`data_sync/`** - Data synchronization operations

### 3. **Centralized Configuration**
- **`config/settings.py`** - Main configuration with environment variable support
- **`config/token_manager.py`** - Token management and updates

### 4. **Core Functionality**
- **`core/headers.py`** - Centralized headers configuration
- **`core/urls.py`** - Centralized URL configuration

## Usage

### Quick Start
```bash
# Install the package
pip install -e .

# Run operations using the main entry point
python main.py create --excel data.xlsx --project PROJ
python main.py update --excel data.xlsx --fields summary,description
python main.py comment --excel data.xlsx --comment "Updated status"
```

### Direct Script Usage
```bash
# Create tickets
python scripts/bulk_operations/create/bulk_create.py --excel data.xlsx --project PROJ

# Update tickets
python scripts/bulk_operations/update/bulk_update.py --excel data.xlsx --fields summary,description

# Upload attachments
python scripts/attachments/bulk_attachment.py --dir ./files --excel data.xlsx
```

### Configuration
```bash
# Set up configuration
python config/token_manager.py

# Or set environment variables
export JIRA_BASE_URL="https://your-jira.com"
export JIRA_TOKEN="your_bearer_token"
```

## Migration from Old Structure

### Import Changes
Old imports:
```python
from utils.jira_headers import get_jira_headers
from utils.jira_urls import get_create_issue_url
```

New imports:
```python
from core.headers import get_jira_headers
from core.urls import get_create_issue_url
```

### Configuration Changes
Old:
```python
from config import get_jira_config
```

New:
```python
from config.settings import get_jira_config
```

## Benefits

### 1. **Maintainability**
- Clear file organization
- Easy to find specific functionality
- Reduced code duplication

### 2. **Scalability**
- Easy to add new operations
- Modular design
- Clear import paths

### 3. **Documentation**
- All docs in one place
- Clear API reference
- Migration guides preserved

### 4. **Testing**
- Dedicated test directory
- Easy to add new tests
- Clear test organization

### 5. **Configuration**
- Centralized configuration
- Environment variable support
- Easy token management

## Development

### Adding New Operations
1. Create new directory in `scripts/bulk_operations/`
2. Add `__init__.py` file
3. Create your script with proper imports
4. Update `main.py` if needed
5. Add tests in `tests/`

### Adding New Core Functionality
1. Add to `core/` directory
2. Update `core/__init__.py`
3. Update imports in scripts
4. Add documentation

### Configuration Updates
1. Modify `config/settings.py` for new settings
2. Update `config/token_manager.py` if needed
3. Update documentation

## Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific tests
python tests/test_headers.py
python tests/test_urls.py
python tests/test_config.py
```

## Documentation

All documentation is now in the `docs/` directory:
- **`TOKEN_MANAGEMENT_GUIDE.md`** - Token setup and management
- **`HEADERS_MIGRATION_SUMMARY.md`** - Headers migration details
- **`URLS_MIGRATION_SUMMARY.md`** - URL migration details
- **`README_HEADERS.md`** - Headers configuration guide
- **`README_URLS.md`** - URL configuration guide

## Support

For issues or questions:
1. Check the documentation in `docs/`
2. Review the migration guides
3. Test with the provided examples
4. Check the test files for usage examples

The new structure provides a solid foundation for future development and makes the codebase much more maintainable and professional. 