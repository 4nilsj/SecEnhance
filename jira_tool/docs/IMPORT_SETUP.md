# Generic Import Setup for Jira Tool Scripts

## Overview

This document explains how to set up imports in any script within the Jira Tool project. The approach is designed to work on any system with any folder structure.

## The Problem

Previously, scripts used hardcoded path calculations like:
```python
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
```

This approach:
- ❌ Is hardcoded to specific directory depths
- ❌ Breaks when moved to different systems
- ❌ Requires manual calculation for each script location
- ❌ Is error-prone and difficult to maintain

## The Solution

Use the generic import setup that automatically finds the project root:

```python
import sys
from pathlib import Path

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

# Now you can import from any module
from core.headers import get_jira_headers
from utils.data_sync_utils import read_excel
from config.settings import get_jira_config
```

## How It Works

1. **Automatic Detection**: The script automatically finds the project root by looking for `jira_tool.py`
2. **Path Resolution**: Uses `pathlib.Path` for cross-platform path handling
3. **Fallback**: If `jira_tool.py` isn't found, assumes it's in a utils directory
4. **No Hardcoding**: Works regardless of where the script is located in the project

## Benefits

✅ **Cross-Platform**: Works on Windows, Linux, macOS  
✅ **System Agnostic**: Works with any folder structure  
✅ **Maintainable**: No hardcoded paths to update  
✅ **Reliable**: Automatically finds the correct project root  
✅ **Future-Proof**: Will work even if project structure changes  

## Usage Examples

### For Scripts in `scripts/bulk_operations/create/`:
```python
import sys
from pathlib import Path

# Generic import setup
def setup_imports():
    current_script = Path(__file__).resolve()
    project_root = find_project_root(current_script)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root

def find_project_root(start_path):
    current_dir = start_path.parent
    while current_dir != current_dir.parent:
        if (current_dir / "jira_tool.py").exists():
            return str(current_dir)
        current_dir = current_dir.parent
    return str(start_path.parent.parent)

setup_imports()

# Now import normally
from core.headers import get_jira_headers
from utils.data_sync_utils import read_excel
```

### For Scripts in `scripts/attachments/`:
```python
import sys
from pathlib import Path

# Same setup works for any location
def setup_imports():
    current_script = Path(__file__).resolve()
    project_root = find_project_root(current_script)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root

def find_project_root(start_path):
    current_dir = start_path.parent
    while current_dir != current_dir.parent:
        if (current_dir / "jira_tool.py").exists():
            return str(current_dir)
        current_dir = current_dir.parent
    return str(start_path.parent.parent)

setup_imports()

# Imports work the same way
from core.headers import get_jira_headers
from utils.data_sync_utils import read_excel
```

## Migration Guide

To update existing scripts:

1. **Replace hardcoded paths** with the generic setup
2. **Add the setup functions** at the top of the script
3. **Call `setup_imports()`** before any imports
4. **Test the script** to ensure imports work

### Before:
```python
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
from core.headers import get_jira_headers
```

### After:
```python
import sys
from pathlib import Path

def setup_imports():
    current_script = Path(__file__).resolve()
    project_root = find_project_root(current_script)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    return project_root

def find_project_root(start_path):
    current_dir = start_path.parent
    while current_dir != current_dir.parent:
        if (current_dir / "jira_tool.py").exists():
            return str(current_dir)
        current_dir = current_dir.parent
    return str(start_path.parent.parent)

setup_imports()
from core.headers import get_jira_headers
```

## Testing

To test that the import setup works:

```python
# Add this to any script to debug import issues
if __name__ == "__main__":
    setup_imports()
    print(f"Project root: {find_project_root(Path(__file__).resolve())}")
    print(f"sys.path[0]: {sys.path[0]}")
    
    try:
        from core.headers import get_jira_headers
        print("✅ core.headers imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import core.headers: {e}")
```

This approach ensures that all scripts will work correctly regardless of the system or folder structure they're deployed on. 