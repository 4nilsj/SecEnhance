"""
Import Helper for Jira Tool Scripts

This module provides a simple way to set up imports for any script in the project.
Just add this at the top of your script:

    from utils.import_helper import setup_imports
    setup_imports()

This will automatically find the project root and set up the import paths.
"""

import sys
import os
from pathlib import Path


def setup_imports():
    """
    Set up import paths for the current script.
    This automatically finds the project root and adds it to sys.path.
    """
    # Get the directory of the current script
    current_script = Path(__file__).resolve()
    
    # Find the project root (where jira_tool.py is located)
    project_root = find_project_root(current_script)
    
    # Add to sys.path if not already there
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    return project_root


def find_project_root(start_path):
    """
    Find the project root by looking for jira_tool.py.
    
    Args:
        start_path (Path): Starting path to search from
        
    Returns:
        str: Path to project root
    """
    current_dir = start_path.parent
    
    # Walk up the directory tree
    while current_dir != current_dir.parent:  # Stop at root
        if (current_dir / "jira_tool.py").exists():
            return str(current_dir)
        current_dir = current_dir.parent
    
    # Fallback: if we can't find jira_tool.py, assume we're in utils
    # and go up one level
    return str(start_path.parent.parent)


# For backward compatibility
def get_project_root():
    """Backward compatibility function."""
    return setup_imports()


if __name__ == "__main__":
    # Test the import setup
    project_root = setup_imports()
    print(f"Project root: {project_root}")
    print(f"sys.path[0]: {sys.path[0]}")
    
    # Test imports
    try:
        from core.headers import get_jira_headers
        print("✅ Successfully imported core.headers")
    except ImportError as e:
        print(f"❌ Failed to import core.headers: {e}")
    
    try:
        from utils.data_sync_utils import read_excel
        print("✅ Successfully imported utils.data_sync_utils")
    except ImportError as e:
        print(f"❌ Failed to import utils.data_sync_utils: {e}") 