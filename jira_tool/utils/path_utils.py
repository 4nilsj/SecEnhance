import os
import sys
from pathlib import Path


def get_project_root():
    """
    Automatically find the project root directory (where jira_tool.py is located).
    This works regardless of the current working directory or system structure.
    
    Returns:
        str: Path to the project root directory
    """
    # Start from the current file's directory
    current_file = Path(__file__).resolve()
    
    # Walk up the directory tree until we find jira_tool.py
    current_dir = current_file.parent
    while current_dir != current_dir.parent:  # Stop at root
        if (current_dir / "jira_tool.py").exists():
            return str(current_dir)
        current_dir = current_dir.parent
    
    # Fallback: if we can't find jira_tool.py, assume we're in the utils directory
    # and go up one level
    return str(current_file.parent.parent)


def setup_import_paths():
    """
    Set up import paths for the current script.
    This should be called at the beginning of any script that needs to import
    from core, utils, config, etc.
    """
    project_root = get_project_root()
    
    # Add the project root to sys.path if it's not already there
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    return project_root


def get_script_relative_path(script_path):
    """
    Get the relative path from a script to the project root.
    This is useful for debugging path issues.
    
    Args:
        script_path (str): Path to the script file
        
    Returns:
        str: Relative path to project root
    """
    script_dir = Path(script_path).parent.resolve()
    project_root = Path(get_project_root()).resolve()
    
    try:
        return str(script_dir.relative_to(project_root))
    except ValueError:
        return f"Outside project: {script_dir}"


# Example usage and testing
if __name__ == "__main__":
    print(f"Project root: {get_project_root()}")
    print(f"Current script relative path: {get_script_relative_path(__file__)}")
    setup_import_paths()
    print(f"sys.path[0]: {sys.path[0]}") 