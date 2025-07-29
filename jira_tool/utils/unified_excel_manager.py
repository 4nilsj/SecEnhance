#!/usr/bin/env python3
"""
Unified Excel Manager
Manages the unified Excel file that contains all Jira tool data in a single sheet.
"""

import os
import sys
import pandas as pd
from pathlib import Path
from datetime import datetime

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import (
    get_unified_excel_config, get_unified_excel_file, get_unified_excel_sheet,
    get_unified_excel_columns, get_unified_excel_template, create_unified_excel_template,
    set_unified_excel_config
)


def create_unified_excel_file(file_path=None, overwrite=False):
    """
    Create a new unified Excel file with template structure.
    
    Args:
        file_path (str): Path to create the file (optional)
        overwrite (bool): Whether to overwrite existing file
        
    Returns:
        str: Path to created file
    """
    if not file_path:
        file_path = get_unified_excel_file()
    
    # Check if file exists
    if os.path.exists(file_path) and not overwrite:
        print(f"⚠️  File already exists: {file_path}")
        print("Use --overwrite to replace existing file")
        return file_path
    
    # Create template
    created_file = create_unified_excel_template(file_path)
    
    print(f"✅ Unified Excel file created: {created_file}")
    print("📊 This file can be used for all Jira tool operations")
    print("🔧 Configure it in your environment or use --excel parameter")
    
    return created_file


def validate_unified_excel_file(file_path=None):
    """
    Validate that a unified Excel file has the correct structure.
    
    Args:
        file_path (str): Path to Excel file (optional)
        
    Returns:
        tuple: (is_valid, missing_columns, extra_columns)
    """
    if not file_path:
        file_path = get_unified_excel_file()
    
    if not os.path.exists(file_path):
        return False, [], []
    
    try:
        # Read Excel file
        df = pd.read_excel(file_path, sheet_name=get_unified_excel_sheet())
        
        # Get expected columns
        expected_columns = get_unified_excel_template()["columns"]
        actual_columns = list(df.columns)
        
        # Find missing and extra columns
        missing_columns = [col for col in expected_columns if col not in actual_columns]
        extra_columns = [col for col in actual_columns if col not in expected_columns]
        
        is_valid = len(missing_columns) == 0
        
        return is_valid, missing_columns, extra_columns
        
    except Exception as e:
        print(f"❌ Error validating file: {str(e)}")
        return False, [], []


def update_unified_excel_structure(file_path=None):
    """
    Update an existing Excel file to match the unified structure.
    
    Args:
        file_path (str): Path to Excel file (optional)
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not file_path:
        file_path = get_unified_excel_file()
    
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False
    
    try:
        # Read existing file
        df = pd.read_excel(file_path, sheet_name=get_unified_excel_sheet())
        
        # Get expected columns
        expected_columns = get_unified_excel_template()["columns"]
        
        # Add missing columns
        for col in expected_columns:
            if col not in df.columns:
                df[col] = ""
                print(f"➕ Added missing column: {col}")
        
        # Reorder columns to match template
        df = df.reindex(columns=expected_columns)
        
        # Write back to file
        df.to_excel(file_path, sheet_name=get_unified_excel_sheet(), index=False)
        
        print(f"✅ Updated file structure: {file_path}")
        print(f"📊 File now has {len(expected_columns)} columns")
        
        return True
        
    except Exception as e:
        print(f"❌ Error updating file: {str(e)}")
        return False


def get_unified_excel_info(file_path=None):
    """
    Get information about the unified Excel file.
    
    Args:
        file_path (str): Path to Excel file (optional)
        
    Returns:
        dict: File information
    """
    if not file_path:
        file_path = get_unified_excel_file()
    
    info = {
        "file_path": file_path,
        "sheet_name": get_unified_excel_sheet(),
        "exists": os.path.exists(file_path),
        "columns": [],
        "row_count": 0,
        "is_valid": False
    }
    
    if info["exists"]:
        try:
            df = pd.read_excel(file_path, sheet_name=get_unified_excel_sheet())
            info["columns"] = list(df.columns)
            info["row_count"] = len(df)
            
            # Validate structure
            is_valid, missing, extra = validate_unified_excel_file(file_path)
            info["is_valid"] = is_valid
            info["missing_columns"] = missing
            info["extra_columns"] = extra
            
        except Exception as e:
            info["error"] = str(e)
    
    return info


def print_unified_excel_info(file_path=None):
    """
    Print information about the unified Excel file.
    
    Args:
        file_path (str): Path to Excel file (optional)
    """
    info = get_unified_excel_info(file_path)
    
    print("📊 Unified Excel File Information")
    print("=" * 50)
    print(f"File: {info['file_path']}")
    print(f"Sheet: {info['sheet_name']}")
    print(f"Exists: {'✅ Yes' if info['exists'] else '❌ No'}")
    
    if info["exists"]:
        print(f"Rows: {info['row_count']}")
        print(f"Columns: {len(info['columns'])}")
        print(f"Valid Structure: {'✅ Yes' if info['is_valid'] else '❌ No'}")
        
        if not info["is_valid"]:
            if info.get("missing_columns"):
                print(f"Missing Columns: {', '.join(info['missing_columns'])}")
            if info.get("extra_columns"):
                print(f"Extra Columns: {', '.join(info['extra_columns'])}")
        
        print("\n📋 Columns:")
        for i, col in enumerate(info["columns"], 1):
            print(f"  {i:2d}. {col}")
    
    else:
        print("\n💡 To create the file, run: python utils/unified_excel_manager.py --create")


def main():
    """Main function for unified Excel management."""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Manage unified Excel file for Jira tool operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create new unified Excel file
  python utils/unified_excel_manager.py --create
  
  # Create with custom path
  python utils/unified_excel_manager.py --create --file my_data.xlsx
  
  # Validate existing file
  python utils/unified_excel_manager.py --validate
  
  # Update file structure
  python utils/unified_excel_manager.py --update
  
  # Show file information
  python utils/unified_excel_manager.py --info
        """
    )
    
    parser.add_argument("--create", action="store_true", help="Create new unified Excel file")
    parser.add_argument("--validate", action="store_true", help="Validate existing file structure")
    parser.add_argument("--update", action="store_true", help="Update file to match unified structure")
    parser.add_argument("--info", action="store_true", help="Show file information")
    parser.add_argument("--file", help="Custom file path")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing file when creating")
    
    args = parser.parse_args()
    
    if args.create:
        create_unified_excel_file(args.file, args.overwrite)
    
    elif args.validate:
        is_valid, missing, extra = validate_unified_excel_file(args.file)
        if is_valid:
            print("✅ File structure is valid")
        else:
            print("❌ File structure is invalid")
            if missing:
                print(f"Missing columns: {', '.join(missing)}")
            if extra:
                print(f"Extra columns: {', '.join(extra)}")
    
    elif args.update:
        success = update_unified_excel_structure(args.file)
        if success:
            print("✅ File structure updated successfully")
        else:
            print("❌ Failed to update file structure")
    
    elif args.info:
        print_unified_excel_info(args.file)
    
    else:
        # Default: show info
        print_unified_excel_info(args.file)


if __name__ == "__main__":
    main() 