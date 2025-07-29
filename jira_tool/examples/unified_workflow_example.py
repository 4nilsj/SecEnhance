#!/usr/bin/env python3
"""
Unified Workflow Example
Demonstrates how to use the unified Excel file for a complete workflow.
"""

import os
import sys
import subprocess
from pathlib import Path

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import get_unified_excel_file, create_unified_excel_template


def run_operation(operation, excel_file, **kwargs):
    """
    Run a Jira tool operation.
    
    Args:
        operation (str): Operation to run
        excel_file (str): Excel file path
        **kwargs: Additional arguments
    """
    cmd = ["python", "main.py", operation, "--excel", excel_file]
    
    # Add additional arguments
    for key, value in kwargs.items():
        if value:
            cmd.extend([f"--{key}", str(value)])
    
    print(f"🔄 Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        if result.returncode == 0:
            print(f"✅ {operation} completed successfully")
            if result.stdout:
                print(f"Output: {result.stdout}")
        else:
            print(f"❌ {operation} failed")
            if result.stderr:
                print(f"Error: {result.stderr}")
                
    except Exception as e:
        print(f"❌ Error running {operation}: {str(e)}")


def main():
    """Main function demonstrating unified workflow."""
    
    print("🚀 Unified Excel Workflow Example")
    print("=" * 50)
    
    # Get unified Excel file path
    excel_file = get_unified_excel_file()
    
    print(f"📊 Using unified Excel file: {excel_file}")
    
    # Check if file exists, create if not
    if not os.path.exists(excel_file):
        print(f"📝 Creating unified Excel file: {excel_file}")
        create_unified_excel_template(excel_file)
    else:
        print(f"✅ Unified Excel file exists: {excel_file}")
    
    print("\n🔄 Starting complete workflow...")
    
    # Step 1: Create true positive tickets
    print("\n1️⃣ Creating true positive tickets...")
    run_operation("true-positive", excel_file, 
                  project="SEC", 
                  issue_type="Bug", 
                  priority="High")
    
    # Step 2: Security workflow transition
    print("\n2️⃣ Running security workflow transitions...")
    run_operation("security-workflow", excel_file)
    
    # Step 3: Update custom fields
    print("\n3️⃣ Updating custom fields...")
    run_operation("custom-fields", excel_file,
                  custom_fields="Risk Level:customfield_10002,Environment:customfield_10003")
    
    # Step 4: Upload POC files
    print("\n4️⃣ Uploading POC files...")
    run_operation("poc-upload", excel_file,
                  poc_dir="./poc_files")
    
    # Step 5: Fetch linked tickets
    print("\n5️⃣ Fetching linked tickets...")
    run_operation("fetch-linked-tickets", excel_file,
                  dev_keywords="dev,fix,implementation")
    
    # Step 6: Dev workflow transition
    print("\n6️⃣ Running dev workflow transitions...")
    run_operation("dev-workflow", excel_file)
    
    # Step 7: Add dev status comments
    print("\n7️⃣ Adding dev status comments...")
    run_operation("dev-status-comment", excel_file)
    
    print("\n✅ Complete workflow finished!")
    print(f"📊 All results saved to: {excel_file}")
    print("\n📋 Next steps:")
    print("   - Review the Excel file for results")
    print("   - Check processing status columns")
    print("   - Validate workflow completion")
    print("   - Generate reports from unified data")


if __name__ == "__main__":
    main() 