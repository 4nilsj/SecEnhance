#!/usr/bin/env python3
"""
Ticket Configuration Manager
Interactive script to manage ticket creation configuration settings.
"""

import os
import sys
from pathlib import Path

# Add the parent directory to the path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import (
    get_issue_type_config, get_priority_config, get_labels_config, 
    get_custom_field_12200_config, get_ticket_creation_config,
    set_issue_type_config, set_priority_config, set_labels_config, 
    set_custom_field_12200_config
)


def display_current_config():
    """Display current ticket creation configuration."""
    print("🔧 Current Ticket Creation Configuration")
    print("=" * 50)
    
    config = get_ticket_creation_config()
    
    print(f"📋 Issue Type:")
    print(f"   ID: {config['issue_type']['id']}")
    print(f"   Name: {config['issue_type']['name']}")
    print()
    
    print(f"📋 Priority: {config['priority']}")
    print()
    
    print(f"📋 Labels: {config['labels']}")
    print()
    
    print(f"📋 Custom Field 12200: {config['custom_field_12200']}")
    print()
    
    print(f"📋 Project Key: {config['project_key']}")
    print("=" * 50)


def configure_issue_type():
    """Configure issue type settings."""
    print("\n🔧 Configure Issue Type")
    print("-" * 30)
    
    current_config = get_issue_type_config()
    print(f"Current Issue Type ID: {current_config['id']}")
    print(f"Current Issue Type Name: {current_config['name']}")
    
    issue_type_id = input("Enter Issue Type ID (or press Enter to keep current): ").strip()
    issue_type_name = input("Enter Issue Type Name (or press Enter to keep current): ").strip()
    
    if issue_type_id or issue_type_name:
        set_issue_type_config(
            issue_type_id if issue_type_id else None,
            issue_type_name if issue_type_name else None
        )
        print("✅ Issue type configuration updated!")
    else:
        print("ℹ️  No changes made to issue type configuration.")


def configure_priority():
    """Configure priority settings."""
    print("\n🔧 Configure Priority")
    print("-" * 20)
    
    current_priority = get_priority_config()
    print(f"Current Priority: {current_priority}")
    
    priority = input("Enter Priority Name (or press Enter to keep current): ").strip()
    
    if priority:
        set_priority_config(priority)
        print("✅ Priority configuration updated!")
    else:
        print("ℹ️  No changes made to priority configuration.")


def configure_labels():
    """Configure labels settings."""
    print("\n🔧 Configure Labels")
    print("-" * 15)
    
    current_labels = get_labels_config()
    print(f"Current Labels: {current_labels}")
    
    labels_input = input("Enter Labels (comma-separated, or press Enter to keep current): ").strip()
    
    if labels_input:
        labels = [label.strip() for label in labels_input.split(",") if label.strip()]
        set_labels_config(labels)
        print("✅ Labels configuration updated!")
    else:
        print("ℹ️  No changes made to labels configuration.")


def configure_custom_field():
    """Configure custom field 12200 settings."""
    print("\n🔧 Configure Custom Field 12200")
    print("-" * 35)
    
    current_value = get_custom_field_12200_config()
    print(f"Current Value: {current_value}")
    
    value = input("Enter Custom Field Value (or press Enter to keep current): ").strip()
    
    if value:
        set_custom_field_12200_config(value)
        print("✅ Custom field configuration updated!")
    else:
        print("ℹ️  No changes made to custom field configuration.")


def main():
    """Main function for ticket configuration management."""
    
    print("🎫 Ticket Configuration Manager")
    print("=" * 40)
    
    while True:
        print("\n📋 Available Options:")
        print("1. Display current configuration")
        print("2. Configure Issue Type")
        print("3. Configure Priority")
        print("4. Configure Labels")
        print("5. Configure Custom Field 12200")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            display_current_config()
        elif choice == "2":
            configure_issue_type()
        elif choice == "3":
            configure_priority()
        elif choice == "4":
            configure_labels()
        elif choice == "5":
            configure_custom_field()
        elif choice == "6":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter a number between 1-6.")


if __name__ == "__main__":
    main() 