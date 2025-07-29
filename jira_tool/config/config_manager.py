#!/usr/bin/env python3
"""
Jira Configuration Manager
Interactive tool to manage Jira configuration including custom fields and column mappings.
"""

import os
import json
import sys
from typing import Dict, Any

# Add the parent directory to the path to import settings
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import (
    get_jira_config, get_custom_fields, get_column_mappings,
    set_jira_config, set_custom_fields, set_column_mappings,
    print_current_config
)


def display_menu():
    """Display the main menu."""
    print("\n🔧 Jira Configuration Manager")
    print("=" * 40)
    print("1. View Current Configuration")
    print("2. Set Jira Connection (URL, Token, Project)")
    print("3. Configure Custom Fields")
    print("4. Configure Column Mappings")
    print("5. Configure Ticket Creation Settings")
    print("6. Export Configuration")
    print("7. Import Configuration")
    print("8. Set Environment Variables")
    print("9. Test Configuration")
    print("0. Exit")
    print("=" * 40)


def view_current_config():
    """Display current configuration."""
    print("\n📋 Current Configuration")
    print("-" * 30)
    
    # Jira connection
    config = get_jira_config()
    print(f"Jira URL: {config['base_url']}")
    print(f"Token: {config['token'][:10]}..." if len(config['token']) > 10 else f"Token: {config['token']}")
    print(f"Project Key: {config['project_key']}")
    
    # Custom fields
    custom_fields = get_custom_fields()
    print(f"\nCustom Fields ({len(custom_fields)}):")
    for field_name, field_id in custom_fields.items():
        print(f"  {field_name}: {field_id}")
    
    # Column mappings
    column_mappings = get_column_mappings()
    print(f"\nColumn Mappings ({len(column_mappings)}):")
    for config_key, excel_column in column_mappings.items():
        print(f"  {config_key}: {excel_column}")


def set_jira_connection():
    """Set Jira connection parameters."""
    print("\n🔗 Set Jira Connection")
    print("-" * 25)
    
    current_config = get_jira_config()
    
    url = input(f"Jira Base URL [{current_config['base_url']}]: ").strip()
    if not url:
        url = current_config['base_url']
    
    token = input(f"Jira API Token [{current_config['token'][:10]}...]: ").strip()
    if not token:
        token = current_config['token']
    
    project = input(f"Project Key [{current_config['project_key']}]: ").strip()
    if not project:
        project = current_config['project_key']
    
    # Set configuration
    set_jira_config(url, token, project)
    print("✅ Jira connection configuration updated!")


def configure_custom_fields():
    """Configure custom fields."""
    print("\n🔧 Configure Custom Fields")
    print("-" * 30)
    
    current_fields = get_custom_fields()
    print("Current custom fields:")
    for field_name, field_id in current_fields.items():
        print(f"  {field_name}: {field_id}")
    
    print("\nOptions:")
    print("1. Add new custom field")
    print("2. Update existing custom field")
    print("3. Remove custom field")
    print("4. Reset to defaults")
    print("5. Import from JSON")
    
    choice = input("\nEnter choice (1-5): ").strip()
    
    if choice == "1":
        field_name = input("Field name: ").strip()
        field_id = input("Custom field ID: ").strip()
        if field_name and field_id:
            current_fields[field_name] = field_id
            set_custom_fields(current_fields)
            print("✅ Custom field added!")
    
    elif choice == "2":
        field_name = input("Field name to update: ").strip()
        if field_name in current_fields:
            field_id = input(f"New custom field ID [{current_fields[field_name]}]: ").strip()
            if field_id:
                current_fields[field_name] = field_id
                set_custom_fields(current_fields)
                print("✅ Custom field updated!")
        else:
            print("❌ Field not found!")
    
    elif choice == "3":
        field_name = input("Field name to remove: ").strip()
        if field_name in current_fields:
            del current_fields[field_name]
            set_custom_fields(current_fields)
            print("✅ Custom field removed!")
        else:
            print("❌ Field not found!")
    
    elif choice == "4":
        from config.settings import DEFAULT_CUSTOM_FIELDS
        set_custom_fields(DEFAULT_CUSTOM_FIELDS)
        print("✅ Reset to default custom fields!")
    
    elif choice == "5":
        json_file = input("JSON file path: ").strip()
        try:
            with open(json_file, 'r') as f:
                fields = json.load(f)
            set_custom_fields(fields)
            print("✅ Custom fields imported!")
        except Exception as e:
            print(f"❌ Error importing: {e}")


def configure_column_mappings():
    """Configure column mappings."""
    print("\n📊 Configure Column Mappings")
    print("-" * 35)
    
    current_mappings = get_column_mappings()
    print("Current column mappings:")
    for config_key, excel_column in current_mappings.items():
        print(f"  {config_key}: {excel_column}")
    
    print("\nOptions:")
    print("1. Update column mapping")
    print("2. Reset to defaults")
    print("3. Import from JSON")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == "1":
        config_key = input("Configuration key (e.g., status, security_ticket): ").strip()
        if config_key in current_mappings:
            excel_column = input(f"Excel column name [{current_mappings[config_key]}]: ").strip()
            if excel_column:
                current_mappings[config_key] = excel_column
                set_column_mappings(current_mappings)
                print("✅ Column mapping updated!")
        else:
            print("❌ Configuration key not found!")
    
    elif choice == "2":
        from config.settings import DEFAULT_COLUMN_MAPPINGS
        set_column_mappings(DEFAULT_COLUMN_MAPPINGS)
        print("✅ Reset to default column mappings!")
    
    elif choice == "3":
        json_file = input("JSON file path: ").strip()
        try:
            with open(json_file, 'r') as f:
                mappings = json.load(f)
            set_column_mappings(mappings)
            print("✅ Column mappings imported!")
        except Exception as e:
            print(f"❌ Error importing: {e}")


def configure_ticket_creation():
    """Configure ticket creation settings."""
    print("\n🎫 Configure Ticket Creation Settings")
    print("=" * 40)
    
    from config.settings import (
        get_issue_type_config, get_priority_config, get_labels_config, 
        get_custom_field_12200_config, get_ticket_creation_config,
        set_issue_type_config, set_priority_config, set_labels_config, 
        set_custom_field_12200_config
    )
    
    while True:
        print("\n📋 Ticket Creation Options:")
        print("1. Configure Issue Type")
        print("2. Configure Priority")
        print("3. Configure Labels")
        print("4. Configure Custom Field 12200")
        print("5. Display Current Settings")
        print("6. Back to Main Menu")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            configure_issue_type()
        elif choice == "2":
            configure_priority()
        elif choice == "3":
            configure_labels()
        elif choice == "4":
            configure_custom_field()
        elif choice == "5":
            display_ticket_config()
        elif choice == "6":
            break
        else:
            print("❌ Invalid choice. Please enter a number between 1-6.")


def configure_issue_type():
    """Configure issue type settings."""
    print("\n🔧 Configure Issue Type")
    print("-" * 30)
    
    from config.settings import get_issue_type_config, set_issue_type_config
    
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
    
    from config.settings import get_priority_config, set_priority_config
    
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
    
    from config.settings import get_labels_config, set_labels_config
    
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
    
    from config.settings import get_custom_field_12200_config, set_custom_field_12200_config
    
    current_value = get_custom_field_12200_config()
    print(f"Current Value: {current_value}")
    
    value = input("Enter Custom Field Value (or press Enter to keep current): ").strip()
    
    if value:
        set_custom_field_12200_config(value)
        print("✅ Custom field configuration updated!")
    else:
        print("ℹ️  No changes made to custom field configuration.")


def display_ticket_config():
    """Display current ticket creation configuration."""
    print("\n🔧 Current Ticket Creation Configuration")
    print("=" * 50)
    
    from config.settings import get_ticket_creation_config
    
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


def export_configuration():
    """Export configuration to JSON file."""
    print("\n📤 Export Configuration")
    print("-" * 25)
    
    config = get_full_config()
    filename = input("Export filename [jira_config.json]: ").strip() or "jira_config.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✅ Configuration exported to {filename}!")
    except Exception as e:
        print(f"❌ Error exporting: {e}")


def import_configuration():
    """Import configuration from JSON file."""
    print("\n📥 Import Configuration")
    print("-" * 25)
    
    filename = input("Import filename: ").strip()
    
    try:
        with open(filename, 'r') as f:
            config = json.load(f)
        
        # Set Jira connection
        if 'base_url' in config and 'token' in config and 'project_key' in config:
            set_jira_config(config['base_url'], config['token'], config['project_key'])
        
        # Set custom fields
        if 'custom_fields' in config:
            set_custom_fields(config['custom_fields'])
        
        # Set column mappings
        if 'column_mappings' in config:
            set_column_mappings(config['column_mappings'])
        
        print("✅ Configuration imported!")
    except Exception as e:
        print(f"❌ Error importing: {e}")


def set_environment_variables():
    """Set environment variables for the current session."""
    print("\n🔧 Set Environment Variables")
    print("-" * 35)
    
    config = get_jira_config()
    custom_fields = get_custom_fields()
    column_mappings = get_column_mappings()
    
    # Set Jira connection
    os.environ["JIRA_BASE_URL"] = config['base_url']
    os.environ["JIRA_TOKEN"] = config['token']
    os.environ["JIRA_PROJECT_KEY"] = config['project_key']
    
    # Set custom fields
    os.environ["JIRA_CUSTOM_FIELDS"] = json.dumps(custom_fields)
    
    # Set column mappings
    os.environ["JIRA_COLUMN_MAPPINGS"] = json.dumps(column_mappings)
    
    print("✅ Environment variables set for current session!")
    print("\nTo make permanent, add to your shell profile:")
    print(f'export JIRA_BASE_URL="{config["base_url"]}"')
    print(f'export JIRA_TOKEN="{config["token"]}"')
    print(f'export JIRA_PROJECT_KEY="{config["project_key"]}"')
    print(f'export JIRA_CUSTOM_FIELDS=\'{json.dumps(custom_fields)}\'')
    print(f'export JIRA_COLUMN_MAPPINGS=\'{json.dumps(column_mappings)}\'')


def test_configuration():
    """Test the current configuration."""
    print("\n🧪 Test Configuration")
    print("-" * 25)
    
    try:
        import requests
        from core.headers import get_jira_headers
        
        config = get_jira_config()
        headers = get_jira_headers(config['token'])
        
        # Test connection
        response = requests.get(f"{config['base_url']}/rest/api/latest/myself", headers=headers, verify=False)
        
        if response.status_code == 200:
            user_info = response.json()
            print(f"✅ Connection successful!")
            print(f"   Connected as: {user_info.get('displayName', 'Unknown')}")
            print(f"   Email: {user_info.get('emailAddress', 'Unknown')}")
        else:
            print(f"❌ Connection failed: {response.status_code}")
            print(f"   Response: {response.text}")
        
        # Test project access
        project_response = requests.get(f"{config['base_url']}/rest/api/latest/project/{config['project_key']}", headers=headers, verify=False)
        
        if project_response.status_code == 200:
            project_info = project_response.json()
            print(f"✅ Project access successful!")
            print(f"   Project: {project_info.get('name', 'Unknown')} ({project_info.get('key', 'Unknown')})")
        else:
            print(f"❌ Project access failed: {project_response.status_code}")
            print(f"   Response: {project_response.text}")
        
        # Show configuration summary
        custom_fields = get_custom_fields()
        column_mappings = get_column_mappings()
        
        print(f"\n📊 Configuration Summary:")
        print(f"   Custom Fields: {len(custom_fields)} configured")
        print(f"   Column Mappings: {len(column_mappings)} configured")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")


def get_full_config() -> Dict[str, Any]:
    """Get complete configuration."""
    return {
        **get_jira_config(),
        "custom_fields": get_custom_fields(),
        "column_mappings": get_column_mappings()
    }


def main():
    """Main function for configuration management."""
    while True:
        display_menu()
        choice = input("\nEnter your choice (0-9): ").strip()
        
        if choice == "1":
            view_current_config()
        elif choice == "2":
            set_jira_connection()
        elif choice == "3":
            configure_custom_fields()
        elif choice == "4":
            configure_column_mappings()
        elif choice == "5":
            configure_ticket_creation()
        elif choice == "6":
            export_configuration()
        elif choice == "7":
            import_configuration()
        elif choice == "8":
            set_environment_variables()
        elif choice == "9":
            test_configuration()
        elif choice == "0":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter a number between 0-9.")
        
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main() 