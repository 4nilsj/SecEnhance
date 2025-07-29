#!/usr/bin/env python3
"""
Jira Token Update Script
Simple script to update Jira bearer token in various ways.
"""

import os
import sys
from .settings import get_jira_config, set_jira_config, update_default_token, print_current_config


def main():
    """Main function to handle token updates."""
    
    print("Jira Bearer Token Update Tool")
    print("=" * 35)
    
    # Show current configuration
    current_config = get_jira_config()
    print(f"Current base URL: {current_config['base_url']}")
    print(f"Current token: {current_config['token'][:10]}..." if len(current_config['token']) > 10 else f"Current token: {current_config['token']}")
    
    print("\nUpdate Options:")
    print("1. Set environment variables (recommended for production)")
    print("2. Update default token in config.py")
    print("3. View current configuration")
    print("4. Test current configuration")
    print("5. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            print("\n" + "="*50)
            print("ENVIRONMENT VARIABLES SETUP")
            print("="*50)
            print("\nSet these environment variables in your terminal:")
            print("\nWindows (PowerShell):")
            print('$env:JIRA_BASE_URL="https://your-jira.com"')
            print('$env:JIRA_TOKEN="your_actual_bearer_token"')
            print("\nWindows (Command Prompt):")
            print('set JIRA_BASE_URL=https://your-jira.com')
            print('set JIRA_TOKEN=your_actual_bearer_token')
            print("\nLinux/Mac:")
            print('export JIRA_BASE_URL="https://your-jira.com"')
            print('export JIRA_TOKEN="your_actual_bearer_token"')
            print("\nAfter setting environment variables, restart your terminal/IDE.")
            
        elif choice == "2":
            print("\n" + "="*50)
            print("UPDATE DEFAULT TOKEN")
            print("="*50)
            new_token = input("Enter your new bearer token: ").strip()
            if new_token:
                update_default_token(new_token)
                print("✓ Token updated in config.py")
                print("Note: This method stores the token in source code.")
                print("For production, use environment variables (option 1).")
            else:
                print("No token provided. Update cancelled.")
                
        elif choice == "3":
            print("\n" + "="*50)
            print("CURRENT CONFIGURATION")
            print("="*50)
            print_current_config()
            
        elif choice == "4":
            print("\n" + "="*50)
            print("TESTING CONFIGURATION")
            print("="*50)
            config = get_jira_config()
            print(f"Testing with:")
            print(f"  Base URL: {config['base_url']}")
            print(f"  Token: {config['token'][:10]}..." if len(config['token']) > 10 else f"  Token: {config['token']}")
            
            # Test if token looks valid (basic check)
            if config['token'] and config['token'] != "your_bearer_token_here":
                print("✓ Token appears to be set")
                print("✓ You can now run Jira scripts without --token parameter")
            else:
                print("⚠ Token not set or using default value")
                print("Please update the token first.")
                
        elif choice == "5":
            print("Exiting...")
            break
            
        else:
            print("Invalid choice. Please enter 1-5.")


if __name__ == "__main__":
    main() 