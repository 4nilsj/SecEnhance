#!/usr/bin/env python3
"""
Jira Tool Main Entry Point
"""

import sys
import argparse
from pathlib import Path


def main():
    """Main entry point for the Jira tool."""
    
    parser = argparse.ArgumentParser(
        description="Jira Tool - Bulk operations for Jira",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create tickets
  python main.py create --excel data.xlsx --project PROJ
  
  # Update tickets
  python main.py update --excel data.xlsx --fields summary,description
  
  # Add comments
  python main.py comment --excel data.xlsx --comment "Updated status"
  
  # Get status
  python main.py status --excel data.xlsx
  
  # Upload attachments
  python main.py attachments --dir ./files --excel data.xlsx
  
For more information, see the documentation in docs/ directory.
        """
    )
    
    parser.add_argument(
        "operation",
        choices=["create", "true-positive", "update", "custom-fields", "comment", "dev-status-comment", "status", "fetch-linked-tickets", "transition", "security-workflow", "dev-workflow", "attachments", "delete"],
        help="Type of operation to perform"
    )
    
    parser.add_argument("--excel", required=True, help="Input Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--url", help="Jira base URL (or set JIRA_BASE_URL env var)")
    parser.add_argument("--token", help="Jira API token (or set JIRA_TOKEN env var)")
    parser.add_argument("--project", help="Jira project key (for create operations)")
    parser.add_argument("--fields", nargs="+", help="Fields to update (for update operations)")
    parser.add_argument("--comment", help="Comment text (for comment operations)")
    parser.add_argument("--dir", help="Directory with files (for attachment operations)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    # Import the appropriate script based on operation
    try:
        if args.operation == "create":
            from scripts.bulk_operations.create.bulk_create import main as create_main
            create_main()
        elif args.operation == "true-positive":
            from scripts.bulk_operations.create.bulk_create_true_positive import main as true_positive_main
            true_positive_main()
        elif args.operation == "update":
            from scripts.bulk_operations.update.bulk_update import main as update_main
            update_main()
        elif args.operation == "custom-fields":
            from scripts.bulk_operations.update.bulk_update_custom_fields import main as custom_fields_main
            custom_fields_main()
        elif args.operation == "comment":
            from scripts.bulk_operations.comment.bulk_comment import main as comment_main
            comment_main()
        elif args.operation == "dev-status-comment":
            from scripts.bulk_operations.comment.bulk_comment_dev_status import main as dev_status_comment_main
            dev_status_comment_main()
        elif args.operation == "status":
            from scripts.bulk_operations.status.bulk_status import main as status_main
            status_main()
        elif args.operation == "fetch-linked-tickets":
            from scripts.bulk_operations.linked_status.bulk_fetch_linked_tickets import main as fetch_linked_tickets_main
            fetch_linked_tickets_main()
        elif args.operation == "transition":
            from scripts.bulk_operations.transition.bulk_transition import main as transition_main
            transition_main()
        elif args.operation == "security-workflow":
            from scripts.bulk_operations.transition.bulk_transition_security_workflow import main as security_workflow_main
            security_workflow_main()
        elif args.operation == "dev-workflow":
            from scripts.bulk_operations.transition.bulk_transition_dev_workflow import main as dev_workflow_main
            dev_workflow_main()
        elif args.operation == "attachments":
            from scripts.attachments.bulk_attachment import main as attachment_main
            attachment_main()
        elif args.operation == "delete":
            from scripts.bulk_operations.delete.bulk_delete_sync import main as delete_main
            delete_main()
        else:
            print(f"Unknown operation: {args.operation}")
            sys.exit(1)
            
    except ImportError as e:
        print(f"Error importing operation module: {e}")
        print("Make sure all dependencies are installed.")
        sys.exit(1)
    except Exception as e:
        print(f"Error executing operation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 