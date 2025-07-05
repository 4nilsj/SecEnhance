#!/usr/bin/env python3
"""
Security Checklist Generator
A comprehensive tool for generating security checklists with detailed test procedures.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import csv
import argparse

class SecurityChecklistGenerator:
    def __init__(self):
        self.checklists = {}
        self.current_checklist = {}
        self.test_procedures = {}
        
    def load_security_frameworks(self):
        """Load predefined security frameworks and checklists."""
        self.frameworks = {
            "OWASP_TOP_10": {
                "name": "OWASP Top 10 2021",
                "description": "Most critical web application security risks",
                "categories": [
                    "A01:2021 - Broken Access Control",
                    "A02:2021 - Cryptographic Failures", 
                    "A03:2021 - Injection",
                    "A04:2021 - Insecure Design",
                    "A05:2021 - Security Misconfiguration",
                    "A06:2021 - Vulnerable and Outdated Components",
                    "A07:2021 - Identification and Authentication Failures",
                    "A08:2021 - Software and Data Integrity Failures",
                    "A09:2021 - Security Logging and Monitoring Failures",
                    "A10:2021 - Server-Side Request Forgery (SSRF)"
                ]
            },
            "API_SECURITY": {
                "name": "API Security Checklist",
                "description": "Comprehensive API security testing checklist",
                "categories": [
                    "Authentication & Authorization",
                    "Input Validation & Sanitization",
                    "Data Protection",
                    "Error Handling",
                    "Rate Limiting",
                    "Logging & Monitoring"
                ]
            },
            "MOBILE_APP_SECURITY": {
                "name": "Mobile App Security Checklist",
                "description": "Mobile application security assessment",
                "categories": [
                    "Data Storage Security",
                    "Network Communication",
                    "Authentication & Session Management",
                    "Code Security",
                    "Platform Security",
                    "Privacy & Compliance"
                ]
            },
            "CLOUD_SECURITY": {
                "name": "Cloud Security Checklist",
                "description": "Cloud infrastructure security assessment",
                "categories": [
                    "Identity & Access Management",
                    "Data Protection",
                    "Network Security",
                    "Compliance & Governance",
                    "Monitoring & Logging",
                    "Incident Response"
                ]
            }
        }
        
        # Load detailed test procedures
        self.load_test_procedures()
    
    def load_test_procedures(self):
        """Load detailed test procedures for each security control."""
        self.test_procedures = {
            "OWASP_TOP_10": {
                "A01:2021 - Broken Access Control": {
                    "controls": [
                        {
                            "id": "A01-01",
                            "control": "Verify that access controls are enforced on every request",
                            "test_procedure": """
1. **Manual Testing:**
   - Log in as a regular user
   - Try to access admin-only endpoints (e.g., /admin, /api/admin/*)
   - Attempt to access other users' data by changing IDs in URLs
   - Test horizontal and vertical privilege escalation

2. **Automated Testing:**
   - Use Burp Suite to intercept requests
   - Modify user IDs, roles, or permissions in requests
   - Test with different user accounts
   - Verify API endpoints with different authorization levels

3. **Tools:**
   - Burp Suite Professional
   - OWASP ZAP
   - Custom scripts for role testing

4. **Expected Result:** All unauthorized access attempts should be blocked with proper error messages
                            """,
                            "risk_level": "Critical",
                            "tools": ["Burp Suite", "OWASP ZAP", "Custom Scripts"],
                            "automation_possible": True
                        },
                        {
                            "id": "A01-02", 
                            "control": "Verify that JWT tokens are properly validated",
                            "test_procedure": """
1. **Token Analysis:**
   - Decode JWT tokens using jwt.io
   - Check token expiration times
   - Verify signature algorithms
   - Test with expired tokens

2. **Token Manipulation:**
   - Modify payload claims (user ID, roles)
   - Test with invalid signatures
   - Try algorithm confusion attacks
   - Test token replay attacks

3. **Tools:**
   - jwt.io for token analysis
   - Burp Suite JWT extension
   - Custom JWT testing scripts

4. **Expected Result:** Invalid or expired tokens should be rejected
                            """,
                            "risk_level": "High",
                            "tools": ["jwt.io", "Burp Suite", "Custom Scripts"],
                            "automation_possible": True
                        }
                    ]
                },
                "A02:2021 - Cryptographic Failures": {
                    "controls": [
                        {
                            "id": "A02-01",
                            "control": "Verify that sensitive data is encrypted in transit",
                            "test_procedure": """
1. **Transport Security:**
   - Check for HTTPS enforcement
   - Verify TLS version (1.2 or higher)
   - Test for weak cipher suites
   - Check certificate validity

2. **Tools:**
   - SSL Labs SSL Test
   - Nmap with SSL scripts
   - OpenSSL command line
   - Burp Suite SSL analysis

3. **Commands:**
   ```bash
   nmap --script ssl-enum-ciphers -p 443 target.com
   openssl s_client -connect target.com:443 -servername target.com
   ```

4. **Expected Result:** All sensitive data transmission should use strong encryption
                            """,
                            "risk_level": "Critical",
                            "tools": ["SSL Labs", "Nmap", "OpenSSL", "Burp Suite"],
                            "automation_possible": True
                        }
                    ]
                }
            },
            "API_SECURITY": {
                "Authentication & Authorization": {
                    "controls": [
                        {
                            "id": "API-01",
                            "control": "Verify API authentication mechanisms",
                            "test_procedure": """
1. **Authentication Testing:**
   - Test with missing authentication headers
   - Test with invalid API keys
   - Test with expired tokens
   - Test OAuth flows if applicable

2. **Authorization Testing:**
   - Test role-based access control
   - Test resource-level permissions
   - Test API endpoint access with different roles

3. **Tools:**
   - Postman for API testing
   - Burp Suite for intercepting requests
   - Custom API testing scripts

4. **Expected Result:** Proper authentication and authorization enforcement
                            """,
                            "risk_level": "Critical",
                            "tools": ["Postman", "Burp Suite", "Custom Scripts"],
                            "automation_possible": True
                        }
                    ]
                }
            }
        }
    
    def create_custom_checklist(self):
        """Create a custom security checklist."""
        print("\n🔧 Creating Custom Security Checklist")
        print("=" * 50)
        
        checklist_name = input("Enter checklist name: ").strip()
        checklist_description = input("Enter checklist description: ").strip()
        
        self.current_checklist = {
            "name": checklist_name,
            "description": checklist_description,
            "created_date": datetime.now().isoformat(),
            "categories": []
        }
        
        while True:
            print(f"\n📋 Current categories: {len(self.current_checklist['categories'])}")
            for i, cat in enumerate(self.current_checklist['categories'], 1):
                print(f"  {i}. {cat['name']}")
            
            choice = input("\nAdd new category? (y/n): ").lower().strip()
            if choice != 'y':
                break
                
            category_name = input("Enter category name: ").strip()
            category_description = input("Enter category description: ").strip()
            
            category = {
                "name": category_name,
                "description": category_description,
                "controls": []
            }
            
            # Add controls to category
            while True:
                control_choice = input(f"\nAdd control to '{category_name}'? (y/n): ").lower().strip()
                if control_choice != 'y':
                    break
                    
                control_id = input("Enter control ID: ").strip()
                control_text = input("Enter control description: ").strip()
                risk_level = input("Enter risk level (Low/Medium/High/Critical): ").strip()
                
                control = {
                    "id": control_id,
                    "control": control_text,
                    "risk_level": risk_level,
                    "test_procedure": "",
                    "tools": [],
                    "automation_possible": False
                }
                
                # Add test procedure
                print("\nEnter test procedure (press Enter twice to finish):")
                test_procedure_lines = []
                while True:
                    line = input()
                    if line == "" and test_procedure_lines and test_procedure_lines[-1] == "":
                        break
                    test_procedure_lines.append(line)
                
                control["test_procedure"] = "\n".join(test_procedure_lines[:-1])  # Remove last empty line
                
                category["controls"].append(control)
            
            self.current_checklist["categories"].append(category)
        
        # Save custom checklist
        filename = f"custom_checklist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.current_checklist, f, indent=2)
        
        print(f"\n✅ Custom checklist saved as: {filename}")
        return self.current_checklist
    
    def select_framework(self):
        """Let user select a security framework."""
        print("\n📚 Available Security Frameworks:")
        print("=" * 40)
        
        frameworks = list(self.frameworks.keys())
        for i, key in enumerate(frameworks, 1):
            framework = self.frameworks[key]
            print(f"{i}. {framework['name']}")
            print(f"   {framework['description']}")
            print()
        
        while True:
            try:
                choice = int(input("Select framework (1-{}): ".format(len(frameworks))))
                if 1 <= choice <= len(frameworks):
                    return frameworks[choice - 1]
                else:
                    print("❌ Invalid selection. Please try again.")
            except ValueError:
                print("❌ Please enter a valid number.")
    
    def generate_checklist(self, framework_key: str, output_format: str = "json"):
        """Generate checklist for selected framework."""
        framework = self.frameworks[framework_key]
        
        checklist = {
            "framework": framework["name"],
            "description": framework["description"],
            "generated_date": datetime.now().isoformat(),
            "categories": []
        }
        
        for category in framework["categories"]:
            category_data = {
                "name": category,
                "controls": []
            }
            
            # Add controls from test procedures if available
            if framework_key in self.test_procedures and category in self.test_procedures[framework_key]:
                category_data["controls"] = self.test_procedures[framework_key][category]["controls"]
            
            checklist["categories"].append(category_data)
        
        # Save checklist
        filename = f"{framework_key.lower()}_checklist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{output_format}"
        
        if output_format == "json":
            with open(filename, 'w') as f:
                json.dump(checklist, f, indent=2)
        elif output_format == "csv":
            self.save_as_csv(checklist, filename)
        
        print(f"\n✅ Checklist generated: {filename}")
        return checklist
    
    def save_as_csv(self, checklist: Dict, filename: str):
        """Save checklist as CSV format."""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Category', 'Control_ID', 'Control', 'Risk_Level', 'Test_Procedure', 'Tools', 'Automation_Possible']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for category in checklist["categories"]:
                for control in category.get("controls", []):
                    writer.writerow({
                        'Category': category["name"],
                        'Control_ID': control.get("id", ""),
                        'Control': control.get("control", ""),
                        'Risk_Level': control.get("risk_level", ""),
                        'Test_Procedure': control.get("test_procedure", ""),
                        'Tools': ", ".join(control.get("tools", [])),
                        'Automation_Possible': control.get("automation_possible", False)
                    })
    
    def view_checklist(self, checklist: Dict):
        """Display the generated checklist."""
        print(f"\n📋 {checklist['framework']}")
        print("=" * 60)
        print(f"Description: {checklist['description']}")
        print(f"Generated: {checklist['generated_date']}")
        print()
        
        for category in checklist["categories"]:
            print(f"🔸 {category['name']}")
            print("-" * 40)
            
            for control in category.get("controls", []):
                print(f"  {control.get('id', 'N/A')}: {control.get('control', 'N/A')}")
                print(f"    Risk Level: {control.get('risk_level', 'N/A')}")
                print(f"    Tools: {', '.join(control.get('tools', []))}")
                print(f"    Automation: {'Yes' if control.get('automation_possible', False) else 'No'}")
                print()
    
    def interactive_mode(self):
        """Run the tool in interactive mode."""
        print("🔒 Security Checklist Generator")
        print("=" * 50)
        print("Generate comprehensive security checklists with detailed test procedures")
        
        self.load_security_frameworks()
        
        while True:
            print("\n📋 Main Menu:")
            print("1. Generate framework-based checklist")
            print("2. Create custom checklist")
            print("3. View available frameworks")
            print("4. Exit")
            
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == "1":
                framework = self.select_framework()
                output_format = input("Output format (json/csv): ").strip().lower()
                if output_format not in ["json", "csv"]:
                    output_format = "json"
                
                checklist = self.generate_checklist(framework, output_format)
                
                view_choice = input("\nView generated checklist? (y/n): ").lower().strip()
                if view_choice == 'y':
                    self.view_checklist(checklist)
            
            elif choice == "2":
                self.create_custom_checklist()
            
            elif choice == "3":
                print("\n📚 Available Frameworks:")
                for key, framework in self.frameworks.items():
                    print(f"\n🔸 {framework['name']}")
                    print(f"   {framework['description']}")
                    print(f"   Categories: {len(framework['categories'])}")
            
            elif choice == "4":
                print("\n👋 Thank you for using Security Checklist Generator!")
                break
            
            else:
                print("❌ Invalid option. Please try again.")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Security Checklist Generator")
    parser.add_argument("--framework", help="Generate checklist for specific framework")
    parser.add_argument("--output", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    
    args = parser.parse_args()
    
    generator = SecurityChecklistGenerator()
    
    if args.interactive or not args.framework:
        generator.interactive_mode()
    else:
        generator.load_security_frameworks()
        if args.framework.upper() in generator.frameworks:
            checklist = generator.generate_checklist(args.framework.upper(), args.output)
            generator.view_checklist(checklist)
        else:
            print(f"❌ Framework '{args.framework}' not found.")
            print("Available frameworks:", list(generator.frameworks.keys()))

if __name__ == "__main__":
    main() 