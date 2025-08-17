#!/usr/bin/env python3
"""
BCheck Builder GUI
A user-friendly interface for creating and editing BCheck files without coding knowledge.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import yaml
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import re

class BCheckBuilder:
    def __init__(self, root):
        self.root = root
        self.root.title("BCheck Builder - Burp Automation Tool")
        self.root.geometry("1200x800")
        
        # Current BCheck data
        self.current_bcheck = {
            "metadata": {
                "name": "",
                "author": "",
                "version": "1.0",
                "description": "",
                "tags": [],
                "severity": "MEDIUM",
                "cwe": "",
                "references": []
            },
            "given": {
                "then": []
            },
            "expression": "",
            "then": []
        }
        
        self.setup_ui()
        self.load_templates()
        
    def setup_ui(self):
        """Setup the main UI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="BCheck Builder", font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Metadata section
        self.create_metadata_section(main_frame)
        
        # Given section
        self.create_given_section(main_frame)
        
        # Expression section
        self.create_expression_section(main_frame)
        
        # Then section
        self.create_then_section(main_frame)
        
        # Buttons
        self.create_buttons(main_frame)
        
        # Template selector
        self.create_template_selector(main_frame)
        
    def create_metadata_section(self, parent):
        """Create the metadata input section"""
        metadata_frame = ttk.LabelFrame(parent, text="Metadata", padding="10")
        metadata_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # Name
        ttk.Label(metadata_frame, text="Name:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.name_entry = ttk.Entry(metadata_frame, width=50)
        self.name_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Author
        ttk.Label(metadata_frame, text="Author:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.author_entry = ttk.Entry(metadata_frame, width=50)
        self.author_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Version
        ttk.Label(metadata_frame, text="Version:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.version_entry = ttk.Entry(metadata_frame, width=20)
        self.version_entry.grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Description
        ttk.Label(metadata_frame, text="Description:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.description_entry = ttk.Entry(metadata_frame, width=50)
        self.description_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        
        # Severity
        ttk.Label(metadata_frame, text="Severity:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.severity_combo = ttk.Combobox(metadata_frame, values=["LOW", "MEDIUM", "HIGH", "CRITICAL"], width=20)
        self.severity_combo.grid(row=4, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        self.severity_combo.set("MEDIUM")
        
        # CWE
        ttk.Label(metadata_frame, text="CWE:").grid(row=5, column=0, sticky=tk.W, pady=2)
        self.cwe_entry = ttk.Entry(metadata_frame, width=20)
        self.cwe_entry.grid(row=5, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Tags
        ttk.Label(metadata_frame, text="Tags:").grid(row=6, column=0, sticky=tk.W, pady=2)
        self.tags_entry = ttk.Entry(metadata_frame, width=50)
        self.tags_entry.grid(row=6, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        ttk.Label(metadata_frame, text="(comma-separated)").grid(row=6, column=2, sticky=tk.W, padx=(5, 0), pady=2)
        
        # References
        ttk.Label(metadata_frame, text="References:").grid(row=7, column=0, sticky=tk.W, pady=2)
        self.references_text = scrolledtext.ScrolledText(metadata_frame, height=3, width=50)
        self.references_text.grid(row=7, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        ttk.Label(metadata_frame, text="(one per line)").grid(row=7, column=2, sticky=tk.W, padx=(5, 0), pady=2)
        
        # Configure grid weights
        metadata_frame.columnconfigure(1, weight=1)
        
    def create_given_section(self, parent):
        """Create the given conditions section"""
        given_frame = ttk.LabelFrame(parent, text="Given Conditions", padding="10")
        given_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # Method
        ttk.Label(given_frame, text="HTTP Method:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.method_combo = ttk.Combobox(given_frame, values=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], width=20)
        self.method_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        # Path conditions
        ttk.Label(given_frame, text="Path Conditions:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.path_conditions_text = scrolledtext.ScrolledText(given_frame, height=4, width=50)
        self.path_conditions_text.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=2)
        ttk.Label(given_frame, text="(one per line, e.g., contains '/api/')").grid(row=1, column=2, sticky=tk.W, padx=(5, 0), pady=2)
        
        # Configure grid weights
        given_frame.columnconfigure(1, weight=1)
        
    def create_expression_section(self, parent):
        """Create the expression section"""
        expression_frame = ttk.LabelFrame(parent, text="Expression Logic", padding="10")
        expression_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Expression editor
        self.expression_text = scrolledtext.ScrolledText(expression_frame, height=15, width=80)
        self.expression_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Quick insert buttons
        button_frame = ttk.Frame(expression_frame)
        button_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        ttk.Button(button_frame, text="Insert Request Check", command=self.insert_request_check).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Insert Response Check", command=self.insert_response_check).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Insert Header Check", command=self.insert_header_check).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="Insert Cookie Check", command=self.insert_cookie_check).pack(side=tk.LEFT, padx=(0, 5))
        
        # Configure grid weights
        expression_frame.columnconfigure(0, weight=1)
        expression_frame.rowconfigure(0, weight=1)
        
    def create_then_section(self, parent):
        """Create the then actions section"""
        then_frame = ttk.LabelFrame(parent, text="Then Actions", padding="10")
        then_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Actions list
        actions_frame = ttk.Frame(then_frame)
        actions_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add action button
        ttk.Button(actions_frame, text="Add Log Action", command=self.add_log_action).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="Add Report Action", command=self.add_report_action).pack(side=tk.LEFT, padx=(0, 5))
        
        # Actions display
        self.actions_text = scrolledtext.ScrolledText(then_frame, height=8, width=80)
        self.actions_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Configure grid weights
        then_frame.columnconfigure(0, weight=1)
        then_frame.rowconfigure(1, weight=1)
        
    def create_buttons(self, parent):
        """Create the action buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="New BCheck", command=self.new_bcheck).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Load BCheck", command=self.load_bcheck).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Save BCheck", command=self.save_bcheck).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Validate BCheck", command=self.validate_bcheck).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Export YAML", command=self.export_yaml).pack(side=tk.LEFT, padx=(0, 10))
        
    def create_template_selector(self, parent):
        """Create the template selector"""
        template_frame = ttk.LabelFrame(parent, text="Templates", padding="10")
        template_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Template dropdown
        ttk.Label(template_frame, text="Load Template:").pack(side=tk.LEFT)
        self.template_combo = ttk.Combobox(template_frame, values=[], width=40)
        self.template_combo.pack(side=tk.LEFT, padx=(10, 0))
        self.template_combo.bind("<<ComboboxSelected>>", self.load_template)
        
        # Load template button
        ttk.Button(template_frame, text="Load", command=self.load_selected_template).pack(side=tk.LEFT, padx=(10, 0))
        
    def load_templates(self):
        """Load available BCheck templates"""
        templates_dir = Path(__file__).parent.parent.parent / "bchecks" / "vulnerability_checks"
        if templates_dir.exists():
            templates = [f.stem for f in templates_dir.glob("*.bcheck")]
            self.template_combo["values"] = templates
            
    def insert_request_check(self):
        """Insert a request check template"""
        template = '''// Check request properties
let method = request.method;
let path = request.path;
let headers = request.headers;
let body = request.body;

// Example: Check if path contains sensitive endpoints
if (path.contains("/admin") || path.contains("/internal")) {
    // Your logic here
    return true;
}

return false;'''
        self.expression_text.insert(tk.INSERT, template)
        
    def insert_response_check(self):
        """Insert a response check template"""
        template = '''// Send request and check response
let response = send(request);

// Check response status
if (response.status() === 200) {
    let body = response.body();
    
    // Check response content
    if (body.contains("error") || body.contains("unauthorized")) {
        return false;
    }
    
    // Check for sensitive information
    if (body.contains("password") || body.contains("secret")) {
        return true;
    }
}

return false;'''
        self.expression_text.insert(tk.INSERT, template)
        
    def insert_header_check(self):
        """Insert a header check template"""
        template = '''// Check request headers
let headers = request.headers || {};

// Check for authentication headers
let authHeaders = ["authorization", "x-api-key", "x-auth-token"];
for (let header of authHeaders) {
    if (headers[header]) {
        // Your authentication logic here
        return true;
    }
}

return false;'''
        self.expression_text.insert(tk.INSERT, template)
        
    def insert_cookie_check(self):
        """Insert a cookie check template"""
        template = '''// Check request cookies
let cookies = request.cookies || {};

// Check for session cookies
let sessionCookies = ["session", "token", "auth"];
for (let cookie of sessionCookies) {
    if (cookies[cookie]) {
        // Your session validation logic here
        return true;
    }
}

return false;'''
        self.expression_text.insert(tk.INSERT, template)
        
    def add_log_action(self):
        """Add a log action to the then section"""
        action = '''- log:
    level: MEDIUM
    output: "Vulnerability detected"
    evidence: "Evidence of the vulnerability"'''
        self.actions_text.insert(tk.INSERT, action + "\n\n")
        
    def add_report_action(self):
        """Add a report action to the then section"""
        action = '''- report:
    issue: "Vulnerability Name"
    severity: "MEDIUM"
    confidence: "HIGH"
    detail: "Detailed description of the vulnerability"
    remediation: "How to fix the vulnerability"'''
        self.actions_text.insert(tk.INSERT, action + "\n\n")
        
    def new_bcheck(self):
        """Create a new BCheck"""
        self.current_bcheck = {
            "metadata": {
                "name": "",
                "author": "",
                "version": "1.0",
                "description": "",
                "tags": [],
                "severity": "MEDIUM",
                "cwe": "",
                "references": []
            },
            "given": {
                "then": []
            },
            "expression": "",
            "then": []
        }
        self.update_ui_from_bcheck()
        
    def load_bcheck(self):
        """Load a BCheck from file"""
        file_path = filedialog.askopenfilename(
            title="Load BCheck",
            filetypes=[("BCheck files", "*.bcheck"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Parse YAML content
                    self.current_bcheck = yaml.safe_load(content)
                    self.update_ui_from_bcheck()
                    messagebox.showinfo("Success", f"Loaded BCheck: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load BCheck: {str(e)}")
                
    def save_bcheck(self):
        """Save the current BCheck"""
        if not self.current_bcheck["metadata"]["name"]:
            messagebox.showerror("Error", "Please provide a name for the BCheck")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save BCheck",
            defaultextension=".bcheck",
            filetypes=[("BCheck files", "*.bcheck"), ("All files", "*.*")]
        )
        if file_path:
            try:
                # Update BCheck data from UI
                self.update_bcheck_from_ui()
                
                # Save to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(self.current_bcheck, f, default_flow_style=False, sort_keys=False)
                    
                messagebox.showinfo("Success", f"Saved BCheck: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save BCheck: {str(e)}")
                
    def validate_bcheck(self):
        """Validate the current BCheck"""
        try:
            self.update_bcheck_from_ui()
            
            # Basic validation
            errors = []
            
            if not self.current_bcheck["metadata"]["name"]:
                errors.append("Name is required")
            if not self.current_bcheck["metadata"]["description"]:
                errors.append("Description is required")
            if not self.current_bcheck["expression"]:
                errors.append("Expression is required")
                
            if errors:
                messagebox.showerror("Validation Errors", "\n".join(errors))
            else:
                messagebox.showinfo("Validation", "BCheck is valid!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Validation failed: {str(e)}")
            
    def export_yaml(self):
        """Export the BCheck as YAML"""
        try:
            self.update_bcheck_from_ui()
            
            file_path = filedialog.asksaveasfilename(
                title="Export YAML",
                defaultextension=".yaml",
                filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.dump(self.current_bcheck, f, default_flow_style=False, sort_keys=False)
                    
                messagebox.showinfo("Success", f"Exported YAML: {os.path.basename(file_path)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
            
    def load_template(self, event):
        """Load a template when selected from dropdown"""
        pass  # Will be implemented
        
    def load_selected_template(self):
        """Load the selected template"""
        template_name = self.template_combo.get()
        if template_name:
            templates_dir = Path(__file__).parent.parent.parent / "bchecks" / "vulnerability_checks"
            template_path = templates_dir / f"{template_name}.bcheck"
            
            if template_path.exists():
                try:
                    with open(template_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        self.current_bcheck = yaml.safe_load(content)
                        self.update_ui_from_bcheck()
                        messagebox.showinfo("Success", f"Loaded template: {template_name}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load template: {str(e)}")
                    
    def update_ui_from_bcheck(self):
        """Update UI fields from current BCheck data"""
        metadata = self.current_bcheck.get("metadata", {})
        
        self.name_entry.delete(0, tk.END)
        self.name_entry.insert(0, metadata.get("name", ""))
        
        self.author_entry.delete(0, tk.END)
        self.author_entry.insert(0, metadata.get("author", ""))
        
        self.version_entry.delete(0, tk.END)
        self.version_entry.insert(0, metadata.get("version", "1.0"))
        
        self.description_entry.delete(0, tk.END)
        self.description_entry.insert(0, metadata.get("description", ""))
        
        self.severity_combo.set(metadata.get("severity", "MEDIUM"))
        
        self.cwe_entry.delete(0, tk.END)
        self.cwe_entry.insert(0, metadata.get("cwe", ""))
        
        # Tags
        tags = metadata.get("tags", [])
        self.tags_entry.delete(0, tk.END)
        self.tags_entry.insert(0, ", ".join(tags))
        
        # References
        references = metadata.get("references", [])
        self.references_text.delete(1.0, tk.END)
        self.references_text.insert(1.0, "\n".join(references))
        
        # Expression
        self.expression_text.delete(1.0, tk.END)
        self.expression_text.insert(1.0, self.current_bcheck.get("expression", ""))
        
        # Actions
        actions = self.current_bcheck.get("then", [])
        self.actions_text.delete(1.0, tk.END)
        if actions:
            self.actions_text.insert(1.0, yaml.dump(actions, default_flow_style=False))
            
    def update_bcheck_from_ui(self):
        """Update BCheck data from UI fields"""
        # Metadata
        self.current_bcheck["metadata"]["name"] = self.name_entry.get()
        self.current_bcheck["metadata"]["author"] = self.author_entry.get()
        self.current_bcheck["metadata"]["version"] = self.version_entry.get()
        self.current_bcheck["metadata"]["description"] = self.description_entry.get()
        self.current_bcheck["metadata"]["severity"] = self.severity_combo.get()
        self.current_bcheck["metadata"]["cwe"] = self.cwe_entry.get()
        
        # Tags
        tags_text = self.tags_entry.get()
        self.current_bcheck["metadata"]["tags"] = [tag.strip() for tag in tags_text.split(",") if tag.strip()]
        
        # References
        references_text = self.references_text.get(1.0, tk.END)
        self.current_bcheck["metadata"]["references"] = [ref.strip() for ref in references_text.split("\n") if ref.strip()]
        
        # Expression
        self.current_bcheck["expression"] = self.expression_text.get(1.0, tk.END).strip()
        
        # Actions
        actions_text = self.actions_text.get(1.0, tk.END)
        try:
            self.current_bcheck["then"] = yaml.safe_load(actions_text) or []
        except yaml.YAMLError:
            # If YAML parsing fails, create a simple log action
            self.current_bcheck["then"] = [
                {
                    "log": {
                        "level": "MEDIUM",
                        "output": "Vulnerability detected",
                        "evidence": "Evidence from expression"
                    }
                }
            ]

def main():
    """Main function to run the BCheck Builder GUI"""
    root = tk.Tk()
    app = BCheckBuilder(root)
    root.mainloop()

if __name__ == "__main__":
    main()
