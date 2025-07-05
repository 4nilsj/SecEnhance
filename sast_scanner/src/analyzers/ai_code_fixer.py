#!/usr/bin/env python3
"""
AI-powered code fix generator for SAST scanner
Generates specific fix recommendations for actual vulnerable code
"""

import re
import ast
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import json

from ..debug_utils import debug_log, debug_print


class AICodeFixer:
    """AI-powered code fix generator for security vulnerabilities."""
    
    def __init__(self, debug: bool = False):
        """Initialize the AI code fixer."""
        self.debug = debug
        debug_log("ai_code_fixer", "Initializing AI Code Fixer")
        
        # Load fix templates and patterns
        self._load_fix_templates()
    
    def _load_fix_templates(self) -> None:
        """Load fix templates for different vulnerability types."""
        self.fix_templates = {
            "sql_injection": {
                "python": {
                    "patterns": [
                        (r"cursor\.execute\s*\(\s*f?[\"'](.*?)\[\"']", "cursor.execute(\"\\1\", ({args}))"),
                        (r"db\.execute\s*\(\s*f?[\"'](.*?)\[\"']", "db.execute(\"\\1\", ({args}))"),
                        (r"connection\.execute\s*\(\s*f?[\"'](.*?)\[\"']", "connection.execute(\"\\1\", ({args}))")
                    ],
                    "description": "Replace string formatting with parameterized queries"
                },
                "javascript": {
                    "patterns": [
                        (r"db\.query\s*\(\s*[\"'](.*?)\$\{.*?\}(.*?)[\"']", "db.query(\"\\1?\\2\", [{args}])"),
                        (r"connection\.query\s*\(\s*[\"'](.*?)\$\{.*?\}(.*?)[\"']", "connection.query(\"\\1?\\2\", [{args}])")
                    ],
                    "description": "Replace template literals with parameterized queries"
                },
                "php": {
                    "patterns": [
                        (r"mysqli_query\s*\(\s*.*?[\"'](.*?)\$.*?(.*?)[\"']", "mysqli_query($connection, \"\\1?\\2\")"),
                        (r"mysql_query\s*\(\s*.*?[\"'](.*?)\$.*?(.*?)[\"']", "mysql_query(\"\\1?\\2\")")
                    ],
                    "description": "Use prepared statements instead of string concatenation"
                }
            },
            "xss": {
                "javascript": {
                    "patterns": [
                        (r"innerHTML\s*=\s*(.*?);", "textContent = \\1;"),
                        (r"document\.write\s*\(\s*(.*?)\s*\)", "document.createTextNode(\\1)"),
                        (r"eval\s*\(\s*(.*?)\s*\)", "JSON.parse(\\1)")
                    ],
                    "description": "Use safe DOM manipulation methods"
                },
                "python": {
                    "patterns": [
                        (r"render_template_string\s*\(\s*(.*?)\s*\)", "render_template('template.html', data=\\1)"),
                        (r"mark_safe\s*\(\s*(.*?)\s*\)", "escape(\\1)")
                    ],
                    "description": "Use proper template rendering and escaping"
                }
            },
            "command_injection": {
                "python": {
                    "patterns": [
                        (r"os\.system\s*\(\s*(.*?)\s*\)", "subprocess.run([\\1], shell=False, capture_output=True)"),
                        (r"subprocess\.call\s*\(\s*(.*?)\s*\)", "subprocess.run([\\1], shell=False, capture_output=True)"),
                        (r"subprocess\.Popen\s*\(\s*(.*?)\s*\)", "subprocess.run([\\1], shell=False, capture_output=True)")
                    ],
                    "description": "Use subprocess.run with shell=False for safe command execution"
                },
                "javascript": {
                    "patterns": [
                        (r"child_process\.exec\s*\(\s*(.*?)\s*\)", "child_process.execFile(\\1, {shell: false})"),
                        (r"child_process\.spawn\s*\(\s*(.*?)\s*\)", "child_process.spawn(\\1, [], {shell: false})")
                    ],
                    "description": "Use execFile or spawn with shell disabled"
                }
            },
            "hardcoded_credentials": {
                "python": {
                    "patterns": [
                        (r"password\s*=\s*[\"']([^\"']+)[\"']", "password = os.environ.get('PASSWORD')"),
                        (r"api_key\s*=\s*[\"']([^\"']+)[\"']", "api_key = os.environ.get('API_KEY')"),
                        (r"secret\s*=\s*[\"']([^\"']+)[\"']", "secret = os.environ.get('SECRET')")
                    ],
                    "description": "Use environment variables for sensitive data"
                },
                "javascript": {
                    "patterns": [
                        (r"password\s*=\s*[\"']([^\"']+)[\"']", "password = process.env.PASSWORD"),
                        (r"api_key\s*=\s*[\"']([^\"']+)[\"']", "api_key = process.env.API_KEY"),
                        (r"secret\s*=\s*[\"']([^\"']+)[\"']", "secret = process.env.SECRET")
                    ],
                    "description": "Use environment variables for sensitive data"
                }
            },
            "weak_crypto": {
                "python": {
                    "patterns": [
                        (r"hashlib\.md5\s*\(\s*(.*?)\s*\)", "hashlib.sha256(\\1)"),
                        (r"hashlib\.sha1\s*\(\s*(.*?)\s*\)", "hashlib.sha256(\\1)"),
                        (r"hashlib\.new\s*\(\s*[\"']md5[\"']", "hashlib.new('sha256')"),
                        (r"hashlib\.new\s*\(\s*[\"']sha1[\"']", "hashlib.new('sha256')")
                    ],
                    "description": "Use strong cryptographic algorithms (SHA-256)"
                },
                "javascript": {
                    "patterns": [
                        (r"crypto\.createHash\s*\(\s*[\"']md5[\"']", "crypto.createHash('sha256')"),
                        (r"crypto\.createHash\s*\(\s*[\"']sha1[\"']", "crypto.createHash('sha256')")
                    ],
                    "description": "Use strong cryptographic algorithms (SHA-256)"
                }
            },
            "insecure_random": {
                "python": {
                    "patterns": [
                        (r"random\.random\s*\(\s*\)", "secrets.randbelow(1000000) / 1000000"),
                        (r"random\.randint\s*\(\s*(.*?)\s*,\s*(.*?)\s*\)", "secrets.randbelow(\\2 - \\1 + 1) + \\1")
                    ],
                    "description": "Use cryptographically secure random functions"
                },
                "javascript": {
                    "patterns": [
                        (r"Math\.random\s*\(\s*\)", "crypto.randomBytes(4).readUInt32LE(0) / 0xffffffff")
                    ],
                    "description": "Use cryptographically secure random functions"
                }
            }
        }
    
    def extract_vulnerable_code_context(self, content: str, line_number: int, 
                                      pattern_match: str, file_type: str) -> str:
        """Extract the actual vulnerable code with context."""
        lines = content.split('\n')
        start_line = max(0, line_number - 2)  # Include 2 lines before
        end_line = min(len(lines), line_number + 2)  # Include 2 lines after
        
        context_lines = []
        for i in range(start_line, end_line):
            line_num = i + 1
            prefix = ">>> " if line_num == line_number else "    "
            context_lines.append(f"{prefix}{lines[i]}")
        
        return "\n".join(context_lines)
    
    def generate_specific_fix(self, vulnerability: Dict, content: str, file_path: str) -> Dict:
        """Generate a specific fix for the actual vulnerable code."""
        vuln_type = vulnerability.get('type', '')
        file_type = self._get_file_type(file_path)
        line_number = vulnerability.get('line_number', 1)
        pattern_match = vulnerability.get('pattern_match', '')
        
        debug_log("ai_code_fixer", f"Generating fix for {vuln_type} in {file_path}:{line_number}")
        
        # Extract actual vulnerable code
        actual_vulnerable_code = self.extract_vulnerable_code_context(
            content, line_number, pattern_match, file_type
        )
        
        # Generate specific fix
        specific_fix_code = self._generate_fix_for_code(
            vuln_type, file_type, pattern_match, line_number, content
        )
        
        # Generate explanation
        fix_explanation = self._generate_fix_explanation(vuln_type, file_type, pattern_match)
        
        return {
            "actual_vulnerable_code": actual_vulnerable_code,
            "specific_fix_code": specific_fix_code,
            "fix_explanation": fix_explanation,
            "confidence": self._calculate_fix_confidence(vuln_type, file_type, pattern_match)
        }
    
    def _generate_fix_for_code(self, vuln_type: str, file_type: str, 
                              pattern_match: str, line_number: int, content: str) -> str:
        """Generate specific fix code for the vulnerability."""
        if vuln_type not in self.fix_templates:
            return self._generate_generic_fix(vuln_type, file_type)
        
        if file_type not in self.fix_templates[vuln_type]:
            return self._generate_generic_fix(vuln_type, file_type)
        
        templates = self.fix_templates[vuln_type][file_type]
        
        for pattern, replacement in templates["patterns"]:
            if re.search(pattern, pattern_match, re.IGNORECASE):
                # Extract variables from the pattern match
                variables = self._extract_variables_from_pattern(pattern_match, pattern)
                
                # Apply the fix template
                fixed_code = replacement.format(args=variables)
                return fixed_code
        
        return self._generate_generic_fix(vuln_type, file_type)
    
    def _extract_variables_from_pattern(self, pattern_match: str, pattern: str) -> str:
        """Extract variables from the pattern match for use in the fix."""
        # This is a simplified version - in practice, you'd want more sophisticated parsing
        if "user_input" in pattern_match:
            return "user_input"
        elif "userInput" in pattern_match:
            return "userInput"
        elif "data" in pattern_match:
            return "data"
        else:
            return "variable_name"  # Generic placeholder
    
    def _generate_generic_fix(self, vuln_type: str, file_type: str) -> str:
        """Generate a generic fix when specific patterns don't match."""
        generic_fixes = {
            "sql_injection": {
                "python": "cursor.execute(\"SELECT * FROM table WHERE id = %s\", (variable,))",
                "javascript": "db.query(\"SELECT * FROM table WHERE id = ?\", [variable])",
                "php": "$stmt = $pdo->prepare(\"SELECT * FROM table WHERE id = ?\");\n$stmt->execute([$variable]);"
            },
            "xss": {
                "python": "from markupsafe import escape\noutput = escape(user_input)",
                "javascript": "element.textContent = userInput;",
                "php": "echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');"
            },
            "command_injection": {
                "python": "import subprocess\nresult = subprocess.run([command], shell=False, capture_output=True)",
                "javascript": "const { execFile } = require('child_process');\nexecFile(command, [], (error, stdout, stderr) => {});",
                "php": "escapeshellcmd($command);"
            }
        }
        
        return generic_fixes.get(vuln_type, {}).get(file_type, "# Fix: Implement secure alternative")
    
    def _generate_fix_explanation(self, vuln_type: str, file_type: str, pattern_match: str) -> str:
        """Generate explanation for the fix."""
        explanations = {
            "sql_injection": "This fix uses parameterized queries to prevent SQL injection by separating code from data.",
            "xss": "This fix uses safe output encoding to prevent XSS by properly escaping user input.",
            "command_injection": "This fix uses safe command execution methods that don't allow shell interpretation.",
            "hardcoded_credentials": "This fix uses environment variables to keep sensitive data out of source code.",
            "weak_crypto": "This fix uses strong cryptographic algorithms that are resistant to attacks.",
            "insecure_random": "This fix uses cryptographically secure random number generators."
        }
        
        return explanations.get(vuln_type, "This fix implements a secure alternative to the vulnerable code.")
    
    def _calculate_fix_confidence(self, vuln_type: str, file_type: str, pattern_match: str) -> float:
        """Calculate confidence level for the generated fix."""
        # Higher confidence for well-known patterns
        high_confidence_patterns = [
            "sql_injection",
            "xss", 
            "command_injection",
            "hardcoded_credentials"
        ]
        
        if vuln_type in high_confidence_patterns:
            return 0.9
        elif vuln_type in ["weak_crypto", "insecure_random"]:
            return 0.8
        else:
            return 0.7
    
    def _get_file_type(self, file_path: str) -> str:
        """Determine file type from extension."""
        extension = Path(file_path).suffix.lower()
        
        type_mapping = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".java": "java",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".c": "c",
            ".h": "c",
            ".hpp": "cpp",
            ".php": "php",
            ".rb": "ruby",
            ".go": "go",
            ".rs": "rust"
        }
        
        return type_mapping.get(extension, "unknown")
    
    def enhance_vulnerabilities_with_fixes(self, vulnerabilities: List[Dict], 
                                         content: str, file_path: str) -> List[Dict]:
        """Enhance vulnerabilities with AI-generated specific fixes."""
        enhanced_vulnerabilities = []
        
        for vuln in vulnerabilities:
            # Generate specific fix for this vulnerability
            fix_data = self.generate_specific_fix(vuln, content, file_path)
            
            # Enhance the vulnerability with fix data
            enhanced_vuln = vuln.copy()
            enhanced_vuln.update({
                "actual_vulnerable_code": fix_data["actual_vulnerable_code"],
                "specific_fix_code": fix_data["specific_fix_code"],
                "fix_explanation": fix_data["fix_explanation"],
                "fix_confidence": fix_data["confidence"]
            })
            
            enhanced_vulnerabilities.append(enhanced_vuln)
        
        debug_log("ai_code_fixer", f"Enhanced {len(enhanced_vulnerabilities)} vulnerabilities with specific fixes")
        return enhanced_vulnerabilities 