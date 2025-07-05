"""
Code Analyzer for SAST Scanner
Analyzes code structure, metrics, and patterns for security analysis.
"""

import ast
import re
import tokenize
from io import StringIO
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json

from ..debug_utils import debug_print, debug_log

class CodeAnalyzer:
    """Analyzes code structure and extracts metrics for security analysis."""
    
    def __init__(self, debug: bool = False):
        """Initialize the code analyzer."""
        self.debug = debug
        self.supported_languages = {
            "python": self._analyze_python,
            "javascript": self._analyze_javascript,
            "java": self._analyze_java,
            "cpp": self._analyze_cpp,
            "c": self._analyze_c,
            "php": self._analyze_php,
            "ruby": self._analyze_ruby,
            "go": self._analyze_go
        }
        
        debug_log("code_analyzer", "Code Analyzer initialized")
    
    def analyze_code(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze code content and extract metrics."""
        debug_log("code_analyzer", f"Analyzing code: {file_path}")
        
        # Basic metrics
        basic_metrics = self._get_basic_metrics(content)
        
        # Language-specific analysis
        file_type = self._get_file_type(file_path)
        language_analysis = {}
        
        if file_type in self.supported_languages:
            try:
                language_analysis = self.supported_languages[file_type](content, file_path)
            except Exception as e:
                debug_log("code_analyzer", f"Error in language-specific analysis: {e}", "ERROR")
                language_analysis = {"error": str(e)}
        
        # Combine results
        analysis_result = {
            "file_type": file_type,
            "basic_metrics": basic_metrics,
            "language_analysis": language_analysis,
            "security_patterns": self._detect_security_patterns(content, file_type),
            "complexity_metrics": self._calculate_complexity(content, file_type)
        }
        
        debug_log("code_analyzer", "Code analysis completed", data=analysis_result)
        return analysis_result
    
    def _get_basic_metrics(self, content: str) -> Dict[str, Any]:
        """Calculate basic code metrics."""
        lines = content.split('\n')
        total_lines = len(lines)
        empty_lines = len([line for line in lines if line.strip() == ''])
        comment_lines = len([line for line in lines if line.strip().startswith(('#', '//', '/*', '*', '*/'))])
        code_lines = total_lines - empty_lines - comment_lines
        
        return {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "comment_lines": comment_lines,
            "empty_lines": empty_lines,
            "comment_ratio": comment_lines / total_lines if total_lines > 0 else 0,
            "file_size_bytes": len(content.encode('utf-8')),
            "characters": len(content)
        }
    
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
    
    def _analyze_python(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Python code structure."""
        try:
            tree = ast.parse(content)
            
            # Extract functions and classes
            functions = []
            classes = []
            imports = []
            calls = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        "name": node.name,
                        "line": node.lineno,
                        "args": [arg.arg for arg in node.args.args],
                        "decorators": [d.id for d in node.decorator_list if hasattr(d, 'id')]
                    })
                elif isinstance(node, ast.ClassDef):
                    classes.append({
                        "name": node.name,
                        "line": node.lineno,
                        "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                    })
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for alias in node.names:
                        imports.append(f"{module}.{alias.name}")
                elif isinstance(node, ast.Call):
                    if hasattr(node.func, 'id'):
                        calls.append(node.func.id)
                    elif hasattr(node.func, 'attr'):
                        calls.append(node.func.attr)
            
            return {
                "functions": functions,
                "classes": classes,
                "imports": imports,
                "function_calls": calls,
                "function_count": len(functions),
                "class_count": len(classes),
                "import_count": len(imports)
            }
            
        except SyntaxError as e:
            debug_log("code_analyzer", f"Python syntax error: {e}", "ERROR")
            return {"error": f"Syntax error: {e}"}
        except Exception as e:
            debug_log("code_analyzer", f"Python analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_javascript(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze JavaScript code structure."""
        try:
            # Extract functions using regex
            function_pattern = r'function\s+(\w+)\s*\([^)]*\)|(\w+)\s*[:=]\s*function\s*\([^)]*\)|(\w+)\s*[:=]\s*\([^)]*\)\s*=>'
            functions = []
            for match in re.finditer(function_pattern, content):
                func_name = match.group(1) or match.group(2) or match.group(3)
                if func_name:
                    functions.append({
                        "name": func_name,
                        "line": content[:match.start()].count('\n') + 1
                    })
            
            # Extract imports
            import_pattern = r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]|require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
            imports = []
            for match in re.finditer(import_pattern, content):
                module = match.group(1) or match.group(2)
                if module:
                    imports.append(module)
            
            # Extract function calls
            call_pattern = r'(\w+)\s*\('
            calls = []
            for match in re.finditer(call_pattern, content):
                call_name = match.group(1)
                if call_name not in ['if', 'for', 'while', 'switch', 'catch']:
                    calls.append(call_name)
            
            return {
                "functions": functions,
                "imports": imports,
                "function_calls": calls,
                "function_count": len(functions),
                "import_count": len(imports)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"JavaScript analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_java(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Java code structure."""
        try:
            # Extract classes
            class_pattern = r'(?:public\s+)?class\s+(\w+)'
            classes = []
            for match in re.finditer(class_pattern, content):
                classes.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract methods
            method_pattern = r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:native\s+)?(?:abstract\s+)?(?:strictfp\s+)?(?:<[^>]+>\s+)?(?:[\w\[\]]+\s+)?(\w+)\s*\([^)]*\)'
            methods = []
            for match in re.finditer(method_pattern, content):
                method_name = match.group(1)
                if method_name not in ['if', 'for', 'while', 'switch', 'catch', 'try']:
                    methods.append({
                        "name": method_name,
                        "line": content[:match.start()].count('\n') + 1
                    })
            
            # Extract imports
            import_pattern = r'import\s+(?:static\s+)?([^;]+);'
            imports = []
            for match in re.finditer(import_pattern, content):
                imports.append(match.group(1).strip())
            
            return {
                "classes": classes,
                "methods": methods,
                "imports": imports,
                "class_count": len(classes),
                "method_count": len(methods),
                "import_count": len(imports)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"Java analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_cpp(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze C++ code structure."""
        try:
            # Extract classes
            class_pattern = r'class\s+(\w+)'
            classes = []
            for match in re.finditer(class_pattern, content):
                classes.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract functions
            function_pattern = r'(?:[\w\[\]]+\s+)?(\w+)\s+(\w+)\s*\([^)]*\)'
            functions = []
            for match in re.finditer(function_pattern, content):
                func_name = match.group(2)
                if func_name not in ['if', 'for', 'while', 'switch', 'catch', 'try']:
                    functions.append({
                        "name": func_name,
                        "line": content[:match.start()].count('\n') + 1
                    })
            
            # Extract includes
            include_pattern = r'#include\s*[<"]([^>"]+)[>"]'
            includes = []
            for match in re.finditer(include_pattern, content):
                includes.append(match.group(1))
            
            return {
                "classes": classes,
                "functions": functions,
                "includes": includes,
                "class_count": len(classes),
                "function_count": len(functions),
                "include_count": len(includes)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"C++ analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_c(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze C code structure."""
        try:
            # Extract functions
            function_pattern = r'(?:[\w\[\]]+\s+)?(\w+)\s+(\w+)\s*\([^)]*\)'
            functions = []
            for match in re.finditer(function_pattern, content):
                func_name = match.group(2)
                if func_name not in ['if', 'for', 'while', 'switch', 'catch', 'try']:
                    functions.append({
                        "name": func_name,
                        "line": content[:match.start()].count('\n') + 1
                    })
            
            # Extract includes
            include_pattern = r'#include\s*[<"]([^>"]+)[>"]'
            includes = []
            for match in re.finditer(include_pattern, content):
                includes.append(match.group(1))
            
            return {
                "functions": functions,
                "includes": includes,
                "function_count": len(functions),
                "include_count": len(includes)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"C analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_php(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze PHP code structure."""
        try:
            # Extract functions
            function_pattern = r'function\s+(\w+)\s*\([^)]*\)'
            functions = []
            for match in re.finditer(function_pattern, content):
                functions.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract classes
            class_pattern = r'class\s+(\w+)'
            classes = []
            for match in re.finditer(class_pattern, content):
                classes.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract includes/requires
            include_pattern = r'(?:include|require)(?:_once)?\s*[\'"]([^\'"]+)[\'"]'
            includes = []
            for match in re.finditer(include_pattern, content):
                includes.append(match.group(1))
            
            return {
                "functions": functions,
                "classes": classes,
                "includes": includes,
                "function_count": len(functions),
                "class_count": len(classes),
                "include_count": len(includes)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"PHP analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_ruby(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Ruby code structure."""
        try:
            # Extract methods
            method_pattern = r'def\s+(\w+)'
            methods = []
            for match in re.finditer(method_pattern, content):
                methods.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract classes
            class_pattern = r'class\s+(\w+)'
            classes = []
            for match in re.finditer(class_pattern, content):
                classes.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract requires
            require_pattern = r'require\s+[\'"]([^\'"]+)[\'"]'
            requires = []
            for match in re.finditer(require_pattern, content):
                requires.append(match.group(1))
            
            return {
                "methods": methods,
                "classes": classes,
                "requires": requires,
                "method_count": len(methods),
                "class_count": len(classes),
                "require_count": len(requires)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"Ruby analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _analyze_go(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Go code structure."""
        try:
            # Extract functions
            function_pattern = r'func\s+(\w+)\s*\([^)]*\)'
            functions = []
            for match in re.finditer(function_pattern, content):
                functions.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract structs
            struct_pattern = r'type\s+(\w+)\s+struct'
            structs = []
            for match in re.finditer(struct_pattern, content):
                structs.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Extract imports
            import_pattern = r'import\s+[\'"]([^\'"]+)[\'"]'
            imports = []
            for match in re.finditer(import_pattern, content):
                imports.append(match.group(1))
            
            return {
                "functions": functions,
                "structs": structs,
                "imports": imports,
                "function_count": len(functions),
                "struct_count": len(structs),
                "import_count": len(imports)
            }
            
        except Exception as e:
            debug_log("code_analyzer", f"Go analysis error: {e}", "ERROR")
            return {"error": str(e)}
    
    def _detect_security_patterns(self, content: str, file_type: str) -> Dict[str, Any]:
        """Detect security-related patterns in code."""
        patterns = {
            "authentication": {
                "patterns": [
                    r'auth', r'login', r'password', r'credential', r'token',
                    r'session', r'jwt', r'oauth', r'saml', r'ldap'
                ],
                "count": 0,
                "locations": []
            },
            "encryption": {
                "patterns": [
                    r'encrypt', r'decrypt', r'hash', r'salt', r'cipher',
                    r'aes', r'rsa', r'sha', r'md5', r'bcrypt'
                ],
                "count": 0,
                "locations": []
            },
            "database": {
                "patterns": [
                    r'sql', r'query', r'database', r'connection', r'cursor',
                    r'execute', r'fetch', r'insert', r'update', r'delete'
                ],
                "count": 0,
                "locations": []
            },
            "file_operations": {
                "patterns": [
                    r'file', r'open', r'read', r'write', r'upload', r'download',
                    r'path', r'directory', r'folder'
                ],
                "count": 0,
                "locations": []
            },
            "network": {
                "patterns": [
                    r'http', r'https', r'url', r'request', r'response',
                    r'socket', r'network', r'api', r'endpoint'
                ],
                "count": 0,
                "locations": []
            }
        }
        
        content_lower = content.lower()
        
        for category, pattern_info in patterns.items():
            for pattern in pattern_info["patterns"]:
                for match in re.finditer(pattern, content_lower):
                    patterns[category]["count"] += 1
                    patterns[category]["locations"].append({
                        "line": content[:match.start()].count('\n') + 1,
                        "column": match.start() - content[:match.start()].rfind('\n') - 1,
                        "match": match.group()
                    })
        
        return patterns
    
    def _calculate_complexity(self, content: str, file_type: str) -> Dict[str, Any]:
        """Calculate code complexity metrics."""
        lines = content.split('\n')
        
        # Cyclomatic complexity approximation
        complexity_keywords = ['if', 'elif', 'else', 'for', 'while', 'and', 'or', 'case', 'catch', 'except']
        complexity_count = 0
        
        for line in lines:
            line_lower = line.lower().strip()
            for keyword in complexity_keywords:
                if keyword in line_lower:
                    complexity_count += 1
        
        # Nesting depth
        max_nesting = 0
        current_nesting = 0
        
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith(('#', '//', '/*', '*', '*/')):
                # Count opening braces/brackets
                current_nesting += stripped.count('{') + stripped.count('(') + stripped.count('[')
                # Count closing braces/brackets
                current_nesting -= stripped.count('}') + stripped.count(')') + stripped.count(']')
                max_nesting = max(max_nesting, current_nesting)
        
        return {
            "cyclomatic_complexity": complexity_count,
            "max_nesting_depth": max_nesting,
            "complexity_level": "high" if complexity_count > 20 else "medium" if complexity_count > 10 else "low"
        } 