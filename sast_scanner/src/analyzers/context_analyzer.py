"""
Context Analyzer for SAST Scanner
Analyzes code context, dependencies, and relationships for better security understanding.
"""

import re
import json
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from collections import defaultdict

from ..debug_utils import debug_print, debug_log

class ContextAnalyzer:
    """Analyzes code context and relationships for security analysis."""
    
    def __init__(self, debug: bool = False):
        """Initialize the context analyzer."""
        self.debug = debug
        self.context_patterns = {}
        self.dependency_patterns = {}
        self.relationship_patterns = {}
        
        # Load context patterns
        self._load_context_patterns()
        
        debug_log("context_analyzer", "Context Analyzer initialized")
    
    def _load_context_patterns(self) -> None:
        """Load context analysis patterns."""
        self.context_patterns = {
            "authentication_context": {
                "indicators": [
                    "login", "auth", "authenticate", "session", "token", "jwt", "oauth",
                    "password", "credential", "user", "admin", "authorization"
                ],
                "security_concerns": [
                    "weak_password_policy", "session_management", "token_validation",
                    "privilege_escalation", "authentication_bypass"
                ]
            },
            "data_processing_context": {
                "indicators": [
                    "process", "parse", "validate", "sanitize", "filter", "transform",
                    "convert", "format", "encode", "decode", "serialize", "deserialize"
                ],
                "security_concerns": [
                    "input_validation", "data_sanitization", "injection_attacks",
                    "data_exposure", "unsafe_processing"
                ]
            },
            "file_handling_context": {
                "indicators": [
                    "upload", "download", "read", "write", "save", "load", "import",
                    "export", "file", "path", "directory", "folder", "upload_dir"
                ],
                "security_concerns": [
                    "file_upload_vulnerabilities", "path_traversal", "file_permissions",
                    "file_type_validation", "file_size_limits"
                ]
            },
            "network_context": {
                "indicators": [
                    "http", "https", "api", "request", "response", "url", "endpoint",
                    "socket", "network", "connection", "client", "server", "proxy"
                ],
                "security_concerns": [
                    "insecure_communication", "api_security", "input_validation",
                    "rate_limiting", "authentication", "authorization"
                ]
            },
            "database_context": {
                "indicators": [
                    "database", "db", "query", "sql", "connection", "cursor",
                    "transaction", "table", "column", "row", "select", "insert",
                    "update", "delete", "where", "join"
                ],
                "security_concerns": [
                    "sql_injection", "database_access_control", "query_optimization",
                    "data_encryption", "connection_security"
                ]
            },
            "cryptography_context": {
                "indicators": [
                    "encrypt", "decrypt", "hash", "salt", "cipher", "key", "iv",
                    "aes", "rsa", "sha", "md5", "bcrypt", "pbkdf2", "hmac"
                ],
                "security_concerns": [
                    "weak_cryptography", "key_management", "random_number_generation",
                    "algorithm_selection", "implementation_errors"
                ]
            },
            "logging_context": {
                "indicators": [
                    "log", "logger", "logging", "debug", "info", "warn", "error",
                    "trace", "audit", "monitor", "track", "record"
                ],
                "security_concerns": [
                    "information_disclosure", "log_injection", "log_retention",
                    "log_access_control", "sensitive_data_logging"
                ]
            },
            "configuration_context": {
                "indicators": [
                    "config", "configuration", "setting", "option", "parameter",
                    "env", "environment", "ini", "yaml", "json", "xml", "property"
                ],
                "security_concerns": [
                    "hardcoded_credentials", "insecure_defaults", "configuration_exposure",
                    "privilege_configuration", "debug_settings"
                ]
            }
        }
        
        # Dependency patterns
        self.dependency_patterns = {
            "import_patterns": {
                "python": [
                    r"import\s+(\w+)",
                    r"from\s+(\w+)\s+import",
                    r"import\s+(\w+)\s+as"
                ],
                "javascript": [
                    r"import\s+.*?from\s+[\"']([^\"']+)[\"']",
                    r"require\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
                    r"import\s*\(\s*[\"']([^\"']+)[\"']\s*\)"
                ],
                "java": [
                    r"import\s+([^;]+);",
                    r"package\s+([^;]+);"
                ],
                "php": [
                    r"require\s*[\"']([^\"']+)[\"']",
                    r"include\s*[\"']([^\"']+)[\"']",
                    r"use\s+([^;]+);"
                ]
            },
            "function_call_patterns": {
                "python": [
                    r"(\w+)\s*\(",
                    r"(\w+)\.(\w+)\s*\("
                ],
                "javascript": [
                    r"(\w+)\s*\(",
                    r"(\w+)\.(\w+)\s*\(",
                    r"(\w+)\[(\w+)\]\s*\("
                ],
                "java": [
                    r"(\w+)\s*\(",
                    r"(\w+)\.(\w+)\s*\("
                ]
            }
        }
    
    def analyze_context(self, content: str, file_path: str, 
                       additional_context: Optional[Dict] = None) -> Dict[str, Any]:
        """Analyze the context of the given content."""
        debug_log("context_analyzer", f"Analyzing context for {file_path}")
        
        file_type = self._get_file_type(file_path)
        
        context_analysis = {
            "file_context": self._analyze_file_context(content, file_path, file_type),
            "code_context": self._analyze_code_context(content, file_type),
            "dependency_context": self._analyze_dependency_context(content, file_type),
            "security_context": self._analyze_security_context(content, file_type),
            "relationship_context": self._analyze_relationship_context(content, file_path, file_type),
            "risk_context": self._analyze_risk_context(content, file_type)
        }
        
        # Add additional context if provided
        if additional_context:
            context_analysis["additional_context"] = additional_context
        
        debug_log("context_analyzer", "Context analysis completed")
        return context_analysis
    
    def _analyze_file_context(self, content: str, file_path: str, file_type: str) -> Dict[str, Any]:
        """Analyze file-level context."""
        file_path_obj = Path(file_path)
        
        context = {
            "file_name": file_path_obj.name,
            "file_extension": file_path_obj.suffix,
            "file_type": file_type,
            "file_size": len(content.encode('utf-8')),
            "line_count": len(content.split('\n')),
            "directory_structure": self._analyze_directory_context(file_path_obj),
            "file_purpose": self._infer_file_purpose(content, file_path_obj),
            "file_complexity": self._analyze_file_complexity(content)
        }
        
        return context
    
    def _analyze_directory_context(self, file_path: Path) -> Dict[str, Any]:
        """Analyze directory structure context."""
        directory_context = {
            "depth": len(file_path.parts) - 1,
            "parent_directories": list(file_path.parents),
            "sibling_files": [],
            "project_structure": {}
        }
        
        # Analyze sibling files
        if file_path.parent.exists():
            for sibling in file_path.parent.iterdir():
                if sibling.is_file() and sibling != file_path:
                    directory_context["sibling_files"].append({
                        "name": sibling.name,
                        "extension": sibling.suffix,
                        "size": sibling.stat().st_size
                    })
        
        # Analyze project structure
        project_root = self._find_project_root(file_path)
        if project_root:
            directory_context["project_structure"] = self._analyze_project_structure(project_root, file_path)
        
        return directory_context
    
    def _find_project_root(self, file_path: Path) -> Optional[Path]:
        """Find the project root directory."""
        current = file_path.parent
        
        # Look for common project indicators
        project_indicators = [
            ".git", "package.json", "requirements.txt", "pom.xml", 
            "build.gradle", "Cargo.toml", "composer.json", "Gemfile"
        ]
        
        while current != current.parent:
            for indicator in project_indicators:
                if (current / indicator).exists():
                    return current
            current = current.parent
        
        return None
    
    def _analyze_project_structure(self, project_root: Path, file_path: Path) -> Dict[str, Any]:
        """Analyze the project structure."""
        structure = {
            "project_type": self._detect_project_type(project_root),
            "relative_path": file_path.relative_to(project_root),
            "project_files": [],
            "dependencies": {}
        }
        
        # Analyze project files
        for item in project_root.rglob("*"):
            if item.is_file() and item.name in [
                "package.json", "requirements.txt", "pom.xml", "build.gradle",
                "Cargo.toml", "composer.json", "Gemfile", "go.mod"
            ]:
                structure["project_files"].append({
                    "name": item.name,
                    "path": str(item.relative_to(project_root))
                })
        
        return structure
    
    def _detect_project_type(self, project_root: Path) -> str:
        """Detect the type of project."""
        if (project_root / "package.json").exists():
            return "nodejs"
        elif (project_root / "requirements.txt").exists() or (project_root / "setup.py").exists():
            return "python"
        elif (project_root / "pom.xml").exists():
            return "java_maven"
        elif (project_root / "build.gradle").exists():
            return "java_gradle"
        elif (project_root / "Cargo.toml").exists():
            return "rust"
        elif (project_root / "composer.json").exists():
            return "php"
        elif (project_root / "Gemfile").exists():
            return "ruby"
        elif (project_root / "go.mod").exists():
            return "go"
        else:
            return "unknown"
    
    def _infer_file_purpose(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Infer the purpose of the file based on content and name."""
        purpose = {
            "primary_purpose": "unknown",
            "secondary_purposes": [],
            "confidence": 0.0
        }
        
        file_name = file_path.name.lower()
        content_lower = content.lower()
        
        # Check for common file patterns
        if "test" in file_name or "spec" in file_name:
            purpose["primary_purpose"] = "testing"
            purpose["confidence"] = 0.9
        elif "config" in file_name or "conf" in file_name:
            purpose["primary_purpose"] = "configuration"
            purpose["confidence"] = 0.8
        elif "main" in file_name or "app" in file_name:
            purpose["primary_purpose"] = "application_entry"
            purpose["confidence"] = 0.7
        elif "util" in file_name or "helper" in file_name:
            purpose["primary_purpose"] = "utility"
            purpose["confidence"] = 0.8
        elif "model" in file_name:
            purpose["primary_purpose"] = "data_model"
            purpose["confidence"] = 0.8
        elif "controller" in file_name:
            purpose["primary_purpose"] = "controller"
            purpose["confidence"] = 0.8
        elif "service" in file_name:
            purpose["primary_purpose"] = "service"
            purpose["confidence"] = 0.8
        
        # Analyze content for additional purposes
        if "def test_" in content or "function test" in content:
            purpose["secondary_purposes"].append("testing")
        if "class Test" in content:
            purpose["secondary_purposes"].append("testing")
        if "import unittest" in content:
            purpose["secondary_purposes"].append("testing")
        
        return purpose
    
    def _analyze_file_complexity(self, content: str) -> Dict[str, Any]:
        """Analyze file complexity."""
        lines = content.split('\n')
        
        complexity = {
            "total_lines": len(lines),
            "code_lines": 0,
            "comment_lines": 0,
            "empty_lines": 0,
            "function_count": 0,
            "class_count": 0,
            "import_count": 0,
            "complexity_score": 0.0
        }
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                complexity["empty_lines"] += 1
            elif stripped.startswith(('#', '//', '/*', '*', '*/')):
                complexity["comment_lines"] += 1
            else:
                complexity["code_lines"] += 1
        
        # Count functions and classes
        complexity["function_count"] = len(re.findall(r'def\s+\w+|function\s+\w+|public\s+\w+\s*\('), content)
        complexity["class_count"] = len(re.findall(r'class\s+\w+', content))
        complexity["import_count"] = len(re.findall(r'import\s+|from\s+.*\s+import|require\s*\(', content))
        
        # Calculate complexity score
        complexity["complexity_score"] = (
            complexity["function_count"] * 2 +
            complexity["class_count"] * 3 +
            complexity["import_count"] * 0.5
        ) / max(complexity["code_lines"], 1)
        
        return complexity
    
    def _analyze_code_context(self, content: str, file_type: str) -> Dict[str, Any]:
        """Analyze code-level context."""
        context = {
            "context_types": self._identify_context_types(content),
            "code_patterns": self._identify_code_patterns(content, file_type),
            "security_focus_areas": self._identify_security_focus_areas(content),
            "data_flow": self._analyze_data_flow(content, file_type),
            "control_flow": self._analyze_control_flow(content, file_type)
        }
        
        return context
    
    def _identify_context_types(self, content: str) -> List[Dict[str, Any]]:
        """Identify the types of context present in the code."""
        identified_contexts = []
        content_lower = content.lower()
        
        for context_type, context_info in self.context_patterns.items():
            indicators_found = []
            for indicator in context_info["indicators"]:
                if indicator in content_lower:
                    indicators_found.append(indicator)
            
            if indicators_found:
                identified_contexts.append({
                    "context_type": context_type,
                    "indicators_found": indicators_found,
                    "security_concerns": context_info["security_concerns"],
                    "confidence": len(indicators_found) / len(context_info["indicators"])
                })
        
        return identified_contexts
    
    def _identify_code_patterns(self, content: str, file_type: str) -> Dict[str, Any]:
        """Identify code patterns in the content."""
        patterns = {
            "design_patterns": [],
            "anti_patterns": [],
            "security_patterns": [],
            "performance_patterns": []
        }
        
        # Identify design patterns
        if "class" in content and "def __init__" in content:
            patterns["design_patterns"].append("constructor_pattern")
        
        if "def __enter__" in content and "def __exit__" in content:
            patterns["design_patterns"].append("context_manager_pattern")
        
        if "try:" in content and "except:" in content:
            patterns["design_patterns"].append("exception_handling_pattern")
        
        # Identify anti-patterns
        if "global" in content:
            patterns["anti_patterns"].append("global_variable_usage")
        
        if "eval(" in content:
            patterns["anti_patterns"].append("eval_usage")
        
        if "exec(" in content:
            patterns["anti_patterns"].append("exec_usage")
        
        # Identify security patterns
        if "hashlib" in content:
            patterns["security_patterns"].append("hashing_usage")
        
        if "cryptography" in content:
            patterns["security_patterns"].append("encryption_usage")
        
        if "jwt" in content:
            patterns["security_patterns"].append("jwt_usage")
        
        return patterns
    
    def _identify_security_focus_areas(self, content: str) -> List[Dict[str, Any]]:
        """Identify security focus areas in the code."""
        focus_areas = []
        content_lower = content.lower()
        
        security_areas = {
            "input_validation": ["validate", "sanitize", "filter", "check"],
            "authentication": ["login", "auth", "password", "token"],
            "authorization": ["permission", "role", "access", "grant"],
            "data_protection": ["encrypt", "hash", "secure", "protect"],
            "error_handling": ["try", "except", "catch", "error"],
            "logging": ["log", "logger", "audit", "trace"]
        }
        
        for area, keywords in security_areas.items():
            found_keywords = [kw for kw in keywords if kw in content_lower]
            if found_keywords:
                focus_areas.append({
                    "area": area,
                    "keywords_found": found_keywords,
                    "relevance_score": len(found_keywords) / len(keywords)
                })
        
        return focus_areas
    
    def _analyze_data_flow(self, content: str, file_type: str) -> Dict[str, Any]:
        """Analyze data flow in the code."""
        data_flow = {
            "input_sources": [],
            "output_sinks": [],
            "data_transformations": [],
            "data_storage": []
        }
        
        # Identify input sources
        input_patterns = [
            r'input\s*\(',
            r'raw_input\s*\(',
            r'request\.form',
            r'request\.args',
            r'request\.json',
            r'getParameter\s*\(',
            r'$_GET',
            r'$_POST',
            r'$_REQUEST'
        ]
        
        for pattern in input_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                data_flow["input_sources"].append(pattern)
        
        # Identify output sinks
        output_patterns = [
            r'print\s*\(',
            r'echo\s+',
            r'console\.log\s*\(',
            r'response\.write',
            r'out\.print',
            r'printf\s*\('
        ]
        
        for pattern in output_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                data_flow["output_sinks"].append(pattern)
        
        return data_flow
    
    def _analyze_control_flow(self, content: str, file_type: str) -> Dict[str, Any]:
        """Analyze control flow in the code."""
        control_flow = {
            "conditional_statements": 0,
            "loops": 0,
            "function_calls": 0,
            "exception_handling": 0,
            "complexity_indicators": []
        }
        
        # Count control flow elements
        control_flow["conditional_statements"] = len(re.findall(r'\bif\b|\belse\b|\belif\b', content))
        control_flow["loops"] = len(re.findall(r'\bfor\b|\bwhile\b|\bdo\b', content))
        control_flow["function_calls"] = len(re.findall(r'\w+\s*\(', content))
        control_flow["exception_handling"] = len(re.findall(r'\btry\b|\bcatch\b|\bexcept\b|\bfinally\b', content))
        
        # Identify complexity indicators
        if control_flow["conditional_statements"] > 10:
            control_flow["complexity_indicators"].append("high_conditional_complexity")
        
        if control_flow["loops"] > 5:
            control_flow["complexity_indicators"].append("high_loop_complexity")
        
        if control_flow["function_calls"] > 50:
            control_flow["complexity_indicators"].append("high_function_calls")
        
        return control_flow
    
    def _analyze_dependency_context(self, content: str, file_type: str) -> Dict[str, Any]:
        """Analyze dependency context."""
        dependencies = {
            "imports": [],
            "function_calls": [],
            "external_dependencies": [],
            "internal_dependencies": [],
            "security_dependencies": []
        }
        
        if file_type in self.dependency_patterns["import_patterns"]:
            import_patterns = self.dependency_patterns["import_patterns"][file_type]
            for pattern in import_patterns:
                for match in re.finditer(pattern, content):
                    dependencies["imports"].append(match.group(1))
        
        if file_type in self.dependency_patterns["function_call_patterns"]:
            call_patterns = self.dependency_patterns["function_call_patterns"][file_type]
            for pattern in call_patterns:
                for match in re.finditer(pattern, content):
                    dependencies["function_calls"].append(match.group(1))
        
        # Categorize dependencies
        security_libraries = [
            "cryptography", "bcrypt", "passlib", "jwt", "oauth", "saml",
            "helmet", "express-rate-limit", "bcryptjs", "jsonwebtoken"
        ]
        
        for dep in dependencies["imports"]:
            if any(sec_lib in dep.lower() for sec_lib in security_libraries):
                dependencies["security_dependencies"].append(dep)
            elif dep.startswith(('.', '/')):
                dependencies["internal_dependencies"].append(dep)
            else:
                dependencies["external_dependencies"].append(dep)
        
        return dependencies
    
    def _analyze_security_context(self, content: str, file_type: str) -> Dict[str, Any]:
        """Analyze security-specific context."""
        security_context = {
            "security_controls": [],
            "vulnerability_indicators": [],
            "security_best_practices": [],
            "risk_areas": [],
            "compliance_indicators": []
        }
        
        # Identify security controls
        security_controls = {
            "input_validation": [r'validate\s*\(', r'isinstance\s*\(', r'check\s*\('],
            "authentication": [r'auth\s*\(', r'login\s*\(', r'password\s*='],
            "authorization": [r'permission\s*\(', r'role\s*\(', r'access\s*\('],
            "encryption": [r'encrypt\s*\(', r'hash\s*\(', r'cipher\s*\('],
            "logging": [r'log\s*\(', r'logger\s*\.', r'audit\s*\(']
        }
        
        for control, patterns in security_controls.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    security_context["security_controls"].append(control)
                    break
        
        # Identify vulnerability indicators
        vuln_indicators = [
            (r'eval\s*\(', "code_injection"),
            (r'exec\s*\(', "command_injection"),
            (r'innerHTML\s*=', "xss"),
            (r'execute\s*\(\s*[\"'].*?\%.*?[\"']', "sql_injection"),
            (r'password\s*=\s*[\"'][^\"']+[\"']', "hardcoded_credentials")
        ]
        
        for pattern, vuln_type in vuln_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                security_context["vulnerability_indicators"].append(vuln_type)
        
        return security_context
    
    def _analyze_relationship_context(self, content: str, file_path: str, file_type: str) -> Dict[str, Any]:
        """Analyze relationships between code elements."""
        relationships = {
            "inheritance": [],
            "composition": [],
            "dependencies": [],
            "calls": [],
            "references": []
        }
        
        # Analyze inheritance relationships
        if file_type == "python":
            inheritance_pattern = r'class\s+(\w+)\s*\(\s*(\w+)\s*\)'
            for match in re.finditer(inheritance_pattern, content):
                relationships["inheritance"].append({
                    "child": match.group(1),
                    "parent": match.group(2)
                })
        
        # Analyze function calls
        call_pattern = r'(\w+)\s*\(\s*'
        for match in re.finditer(call_pattern, content):
            relationships["calls"].append(match.group(1))
        
        return relationships
    
    def _analyze_risk_context(self, content: str, file_type: str) -> Dict[str, Any]:
        """Analyze risk context of the code."""
        risk_context = {
            "risk_level": "low",
            "risk_factors": [],
            "exposure_areas": [],
            "mitigation_efforts": [],
            "compliance_risks": []
        }
        
        # Determine risk level based on various factors
        risk_score = 0
        
        # Check for high-risk patterns
        high_risk_patterns = [
            (r'eval\s*\(', 10),
            (r'exec\s*\(', 10),
            (r'innerHTML\s*=', 8),
            (r'execute\s*\(\s*[\"'].*?\%.*?[\"']', 9),
            (r'password\s*=\s*[\"'][^\"']+[\"']', 6)
        ]
        
        for pattern, score in high_risk_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                risk_score += score
                risk_context["risk_factors"].append(f"high_risk_pattern: {pattern}")
        
        # Check for medium-risk patterns
        medium_risk_patterns = [
            (r'console\.log\s*\(', 2),
            (r'print\s*\(', 2),
            (r'var_dump\s*\(', 2),
            (r'debug\s*\(', 2)
        ]
        
        for pattern, score in medium_risk_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                risk_score += score
                risk_context["risk_factors"].append(f"medium_risk_pattern: {pattern}")
        
        # Determine overall risk level
        if risk_score >= 15:
            risk_context["risk_level"] = "high"
        elif risk_score >= 8:
            risk_context["risk_level"] = "medium"
        else:
            risk_context["risk_level"] = "low"
        
        return risk_context
    
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