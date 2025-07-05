"""
AI Analyzer for SAST Scanner
Uses machine learning to identify security issues and understand code context.
"""

import re
import json
from typing import Dict, List, Any, Optional
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from ..debug_utils import debug_print, debug_log

class AIAnalyzer:
    """AI-powered code analysis for security insights."""
    
    def __init__(self, debug: bool = False):
        """Initialize the AI analyzer."""
        self.debug = debug
        self.embedding_model = None
        self.security_patterns = {}
        self.vulnerability_signatures = {}
        self.context_indicators = {}
        
        # Initialize AI models
        self._load_models()
        self._load_security_patterns()
        
        debug_log("ai_analyzer", "AI Analyzer initialized")
    
    def _load_models(self) -> None:
        """Load AI models for analysis."""
        try:
            debug_log("ai_analyzer", "Loading AI models")
            
            # Load sentence transformer for semantic analysis
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            debug_log("ai_analyzer", "AI models loaded successfully")
            
        except Exception as e:
            debug_log("ai_analyzer", f"Error loading AI models: {e}", "ERROR")
            self.embedding_model = None
    
    def _load_security_patterns(self) -> None:
        """Load security patterns and vulnerability signatures."""
        self.security_patterns = {
            "sql_injection": {
                "patterns": [
                    r"execute\s*\(\s*[\"'].*?\%.*?[\"']",
                    r"query\s*\(\s*[\"'].*?\%.*?[\"']",
                    r"cursor\.execute\s*\(\s*[\"'].*?\%.*?[\"']",
                    r"db\.execute\s*\(\s*[\"'].*?\%.*?[\"']",
                    r"connection\.execute\s*\(\s*[\"'].*?\%.*?[\"']"
                ],
                "risk_level": "high",
                "description": "SQL injection vulnerability detected",
                "mitigation": "Use parameterized queries or prepared statements"
            },
            "xss": {
                "patterns": [
                    r"innerHTML\s*=\s*.*?[\"'].*?[\"']",
                    r"document\.write\s*\(\s*.*?[\"'].*?[\"']",
                    r"eval\s*\(\s*.*?[\"'].*?[\"']",
                    r"innerHTML\s*\+\s*.*?[\"'].*?[\"']",
                    r"document\.body\.innerHTML\s*="
                ],
                "risk_level": "high",
                "description": "Cross-site scripting vulnerability detected",
                "mitigation": "Use proper output encoding and Content Security Policy"
            },
            "command_injection": {
                "patterns": [
                    r"os\.system\s*\(\s*.*?[\"'].*?[\"']",
                    r"subprocess\.call\s*\(\s*.*?[\"'].*?[\"']",
                    r"exec\s*\(\s*.*?[\"'].*?[\"']",
                    r"shell_exec\s*\(\s*.*?[\"'].*?[\"']",
                    r"system\s*\(\s*.*?[\"'].*?[\"']"
                ],
                "risk_level": "critical",
                "description": "Command injection vulnerability detected",
                "mitigation": "Avoid command execution with user input, use safe APIs"
            },
            "path_traversal": {
                "patterns": [
                    r"open\s*\(\s*.*?\.\./",
                    r"file_get_contents\s*\(\s*.*?\.\./",
                    r"readfile\s*\(\s*.*?\.\./",
                    r"include\s*\(\s*.*?\.\./",
                    r"require\s*\(\s*.*?\.\./"
                ],
                "risk_level": "high",
                "description": "Path traversal vulnerability detected",
                "mitigation": "Validate and sanitize file paths, use safe path resolution"
            },
            "hardcoded_credentials": {
                "patterns": [
                    r"password\s*=\s*[\"'][^\"']+[\"']",
                    r"passwd\s*=\s*[\"'][^\"']+[\"']",
                    r"secret\s*=\s*[\"'][^\"']+[\"']",
                    r"key\s*=\s*[\"'][^\"']+[\"']",
                    r"token\s*=\s*[\"'][^\"']+[\"']"
                ],
                "risk_level": "medium",
                "description": "Hardcoded credentials detected",
                "mitigation": "Use environment variables or secure configuration management"
            },
            "weak_crypto": {
                "patterns": [
                    r"md5\s*\(\s*",
                    r"sha1\s*\(\s*",
                    r"hashlib\.md5",
                    r"hashlib\.sha1",
                    r"crypto\.createHash\s*\(\s*[\"']md5[\"']"
                ],
                "risk_level": "medium",
                "description": "Weak cryptographic algorithm detected",
                "mitigation": "Use strong cryptographic algorithms (SHA-256, bcrypt, etc.)"
            },
            "insecure_random": {
                "patterns": [
                    r"Math\.random\s*\(\s*\)",
                    r"random\s*\(\s*\)",
                    r"rand\s*\(\s*\)",
                    r"\.random\s*\(\s*\)"
                ],
                "risk_level": "medium",
                "description": "Insecure random number generation detected",
                "mitigation": "Use cryptographically secure random number generators"
            },
            "debug_code": {
                "patterns": [
                    r"console\.log\s*\(\s*",
                    r"print\s*\(\s*",
                    r"debug\s*\(\s*",
                    r"dump\s*\(\s*",
                    r"var_dump\s*\(\s*"
                ],
                "risk_level": "low",
                "description": "Debug code detected in production",
                "mitigation": "Remove debug statements before production deployment"
            }
        }
        
        # Context indicators for better understanding
        self.context_indicators = {
            "authentication_context": [
                "login", "auth", "authenticate", "session", "token", "jwt", "oauth"
            ],
            "data_processing_context": [
                "process", "parse", "validate", "sanitize", "filter", "transform"
            ],
            "file_handling_context": [
                "upload", "download", "read", "write", "save", "load", "import", "export"
            ],
            "network_context": [
                "http", "https", "api", "request", "response", "url", "endpoint"
            ],
            "database_context": [
                "database", "db", "query", "sql", "connection", "cursor", "transaction"
            ]
        }
    
    def analyze_file(self, content: str, file_path: str, code_analysis: Dict, 
                    context_analysis: Dict) -> List[Dict]:
        """Perform AI analysis on a file."""
        debug_log("ai_analyzer", f"Starting AI analysis for {file_path}")
        
        insights = []
        
        # Pattern-based vulnerability detection
        pattern_insights = self._detect_pattern_vulnerabilities(content, file_path)
        insights.extend(pattern_insights)
        
        # Semantic analysis
        semantic_insights = self._perform_semantic_analysis(content, file_path, code_analysis)
        insights.extend(semantic_insights)
        
        # Context-aware analysis
        context_insights = self._analyze_context_awareness(content, file_path, context_analysis)
        insights.extend(context_insights)
        
        # Code quality insights
        quality_insights = self._analyze_code_quality(content, file_path, code_analysis)
        insights.extend(quality_insights)
        
        # Security best practices
        best_practice_insights = self._check_security_best_practices(content, file_path)
        insights.extend(best_practice_insights)
        
        debug_log("ai_analyzer", f"AI analysis completed: {len(insights)} insights found")
        return insights
    
    def _detect_pattern_vulnerabilities(self, content: str, file_path: str) -> List[Dict]:
        """Detect vulnerabilities using pattern matching."""
        insights = []
        
        for vuln_type, pattern_info in self.security_patterns.items():
            for pattern in pattern_info["patterns"]:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_number = content[:match.start()].count('\n') + 1
                    line_content = content.split('\n')[line_number - 1] if line_number <= len(content.split('\n')) else ""
                    
                    insights.append({
                        "type": "vulnerability_pattern",
                        "vulnerability_type": vuln_type,
                        "severity": pattern_info["risk_level"],
                        "description": pattern_info["description"],
                        "line_number": line_number,
                        "line_content": line_content.strip(),
                        "pattern_match": match.group(),
                        "mitigation": pattern_info["mitigation"],
                        "confidence": 0.85,
                        "ai_generated": True
                    })
        
        return insights
    
    def _perform_semantic_analysis(self, content: str, file_path: str, 
                                 code_analysis: Dict) -> List[Dict]:
        """Perform semantic analysis using AI models."""
        insights = []
        
        if not self.embedding_model:
            return insights
        
        try:
            # Extract code segments for analysis
            code_segments = self._extract_code_segments(content)
            
            # Analyze each segment
            for segment in code_segments:
                segment_insights = self._analyze_code_segment(segment, file_path)
                insights.extend(segment_insights)
            
            # Analyze function-level security
            if "language_analysis" in code_analysis:
                lang_analysis = code_analysis["language_analysis"]
                if "functions" in lang_analysis:
                    for func in lang_analysis["functions"]:
                        func_insights = self._analyze_function_security(func, content, file_path)
                        insights.extend(func_insights)
            
        except Exception as e:
            debug_log("ai_analyzer", f"Error in semantic analysis: {e}", "ERROR")
        
        return insights
    
    def _extract_code_segments(self, content: str) -> List[Dict]:
        """Extract meaningful code segments for analysis."""
        segments = []
        lines = content.split('\n')
        
        current_segment = []
        current_line_start = 1
        
        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()
            
            # Start new segment on function/class definitions
            if (stripped.startswith(('def ', 'class ', 'function ', 'public ', 'private ')) and 
                current_segment):
                if current_segment:
                    segments.append({
                        "content": '\n'.join(current_segment),
                        "start_line": current_line_start,
                        "end_line": line_num - 1,
                        "type": "code_block"
                    })
                current_segment = [line]
                current_line_start = line_num
            else:
                current_segment.append(line)
        
        # Add final segment
        if current_segment:
            segments.append({
                "content": '\n'.join(current_segment),
                "start_line": current_line_start,
                "end_line": len(lines),
                "type": "code_block"
            })
        
        return segments
    
    def _analyze_code_segment(self, segment: Dict, file_path: str) -> List[Dict]:
        """Analyze a code segment for security issues."""
        insights = []
        
        content = segment["content"]
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'eval\s*\(', "Use of eval() function", "high"),
            (r'exec\s*\(', "Use of exec() function", "high"),
            (r'globals\s*\(', "Use of globals() function", "medium"),
            (r'locals\s*\(', "Use of locals() function", "medium"),
            (r'__import__\s*\(', "Dynamic import detected", "medium"),
            (r'pickle\.loads', "Unsafe deserialization", "high"),
            (r'yaml\.load\s*\(', "Unsafe YAML loading", "high"),
            (r'json\.loads\s*\(.*?\)', "JSON deserialization", "medium")
        ]
        
        for pattern, description, severity in suspicious_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                insights.append({
                    "type": "suspicious_pattern",
                    "description": description,
                    "severity": severity,
                    "line_number": segment["start_line"] + content[:match.start()].count('\n'),
                    "line_content": match.group(),
                    "mitigation": "Review and validate input before processing",
                    "confidence": 0.8,
                    "ai_generated": True
                })
        
        return insights
    
    def _analyze_function_security(self, func: Dict, content: str, file_path: str) -> List[Dict]:
        """Analyze function-level security issues."""
        insights = []
        
        func_name = func.get("name", "")
        func_line = func.get("line", 1)
        
        # Check for dangerous function names
        dangerous_functions = [
            "eval", "exec", "system", "shell_exec", "passthru", "backticks",
            "popen", "proc_open", "pcntl_exec", "assert", "extract"
        ]
        
        if any(dangerous in func_name.lower() for dangerous in dangerous_functions):
            insights.append({
                "type": "dangerous_function",
                "description": f"Dangerous function name detected: {func_name}",
                "severity": "high",
                "line_number": func_line,
                "line_content": f"def {func_name}",
                "mitigation": "Review function implementation for security issues",
                "confidence": 0.9,
                "ai_generated": True
            })
        
        # Check for missing input validation
        if "args" in func:
            args = func["args"]
            if args and not self._has_input_validation(content, func_line):
                insights.append({
                    "type": "missing_validation",
                    "description": f"Function {func_name} may lack input validation",
                    "severity": "medium",
                    "line_number": func_line,
                    "line_content": f"def {func_name}",
                    "mitigation": "Add input validation and sanitization",
                    "confidence": 0.7,
                    "ai_generated": True
                })
        
        return insights
    
    def _has_input_validation(self, content: str, func_line: int) -> bool:
        """Check if function has input validation."""
        lines = content.split('\n')
        start_line = max(0, func_line - 1)
        end_line = min(len(lines), func_line + 20)  # Check next 20 lines
        
        validation_patterns = [
            r'if\s+.*?is\s+not\s+None',
            r'if\s+.*?len\s*\(',
            r'if\s+.*?in\s+\[',
            r'assert\s+',
            r'validate\s*\(',
            r'check\s*\(',
            r'isinstance\s*\(',
            r'type\s*\('
        ]
        
        for i in range(start_line, end_line):
            line = lines[i].lower()
            for pattern in validation_patterns:
                if re.search(pattern, line):
                    return True
        
        return False
    
    def _analyze_context_awareness(self, content: str, file_path: str, 
                                 context_analysis: Dict) -> List[Dict]:
        """Analyze code in context of its purpose."""
        insights = []
        
        content_lower = content.lower()
        
        # Check authentication context
        if any(indicator in content_lower for indicator in self.context_indicators["authentication_context"]):
            auth_insights = self._analyze_authentication_context(content, file_path)
            insights.extend(auth_insights)
        
        # Check data processing context
        if any(indicator in content_lower for indicator in self.context_indicators["data_processing_context"]):
            data_insights = self._analyze_data_processing_context(content, file_path)
            insights.extend(data_insights)
        
        # Check file handling context
        if any(indicator in content_lower for indicator in self.context_indicators["file_handling_context"]):
            file_insights = self._analyze_file_handling_context(content, file_path)
            insights.extend(file_insights)
        
        return insights
    
    def _analyze_authentication_context(self, content: str, file_path: str) -> List[Dict]:
        """Analyze authentication-related code."""
        insights = []
        
        # Check for weak password policies
        weak_password_patterns = [
            (r'password.*?len.*?<.*?8', "Weak password length requirement", "medium"),
            (r'password.*?=.*?[\"\'][^\"\']{1,7}[\"\']', "Very short password", "high"),
            (r'password.*?=.*?[\"\'][^\"\']{8,15}[\"\']', "Short password", "medium")
        ]
        
        for pattern, description, severity in weak_password_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                insights.append({
                    "type": "weak_password_policy",
                    "description": description,
                    "severity": severity,
                    "line_content": "Password policy check",
                    "mitigation": "Implement strong password policies (min 12 chars, complexity)",
                    "confidence": 0.8,
                    "ai_generated": True
                })
        
        # Check for missing session management
        if "session" in content.lower() and not re.search(r'session.*?timeout|expire', content, re.IGNORECASE):
            insights.append({
                "type": "missing_session_timeout",
                "description": "Session timeout not configured",
                "severity": "medium",
                "line_content": "Session management",
                "mitigation": "Implement session timeout and secure session handling",
                "confidence": 0.7,
                "ai_generated": True
            })
        
        return insights
    
    def _analyze_data_processing_context(self, content: str, file_path: str) -> List[Dict]:
        """Analyze data processing code."""
        insights = []
        
        # Check for missing data validation
        if "process" in content.lower() and not re.search(r'validate|check|verify', content, re.IGNORECASE):
            insights.append({
                "type": "missing_data_validation",
                "description": "Data processing without validation",
                "severity": "medium",
                "line_content": "Data processing",
                "mitigation": "Add input validation and data sanitization",
                "confidence": 0.6,
                "ai_generated": True
            })
        
        # Check for unsafe data transformation
        unsafe_transform_patterns = [
            (r'str_replace.*?\$.*?\$', "Unsafe string replacement", "medium"),
            (r'replace.*?[\"\'][^\"\']*[\"\']', "Potential unsafe replacement", "low")
        ]
        
        for pattern, description, severity in unsafe_transform_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                insights.append({
                    "type": "unsafe_data_transformation",
                    "description": description,
                    "severity": severity,
                    "line_content": "Data transformation",
                    "mitigation": "Validate and sanitize data before transformation",
                    "confidence": 0.7,
                    "ai_generated": True
                })
        
        return insights
    
    def _analyze_file_handling_context(self, content: str, file_path: str) -> List[Dict]:
        """Analyze file handling code."""
        insights = []
        
        # Check for missing file type validation
        if "upload" in content.lower() and not re.search(r'file.*?type|mime.*?type|extension', content, re.IGNORECASE):
            insights.append({
                "type": "missing_file_validation",
                "description": "File upload without type validation",
                "severity": "high",
                "line_content": "File upload",
                "mitigation": "Validate file types, extensions, and MIME types",
                "confidence": 0.8,
                "ai_generated": True
            })
        
        # Check for unsafe file operations
        unsafe_file_patterns = [
            (r'file_get_contents.*?\$', "Unsafe file reading", "high"),
            (r'include.*?\$', "Unsafe file inclusion", "high"),
            (r'require.*?\$', "Unsafe file requirement", "high")
        ]
        
        for pattern, description, severity in unsafe_file_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                insights.append({
                    "type": "unsafe_file_operation",
                    "description": description,
                    "severity": severity,
                    "line_content": "File operation",
                    "mitigation": "Validate file paths and use safe file operations",
                    "confidence": 0.9,
                    "ai_generated": True
                })
        
        return insights
    
    def _analyze_code_quality(self, content: str, file_path: str, 
                            code_analysis: Dict) -> List[Dict]:
        """Analyze code quality and maintainability."""
        insights = []
        
        # Check for code complexity
        if "complexity_metrics" in code_analysis:
            complexity = code_analysis["complexity_metrics"]
            if complexity.get("complexity_level") == "high":
                insights.append({
                    "type": "high_complexity",
                    "description": "High code complexity detected",
                    "severity": "low",
                    "line_content": "Code complexity",
                    "mitigation": "Refactor code to reduce complexity and improve maintainability",
                    "confidence": 0.8,
                    "ai_generated": True
                })
        
        # Check for long functions
        lines = content.split('\n')
        if len(lines) > 100:
            insights.append({
                "type": "long_file",
                "description": "File is very long (>100 lines)",
                "severity": "low",
                "line_content": f"File length: {len(lines)} lines",
                "mitigation": "Consider breaking file into smaller modules",
                "confidence": 0.7,
                "ai_generated": True
            })
        
        return insights
    
    def _check_security_best_practices(self, content: str, file_path: str) -> List[Dict]:
        """Check for security best practices."""
        insights = []
        
        # Check for HTTPS usage
        if "http://" in content and "https://" not in content:
            insights.append({
                "type": "insecure_protocol",
                "description": "HTTP protocol used instead of HTTPS",
                "severity": "medium",
                "line_content": "HTTP protocol",
                "mitigation": "Use HTTPS for all external communications",
                "confidence": 0.9,
                "ai_generated": True
            })
        
        # Check for proper error handling
        if "try:" in content and "except:" in content:
            if "except Exception:" in content or "except:" in content:
                insights.append({
                    "type": "broad_exception_handling",
                    "description": "Broad exception handling detected",
                    "severity": "low",
                    "line_content": "Exception handling",
                    "mitigation": "Use specific exception types instead of broad exceptions",
                    "confidence": 0.7,
                    "ai_generated": True
                })
        
        return insights 