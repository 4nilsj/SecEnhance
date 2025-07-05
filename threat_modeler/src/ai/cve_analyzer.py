"""
CVE Analyzer for AI-Assisted Threat Discovery
Uses transformer models trained on CVE databases to identify potential threats.
"""

import json
import re
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from sentence_transformers import SentenceTransformer, util
import torch

from ..debug_utils import debug_print, debug_log

class CVEAnalyzer:
    """Analyze CVEs using transformer models for threat discovery."""
    
    def __init__(self, debug: bool = False):
        """Initialize the CVE analyzer."""
        self.debug = debug
        self.cve_cache = {}
        self.embedding_model = None
        self.classification_model = None
        self.tokenizer = None
        self.cve_database = {}
        
        # Initialize models
        self._load_models()
        
        debug_log("cve_analyzer", "CVE Analyzer initialized")
    
    def _load_models(self) -> None:
        """Load transformer models for CVE analysis."""
        try:
            debug_log("cve_analyzer", "Loading transformer models")
            
            # Load sentence transformer for similarity matching
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Load classification model for CVE severity prediction
            model_name = "microsoft/DialoGPT-medium"  # Placeholder - would use CVE-specific model
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.classification_model = AutoModelForSequenceClassification.from_pretrained(model_name)
            
            # Load CVE database
            self._load_cve_database()
            
            debug_log("cve_analyzer", "Transformer models loaded successfully")
            
        except Exception as e:
            debug_log("cve_analyzer", f"Error loading models: {e}", "ERROR")
            # Fallback to basic analysis
            self.embedding_model = None
            self.classification_model = None
    
    def _load_cve_database(self) -> None:
        """Load CVE database from local cache or API."""
        try:
            # Try to load from local cache first
            cache_file = "cve_database.json"
            if self._load_cve_cache(cache_file):
                debug_log("cve_analyzer", "CVE database loaded from cache")
                return
            
            # Load from NVD API
            self._fetch_cve_data()
            
        except Exception as e:
            debug_log("cve_analyzer", f"Error loading CVE database: {e}", "ERROR")
            # Use sample data as fallback
            self._load_sample_cve_data()
    
    def _load_cve_cache(self, cache_file: str) -> bool:
        """Load CVE data from local cache."""
        try:
            with open(cache_file, 'r') as f:
                self.cve_database = json.load(f)
            return True
        except FileNotFoundError:
            return False
    
    def _fetch_cve_data(self) -> None:
        """Fetch CVE data from NVD API."""
        debug_log("cve_analyzer", "Fetching CVE data from NVD API")
        
        # Fetch recent CVEs (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00"),
            "resultsPerPage": 100
        }
        
        try:
            response = requests.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            self.cve_database = self._process_nvd_data(data)
            
            # Cache the data
            with open("cve_database.json", 'w') as f:
                json.dump(self.cve_database, f, indent=2)
                
            debug_log("cve_analyzer", f"Fetched {len(self.cve_database)} CVEs from NVD")
            
        except Exception as e:
            debug_log("cve_analyzer", f"Error fetching CVE data: {e}", "ERROR")
            self._load_sample_cve_data()
    
    def _process_nvd_data(self, data: Dict) -> Dict:
        """Process NVD API response into internal format."""
        processed_cves = {}
        
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            
            if not cve_id:
                continue
            
            # Extract relevant information
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract metrics
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
            cvss_data = cvss_v3.get("cvssData", {})
            
            processed_cves[cve_id] = {
                "id": cve_id,
                "description": description,
                "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                "score": cvss_data.get("baseScore", 0.0),
                "vector": cvss_data.get("vectorString", ""),
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "references": [ref.get("url", "") for ref in cve.get("references", [])],
                "configurations": self._extract_configurations(cve.get("configurations", {})),
                "weaknesses": self._extract_weaknesses(cve.get("weaknesses", []))
            }
        
        return processed_cves
    
    def _extract_configurations(self, configs: Dict) -> List[Dict]:
        """Extract configuration information from CVE."""
        configurations = []
        
        for node in configs.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                configurations.append({
                    "cpe": cpe_match.get("criteria", ""),
                    "version_start": cpe_match.get("versionStartIncluding", ""),
                    "version_end": cpe_match.get("versionEndExcluding", ""),
                    "vulnerable": cpe_match.get("vulnerable", True)
                })
        
        return configurations
    
    def _extract_weaknesses(self, weaknesses: List[Dict]) -> List[str]:
        """Extract weakness types from CVE."""
        weakness_types = []
        
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    weakness_types.append(desc.get("value", ""))
        
        return weakness_types
    
    def _load_sample_cve_data(self) -> None:
        """Load sample CVE data for testing."""
        self.cve_database = {
            "CVE-2023-1234": {
                "id": "CVE-2023-1234",
                "description": "SQL injection vulnerability in web application",
                "severity": "HIGH",
                "score": 8.5,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published": "2023-01-01T00:00:00Z",
                "last_modified": "2023-01-01T00:00:00Z",
                "references": ["https://example.com/cve-2023-1234"],
                "configurations": [
                    {"cpe": "cpe:2.3:a:example:webapp:*:*:*:*:*:*:*:*", "vulnerable": True}
                ],
                "weaknesses": ["CWE-89: SQL Injection"]
            },
            "CVE-2023-5678": {
                "id": "CVE-2023-5678",
                "description": "Cross-site scripting vulnerability in user input",
                "severity": "MEDIUM",
                "score": 6.1,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "published": "2023-01-02T00:00:00Z",
                "last_modified": "2023-01-02T00:00:00Z",
                "references": ["https://example.com/cve-2023-5678"],
                "configurations": [
                    {"cpe": "cpe:2.3:a:example:webapp:*:*:*:*:*:*:*:*", "vulnerable": True}
                ],
                "weaknesses": ["CWE-79: Cross-site Scripting"]
            }
        }
    
    def analyze_architecture_for_cves(self, architecture: Dict) -> List[Dict]:
        """Analyze architecture for potential CVE matches."""
        debug_log("cve_analyzer", "Analyzing architecture for CVE matches")
        
        potential_cves = []
        
        # Extract technologies and components
        technologies = self._extract_technologies(architecture)
        components = architecture.get("components", [])
        
        for cve_id, cve_data in self.cve_database.items():
            # Check if CVE applies to any technology in the architecture
            if self._cve_applies_to_technologies(cve_data, technologies):
                # Calculate relevance score
                relevance_score = self._calculate_cve_relevance(cve_data, architecture)
                
                if relevance_score > 0.3:  # Threshold for relevance
                    potential_cves.append({
                        "cve_id": cve_id,
                        "description": cve_data["description"],
                        "severity": cve_data["severity"],
                        "score": cve_data["score"],
                        "relevance_score": relevance_score,
                        "affected_components": self._get_affected_components(cve_data, components),
                        "recommendations": self._generate_cve_recommendations(cve_data),
                        "vector": cve_data.get("vector", ""),
                        "weaknesses": cve_data.get("weaknesses", [])
                    })
        
        # Sort by relevance score
        potential_cves.sort(key=lambda x: x["relevance_score"], reverse=True)
        
        debug_log("cve_analyzer", f"Found {len(potential_cves)} potential CVEs")
        return potential_cves
    
    def _extract_technologies(self, architecture: Dict) -> List[str]:
        """Extract all technologies from architecture."""
        technologies = []
        
        for component in architecture.get("components", []):
            techs = component.get("technologies", [])
            technologies.extend(techs)
            
            # Also add component type as technology
            component_type = component.get("type", "")
            if component_type:
                technologies.append(component_type)
        
        return list(set(technologies))  # Remove duplicates
    
    def _cve_applies_to_technologies(self, cve_data: Dict, technologies: List[str]) -> bool:
        """Check if CVE applies to any of the technologies."""
        description = cve_data["description"].lower()
        
        for tech in technologies:
            tech_lower = tech.lower()
            
            # Check if technology appears in CVE description
            if tech_lower in description:
                return True
            
            # Check CPE configurations
            for config in cve_data.get("configurations", []):
                cpe = config.get("cpe", "").lower()
                if tech_lower in cpe:
                    return True
        
        return False
    
    def _calculate_cve_relevance(self, cve_data: Dict, architecture: Dict) -> float:
        """Calculate relevance score for CVE in the architecture."""
        if not self.embedding_model:
            return self._calculate_basic_relevance(cve_data, architecture)
        
        try:
            # Create architecture description
            arch_desc = self._create_architecture_description(architecture)
            
            # Calculate similarity
            cve_desc = cve_data["description"]
            
            # Encode descriptions
            cve_embedding = self.embedding_model.encode(cve_desc, convert_to_tensor=True)
            arch_embedding = self.embedding_model.encode(arch_desc, convert_to_tensor=True)
            
            # Calculate cosine similarity
            similarity = util.pytorch_cos_sim(cve_embedding, arch_embedding).item()
            
            # Combine with severity score
            severity_multiplier = self._get_severity_multiplier(cve_data["severity"])
            
            relevance = similarity * severity_multiplier
            
            debug_log("cve_analyzer", f"CVE {cve_data['id']} relevance: {relevance:.3f}")
            
            return relevance
            
        except Exception as e:
            debug_log("cve_analyzer", f"Error calculating relevance: {e}", "ERROR")
            return self._calculate_basic_relevance(cve_data, architecture)
    
    def _calculate_basic_relevance(self, cve_data: Dict, architecture: Dict) -> float:
        """Calculate basic relevance score without ML models."""
        relevance = 0.0
        
        # Base score from CVE severity
        severity_scores = {"LOW": 0.3, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}
        relevance += severity_scores.get(cve_data["severity"], 0.5)
        
        # Technology match bonus
        technologies = self._extract_technologies(architecture)
        description = cve_data["description"].lower()
        
        tech_matches = sum(1 for tech in technologies if tech.lower() in description)
        if tech_matches > 0:
            relevance += 0.2 * min(tech_matches, 3)  # Cap at 0.6
        
        return min(relevance, 1.0)
    
    def _create_architecture_description(self, architecture: Dict) -> str:
        """Create a description of the architecture for similarity matching."""
        desc_parts = []
        
        desc_parts.append(architecture.get("description", ""))
        
        for component in architecture.get("components", []):
            desc_parts.append(f"{component.get('type', '')} component using {', '.join(component.get('technologies', []))}")
        
        for flow in architecture.get("data_flows", []):
            desc_parts.append(f"Data flow from {flow.get('from', '')} to {flow.get('to', '')} using {flow.get('protocol', '')}")
        
        return " ".join(desc_parts)
    
    def _get_severity_multiplier(self, severity: str) -> float:
        """Get multiplier based on CVE severity."""
        multipliers = {
            "LOW": 0.5,
            "MEDIUM": 0.7,
            "HIGH": 0.9,
            "CRITICAL": 1.0
        }
        return multipliers.get(severity, 0.7)
    
    def _get_affected_components(self, cve_data: Dict, components: List[Dict]) -> List[str]:
        """Get list of components affected by the CVE."""
        affected = []
        description = cve_data["description"].lower()
        
        for component in components:
            component_name = component.get("name", "").lower()
            component_type = component.get("type", "").lower()
            
            if component_name in description or component_type in description:
                affected.append(component.get("name", ""))
        
        return affected
    
    def _generate_cve_recommendations(self, cve_data: Dict) -> List[str]:
        """Generate recommendations for CVE mitigation."""
        recommendations = []
        
        # Generic recommendations based on CVE type
        description = cve_data["description"].lower()
        
        if "sql injection" in description:
            recommendations.extend([
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Use an ORM framework with built-in SQL injection protection",
                "Apply principle of least privilege to database accounts"
            ])
        
        elif "cross-site scripting" in description or "xss" in description:
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Use output encoding for all user-supplied data",
                "Validate and sanitize all user inputs",
                "Use modern frameworks with built-in XSS protection"
            ])
        
        elif "authentication" in description:
            recommendations.extend([
                "Implement multi-factor authentication",
                "Use secure session management",
                "Implement proper password policies",
                "Use OAuth 2.0 or similar modern authentication protocols"
            ])
        
        elif "authorization" in description:
            recommendations.extend([
                "Implement role-based access control (RBAC)",
                "Apply principle of least privilege",
                "Implement proper authorization checks",
                "Use secure token-based authentication"
            ])
        
        # Add general recommendations
        recommendations.extend([
            "Keep all software and dependencies updated",
            "Regularly scan for vulnerabilities",
            "Implement security monitoring and logging",
            "Conduct regular security assessments"
        ])
        
        return recommendations
    
    def predict_threats_from_description(self, description: str) -> List[Dict]:
        """Predict potential threats from natural language description."""
        debug_log("cve_analyzer", "Predicting threats from description")
        
        if not self.embedding_model:
            return self._basic_threat_prediction(description)
        
        try:
            # Encode the description
            desc_embedding = self.embedding_model.encode(description, convert_to_tensor=True)
            
            predicted_threats = []
            
            # Find similar CVEs
            for cve_id, cve_data in self.cve_database.items():
                cve_embedding = self.embedding_model.encode(cve_data["description"], convert_to_tensor=True)
                similarity = util.pytorch_cos_sim(desc_embedding, cve_embedding).item()
                
                if similarity > 0.6:  # High similarity threshold
                    predicted_threats.append({
                        "threat_type": self._classify_threat_type(cve_data),
                        "confidence": similarity,
                        "description": cve_data["description"],
                        "severity": cve_data["severity"],
                        "cve_reference": cve_id
                    })
            
            # Sort by confidence
            predicted_threats.sort(key=lambda x: x["confidence"], reverse=True)
            
            debug_log("cve_analyzer", f"Predicted {len(predicted_threats)} threats")
            return predicted_threats
            
        except Exception as e:
            debug_log("cve_analyzer", f"Error predicting threats: {e}", "ERROR")
            return self._basic_threat_prediction(description)
    
    def _basic_threat_prediction(self, description: str) -> List[Dict]:
        """Basic threat prediction without ML models."""
        threats = []
        desc_lower = description.lower()
        
        # Keyword-based threat classification
        threat_keywords = {
            "SQL Injection": ["sql", "database", "query", "injection"],
            "XSS": ["xss", "cross-site scripting", "script", "javascript"],
            "Authentication": ["auth", "login", "password", "credential"],
            "Authorization": ["authorization", "permission", "access", "role"],
            "CSRF": ["csrf", "cross-site request forgery", "forgery"],
            "File Upload": ["upload", "file", "attachment"],
            "Path Traversal": ["path", "directory", "traversal", "../"],
            "Command Injection": ["command", "exec", "system", "shell"]
        }
        
        for threat_type, keywords in threat_keywords.items():
            if any(keyword in desc_lower for keyword in keywords):
                threats.append({
                    "threat_type": threat_type,
                    "confidence": 0.7,
                    "description": f"Potential {threat_type.lower()} vulnerability",
                    "severity": "MEDIUM",
                    "cve_reference": None
                })
        
        return threats
    
    def _classify_threat_type(self, cve_data: Dict) -> str:
        """Classify threat type from CVE data."""
        description = cve_data["description"].lower()
        weaknesses = [w.lower() for w in cve_data.get("weaknesses", [])]
        
        # Map CWE to threat types
        cwe_mapping = {
            "sql injection": "SQL Injection",
            "cross-site scripting": "XSS",
            "authentication": "Authentication",
            "authorization": "Authorization",
            "csrf": "CSRF",
            "file upload": "File Upload",
            "path traversal": "Path Traversal",
            "command injection": "Command Injection"
        }
        
        for cwe in weaknesses:
            for keyword, threat_type in cwe_mapping.items():
                if keyword in cwe:
                    return threat_type
        
        # Fallback to description analysis
        for keyword, threat_type in cwe_mapping.items():
            if keyword in description:
                return threat_type
        
        return "General Vulnerability" 