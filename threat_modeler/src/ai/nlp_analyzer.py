"""
NLP Analyzer for AI-Assisted Threat Discovery
Uses natural language processing to extract security-relevant information from design documents.
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
import nltk
import spacy
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk.corpus import stopwords
from nltk.tag import pos_tag
from nltk.chunk import ne_chunk
import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from ..debug_utils import debug_print, debug_log

class NLPAnalyzer:
    """Analyze design documents using natural language processing."""
    
    def __init__(self, debug: bool = False):
        """Initialize the NLP analyzer."""
        self.debug = debug
        self.nlp = None
        self.embedding_model = None
        self.security_keywords = {}
        self.threat_indicators = {}
        self.requirement_patterns = {}
        
        # Initialize NLP models
        self._load_nlp_models()
        self._load_security_keywords()
        
        debug_log("nlp_analyzer", "NLP Analyzer initialized")
    
    def _load_nlp_models(self) -> None:
        """Load NLP models for text analysis."""
        try:
            debug_log("nlp_analyzer", "Loading NLP models")
            
            # Download required NLTK data
            try:
                nltk.data.find('tokenizers/punkt')
            except LookupError:
                nltk.download('punkt')
            
            try:
                nltk.data.find('taggers/averaged_perceptron_tagger')
            except LookupError:
                nltk.download('averaged_perceptron_tagger')
            
            try:
                nltk.data.find('chunkers/maxent_ne_chunker')
            except LookupError:
                nltk.download('maxent_ne_chunker')
            
            try:
                nltk.data.find('corpora/stopwords')
            except LookupError:
                nltk.download('stopwords')
            
            # Load spaCy model
            try:
                self.nlp = spacy.load("en_core_web_sm")
            except OSError:
                debug_log("nlp_analyzer", "spaCy model not found, using basic NLP", "WARNING")
                self.nlp = None
            
            # Load sentence transformer
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            debug_log("nlp_analyzer", "NLP models loaded successfully")
            
        except Exception as e:
            debug_log("nlp_analyzer", f"Error loading NLP models: {e}", "ERROR")
            self.nlp = None
            self.embedding_model = None
    
    def _load_security_keywords(self) -> None:
        """Load security-related keywords and patterns."""
        self.security_keywords = {
            "authentication": [
                "login", "password", "credential", "token", "session", "oauth", "saml",
                "jwt", "authentication", "authorization", "identity", "user", "admin"
            ],
            "data_protection": [
                "encryption", "decryption", "hash", "salt", "key", "certificate",
                "ssl", "tls", "pii", "personal data", "sensitive", "confidential"
            ],
            "network_security": [
                "firewall", "vpn", "network", "protocol", "port", "ip", "dns",
                "load balancer", "proxy", "gateway", "router", "switch"
            ],
            "input_validation": [
                "input", "validation", "sanitization", "filter", "escape",
                "sql injection", "xss", "csrf", "injection", "malicious"
            ],
            "access_control": [
                "permission", "role", "access", "privilege", "authorization",
                "rbac", "acl", "policy", "rule", "restriction"
            ],
            "logging_monitoring": [
                "log", "audit", "monitor", "alert", "trace", "debug",
                "analytics", "metrics", "dashboard", "siem", "detection"
            ],
            "vulnerabilities": [
                "vulnerability", "exploit", "attack", "breach", "compromise",
                "malware", "virus", "trojan", "backdoor", "rootkit"
            ]
        }
        
        # Threat indicators
        self.threat_indicators = {
            "high_risk": [
                "critical", "urgent", "immediate", "severe", "high priority",
                "production", "live", "customer data", "financial", "health"
            ],
            "external_exposure": [
                "public", "internet", "external", "third party", "vendor",
                "api", "web", "mobile", "cloud", "saas"
            ],
            "data_handling": [
                "store", "process", "transmit", "share", "export", "import",
                "backup", "archive", "delete", "retention"
            ],
            "user_interaction": [
                "upload", "download", "submit", "form", "file", "attachment",
                "comment", "review", "rating", "feedback"
            ]
        }
        
        # Requirement patterns
        self.requirement_patterns = {
            "functional": r"(?:shall|must|should|will)\s+(?:provide|support|allow|enable|implement)",
            "security": r"(?:secure|protect|encrypt|authenticate|authorize|validate)",
            "performance": r"(?:performance|speed|latency|throughput|response time)",
            "availability": r"(?:availability|uptime|reliability|backup|recovery)",
            "compliance": r"(?:compliance|regulation|standard|policy|requirement)"
        }
    
    def analyze_design_document(self, document_text: str) -> Dict[str, Any]:
        """Analyze design document for security-relevant information."""
        debug_log("nlp_analyzer", "Analyzing design document")
        
        analysis = {
            "security_requirements": [],
            "threat_indicators": [],
            "data_flows": [],
            "components": [],
            "risks": [],
            "recommendations": []
        }
        
        # Extract sentences
        sentences = sent_tokenize(document_text)
        
        # Analyze each sentence
        for sentence in sentences:
            sentence_analysis = self._analyze_sentence(sentence)
            
            if sentence_analysis["security_requirements"]:
                analysis["security_requirements"].extend(sentence_analysis["security_requirements"])
            
            if sentence_analysis["threat_indicators"]:
                analysis["threat_indicators"].extend(sentence_analysis["threat_indicators"])
            
            if sentence_analysis["data_flows"]:
                analysis["data_flows"].extend(sentence_analysis["data_flows"])
            
            if sentence_analysis["components"]:
                analysis["components"].extend(sentence_analysis["components"])
        
        # Remove duplicates
        analysis["security_requirements"] = list(set(analysis["security_requirements"]))
        analysis["threat_indicators"] = list(set(analysis["threat_indicators"]))
        analysis["data_flows"] = list(set(analysis["data_flows"]))
        analysis["components"] = list(set(analysis["components"]))
        
        # Generate risks and recommendations
        analysis["risks"] = self._identify_risks(analysis)
        analysis["recommendations"] = self._generate_recommendations(analysis)
        
        debug_log("nlp_analyzer", f"Document analysis completed: {len(analysis['security_requirements'])} requirements found")
        return analysis
    
    def _analyze_sentence(self, sentence: str) -> Dict[str, List[str]]:
        """Analyze a single sentence for security-relevant information."""
        analysis = {
            "security_requirements": [],
            "threat_indicators": [],
            "data_flows": [],
            "components": []
        }
        
        sentence_lower = sentence.lower()
        
        # Check for security keywords
        for category, keywords in self.security_keywords.items():
            for keyword in keywords:
                if keyword in sentence_lower:
                    analysis["security_requirements"].append(f"{category}: {sentence.strip()}")
                    break
        
        # Check for threat indicators
        for category, indicators in self.threat_indicators.items():
            for indicator in indicators:
                if indicator in sentence_lower:
                    analysis["threat_indicators"].append(f"{category}: {sentence.strip()}")
                    break
        
        # Extract data flows using regex patterns
        data_flow_patterns = [
            r"(\w+)\s+(?:sends|transmits|receives|processes)\s+(\w+)",
            r"data\s+(?:flows|moves|transfers)\s+(?:from|to|between)\s+(\w+)",
            r"(\w+)\s+(?:communicates|connects|interfaces)\s+with\s+(\w+)"
        ]
        
        for pattern in data_flow_patterns:
            matches = re.findall(pattern, sentence_lower)
            for match in matches:
                if len(match) == 2:
                    analysis["data_flows"].append(f"{match[0]} -> {match[1]}: {sentence.strip()}")
        
        # Extract components using NER
        if self.nlp:
            doc = self.nlp(sentence)
            for ent in doc.ents:
                if ent.label_ in ["ORG", "PRODUCT", "GPE"]:
                    analysis["components"].append(f"{ent.label_}: {ent.text} - {sentence.strip()}")
        
        return analysis
    
    def _identify_risks(self, analysis: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Identify risks based on analysis results."""
        risks = []
        
        # Risk based on threat indicators
        high_risk_indicators = [ind for ind in analysis["threat_indicators"] if "high_risk" in ind]
        if high_risk_indicators:
            risks.append({
                "type": "High Risk Operations",
                "description": "System handles high-risk operations or data",
                "severity": "High",
                "evidence": high_risk_indicators,
                "mitigation": "Implement additional security controls and monitoring"
            })
        
        # Risk based on external exposure
        external_indicators = [ind for ind in analysis["threat_indicators"] if "external_exposure" in ind]
        if external_indicators:
            risks.append({
                "type": "External Exposure",
                "description": "System has external interfaces or public exposure",
                "severity": "Medium",
                "evidence": external_indicators,
                "mitigation": "Implement strong authentication and input validation"
            })
        
        # Risk based on data handling
        data_indicators = [ind for ind in analysis["threat_indicators"] if "data_handling" in ind]
        if data_indicators:
            risks.append({
                "type": "Data Processing",
                "description": "System processes sensitive or personal data",
                "severity": "Medium",
                "evidence": data_indicators,
                "mitigation": "Implement data encryption and access controls"
            })
        
        # Risk based on missing security requirements
        if not analysis["security_requirements"]:
            risks.append({
                "type": "Missing Security Requirements",
                "description": "No explicit security requirements identified",
                "severity": "High",
                "evidence": ["No security keywords found in document"],
                "mitigation": "Add explicit security requirements and controls"
            })
        
        return risks
    
    def _generate_recommendations(self, analysis: Dict[str, List[str]]) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Recommendations based on security requirements
        if analysis["security_requirements"]:
            recommendations.extend([
                "Review and validate all identified security requirements",
                "Ensure security requirements are properly implemented",
                "Conduct security testing against identified requirements"
            ])
        
        # Recommendations based on threat indicators
        if analysis["threat_indicators"]:
            recommendations.extend([
                "Implement threat modeling for identified risk areas",
                "Add security controls for high-risk operations",
                "Implement monitoring for threat indicators"
            ])
        
        # Recommendations based on data flows
        if analysis["data_flows"]:
            recommendations.extend([
                "Validate security of all identified data flows",
                "Implement encryption for data in transit",
                "Add access controls for data processing"
            ])
        
        # General recommendations
        recommendations.extend([
            "Conduct regular security assessments",
            "Implement security monitoring and alerting",
            "Establish incident response procedures",
            "Provide security training for development team"
        ])
        
        return list(set(recommendations))
    
    def extract_requirements(self, document_text: str) -> List[Dict[str, Any]]:
        """Extract requirements from design document."""
        debug_log("nlp_analyzer", "Extracting requirements from document")
        
        requirements = []
        sentences = sent_tokenize(document_text)
        
        for sentence in sentences:
            sentence_lower = sentence.lower()
            
            # Check for requirement patterns
            for req_type, pattern in self.requirement_patterns.items():
                if re.search(pattern, sentence_lower):
                    requirements.append({
                        "type": req_type,
                        "text": sentence.strip(),
                        "priority": self._determine_priority(sentence_lower),
                        "security_relevant": self._is_security_relevant(sentence_lower)
                    })
        
        debug_log("nlp_analyzer", f"Extracted {len(requirements)} requirements")
        return requirements
    
    def _determine_priority(self, sentence: str) -> str:
        """Determine priority of a requirement."""
        priority_keywords = {
            "high": ["critical", "urgent", "must", "shall", "essential"],
            "medium": ["should", "important", "necessary"],
            "low": ["nice to have", "optional", "may", "could"]
        }
        
        for priority, keywords in priority_keywords.items():
            if any(keyword in sentence for keyword in keywords):
                return priority
        
        return "medium"
    
    def _is_security_relevant(self, sentence: str) -> bool:
        """Check if a sentence is security-relevant."""
        security_keywords = []
        for category in self.security_keywords.values():
            security_keywords.extend(category)
        
        return any(keyword in sentence for keyword in security_keywords)
    
    def analyze_architecture_description(self, description: str) -> Dict[str, Any]:
        """Analyze architecture description for security insights."""
        debug_log("nlp_analyzer", "Analyzing architecture description")
        
        analysis = {
            "components": [],
            "technologies": [],
            "security_controls": [],
            "vulnerabilities": [],
            "recommendations": []
        }
        
        if self.nlp:
            doc = self.nlp(description)
            
            # Extract named entities
            for ent in doc.ents:
                if ent.label_ in ["ORG", "PRODUCT", "GPE"]:
                    analysis["components"].append({
                        "name": ent.text,
                        "type": ent.label_,
                        "context": ent.sent.text
                    })
            
            # Extract technical terms
            for token in doc:
                if token.pos_ in ["NOUN", "PROPN"] and token.is_alpha:
                    if len(token.text) > 3:  # Filter out short words
                        analysis["technologies"].append(token.text)
        
        # Check for security controls
        security_control_patterns = [
            r"encrypt(?:ed|ion)?",
            r"authenticat(?:ed|ion)?",
            r"authoriz(?:ed|ation)?",
            r"firewall",
            r"vpn",
            r"ssl/tls",
            r"https"
        ]
        
        for pattern in security_control_patterns:
            matches = re.findall(pattern, description.lower())
            if matches:
                analysis["security_controls"].extend(matches)
        
        # Check for potential vulnerabilities
        vulnerability_patterns = [
            r"sql injection",
            r"xss",
            r"csrf",
            r"injection",
            r"buffer overflow",
            r"race condition"
        ]
        
        for pattern in vulnerability_patterns:
            if re.search(pattern, description.lower()):
                analysis["vulnerabilities"].append(pattern)
        
        # Generate recommendations
        analysis["recommendations"] = self._generate_architecture_recommendations(analysis)
        
        debug_log("nlp_analyzer", f"Architecture analysis completed: {len(analysis['components'])} components found")
        return analysis
    
    def _generate_architecture_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on architecture analysis."""
        recommendations = []
        
        # Recommendations based on components
        if analysis["components"]:
            recommendations.append("Review security of all identified components")
        
        # Recommendations based on technologies
        if analysis["technologies"]:
            recommendations.append("Ensure all technologies are up-to-date and secure")
        
        # Recommendations based on security controls
        if not analysis["security_controls"]:
            recommendations.append("Add explicit security controls to architecture")
        else:
            recommendations.append("Validate implementation of identified security controls")
        
        # Recommendations based on vulnerabilities
        if analysis["vulnerabilities"]:
            recommendations.append("Address identified potential vulnerabilities")
        
        return recommendations
    
    def compare_documents(self, doc1: str, doc2: str) -> Dict[str, Any]:
        """Compare two documents for security-relevant differences."""
        debug_log("nlp_analyzer", "Comparing documents")
        
        if not self.embedding_model:
            return {"error": "Embedding model not available"}
        
        try:
            # Analyze both documents
            analysis1 = self.analyze_design_document(doc1)
            analysis2 = self.analyze_design_document(doc2)
            
            # Calculate similarity
            embedding1 = self.embedding_model.encode(doc1)
            embedding2 = self.embedding_model.encode(doc2)
            
            similarity = cosine_similarity([embedding1], [embedding2])[0][0]
            
            # Find differences
            differences = {
                "similarity_score": similarity,
                "new_security_requirements": list(set(analysis2["security_requirements"]) - set(analysis1["security_requirements"])),
                "removed_security_requirements": list(set(analysis1["security_requirements"]) - set(analysis2["security_requirements"])),
                "new_threat_indicators": list(set(analysis2["threat_indicators"]) - set(analysis1["threat_indicators"])),
                "removed_threat_indicators": list(set(analysis1["threat_indicators"]) - set(analysis2["threat_indicators"]))
            }
            
            debug_log("nlp_analyzer", f"Document comparison completed: similarity {similarity:.3f}")
            return differences
            
        except Exception as e:
            debug_log("nlp_analyzer", f"Error comparing documents: {e}", "ERROR")
            return {"error": str(e)} 