"""
Architecture Pattern Recognition for AI-Assisted Threat Discovery
Uses machine learning to identify common architectural patterns and their associated threats.
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_similarity
import networkx as nx
from sentence_transformers import SentenceTransformer

from ..debug_utils import debug_print, debug_log

class ArchitecturePatternRecognizer:
    """Recognize architectural patterns and their associated threats."""
    
    def __init__(self, debug: bool = False):
        """Initialize the pattern recognizer."""
        self.debug = debug
        self.embedding_model = None
        self.pattern_database = {}
        self.threat_patterns = {}
        self.vectorizer = None
        self.pattern_classifier = None
        
        # Initialize models and load patterns
        self._load_models()
        self._load_pattern_database()
        
        debug_log("pattern_recognizer", "Architecture Pattern Recognizer initialized")
    
    def _load_models(self) -> None:
        """Load ML models for pattern recognition."""
        try:
            debug_log("pattern_recognizer", "Loading pattern recognition models")
            
            # Load sentence transformer for pattern matching
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Initialize TF-IDF vectorizer for pattern classification
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2)
            )
            
            debug_log("pattern_recognizer", "Pattern recognition models loaded successfully")
            
        except Exception as e:
            debug_log("pattern_recognizer", f"Error loading models: {e}", "ERROR")
            self.embedding_model = None
            self.vectorizer = None
    
    def _load_pattern_database(self) -> None:
        """Load architectural patterns and their associated threats."""
        self.pattern_database = {
            "microservices": {
                "name": "Microservices Architecture",
                "description": "Distributed system with independent services",
                "characteristics": [
                    "multiple independent services",
                    "service-to-service communication",
                    "distributed data management",
                    "API gateways",
                    "containerization"
                ],
                "threats": [
                    "service-to-service authentication",
                    "API security",
                    "distributed denial of service",
                    "data consistency",
                    "service discovery attacks",
                    "inter-service communication security"
                ],
                "risk_score": 7.5,
                "mitigations": [
                    "Implement service mesh for security",
                    "Use API gateways with authentication",
                    "Implement circuit breakers",
                    "Use distributed tracing",
                    "Implement proper service discovery security"
                ]
            },
            "monolithic": {
                "name": "Monolithic Architecture",
                "description": "Single application with all functionality",
                "characteristics": [
                    "single codebase",
                    "shared database",
                    "single deployment unit",
                    "tightly coupled components"
                ],
                "threats": [
                    "single point of failure",
                    "privilege escalation",
                    "data access control",
                    "session management",
                    "input validation"
                ],
                "risk_score": 6.0,
                "mitigations": [
                    "Implement proper access controls",
                    "Use secure session management",
                    "Implement input validation",
                    "Use secure coding practices",
                    "Regular security testing"
                ]
            },
            "serverless": {
                "name": "Serverless Architecture",
                "description": "Event-driven functions without server management",
                "characteristics": [
                    "function-as-a-service",
                    "event-driven",
                    "auto-scaling",
                    "pay-per-use",
                    "stateless functions"
                ],
                "threats": [
                    "function injection",
                    "event injection",
                    "cold start attacks",
                    "resource exhaustion",
                    "function permissions",
                    "data exposure in logs"
                ],
                "risk_score": 6.5,
                "mitigations": [
                    "Implement proper function permissions",
                    "Use secure event handling",
                    "Implement rate limiting",
                    "Secure function configuration",
                    "Monitor function execution"
                ]
            },
            "event-driven": {
                "name": "Event-Driven Architecture",
                "description": "System based on event production and consumption",
                "characteristics": [
                    "event producers",
                    "event consumers",
                    "message queues",
                    "event streaming",
                    "asynchronous processing"
                ],
                "threats": [
                    "event injection",
                    "message queue attacks",
                    "event replay attacks",
                    "event ordering issues",
                    "dead letter queue attacks"
                ],
                "risk_score": 7.0,
                "mitigations": [
                    "Implement event validation",
                    "Use secure message queues",
                    "Implement event replay protection",
                    "Use event versioning",
                    "Monitor event processing"
                ]
            },
            "layered": {
                "name": "Layered Architecture",
                "description": "System organized in horizontal layers",
                "characteristics": [
                    "presentation layer",
                    "business logic layer",
                    "data access layer",
                    "database layer",
                    "layer separation"
                ],
                "threats": [
                    "layer bypass attacks",
                    "data validation bypass",
                    "privilege escalation between layers",
                    "input validation at boundaries"
                ],
                "risk_score": 5.5,
                "mitigations": [
                    "Implement layer validation",
                    "Use proper access controls",
                    "Validate data at layer boundaries",
                    "Implement secure layer communication"
                ]
            },
            "client-server": {
                "name": "Client-Server Architecture",
                "description": "Distributed system with client and server components",
                "characteristics": [
                    "client applications",
                    "server applications",
                    "network communication",
                    "centralized data",
                    "client authentication"
                ],
                "threats": [
                    "client-side attacks",
                    "server-side attacks",
                    "network attacks",
                    "authentication bypass",
                    "data transmission security"
                ],
                "risk_score": 6.5,
                "mitigations": [
                    "Implement secure client validation",
                    "Use secure server configuration",
                    "Implement network security",
                    "Use strong authentication",
                    "Encrypt data in transit"
                ]
            },
            "peer-to-peer": {
                "name": "Peer-to-Peer Architecture",
                "description": "Distributed system with equal peer nodes",
                "characteristics": [
                    "equal peer nodes",
                    "distributed data",
                    "peer discovery",
                    "decentralized control",
                    "peer communication"
                ],
                "threats": [
                    "peer spoofing",
                    "data consistency attacks",
                    "peer discovery attacks",
                    "distributed denial of service",
                    "malicious peer injection"
                ],
                "risk_score": 8.0,
                "mitigations": [
                    "Implement peer authentication",
                    "Use consensus mechanisms",
                    "Implement peer validation",
                    "Use secure peer discovery",
                    "Monitor peer behavior"
                ]
            }
        }
        
        # Create threat patterns mapping
        self._create_threat_patterns()
    
    def _create_threat_patterns(self) -> None:
        """Create mapping of threats to architectural patterns."""
        self.threat_patterns = {}
        
        for pattern_name, pattern_data in self.pattern_database.items():
            for threat in pattern_data["threats"]:
                if threat not in self.threat_patterns:
                    self.threat_patterns[threat] = []
                self.threat_patterns[threat].append(pattern_name)
    
    def recognize_patterns(self, architecture: Dict) -> List[Dict]:
        """Recognize architectural patterns in the given architecture."""
        debug_log("pattern_recognizer", "Recognizing architectural patterns")
        
        recognized_patterns = []
        
        # Extract architecture features
        features = self._extract_architecture_features(architecture)
        
        # Match against known patterns
        for pattern_name, pattern_data in self.pattern_database.items():
            confidence = self._calculate_pattern_confidence(features, pattern_data)
            
            if confidence > 0.6:  # Threshold for pattern recognition
                recognized_patterns.append({
                    "pattern": pattern_name,
                    "name": pattern_data["name"],
                    "description": pattern_data["description"],
                    "confidence": confidence,
                    "threats": pattern_data["threats"],
                    "risk_score": pattern_data["risk_score"],
                    "mitigations": pattern_data["mitigations"],
                    "characteristics": pattern_data["characteristics"]
                })
        
        # Sort by confidence
        recognized_patterns.sort(key=lambda x: x["confidence"], reverse=True)
        
        debug_log("pattern_recognizer", f"Recognized {len(recognized_patterns)} patterns")
        return recognized_patterns
    
    def _extract_architecture_features(self, architecture: Dict) -> Dict[str, Any]:
        """Extract features from architecture for pattern recognition."""
        features = {
            "components": [],
            "data_flows": [],
            "technologies": [],
            "characteristics": [],
            "description": architecture.get("description", "").lower()
        }
        
        # Extract component features
        for component in architecture.get("components", []):
            comp_type = component.get("type", "").lower()
            techs = [tech.lower() for tech in component.get("technologies", [])]
            
            features["components"].append(comp_type)
            features["technologies"].extend(techs)
            
            # Extract characteristics from component type
            if comp_type in ["api", "service", "microservice"]:
                features["characteristics"].append("service-based")
            elif comp_type == "database":
                features["characteristics"].append("data-storage")
            elif comp_type == "gateway":
                features["characteristics"].append("gateway")
            elif comp_type == "queue":
                features["characteristics"].append("message-queue")
            elif comp_type == "function":
                features["characteristics"].append("function-based")
        
        # Extract data flow features
        for flow in architecture.get("data_flows", []):
            protocol = flow.get("protocol", "").lower()
            flow_desc = f"{flow.get('from', '')} to {flow.get('to', '')} via {protocol}"
            features["data_flows"].append(flow_desc)
            
            # Extract characteristics from protocols
            if protocol in ["http", "https", "rest", "graphql"]:
                features["characteristics"].append("http-based")
            elif protocol in ["tcp", "udp"]:
                features["characteristics"].append("network-based")
            elif protocol in ["amqp", "mqtt", "kafka"]:
                features["characteristics"].append("message-based")
        
        # Remove duplicates
        features["components"] = list(set(features["components"]))
        features["technologies"] = list(set(features["technologies"]))
        features["characteristics"] = list(set(features["characteristics"]))
        
        return features
    
    def _calculate_pattern_confidence(self, features: Dict, pattern_data: Dict) -> float:
        """Calculate confidence score for pattern match."""
        if not self.embedding_model:
            return self._calculate_basic_confidence(features, pattern_data)
        
        try:
            # Create feature description
            feature_desc = self._create_feature_description(features)
            pattern_desc = pattern_data["description"]
            
            # Calculate similarity
            feature_embedding = self.embedding_model.encode(feature_desc, convert_to_tensor=True)
            pattern_embedding = self.embedding_model.encode(pattern_desc, convert_to_tensor=True)
            
            # Calculate cosine similarity
            similarity = self._cosine_similarity_torch(feature_embedding, pattern_embedding)
            
            # Boost confidence based on characteristic matches
            characteristic_matches = self._count_characteristic_matches(
                features, pattern_data["characteristics"]
            )
            
            confidence = similarity + (characteristic_matches * 0.1)
            
            return min(confidence, 1.0)
            
        except Exception as e:
            debug_log("pattern_recognizer", f"Error calculating confidence: {e}", "ERROR")
            return self._calculate_basic_confidence(features, pattern_data)
    
    def _calculate_basic_confidence(self, features: Dict, pattern_data: Dict) -> float:
        """Calculate basic confidence without ML models."""
        confidence = 0.0
        
        # Match characteristics
        pattern_chars = [char.lower() for char in pattern_data["characteristics"]]
        feature_chars = [char.lower() for char in features["characteristics"]]
        
        matches = sum(1 for char in feature_chars if any(pchar in char for pchar in pattern_chars))
        if len(pattern_chars) > 0:
            confidence += (matches / len(pattern_chars)) * 0.6
        
        # Match component types
        pattern_desc = pattern_data["description"].lower()
        component_matches = sum(1 for comp in features["components"] if comp in pattern_desc)
        if len(features["components"]) > 0:
            confidence += (component_matches / len(features["components"])) * 0.4
        
        return min(confidence, 1.0)
    
    def _create_feature_description(self, features: Dict) -> str:
        """Create a description of architecture features for similarity matching."""
        desc_parts = []
        
        desc_parts.append(features["description"])
        desc_parts.extend(features["characteristics"])
        desc_parts.extend(features["components"])
        desc_parts.extend(features["technologies"])
        
        return " ".join(desc_parts)
    
    def _cosine_similarity_torch(self, vec1, vec2) -> float:
        """Calculate cosine similarity between PyTorch tensors."""
        import torch
        return torch.nn.functional.cosine_similarity(vec1, vec2, dim=0).item()
    
    def _count_characteristic_matches(self, features: Dict, pattern_characteristics: List[str]) -> int:
        """Count matches between feature characteristics and pattern characteristics."""
        matches = 0
        
        for pattern_char in pattern_characteristics:
            pattern_char_lower = pattern_char.lower()
            for feature_char in features["characteristics"]:
                feature_char_lower = feature_char.lower()
                if pattern_char_lower in feature_char_lower or feature_char_lower in pattern_char_lower:
                    matches += 1
        
        return matches
    
    def predict_threats_from_patterns(self, recognized_patterns: List[Dict]) -> List[Dict]:
        """Predict threats based on recognized architectural patterns."""
        debug_log("pattern_recognizer", "Predicting threats from patterns")
        
        predicted_threats = []
        threat_scores = {}
        
        for pattern in recognized_patterns:
            pattern_name = pattern["pattern"]
            confidence = pattern["confidence"]
            
            for threat in pattern["threats"]:
                if threat not in threat_scores:
                    threat_scores[threat] = {
                        "threat": threat,
                        "patterns": [],
                        "total_score": 0.0,
                        "max_confidence": 0.0
                    }
                
                threat_scores[threat]["patterns"].append(pattern_name)
                threat_scores[threat]["total_score"] += pattern["risk_score"] * confidence
                threat_scores[threat]["max_confidence"] = max(
                    threat_scores[threat]["max_confidence"], confidence
                )
        
        # Convert to list and calculate final scores
        for threat_data in threat_scores.values():
            # Calculate weighted score
            avg_score = threat_data["total_score"] / len(threat_data["patterns"])
            final_score = avg_score * threat_data["max_confidence"]
            
            predicted_threats.append({
                "threat": threat_data["threat"],
                "patterns": threat_data["patterns"],
                "confidence": threat_data["max_confidence"],
                "risk_score": final_score,
                "description": f"Threat associated with {', '.join(threat_data['patterns'])} patterns"
            })
        
        # Sort by risk score
        predicted_threats.sort(key=lambda x: x["risk_score"], reverse=True)
        
        debug_log("pattern_recognizer", f"Predicted {len(predicted_threats)} threats from patterns")
        return predicted_threats
    
    def analyze_architecture_complexity(self, architecture: Dict) -> Dict[str, Any]:
        """Analyze architecture complexity and its security implications."""
        debug_log("pattern_recognizer", "Analyzing architecture complexity")
        
        components = architecture.get("components", [])
        data_flows = architecture.get("data_flows", [])
        trust_boundaries = architecture.get("trust_boundaries", [])
        
        # Calculate complexity metrics
        complexity_metrics = {
            "component_count": len(components),
            "data_flow_count": len(data_flows),
            "trust_boundary_count": len(trust_boundaries),
            "external_components": sum(1 for c in components if c.get("external", False)),
            "unique_technologies": len(set(tech for c in components for tech in c.get("technologies", []))),
            "complexity_score": 0.0
        }
        
        # Calculate complexity score
        complexity_score = 0.0
        
        # Component complexity
        complexity_score += min(len(components) * 0.1, 2.0)
        
        # Data flow complexity
        complexity_score += min(len(data_flows) * 0.15, 2.0)
        
        # Technology diversity
        complexity_score += min(complexity_metrics["unique_technologies"] * 0.2, 1.5)
        
        # External dependencies
        complexity_score += complexity_metrics["external_components"] * 0.3
        
        # Trust boundary complexity
        complexity_score += len(trust_boundaries) * 0.25
        
        complexity_metrics["complexity_score"] = min(complexity_score, 10.0)
        
        # Determine complexity level
        if complexity_score < 3.0:
            complexity_level = "Low"
        elif complexity_score < 6.0:
            complexity_level = "Medium"
        else:
            complexity_level = "High"
        
        complexity_metrics["complexity_level"] = complexity_level
        
        # Security implications
        security_implications = self._get_complexity_security_implications(complexity_metrics)
        complexity_metrics["security_implications"] = security_implications
        
        debug_log("pattern_recognizer", f"Architecture complexity: {complexity_level} ({complexity_score:.2f})")
        return complexity_metrics
    
    def _get_complexity_security_implications(self, metrics: Dict) -> List[str]:
        """Get security implications based on complexity metrics."""
        implications = []
        
        if metrics["complexity_score"] > 7.0:
            implications.extend([
                "High attack surface due to many components",
                "Complex trust relationships increase risk",
                "Multiple technologies increase vulnerability surface",
                "External dependencies introduce additional risks",
                "Complex data flows increase attack vectors"
            ])
        elif metrics["complexity_score"] > 4.0:
            implications.extend([
                "Moderate attack surface",
                "Some complexity in trust relationships",
                "Multiple technologies require careful management",
                "External dependencies need monitoring"
            ])
        else:
            implications.extend([
                "Low attack surface",
                "Simple trust relationships",
                "Limited technology stack reduces risk",
                "Few external dependencies"
            ])
        
        # Add specific implications based on metrics
        if metrics["external_components"] > 3:
            implications.append("High number of external components increases supply chain risk")
        
        if metrics["unique_technologies"] > 5:
            implications.append("Technology diversity requires comprehensive security knowledge")
        
        if metrics["data_flow_count"] > 10:
            implications.append("Complex data flows require careful security monitoring")
        
        return implications
    
    def generate_architecture_recommendations(self, architecture: Dict, recognized_patterns: List[Dict]) -> List[str]:
        """Generate security recommendations based on architecture analysis."""
        debug_log("pattern_recognizer", "Generating architecture recommendations")
        
        recommendations = []
        
        # Pattern-based recommendations
        for pattern in recognized_patterns:
            recommendations.extend(pattern["mitigations"])
        
        # Complexity-based recommendations
        complexity_metrics = self.analyze_architecture_complexity(architecture)
        
        if complexity_metrics["complexity_level"] == "High":
            recommendations.extend([
                "Implement comprehensive security monitoring",
                "Use security automation tools",
                "Conduct regular security assessments",
                "Implement defense in depth",
                "Use security-focused CI/CD pipelines"
            ])
        
        # Technology-based recommendations
        technologies = set()
        for component in architecture.get("components", []):
            technologies.update(component.get("technologies", []))
        
        if "docker" in technologies or "kubernetes" in technologies:
            recommendations.extend([
                "Implement container security scanning",
                "Use image signing and verification",
                "Implement runtime security monitoring",
                "Use network policies for container isolation"
            ])
        
        if "api" in [c.get("type") for c in architecture.get("components", [])]:
            recommendations.extend([
                "Implement API rate limiting",
                "Use API authentication and authorization",
                "Implement API input validation",
                "Use API security testing tools"
            ])
        
        # Remove duplicates and return
        return list(set(recommendations)) 