"""
Threat Engine for Threat Modeling Tool
Implements STRIDE, PASTA, and DREAD methodologies for threat analysis.
"""

import json
from typing import Dict, List, Any, Optional
from pathlib import Path

from .debug_utils import debug_print, debug_log

class ThreatEngine:
    """Core threat analysis engine supporting multiple methodologies."""
    
    def __init__(self):
        """Initialize the threat engine."""
        self.threat_library = self._load_threat_library()
        self.mitigation_library = self._load_mitigation_library()
        
    def _load_threat_library(self) -> Dict[str, Any]:
        """Load predefined threat library."""
        # This would typically load from a JSON file
        # For now, we'll define it inline
        return {
            "STRIDE": {
                "Spoofing": [
                    {
                        "title": "Identity Spoofing",
                        "description": "An attacker impersonates a legitimate user or system",
                        "examples": ["Fake authentication tokens", "IP spoofing", "Email spoofing"],
                        "risk_factors": ["weak_authentication", "no_identity_verification"]
                    },
                    {
                        "title": "Session Hijacking",
                        "description": "An attacker steals or predicts session tokens",
                        "examples": ["Session fixation", "Token prediction", "Man-in-the-middle"],
                        "risk_factors": ["weak_session_management", "insecure_transmission"]
                    }
                ],
                "Tampering": [
                    {
                        "title": "Data Tampering",
                        "description": "An attacker modifies data in transit or at rest",
                        "examples": ["SQL injection", "XSS", "File modification"],
                        "risk_factors": ["no_input_validation", "weak_encryption"]
                    },
                    {
                        "title": "Configuration Tampering",
                        "description": "An attacker modifies application configuration",
                        "examples": ["Config file modification", "Environment variable tampering"],
                        "risk_factors": ["insecure_configuration", "excessive_permissions"]
                    }
                ],
                "Repudiation": [
                    {
                        "title": "Action Repudiation",
                        "description": "Users can deny performing actions",
                        "examples": ["No audit logs", "Weak logging", "Log deletion"],
                        "risk_factors": ["no_audit_trail", "weak_logging"]
                    }
                ],
                "Information Disclosure": [
                    {
                        "title": "Sensitive Data Exposure",
                        "description": "Sensitive information is exposed to unauthorized parties",
                        "examples": ["Error messages", "Debug information", "Data leakage"],
                        "risk_factors": ["verbose_error_messages", "weak_access_controls"]
                    },
                    {
                        "title": "Information Disclosure in Logs",
                        "description": "Sensitive data is logged in plain text",
                        "examples": ["Password in logs", "PII in debug logs"],
                        "risk_factors": ["sensitive_data_logging", "weak_log_security"]
                    }
                ],
                "Denial of Service": [
                    {
                        "title": "Resource Exhaustion",
                        "description": "System resources are consumed to the point of failure",
                        "examples": ["Memory exhaustion", "CPU exhaustion", "Disk space exhaustion"],
                        "risk_factors": ["no_resource_limits", "inefficient_algorithms"]
                    },
                    {
                        "title": "Service Disruption",
                        "description": "Service becomes unavailable due to attacks",
                        "examples": ["DDoS", "Database connection exhaustion"],
                        "risk_factors": ["no_rate_limiting", "weak_resilience"]
                    }
                ],
                "Elevation of Privilege": [
                    {
                        "title": "Privilege Escalation",
                        "description": "An attacker gains higher privileges than intended",
                        "examples": ["Admin access", "Root access", "Role escalation"],
                        "risk_factors": ["weak_authorization", "privilege_creep"]
                    },
                    {
                        "title": "Code Execution",
                        "description": "An attacker executes arbitrary code",
                        "examples": ["RCE", "Code injection", "Malicious uploads"],
                        "risk_factors": ["unsafe_code_execution", "weak_input_validation"]
                    }
                ]
            },
            "PASTA": {
                "Business Impact": [
                    {
                        "title": "Business Continuity Impact",
                        "description": "Security incidents affecting business operations",
                        "examples": ["Service downtime", "Data loss", "Compliance violations"],
                        "risk_factors": ["critical_business_function", "regulatory_requirements"]
                    }
                ],
                "Attack Vectors": [
                    {
                        "title": "Multi-Vector Attacks",
                        "description": "Combined attack vectors targeting multiple weaknesses",
                        "examples": ["Phishing + credential theft", "Social engineering + technical exploit"],
                        "risk_factors": ["multiple_attack_surfaces", "complex_architecture"]
                    }
                ],
                "Threat Intelligence": [
                    {
                        "title": "Targeted Attacks",
                        "description": "Advanced persistent threats targeting specific assets",
                        "examples": ["APT groups", "Nation-state actors", "Organized crime"],
                        "risk_factors": ["high_value_target", "sensitive_data"]
                    }
                ]
            },
            "DREAD": {
                "Damage": [
                    {
                        "title": "High Impact Damage",
                        "description": "Threats causing significant damage to business",
                        "examples": ["Data breach", "Financial loss", "Reputation damage"],
                        "risk_factors": ["sensitive_data", "financial_transactions"]
                    }
                ],
                "Reproducibility": [
                    {
                        "title": "Easy to Reproduce",
                        "description": "Threats that can be easily reproduced by attackers",
                        "examples": ["Predictable vulnerabilities", "Public exploits"],
                        "risk_factors": ["known_vulnerabilities", "weak_controls"]
                    }
                ],
                "Exploitability": [
                    {
                        "title": "High Exploitability",
                        "description": "Threats that are easy to exploit",
                        "examples": ["No authentication", "Weak encryption", "Default credentials"],
                        "risk_factors": ["low_complexity", "public_tools"]
                    }
                ],
                "Affected Users": [
                    {
                        "title": "Wide User Impact",
                        "description": "Threats affecting many users or critical users",
                        "examples": ["All users", "Admin users", "VIP customers"],
                        "risk_factors": ["large_user_base", "privileged_users"]
                    }
                ],
                "Discoverability": [
                    {
                        "title": "Easy to Discover",
                        "description": "Threats that are easy to discover",
                        "examples": ["Visible vulnerabilities", "Information disclosure"],
                        "risk_factors": ["public_exposure", "weak_obfuscation"]
                    }
                ]
            }
        }
    
    def _load_mitigation_library(self) -> Dict[str, List[str]]:
        """Load predefined mitigation library."""
        return {
            "Spoofing": [
                "Implement strong authentication (MFA, OAuth, SAML)",
                "Use secure session management with random tokens",
                "Implement certificate pinning",
                "Use HTTPS for all communications",
                "Implement proper identity verification"
            ],
            "Tampering": [
                "Implement input validation and sanitization",
                "Use parameterized queries to prevent SQL injection",
                "Implement Content Security Policy (CSP)",
                "Use digital signatures for data integrity",
                "Implement proper access controls"
            ],
            "Repudiation": [
                "Implement comprehensive audit logging",
                "Use secure logging with integrity protection",
                "Implement log retention policies",
                "Use digital signatures for critical actions",
                "Implement user activity monitoring"
            ],
            "Information Disclosure": [
                "Implement proper error handling without sensitive data",
                "Use encryption for data at rest and in transit",
                "Implement proper access controls",
                "Use data classification and handling procedures",
                "Implement secure configuration management"
            ],
            "Denial of Service": [
                "Implement rate limiting and throttling",
                "Use resource monitoring and alerting",
                "Implement circuit breakers and timeouts",
                "Use CDN and load balancing",
                "Implement graceful degradation"
            ],
            "Elevation of Privilege": [
                "Implement principle of least privilege",
                "Use role-based access control (RBAC)",
                "Implement proper authorization checks",
                "Use secure coding practices",
                "Implement regular privilege reviews"
            ]
        }
    
    def analyze_threats(self, architecture: Dict[str, Any], methodology: str = "STRIDE") -> List[Dict[str, Any]]:
        """Analyze threats using the specified methodology."""
        debug_log("engine", f"Starting threat analysis with {methodology} methodology")
        
        threats = []
        
        if methodology == "STRIDE":
            threats = self._analyze_stride(architecture)
        elif methodology == "PASTA":
            threats = self._analyze_pasta(architecture)
        elif methodology == "DREAD":
            threats = self._analyze_dread(architecture)
        else:
            debug_log("engine", f"Unknown methodology: {methodology}", "ERROR")
            return []
        
        # Enhance threats with risk scoring
        for threat in threats:
            threat["risk_score"] = self._calculate_risk_score(threat, architecture)
            threat["mitigations"] = self._get_mitigations(threat["category"])
        
        # Sort by risk score
        threats.sort(key=lambda x: x["risk_score"], reverse=True)
        
        debug_log("engine", f"Threat analysis completed. Found {len(threats)} threats")
        return threats
    
    def _analyze_stride(self, architecture: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze threats using STRIDE methodology."""
        debug_log("engine", "Analyzing threats using STRIDE methodology")
        
        threats = []
        components = architecture.get("components", [])
        data_flows = architecture.get("data_flows", [])
        
        # Analyze each STRIDE category
        for category, threat_types in self.threat_library["STRIDE"].items():
            for threat_type in threat_types:
                # Check if threat applies to any component or data flow
                if self._threat_applies_to_architecture(threat_type, architecture):
                    threat = {
                        "title": threat_type["title"],
                        "category": category,
                        "description": threat_type["description"],
                        "examples": threat_type["examples"],
                        "affected_components": self._get_affected_components(threat_type, components),
                        "affected_data_flows": self._get_affected_data_flows(threat_type, data_flows),
                        "methodology": "STRIDE",
                        "severity": self._assess_severity(threat_type, architecture)
                    }
                    threats.append(threat)
        
        return threats
    
    def _analyze_pasta(self, architecture: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze threats using PASTA methodology."""
        debug_log("engine", "Analyzing threats using PASTA methodology")
        
        threats = []
        assets = architecture.get("assets", [])
        
        # Analyze business impact
        for category, threat_types in self.threat_library["PASTA"].items():
            for threat_type in threat_types:
                if self._threat_applies_to_architecture(threat_type, architecture):
                    threat = {
                        "title": threat_type["title"],
                        "category": category,
                        "description": threat_type["description"],
                        "examples": threat_type["examples"],
                        "affected_assets": self._get_affected_assets(threat_type, assets),
                        "methodology": "PASTA",
                        "severity": self._assess_severity(threat_type, architecture)
                    }
                    threats.append(threat)
        
        return threats
    
    def _analyze_dread(self, architecture: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze threats using DREAD methodology."""
        debug_log("engine", "Analyzing threats using DREAD methodology")
        
        threats = []
        
        # Analyze each DREAD category
        for category, threat_types in self.threat_library["DREAD"].items():
            for threat_type in threat_types:
                if self._threat_applies_to_architecture(threat_type, architecture):
                    threat = {
                        "title": threat_type["title"],
                        "category": category,
                        "description": threat_type["description"],
                        "examples": threat_type["examples"],
                        "methodology": "DREAD",
                        "severity": self._assess_severity(threat_type, architecture),
                        "dread_scores": self._calculate_dread_scores(threat_type, architecture)
                    }
                    threats.append(threat)
        
        return threats
    
    def _threat_applies_to_architecture(self, threat_type: Dict, architecture: Dict) -> bool:
        """Check if a threat type applies to the given architecture."""
        components = architecture.get("components", [])
        data_flows = architecture.get("data_flows", [])
        
        # Check risk factors against architecture characteristics
        risk_factors = threat_type.get("risk_factors", [])
        
        for factor in risk_factors:
            if factor == "weak_authentication":
                # Check if any component lacks strong authentication
                for component in components:
                    if component.get("type") in ["web_server", "api"]:
                        return True
            
            elif factor == "no_input_validation":
                # Check if any component handles user input
                for component in components:
                    if component.get("type") in ["web_server", "api"]:
                        return True
            
            elif factor == "sensitive_data":
                # Check if architecture handles sensitive data
                for flow in data_flows:
                    if flow.get("data_type") in ["user_data", "auth_data"]:
                        return True
            
            elif factor == "external_components":
                # Check if there are external components
                for component in components:
                    if component.get("external", False):
                        return True
        
        return True  # Default to applying the threat
    
    def _get_affected_components(self, threat_type: Dict, components: List[Dict]) -> List[str]:
        """Get list of components affected by a threat."""
        affected = []
        
        for component in components:
            if self._component_vulnerable_to_threat(component, threat_type):
                affected.append(component["name"])
        
        return affected
    
    def _get_affected_data_flows(self, threat_type: Dict, data_flows: List[Dict]) -> List[str]:
        """Get list of data flows affected by a threat."""
        affected = []
        
        for flow in data_flows:
            if self._data_flow_vulnerable_to_threat(flow, threat_type):
                affected.append(f"{flow['from']} -> {flow['to']}")
        
        return affected
    
    def _get_affected_assets(self, threat_type: Dict, assets: List[Dict]) -> List[str]:
        """Get list of assets affected by a threat."""
        affected = []
        
        for asset in assets:
            if self._asset_vulnerable_to_threat(asset, threat_type):
                affected.append(asset["name"])
        
        return affected
    
    def _component_vulnerable_to_threat(self, component: Dict, threat_type: Dict) -> bool:
        """Check if a component is vulnerable to a specific threat."""
        comp_type = component.get("type", "")
        risk_factors = threat_type.get("risk_factors", [])
        
        # Simple vulnerability mapping
        if "weak_authentication" in risk_factors and comp_type in ["web_server", "api"]:
            return True
        elif "no_input_validation" in risk_factors and comp_type in ["web_server", "api"]:
            return True
        elif "external_components" in risk_factors and component.get("external", False):
            return True
        
        return True  # Default to vulnerable
    
    def _data_flow_vulnerable_to_threat(self, flow: Dict, threat_type: Dict) -> bool:
        """Check if a data flow is vulnerable to a specific threat."""
        data_type = flow.get("data_type", "")
        protocol = flow.get("protocol", "")
        encrypted = flow.get("encrypted", False)
        
        risk_factors = threat_type.get("risk_factors", [])
        
        if "sensitive_data" in risk_factors and data_type in ["user_data", "auth_data"]:
            return True
        elif "insecure_transmission" in risk_factors and not encrypted:
            return True
        
        return True  # Default to vulnerable
    
    def _asset_vulnerable_to_threat(self, asset: Dict, threat_type: Dict) -> bool:
        """Check if an asset is vulnerable to a specific threat."""
        asset_type = asset.get("type", "")
        value = asset.get("value", "")
        
        risk_factors = threat_type.get("risk_factors", [])
        
        if "sensitive_data" in risk_factors and asset_type == "data":
            return True
        elif "high_value_target" in risk_factors and value in ["high", "critical"]:
            return True
        
        return True  # Default to vulnerable
    
    def _assess_severity(self, threat_type: Dict, architecture: Dict) -> str:
        """Assess the severity of a threat."""
        # Simple severity assessment based on architecture characteristics
        components = architecture.get("components", [])
        data_flows = architecture.get("data_flows", [])
        
        # Count external components
        external_count = sum(1 for c in components if c.get("external", False))
        
        # Count sensitive data flows
        sensitive_flows = sum(1 for f in data_flows if f.get("data_type") in ["user_data", "auth_data"])
        
        if external_count > 2 or sensitive_flows > 3:
            return "High"
        elif external_count > 0 or sensitive_flows > 1:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_dread_scores(self, threat_type: Dict, architecture: Dict) -> Dict[str, int]:
        """Calculate DREAD scores for a threat."""
        return {
            "Damage": self._calculate_damage_score(threat_type, architecture),
            "Reproducibility": self._calculate_reproducibility_score(threat_type, architecture),
            "Exploitability": self._calculate_exploitability_score(threat_type, architecture),
            "Affected_Users": self._calculate_affected_users_score(threat_type, architecture),
            "Discoverability": self._calculate_discoverability_score(threat_type, architecture)
        }
    
    def _calculate_damage_score(self, threat_type: Dict, architecture: Dict) -> int:
        """Calculate damage score (1-10)."""
        # Base score
        score = 5
        
        # Adjust based on architecture characteristics
        assets = architecture.get("assets", [])
        high_value_assets = sum(1 for a in assets if a.get("value") in ["high", "critical"])
        
        if high_value_assets > 0:
            score += 3
        
        return min(score, 10)
    
    def _calculate_reproducibility_score(self, threat_type: Dict, architecture: Dict) -> int:
        """Calculate reproducibility score (1-10)."""
        # Base score
        score = 5
        
        # Adjust based on threat characteristics
        risk_factors = threat_type.get("risk_factors", [])
        
        if "known_vulnerabilities" in risk_factors:
            score += 3
        if "public_exploits" in risk_factors:
            score += 2
        
        return min(score, 10)
    
    def _calculate_exploitability_score(self, threat_type: Dict, architecture: Dict) -> int:
        """Calculate exploitability score (1-10)."""
        # Base score
        score = 5
        
        # Adjust based on architecture complexity
        components = architecture.get("components", [])
        
        if len(components) > 5:
            score += 2
        
        return min(score, 10)
    
    def _calculate_affected_users_score(self, threat_type: Dict, architecture: Dict) -> int:
        """Calculate affected users score (1-10)."""
        # Base score
        score = 5
        
        # Adjust based on architecture scope
        components = architecture.get("components", [])
        
        if len(components) > 3:
            score += 2
        
        return min(score, 10)
    
    def _calculate_discoverability_score(self, threat_type: Dict, architecture: Dict) -> int:
        """Calculate discoverability score (1-10)."""
        # Base score
        score = 5
        
        # Adjust based on exposure
        components = architecture.get("components", [])
        external_components = sum(1 for c in components if c.get("external", False))
        
        if external_components > 0:
            score += 3
        
        return min(score, 10)
    
    def _calculate_risk_score(self, threat: Dict, architecture: Dict) -> float:
        """Calculate overall risk score for a threat."""
        base_score = 5.0
        
        # Adjust based on severity
        severity_multipliers = {"Low": 0.5, "Medium": 1.0, "High": 2.0}
        severity = threat.get("severity", "Medium")
        base_score *= severity_multipliers.get(severity, 1.0)
        
        # Adjust based on affected components
        affected_components = threat.get("affected_components", [])
        if len(affected_components) > 2:
            base_score *= 1.5
        
        # Adjust based on methodology
        methodology = threat.get("methodology", "STRIDE")
        if methodology == "DREAD":
            dread_scores = threat.get("dread_scores", {})
            if dread_scores:
                avg_dread = sum(dread_scores.values()) / len(dread_scores)
                base_score = (base_score + avg_dread) / 2
        
        return min(base_score, 10.0)
    
    def _get_mitigations(self, category: str) -> List[str]:
        """Get mitigations for a threat category."""
        return self.mitigation_library.get(category, []) 