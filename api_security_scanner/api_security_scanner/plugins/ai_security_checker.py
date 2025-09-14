"""
AI-Powered Security Checker Plugin

This plugin provides machine learning-based vulnerability detection capabilities
that can be configured by users. It includes anomaly detection, vulnerability
classification, risk scoring, and intelligent fuzzing suggestions.
"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime

from ..core.scanner_plugins import BasePlugin, PluginResult, Vulnerability, ProofOfConcept
from ..core.ai_detector import AIDetector
from ..utils.logger import get_logger


class AISecurityChecker(BasePlugin):
    """
    AI-Powered security checker using machine learning models.
    
    This plugin provides:
    - Anomaly detection for unusual API behavior
    - Vulnerability classification using ML models
    - Risk scoring and assessment
    - Intelligent fuzzing suggestions
    - Learning from scan results
    """
    
    name = "AISecurityChecker"
    description = "AI-powered vulnerability detection using machine learning models"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def __init__(self, zap=None, target=None):
        super().__init__(zap=zap, target=target)
        self.logger = get_logger(__name__)
        
        # Plugin configuration - will be set by PluginManager
        self.config = {}
        self.enabled = True
        
        # Initialize AI detector with default config
        self.ai_detector = AIDetector()
        
        if not self.enabled:
            self.logger.info("AI Security Checker is disabled")
            return
        
        # Check if ML is available
        if not self.ai_detector.ml_available:
            self.logger.warning("ML libraries not available. AI detection will use rule-based fallback.")
        
        self.logger.info(f"AI Security Checker initialized. ML available: {self.ai_detector.ml_available}")
    
    def configure(self, config: Dict[str, Any]):
        """Configure the AI plugin with custom settings."""
        self.config = config
        self.enabled = config.get('enabled', True)
        
        # Reinitialize AI detector with new config
        self.ai_detector = AIDetector(config)
        
        self.logger.info(f"AI Security Checker configured. Enabled: {self.enabled}")
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """
        Perform AI-powered security analysis on requests.
        
        Args:
            target_url: Base URL of the target
            requests_data: List of request dictionaries
            auth_headers: Authentication headers
            
        Returns:
            PluginResult with AI-detected vulnerabilities
        """
        vulnerabilities = []
        
        if not self.enabled:
            return PluginResult(
                plugin_name=self.name,
                success=True,
                vulnerabilities=[],
                error=None
            )
        
        try:
            self.logger.info(f"Starting AI-powered security analysis on {len(requests_data)} requests")
            
            # 1. Anomaly Detection
            if self.config.get('models', {}).get('anomaly_detection', {}).get('enabled', True):
                anomalies = self._detect_anomalies(requests_data)
                vulnerabilities.extend(anomalies)
            
            # 2. Vulnerability Classification
            if self.config.get('models', {}).get('vulnerability_classification', {}).get('enabled', True):
                classifications = self._classify_vulnerabilities(requests_data)
                vulnerabilities.extend(classifications)
            
            # 3. Risk Assessment
            if self.config.get('models', {}).get('risk_scoring', {}).get('enabled', True):
                risk_assessments = self._assess_risks(requests_data)
                vulnerabilities.extend(risk_assessments)
            
            # 4. Generate Fuzzing Suggestions
            if self.config.get('models', {}).get('intelligent_fuzzing', {}).get('enabled', True):
                fuzzing_suggestions = self._generate_fuzzing_suggestions(requests_data)
                vulnerabilities.extend(fuzzing_suggestions)
            
            self.logger.info(f"AI analysis completed. Found {len(vulnerabilities)} potential issues")
            
            return PluginResult(
                plugin_name=self.name,
                success=True,
                vulnerabilities=vulnerabilities,
                error=None
            )
        
        except Exception as e:
            self.logger.error(f"AI security check failed: {e}")
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=f"AI security check failed: {str(e)}"
            )
    
    def _detect_anomalies(self, requests_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Detect anomalous requests using AI models."""
        vulnerabilities = []
        
        try:
            anomalies = self.ai_detector.detect_anomalies(requests_data)
            
            for anomaly in anomalies:
                request = anomaly['request']
                confidence = anomaly['confidence']
                
                if confidence > 0.7:  # High confidence threshold
                    vuln = Vulnerability(
                        id=f"ai-anomaly-{hash(str(request)) % 10000}",
                        name="AI-Detected Anomalous Request",
                        description=f"AI model detected anomalous behavior in request with confidence {confidence:.2f}",
                        risk=self._get_severity_from_confidence(confidence),
                        cvss_score=self._calculate_cvss_score(confidence, "anomaly"),
                        solution="Review this request for unusual patterns or potential security issues",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/API_Security_Cheat_Sheet.html"
                        ],
                        cwe_id="CWE-000",  # Generic CWE ID
                        wasc_id="WASC-00",  # Generic WASC ID
                        request=str(request),
                        response="",
                        url=request.get('url', 'unknown'),
                        parameter="",
                        evidence=f"Anomaly detected with score: {anomaly['anomaly_score']:.3f}",
                        scan_id="",
                        timestamp=datetime.now()
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
        
        return vulnerabilities
    
    def _classify_vulnerabilities(self, requests_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Classify potential vulnerabilities using AI models."""
        vulnerabilities = []
        
        try:
            classifications = self.ai_detector.classify_vulnerabilities(requests_data)
            
            for classification in classifications:
                request = classification['request']
                vuln_type = classification['vulnerability_type']
                confidence = classification['confidence']
                
                if confidence > 0.6:  # Medium confidence threshold
                    vuln = Vulnerability(
                        id=f"ai-classification-{hash(str(request)) % 10000}",
                        name=f"AI-Detected {vuln_type.replace('_', ' ').title()}",
                        description=f"AI model classified this request as potentially vulnerable to {vuln_type} with confidence {confidence:.2f}",
                        risk=self._get_severity_from_vuln_type(vuln_type, confidence),
                        cvss_score=self._calculate_cvss_score(confidence, vuln_type),
                        solution=self._get_recommendation_for_vuln_type(vuln_type),
                        references=self._get_references_for_vuln_type(vuln_type),
                        cwe_id="CWE-000",  # Generic CWE ID
                        wasc_id="WASC-00",  # Generic WASC ID
                        request=str(request),
                        response="",
                        url=request.get('url', 'unknown'),
                        parameter="",
                        evidence=f"Vulnerability classification: {vuln_type}",
                        scan_id="",
                        timestamp=datetime.now()
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error in vulnerability classification: {e}")
        
        return vulnerabilities
    
    def _assess_risks(self, requests_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Assess risk scores for requests using AI models."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                risk_assessment = self.ai_detector.calculate_risk_score(request)
                risk_score = risk_assessment['risk_score']
                risk_level = risk_assessment['risk_level']
                
                if risk_score > 0.6:  # High risk threshold
                    vuln = Vulnerability(
                        id=f"ai-risk-{hash(str(request)) % 10000}",
                        name=f"High Risk Request ({risk_level})",
                        description=f"AI model assessed this request as {risk_level} risk with score {risk_score:.2f}",
                        risk=self._get_severity_from_risk_level(risk_level),
                        cvss_score=self._calculate_cvss_score(risk_score, "risk"),
                        solution="Review this request for potential security implications",
                        references=[
                            "https://owasp.org/www-project-risk-rating-methodology/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Risk_Rating_Cheat_Sheet.html"
                        ],
                        cwe_id="CWE-000",  # Generic CWE ID
                        wasc_id="WASC-00",  # Generic WASC ID
                        request=str(request),
                        response="",
                        url=request.get('url', 'unknown'),
                        parameter="",
                        evidence=f"Risk assessment: {risk_level} (score: {risk_score:.3f})",
                        scan_id="",
                        timestamp=datetime.now()
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error in risk assessment: {e}")
        
        return vulnerabilities
    
    def _generate_fuzzing_suggestions(self, requests_data: List[Dict[str, Any]]) -> List[Vulnerability]:
        """Generate intelligent fuzzing suggestions using AI models."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                suggestions = self.ai_detector.generate_fuzzing_suggestions(request)
                
                for suggestion in suggestions:
                    if suggestion['confidence'] > 0.6:  # Medium confidence threshold
                        vuln = Vulnerability(
                            id=f"ai-fuzzing-{hash(str(request)) % 10000}",
                            name=f"AI Fuzzing Suggestion: {suggestion['type'].replace('_', ' ').title()}",
                            description=f"AI model suggests fuzzing this request with {suggestion['type']} techniques (confidence: {suggestion['confidence']:.2f})",
                            risk="Medium",
                            cvss_score=5.0,  # Medium CVSS score for suggestions
                            solution=f"Consider testing with suggested payloads: {', '.join(suggestion['payloads'][:3])}",
                            references=[
                                "https://owasp.org/www-community/attacks/Fuzzing",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
                            ],
                            cwe_id="CWE-000",  # Generic CWE ID
                            wasc_id="WASC-00",  # Generic WASC ID
                            request=str(request),
                            response="",
                            url=request.get('url', 'unknown'),
                            parameter="",
                            evidence=f"Fuzzing suggestion: {suggestion['type']}",
                            scan_id="",
                            timestamp=datetime.now()
                        )
                        vulnerabilities.append(vuln)
        
        except Exception as e:
            self.logger.error(f"Error in fuzzing suggestions: {e}")
        
        return vulnerabilities
    
    def _get_severity_from_confidence(self, confidence: float) -> str:
        """Convert confidence score to severity level."""
        if confidence >= 0.9:
            return "Critical"
        elif confidence >= 0.8:
            return "High"
        elif confidence >= 0.6:
            return "Medium"
        else:
            return "Low"
    
    def _get_severity_from_vuln_type(self, vuln_type: str, confidence: float) -> str:
        """Get severity based on vulnerability type and confidence."""
        high_severity_types = ['sql_injection', 'path_traversal', 'command_injection']
        medium_severity_types = ['xss', 'information_disclosure', 'authentication_bypass']
        
        if vuln_type in high_severity_types:
            return "High" if confidence > 0.7 else "Medium"
        elif vuln_type in medium_severity_types:
            return "Medium" if confidence > 0.6 else "Low"
        else:
            return "Low"
    
    def _get_severity_from_risk_level(self, risk_level: str) -> str:
        """Convert risk level to severity."""
        mapping = {
            'Critical': 'Critical',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Minimal': 'Info'
        }
        return mapping.get(risk_level, 'Medium')
    
    def _calculate_cvss_score(self, confidence: float, vuln_type: str) -> float:
        """Calculate CVSS score based on confidence and vulnerability type."""
        base_score = confidence * 10.0
        
        # Adjust based on vulnerability type
        if vuln_type in ['sql_injection', 'path_traversal', 'command_injection']:
            base_score *= 1.2
        elif vuln_type in ['xss', 'information_disclosure']:
            base_score *= 1.0
        elif vuln_type in ['anomaly', 'risk']:
            base_score *= 0.8
        
        return min(base_score, 10.0)
    
    def _get_recommendation_for_vuln_type(self, vuln_type: str) -> str:
        """Get recommendation based on vulnerability type."""
        recommendations = {
            'sql_injection': 'Implement parameterized queries and input validation',
            'xss': 'Implement output encoding and Content Security Policy',
            'path_traversal': 'Validate and sanitize file paths',
            'command_injection': 'Avoid system command execution with user input',
            'information_disclosure': 'Review error messages and sensitive data exposure',
            'authentication_bypass': 'Implement proper authentication and authorization'
        }
        return recommendations.get(vuln_type, 'Review and implement appropriate security controls')
    
    def _get_references_for_vuln_type(self, vuln_type: str) -> List[str]:
        """Get references based on vulnerability type."""
        references = {
            'sql_injection': [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            'xss': [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            'path_traversal': [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
            ],
            'command_injection': [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
            ],
            'information_disclosure': [
                "https://owasp.org/www-community/attacks/Information_disclosure",
                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
            ],
            'authentication_bypass': [
                "https://owasp.org/www-community/attacks/Authentication_Bypass",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
            ]
        }
        return references.get(vuln_type, [
            "https://owasp.org/www-project-api-security/",
            "https://cheatsheetseries.owasp.org/cheatsheets/API_Security_Cheat_Sheet.html"
        ])
    
    def learn_from_results(self, requests_data: List[Dict[str, Any]], results: List[Dict[str, Any]]):
        """
        Learn from scanning results to improve AI models.
        
        Args:
            requests_data: List of requests that were scanned
            results: List of vulnerability results from other plugins
        """
        if not self.enabled:
            return
        
        try:
            self.ai_detector.learn_from_results(requests_data, results)
            self.logger.info("AI models updated with new learning data")
        except Exception as e:
            self.logger.error(f"Error learning from results: {e}")
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of AI models and detection capabilities."""
        return self.ai_detector.get_model_status()
    
    def should_activate(self, requests_data: List[Dict[str, Any]]) -> bool:
        """
        Check if the AI plugin should be activated.
        
        Args:
            requests_data: List of request dictionaries
            
        Returns:
            True if AI plugin should be activated
        """
        return self.enabled and len(requests_data) > 0
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """
        Generate proof of concept for a specific vulnerability.
        
        Args:
            vulnerability_id: ID of the vulnerability
            
        Returns:
            ProofOfConcept object or None if not found
        """
        # For AI-detected vulnerabilities, we don't have specific POCs
        # as they are based on pattern analysis rather than specific exploits
        return None
