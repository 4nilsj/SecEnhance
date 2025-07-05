"""
AI-Assisted Threat Discovery Module
Integrates all AI capabilities for comprehensive threat analysis and discovery.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from .ai.cve_analyzer import CVEAnalyzer
from .ai.pattern_recognizer import ArchitecturePatternRecognizer
from .ai.nlp_analyzer import NLPAnalyzer
from .ai.predictive_modeler import PredictiveThreatModeler
from .debug_utils import debug_print, debug_log

class AIAssistedThreatDiscovery:
    """Main AI-assisted threat discovery engine."""
    
    def __init__(self, debug: bool = False):
        """Initialize the AI-assisted threat discovery engine."""
        self.debug = debug
        
        # Initialize AI components
        self.cve_analyzer = CVEAnalyzer(debug=debug)
        self.pattern_recognizer = ArchitecturePatternRecognizer(debug=debug)
        self.nlp_analyzer = NLPAnalyzer(debug=debug)
        self.predictive_modeler = PredictiveThreatModeler(debug=debug)
        
        debug_log("ai_discovery", "AI-Assisted Threat Discovery initialized")
    
    def comprehensive_threat_analysis(self, architecture: Dict, 
                                    design_document: Optional[str] = None,
                                    enable_cve_analysis: bool = True,
                                    enable_pattern_recognition: bool = True,
                                    enable_nlp_analysis: bool = True,
                                    enable_predictive_modeling: bool = True) -> Dict[str, Any]:
        """Perform comprehensive AI-assisted threat analysis."""
        debug_log("ai_discovery", "Starting comprehensive AI-assisted threat analysis")
        
        analysis_results = {
            "timestamp": datetime.now().isoformat(),
            "architecture": architecture,
            "ai_analysis": {},
            "combined_threats": [],
            "risk_assessment": {},
            "recommendations": [],
            "confidence_scores": {}
        }
        
        # CVE Analysis
        if enable_cve_analysis:
            debug_log("ai_discovery", "Running CVE analysis")
            try:
                cve_results = self.cve_analyzer.analyze_architecture_for_cves(architecture)
                analysis_results["ai_analysis"]["cve_analysis"] = cve_results
                analysis_results["confidence_scores"]["cve_analysis"] = len(cve_results) / 10.0  # Normalize
            except Exception as e:
                debug_log("ai_discovery", f"Error in CVE analysis: {e}", "ERROR")
                analysis_results["ai_analysis"]["cve_analysis"] = {"error": str(e)}
        
        # Pattern Recognition
        if enable_pattern_recognition:
            debug_log("ai_discovery", "Running pattern recognition")
            try:
                pattern_results = self.pattern_recognizer.recognize_patterns(architecture)
                analysis_results["ai_analysis"]["pattern_recognition"] = pattern_results
                
                # Predict threats from patterns
                pattern_threats = self.pattern_recognizer.predict_threats_from_patterns(pattern_results)
                analysis_results["ai_analysis"]["pattern_threats"] = pattern_threats
                
                # Analyze complexity
                complexity_analysis = self.pattern_recognizer.analyze_architecture_complexity(architecture)
                analysis_results["ai_analysis"]["complexity_analysis"] = complexity_analysis
                
                analysis_results["confidence_scores"]["pattern_recognition"] = sum(p["confidence"] for p in pattern_results) / len(pattern_results) if pattern_results else 0.0
            except Exception as e:
                debug_log("ai_discovery", f"Error in pattern recognition: {e}", "ERROR")
                analysis_results["ai_analysis"]["pattern_recognition"] = {"error": str(e)}
        
        # NLP Analysis
        if enable_nlp_analysis and design_document:
            debug_log("ai_discovery", "Running NLP analysis")
            try:
                nlp_results = self.nlp_analyzer.analyze_design_document(design_document)
                analysis_results["ai_analysis"]["nlp_analysis"] = nlp_results
                
                # Extract requirements
                requirements = self.nlp_analyzer.extract_requirements(design_document)
                analysis_results["ai_analysis"]["requirements"] = requirements
                
                analysis_results["confidence_scores"]["nlp_analysis"] = len(nlp_results["security_requirements"]) / 10.0  # Normalize
            except Exception as e:
                debug_log("ai_discovery", f"Error in NLP analysis: {e}", "ERROR")
                analysis_results["ai_analysis"]["nlp_analysis"] = {"error": str(e)}
        
        # Predictive Modeling
        if enable_predictive_modeling:
            debug_log("ai_discovery", "Running predictive modeling")
            try:
                predictive_results = self.predictive_modeler.predict_threats(architecture)
                analysis_results["ai_analysis"]["predictive_modeling"] = predictive_results
                analysis_results["confidence_scores"]["predictive_modeling"] = predictive_results.get("confidence", 0.0)
            except Exception as e:
                debug_log("ai_discovery", f"Error in predictive modeling: {e}", "ERROR")
                analysis_results["ai_analysis"]["predictive_modeling"] = {"error": str(e)}
        
        # Combine and synthesize results
        analysis_results["combined_threats"] = self._combine_threat_analysis(analysis_results["ai_analysis"])
        analysis_results["risk_assessment"] = self._assess_overall_risk(analysis_results)
        analysis_results["recommendations"] = self._generate_ai_recommendations(analysis_results)
        
        debug_log("ai_discovery", "Comprehensive AI analysis completed")
        return analysis_results
    
    def _combine_threat_analysis(self, ai_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Combine threats from different AI analyses."""
        combined_threats = []
        threat_scores = {}
        
        # Collect threats from CVE analysis
        if "cve_analysis" in ai_analysis and isinstance(ai_analysis["cve_analysis"], list):
            for cve in ai_analysis["cve_analysis"]:
                threat_id = f"cve_{cve.get('cve_id', 'unknown')}"
                threat_scores[threat_id] = {
                    "title": cve.get("title", "Unknown CVE"),
                    "description": cve.get("description", ""),
                    "severity": cve.get("severity", "Unknown"),
                    "risk_score": cve.get("risk_score", 0.0),
                    "relevance_score": cve.get("relevance_score", 0.0),
                    "sources": ["cve_analysis"],
                    "mitigations": cve.get("mitigations", [])
                }
        
        # Collect threats from pattern recognition
        if "pattern_threats" in ai_analysis and isinstance(ai_analysis["pattern_threats"], list):
            for threat in ai_analysis["pattern_threats"]:
                threat_id = f"pattern_{threat.get('threat', 'unknown').replace(' ', '_')}"
                if threat_id in threat_scores:
                    threat_scores[threat_id]["sources"].append("pattern_recognition")
                    threat_scores[threat_id]["risk_score"] = max(
                        threat_scores[threat_id]["risk_score"], 
                        threat.get("risk_score", 0.0)
                    )
                else:
                    threat_scores[threat_id] = {
                        "title": threat.get("threat", "Unknown Pattern Threat"),
                        "description": threat.get("description", ""),
                        "severity": "Medium",  # Default for pattern threats
                        "risk_score": threat.get("risk_score", 0.0),
                        "relevance_score": threat.get("confidence", 0.0),
                        "sources": ["pattern_recognition"],
                        "mitigations": []
                    }
        
        # Collect threats from predictive modeling
        if "predictive_modeling" in ai_analysis and isinstance(ai_analysis["predictive_modeling"], dict):
            pred_results = ai_analysis["predictive_modeling"]
            for threat in pred_results.get("predicted_threats", []):
                threat_id = f"predictive_{threat.replace(' ', '_')}"
                if threat_id in threat_scores:
                    threat_scores[threat_id]["sources"].append("predictive_modeling")
                else:
                    threat_scores[threat_id] = {
                        "title": threat.replace("_", " ").title(),
                        "description": f"Predicted threat: {threat}",
                        "severity": "Medium",
                        "risk_score": 5.0,  # Default for predicted threats
                        "relevance_score": pred_results.get("confidence", 0.0),
                        "sources": ["predictive_modeling"],
                        "mitigations": pred_results.get("recommendations", [])
                    }
        
        # Convert to list and calculate combined scores
        for threat_id, threat_data in threat_scores.items():
            # Calculate combined score based on multiple sources
            source_count = len(threat_data["sources"])
            combined_score = threat_data["risk_score"] * (1 + 0.2 * source_count)
            
            combined_threats.append({
                "id": threat_id,
                "title": threat_data["title"],
                "description": threat_data["description"],
                "severity": threat_data["severity"],
                "risk_score": threat_data["risk_score"],
                "combined_score": min(combined_score, 10.0),
                "sources": threat_data["sources"],
                "mitigations": threat_data["mitigations"],
                "confidence": threat_data["relevance_score"]
            })
        
        # Sort by combined score
        combined_threats.sort(key=lambda x: x["combined_score"], reverse=True)
        
        return combined_threats
    
    def _assess_overall_risk(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk based on AI analysis."""
        combined_threats = analysis_results["combined_threats"]
        confidence_scores = analysis_results["confidence_scores"]
        
        # Calculate risk metrics
        total_threats = len(combined_threats)
        high_severity_threats = len([t for t in combined_threats if t["severity"] == "High"])
        avg_risk_score = sum(t["risk_score"] for t in combined_threats) / total_threats if total_threats > 0 else 0.0
        avg_confidence = sum(confidence_scores.values()) / len(confidence_scores) if confidence_scores else 0.0
        
        # Determine overall risk level
        if avg_risk_score > 7.0 or high_severity_threats > 3:
            overall_risk = "High"
        elif avg_risk_score > 4.0 or high_severity_threats > 1:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        return {
            "overall_risk_level": overall_risk,
            "total_threats": total_threats,
            "high_severity_threats": high_severity_threats,
            "average_risk_score": avg_risk_score,
            "average_confidence": avg_confidence,
            "ai_confidence": avg_confidence,
            "risk_factors": self._identify_risk_factors(analysis_results)
        }
    
    def _identify_risk_factors(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Identify key risk factors from AI analysis."""
        risk_factors = []
        
        # Check complexity
        if "complexity_analysis" in analysis_results["ai_analysis"]:
            complexity = analysis_results["ai_analysis"]["complexity_analysis"]
            if complexity.get("complexity_level") == "High":
                risk_factors.append("High architecture complexity")
        
        # Check pattern risks
        if "pattern_recognition" in analysis_results["ai_analysis"]:
            patterns = analysis_results["ai_analysis"]["pattern_recognition"]
            for pattern in patterns:
                if pattern.get("risk_score", 0) > 7.0:
                    risk_factors.append(f"High-risk pattern: {pattern.get('name', 'Unknown')}")
        
        # Check CVE risks
        if "cve_analysis" in analysis_results["ai_analysis"]:
            cves = analysis_results["ai_analysis"]["cve_analysis"]
            if isinstance(cves, list) and len(cves) > 5:
                risk_factors.append("Multiple CVE matches")
        
        # Check predictive risks
        if "predictive_modeling" in analysis_results["ai_analysis"]:
            pred = analysis_results["ai_analysis"]["predictive_modeling"]
            if pred.get("risk_level") == "high":
                risk_factors.append("High predicted risk")
        
        return risk_factors
    
    def _generate_ai_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate AI-powered recommendations."""
        recommendations = []
        
        # Pattern-based recommendations
        if "pattern_recognition" in analysis_results["ai_analysis"]:
            patterns = analysis_results["ai_analysis"]["pattern_recognition"]
            for pattern in patterns:
                recommendations.extend(pattern.get("mitigations", []))
        
        # Complexity-based recommendations
        if "complexity_analysis" in analysis_results["ai_analysis"]:
            complexity = analysis_results["ai_analysis"]["complexity_analysis"]
            if complexity.get("complexity_level") == "High":
                recommendations.extend([
                    "Consider simplifying architecture to reduce attack surface",
                    "Implement comprehensive security monitoring",
                    "Use security automation tools"
                ])
        
        # CVE-based recommendations
        if "cve_analysis" in analysis_results["ai_analysis"]:
            cves = analysis_results["ai_analysis"]["cve_analysis"]
            if isinstance(cves, list) and len(cves) > 0:
                recommendations.extend([
                    "Address identified CVE vulnerabilities",
                    "Implement regular vulnerability scanning",
                    "Keep dependencies updated"
                ])
        
        # Predictive recommendations
        if "predictive_modeling" in analysis_results["ai_analysis"]:
            pred = analysis_results["ai_analysis"]["predictive_modeling"]
            recommendations.extend(pred.get("recommendations", []))
        
        # NLP-based recommendations
        if "nlp_analysis" in analysis_results["ai_analysis"]:
            nlp = analysis_results["ai_analysis"]["nlp_analysis"]
            if isinstance(nlp, dict):
                recommendations.extend(nlp.get("recommendations", []))
        
        # General AI recommendations
        recommendations.extend([
            "Use AI-assisted threat modeling for continuous improvement",
            "Regularly update AI models with new threat intelligence",
            "Combine AI analysis with manual security review",
            "Implement feedback loop for AI model improvement"
        ])
        
        # Remove duplicates and return
        return list(set(recommendations))
    
    def analyze_design_document(self, document_text: str) -> Dict[str, Any]:
        """Analyze design document using NLP and AI."""
        debug_log("ai_discovery", "Analyzing design document with AI")
        
        analysis = {
            "document_analysis": self.nlp_analyzer.analyze_design_document(document_text),
            "requirements": self.nlp_analyzer.extract_requirements(document_text),
            "architecture_insights": self.nlp_analyzer.analyze_architecture_description(document_text),
            "ai_recommendations": []
        }
        
        # Generate AI-specific recommendations
        analysis["ai_recommendations"] = self._generate_document_recommendations(analysis)
        
        return analysis
    
    def _generate_document_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on document analysis."""
        recommendations = []
        
        # Check for security requirements
        if not analysis["document_analysis"]["security_requirements"]:
            recommendations.append("Add explicit security requirements to design document")
        
        # Check for threat indicators
        if analysis["document_analysis"]["threat_indicators"]:
            recommendations.append("Address identified threat indicators in design")
        
        # Check for data flows
        if analysis["document_analysis"]["data_flows"]:
            recommendations.append("Review security of identified data flows")
        
        # Check for components
        if analysis["document_analysis"]["components"]:
            recommendations.append("Review security of identified components")
        
        return recommendations
    
    def train_ai_models(self) -> Dict[str, float]:
        """Train all AI models."""
        debug_log("ai_discovery", "Training AI models")
        
        training_results = {}
        
        # Train predictive models
        try:
            pred_results = self.predictive_modeler.train_models()
            training_results["predictive_modeling"] = pred_results
        except Exception as e:
            debug_log("ai_discovery", f"Error training predictive models: {e}", "ERROR")
            training_results["predictive_modeling"] = {"error": str(e)}
        
        return training_results
    
    def update_models_with_feedback(self, architecture: Dict, actual_threats: List[str], 
                                  feedback_score: float) -> bool:
        """Update AI models with feedback."""
        debug_log("ai_discovery", "Updating AI models with feedback")
        
        try:
            # Update predictive model
            success = self.predictive_modeler.update_model_with_feedback(
                architecture, actual_threats, feedback_score
            )
            
            if success:
                debug_log("ai_discovery", "AI models updated successfully")
            else:
                debug_log("ai_discovery", "Failed to update AI models", "ERROR")
            
            return success
            
        except Exception as e:
            debug_log("ai_discovery", f"Error updating AI models: {e}", "ERROR")
            return False
    
    def export_ai_analysis(self, analysis_results: Dict[str, Any], format: str = "json") -> str:
        """Export AI analysis results."""
        debug_log("ai_discovery", f"Exporting AI analysis in {format} format")
        
        if format.lower() == "json":
            return json.dumps(analysis_results, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def get_ai_capabilities(self) -> Dict[str, Any]:
        """Get information about available AI capabilities."""
        return {
            "cve_analysis": {
                "enabled": self.cve_analyzer.embedding_model is not None,
                "description": "CVE database analysis using transformer models"
            },
            "pattern_recognition": {
                "enabled": self.pattern_recognizer.embedding_model is not None,
                "description": "Architecture pattern recognition and threat prediction"
            },
            "nlp_analysis": {
                "enabled": self.nlp_analyzer.embedding_model is not None,
                "description": "Natural language processing for design document analysis"
            },
            "predictive_modeling": {
                "enabled": len(self.predictive_modeler.models) > 0,
                "description": "Machine learning-based threat prediction"
            }
        } 