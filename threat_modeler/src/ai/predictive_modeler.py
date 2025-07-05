"""
Predictive Threat Modeler for AI-Assisted Threat Discovery
Uses machine learning to predict potential threats based on historical data and patterns.
"""

import json
import pickle
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from datetime import datetime, timedelta

from ..debug_utils import debug_print, debug_log

class PredictiveThreatModeler:
    """Predict potential threats using machine learning models."""
    
    def __init__(self, debug: bool = False):
        """Initialize the predictive threat modeler."""
        self.debug = debug
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.feature_names = []
        self.training_data = []
        self.model_metadata = {}
        
        # Initialize models
        self._initialize_models()
        self._load_training_data()
        
        debug_log("predictive_modeler", "Predictive Threat Modeler initialized")
    
    def _initialize_models(self) -> None:
        """Initialize machine learning models."""
        debug_log("predictive_modeler", "Initializing ML models")
        
        # Initialize different model types
        self.models = {
            "threat_classification": RandomForestClassifier(n_estimators=100, random_state=42),
            "risk_prediction": GradientBoostingClassifier(n_estimators=100, random_state=42),
            "vulnerability_prediction": LogisticRegression(random_state=42, max_iter=1000)
        }
        
        # Initialize scalers and encoders
        for model_name in self.models.keys():
            self.scalers[model_name] = StandardScaler()
            self.label_encoders[model_name] = LabelEncoder()
        
        debug_log("predictive_modeler", "ML models initialized")
    
    def _load_training_data(self) -> None:
        """Load or generate training data for the models."""
        try:
            # Try to load existing training data
            with open("training_data.json", "r") as f:
                self.training_data = json.load(f)
            debug_log("predictive_modeler", "Training data loaded from file")
        except FileNotFoundError:
            # Generate synthetic training data
            self._generate_synthetic_data()
            debug_log("predictive_modeler", "Generated synthetic training data")
    
    def _generate_synthetic_data(self) -> None:
        """Generate synthetic training data for model training."""
        debug_log("predictive_modeler", "Generating synthetic training data")
        
        # Generate synthetic architecture data
        architectures = []
        
        # Web application patterns
        for i in range(100):
            architectures.append({
                "component_count": np.random.randint(3, 10),
                "external_components": np.random.randint(0, 3),
                "data_flows": np.random.randint(2, 8),
                "technologies": np.random.randint(2, 6),
                "has_database": np.random.choice([0, 1]),
                "has_api": np.random.choice([0, 1]),
                "has_authentication": np.random.choice([0, 1]),
                "has_encryption": np.random.choice([0, 1]),
                "has_external_api": np.random.choice([0, 1]),
                "has_file_upload": np.random.choice([0, 1]),
                "has_user_input": np.random.choice([0, 1]),
                "architecture_type": np.random.choice(["web", "api", "mobile", "desktop"]),
                "threats": self._generate_synthetic_threats("web"),
                "risk_score": np.random.uniform(1, 10)
            })
        
        # Microservices patterns
        for i in range(80):
            architectures.append({
                "component_count": np.random.randint(5, 15),
                "external_components": np.random.randint(1, 5),
                "data_flows": np.random.randint(8, 20),
                "technologies": np.random.randint(4, 10),
                "has_database": np.random.choice([0, 1]),
                "has_api": 1,  # Microservices always have APIs
                "has_authentication": np.random.choice([0, 1]),
                "has_encryption": np.random.choice([0, 1]),
                "has_external_api": np.random.choice([0, 1]),
                "has_file_upload": np.random.choice([0, 1]),
                "has_user_input": np.random.choice([0, 1]),
                "architecture_type": "microservices",
                "threats": self._generate_synthetic_threats("microservices"),
                "risk_score": np.random.uniform(3, 10)
            })
        
        # Cloud-native patterns
        for i in range(60):
            architectures.append({
                "component_count": np.random.randint(3, 8),
                "external_components": np.random.randint(2, 6),
                "data_flows": np.random.randint(5, 12),
                "technologies": np.random.randint(3, 8),
                "has_database": np.random.choice([0, 1]),
                "has_api": np.random.choice([0, 1]),
                "has_authentication": np.random.choice([0, 1]),
                "has_encryption": np.random.choice([0, 1]),
                "has_external_api": 1,  # Cloud-native often has external APIs
                "has_file_upload": np.random.choice([0, 1]),
                "has_user_input": np.random.choice([0, 1]),
                "architecture_type": "cloud",
                "threats": self._generate_synthetic_threats("cloud"),
                "risk_score": np.random.uniform(2, 9)
            })
        
        self.training_data = architectures
        
        # Save training data
        with open("training_data.json", "w") as f:
            json.dump(self.training_data, f, indent=2)
    
    def _generate_synthetic_threats(self, architecture_type: str) -> List[str]:
        """Generate synthetic threats based on architecture type."""
        threat_mapping = {
            "web": ["sql_injection", "xss", "csrf", "authentication_bypass", "session_hijacking"],
            "microservices": ["api_security", "service_discovery", "inter_service_auth", "data_consistency", "distributed_dos"],
            "cloud": ["misconfiguration", "data_breach", "insider_threat", "api_abuse", "resource_exhaustion"]
        }
        
        threats = threat_mapping.get(architecture_type, ["general_vulnerability"])
        num_threats = np.random.randint(1, len(threats) + 1)
        return np.random.choice(threats, num_threats, replace=False).tolist()
    
    def train_models(self) -> Dict[str, float]:
        """Train the machine learning models."""
        debug_log("predictive_modeler", "Training ML models")
        
        if not self.training_data:
            debug_log("predictive_modeler", "No training data available", "ERROR")
            return {}
        
        # Prepare features
        features = self._prepare_features()
        
        # Train each model
        model_scores = {}
        
        for model_name, model in self.models.items():
            try:
                score = self._train_model(model_name, model, features)
                model_scores[model_name] = score
                debug_log("predictive_modeler", f"Model {model_name} trained with score: {score:.3f}")
            except Exception as e:
                debug_log("predictive_modeler", f"Error training {model_name}: {e}", "ERROR")
                model_scores[model_name] = 0.0
        
        # Save trained models
        self._save_models()
        
        return model_scores
    
    def _prepare_features(self) -> pd.DataFrame:
        """Prepare features for model training."""
        features = []
        
        for arch in self.training_data:
            feature_vector = [
                arch["component_count"],
                arch["external_components"],
                arch["data_flows"],
                arch["technologies"],
                arch["has_database"],
                arch["has_api"],
                arch["has_authentication"],
                arch["has_encryption"],
                arch["has_external_api"],
                arch["has_file_upload"],
                arch["has_user_input"]
            ]
            
            # Add architecture type encoding
            arch_type_encoding = {
                "web": [1, 0, 0, 0],
                "api": [0, 1, 0, 0],
                "mobile": [0, 0, 1, 0],
                "desktop": [0, 0, 0, 1],
                "microservices": [0, 0, 0, 0],  # Will be handled separately
                "cloud": [0, 0, 0, 0]  # Will be handled separately
            }
            
            feature_vector.extend(arch_type_encoding.get(arch["architecture_type"], [0, 0, 0, 0]))
            
            # Add threat indicators
            threat_indicators = [0] * 10  # 10 common threat types
            for threat in arch["threats"]:
                if "sql_injection" in threat:
                    threat_indicators[0] = 1
                elif "xss" in threat:
                    threat_indicators[1] = 1
                elif "csrf" in threat:
                    threat_indicators[2] = 1
                elif "authentication" in threat:
                    threat_indicators[3] = 1
                elif "api" in threat:
                    threat_indicators[4] = 1
                elif "data" in threat:
                    threat_indicators[5] = 1
                elif "dos" in threat:
                    threat_indicators[6] = 1
                elif "misconfiguration" in threat:
                    threat_indicators[7] = 1
                elif "insider" in threat:
                    threat_indicators[8] = 1
                else:
                    threat_indicators[9] = 1
            
            feature_vector.extend(threat_indicators)
            features.append(feature_vector)
        
        return pd.DataFrame(features)
    
    def _train_model(self, model_name: str, model, features: pd.DataFrame) -> float:
        """Train a specific model."""
        # Prepare target variables
        if model_name == "threat_classification":
            # Classify threat types
            targets = []
            for arch in self.training_data:
                if "sql_injection" in arch["threats"]:
                    targets.append("sql_injection")
                elif "xss" in arch["threats"]:
                    targets.append("xss")
                elif "api" in str(arch["threats"]):
                    targets.append("api_security")
                else:
                    targets.append("general")
            
            y = self.label_encoders[model_name].fit_transform(targets)
            
        elif model_name == "risk_prediction":
            # Predict risk levels
            targets = []
            for arch in self.training_data:
                if arch["risk_score"] > 7:
                    targets.append("high")
                elif arch["risk_score"] > 4:
                    targets.append("medium")
                else:
                    targets.append("low")
            
            y = self.label_encoders[model_name].fit_transform(targets)
            
        elif model_name == "vulnerability_prediction":
            # Predict vulnerability presence
            targets = []
            for arch in self.training_data:
                targets.append(1 if len(arch["threats"]) > 2 else 0)
            
            y = np.array(targets)
        
        # Scale features
        X_scaled = self.scalers[model_name].fit_transform(features)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42
        )
        
        # Train model
        model.fit(X_train, y_train)
        
        # Evaluate model
        score = model.score(X_test, y_test)
        
        return score
    
    def _save_models(self) -> None:
        """Save trained models to disk."""
        try:
            for model_name, model in self.models.items():
                # Save model
                joblib.dump(model, f"models/{model_name}_model.pkl")
                
                # Save scaler
                joblib.dump(self.scalers[model_name], f"models/{model_name}_scaler.pkl")
                
                # Save label encoder
                joblib.dump(self.label_encoders[model_name], f"models/{model_name}_encoder.pkl")
            
            debug_log("predictive_modeler", "Models saved successfully")
            
        except Exception as e:
            debug_log("predictive_modeler", f"Error saving models: {e}", "ERROR")
    
    def load_models(self) -> bool:
        """Load trained models from disk."""
        try:
            for model_name in self.models.keys():
                # Load model
                self.models[model_name] = joblib.load(f"models/{model_name}_model.pkl")
                
                # Load scaler
                self.scalers[model_name] = joblib.load(f"models/{model_name}_scaler.pkl")
                
                # Load label encoder
                self.label_encoders[model_name] = joblib.load(f"models/{model_name}_encoder.pkl")
            
            debug_log("predictive_modeler", "Models loaded successfully")
            return True
            
        except Exception as e:
            debug_log("predictive_modeler", f"Error loading models: {e}", "ERROR")
            return False
    
    def predict_threats(self, architecture: Dict) -> Dict[str, Any]:
        """Predict threats for a given architecture."""
        debug_log("predictive_modeler", "Predicting threats for architecture")
        
        # Check if models are trained
        if not self.models or not all(model is not None for model in self.models.values()):
            debug_log("predictive_modeler", "Models not trained, training now", "WARNING")
            self.train_models()
        
        # Extract features from architecture
        features = self._extract_architecture_features(architecture)
        
        predictions = {}
        
        # Make predictions with each model
        for model_name, model in self.models.items():
            try:
                prediction = self._make_prediction(model_name, model, features)
                predictions[model_name] = prediction
            except Exception as e:
                debug_log("predictive_modeler", f"Error making prediction with {model_name}: {e}", "ERROR")
                predictions[model_name] = {"error": str(e)}
        
        # Combine predictions
        combined_prediction = self._combine_predictions(predictions, architecture)
        
        debug_log("predictive_modeler", "Threat prediction completed")
        return combined_prediction
    
    def _extract_architecture_features(self, architecture: Dict) -> np.ndarray:
        """Extract features from architecture for prediction."""
        components = architecture.get("components", [])
        data_flows = architecture.get("data_flows", [])
        
        # Basic features
        component_count = len(components)
        external_components = sum(1 for c in components if c.get("external", False))
        data_flow_count = len(data_flows)
        
        # Technology diversity
        technologies = set()
        for component in components:
            technologies.update(component.get("technologies", []))
        technology_count = len(technologies)
        
        # Component type indicators
        has_database = any(c.get("type") == "database" for c in components)
        has_api = any(c.get("type") in ["api", "service"] for c in components)
        has_authentication = any("auth" in c.get("type", "").lower() for c in components)
        has_encryption = any(flow.get("encrypted", False) for flow in data_flows)
        has_external_api = any(c.get("external", False) and c.get("type") == "api" for c in components)
        has_file_upload = any("upload" in flow.get("data_type", "").lower() for flow in data_flows)
        has_user_input = any("user" in flow.get("data_type", "").lower() for flow in data_flows)
        
        # Architecture type encoding
        arch_type = self._determine_architecture_type(architecture)
        arch_type_encoding = {
            "web": [1, 0, 0, 0],
            "api": [0, 1, 0, 0],
            "mobile": [0, 0, 1, 0],
            "desktop": [0, 0, 0, 1],
            "microservices": [0, 0, 0, 0],
            "cloud": [0, 0, 0, 0]
        }
        
        # Build feature vector
        feature_vector = [
            component_count,
            external_components,
            data_flow_count,
            technology_count,
            int(has_database),
            int(has_api),
            int(has_authentication),
            int(has_encryption),
            int(has_external_api),
            int(has_file_upload),
            int(has_user_input)
        ]
        
        feature_vector.extend(arch_type_encoding.get(arch_type, [0, 0, 0, 0]))
        
        # Add threat indicators (initialize to 0)
        feature_vector.extend([0] * 10)
        
        return np.array(feature_vector).reshape(1, -1)
    
    def _determine_architecture_type(self, architecture: Dict) -> str:
        """Determine the type of architecture."""
        components = architecture.get("components", [])
        description = architecture.get("description", "").lower()
        
        # Check for specific patterns
        if any("microservice" in c.get("type", "").lower() for c in components):
            return "microservices"
        elif any("cloud" in description or "aws" in description or "azure" in description):
            return "cloud"
        elif any("mobile" in description or "app" in description):
            return "mobile"
        elif any("api" in c.get("type", "").lower() for c in components):
            return "api"
        else:
            return "web"
    
    def _make_prediction(self, model_name: str, model, features: np.ndarray) -> Dict[str, Any]:
        """Make prediction with a specific model."""
        # Scale features
        features_scaled = self.scalers[model_name].transform(features)
        
        # Make prediction
        prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0] if hasattr(model, 'predict_proba') else None
        
        # Decode prediction if needed
        if model_name in self.label_encoders:
            try:
                decoded_prediction = self.label_encoders[model_name].inverse_transform([prediction])[0]
            except:
                decoded_prediction = str(prediction)
        else:
            decoded_prediction = prediction
        
        return {
            "prediction": decoded_prediction,
            "confidence": max(probabilities) if probabilities is not None else 0.5,
            "probabilities": probabilities.tolist() if probabilities is not None else None
        }
    
    def _combine_predictions(self, predictions: Dict[str, Any], architecture: Dict) -> Dict[str, Any]:
        """Combine predictions from different models."""
        combined = {
            "predicted_threats": [],
            "risk_level": "unknown",
            "confidence": 0.0,
            "recommendations": []
        }
        
        # Extract threat predictions
        if "threat_classification" in predictions:
            threat_pred = predictions["threat_classification"]
            if "prediction" in threat_pred:
                combined["predicted_threats"].append(threat_pred["prediction"])
        
        # Extract risk level
        if "risk_prediction" in predictions:
            risk_pred = predictions["risk_prediction"]
            if "prediction" in risk_pred:
                combined["risk_level"] = risk_pred["prediction"]
                combined["confidence"] = risk_pred.get("confidence", 0.0)
        
        # Extract vulnerability prediction
        if "vulnerability_prediction" in predictions:
            vuln_pred = predictions["vulnerability_prediction"]
            if "prediction" in vuln_pred and vuln_pred["prediction"] == 1:
                combined["predicted_threats"].append("general_vulnerability")
        
        # Generate recommendations based on predictions
        combined["recommendations"] = self._generate_predictive_recommendations(combined, architecture)
        
        return combined
    
    def _generate_predictive_recommendations(self, prediction: Dict[str, Any], architecture: Dict) -> List[str]:
        """Generate recommendations based on predictions."""
        recommendations = []
        
        # Recommendations based on predicted threats
        for threat in prediction["predicted_threats"]:
            if "sql_injection" in threat:
                recommendations.extend([
                    "Implement parameterized queries",
                    "Use input validation and sanitization",
                    "Apply principle of least privilege to database accounts"
                ])
            elif "xss" in threat:
                recommendations.extend([
                    "Implement Content Security Policy (CSP)",
                    "Use output encoding for user data",
                    "Validate and sanitize all inputs"
                ])
            elif "api" in threat:
                recommendations.extend([
                    "Implement API authentication and authorization",
                    "Use rate limiting and throttling",
                    "Validate all API inputs and outputs"
                ])
        
        # Recommendations based on risk level
        if prediction["risk_level"] == "high":
            recommendations.extend([
                "Conduct comprehensive security assessment",
                "Implement additional security controls",
                "Increase monitoring and alerting",
                "Consider security-focused architecture review"
            ])
        elif prediction["risk_level"] == "medium":
            recommendations.extend([
                "Review security controls",
                "Implement security testing",
                "Monitor for security issues"
            ])
        
        # Remove duplicates
        return list(set(recommendations))
    
    def update_model_with_feedback(self, architecture: Dict, actual_threats: List[str], feedback_score: float) -> bool:
        """Update model with feedback from actual threat analysis."""
        debug_log("predictive_modeler", "Updating model with feedback")
        
        try:
            # Add feedback to training data
            feedback_data = {
                "architecture": architecture,
                "actual_threats": actual_threats,
                "feedback_score": feedback_score,
                "timestamp": datetime.now().isoformat()
            }
            
            # Save feedback for model retraining
            try:
                with open("feedback_data.json", "r") as f:
                    feedback_list = json.load(f)
            except FileNotFoundError:
                feedback_list = []
            
            feedback_list.append(feedback_data)
            
            with open("feedback_data.json", "w") as f:
                json.dump(feedback_list, f, indent=2)
            
            # Retrain models periodically (every 10 feedback entries)
            if len(feedback_list) % 10 == 0:
                debug_log("predictive_modeler", "Retraining models with feedback")
                self._incorporate_feedback(feedback_list)
                self.train_models()
            
            return True
            
        except Exception as e:
            debug_log("predictive_modeler", f"Error updating model: {e}", "ERROR")
            return False
    
    def _incorporate_feedback(self, feedback_list: List[Dict]) -> None:
        """Incorporate feedback into training data."""
        for feedback in feedback_list:
            # Extract features from feedback architecture
            features = self._extract_architecture_features(feedback["architecture"])
            
            # Adjust training data based on feedback
            # This is a simplified approach - in practice, you'd want more sophisticated feedback incorporation
            if feedback["feedback_score"] > 0.7:  # Good prediction
                # Add to training data with high confidence
                pass
            elif feedback["feedback_score"] < 0.3:  # Poor prediction
                # Add to training data with corrected labels
                pass
        
        debug_log("predictive_modeler", f"Incorporated {len(feedback_list)} feedback entries") 