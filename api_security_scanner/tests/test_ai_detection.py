"""
Test AI-powered detection functionality.
"""

import pytest
import json
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from api_security_scanner.core.ai_detector import AIDetector
from api_security_scanner.plugins.ai_security_checker import AISecurityChecker
from api_security_scanner.core.scanner_plugins import PluginResult, Vulnerability


class TestAIDetector:
    """Test AI detector functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'enabled': True,
            'models': {
                'anomaly_detection': {'enabled': True, 'threshold': 0.7, 'contamination': 0.1},
                'vulnerability_classification': {'enabled': True, 'threshold': 0.8, 'min_samples': 10},
                'risk_scoring': {'enabled': True, 'weights': {'endpoint_complexity': 0.3, 'parameter_count': 0.2, 'authentication': 0.3, 'data_sensitivity': 0.2}},
                'intelligent_fuzzing': {'enabled': True, 'max_suggestions': 50, 'confidence_threshold': 0.6}
            },
            'learning': {'enabled': True, 'auto_retrain': True, 'retrain_interval': 100, 'min_training_samples': 50},
            'fallback_to_rules': True
        }
        
        # Mock the model path to use temp directory
        with patch('api_security_scanner.core.ai_detector.Path') as mock_path:
            mock_path.return_value = Path(self.temp_dir)
            self.ai_detector = AIDetector(self.config)
    
    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_ai_detector_initialization(self):
        """Test AI detector initialization."""
        assert self.ai_detector.config == self.config
        assert self.ai_detector.ml_available is not None
        assert isinstance(self.ai_detector.training_data, dict)
        assert 'vulnerabilities' in self.ai_detector.training_data
        assert 'normal_requests' in self.ai_detector.training_data
    
    def test_extract_features(self):
        """Test feature extraction from requests."""
        request = {
            'url': 'https://api.example.com/users?page=1&limit=10',
            'method': 'GET',
            'headers': {'Content-Type': 'application/json', 'Authorization': 'Bearer token123'},
            'body': '{"name": "John", "email": "john@example.com"}'
        }
        
        features = self.ai_detector.extract_features(request)
        
        # Check that features are extracted
        assert 'url_length' in features
        assert 'path_depth' in features
        assert 'has_query_params' in features
        assert 'query_param_count' in features
        assert 'method_complexity' in features
        assert 'header_count' in features
        assert 'has_auth_header' in features
        assert 'body_length' in features
        assert 'has_json_body' in features
        assert 'has_sensitive_patterns' in features
        
        # Check specific values
        assert features['url_length'] > 0
        assert features['path_depth'] > 0
        assert features['has_query_params'] == True
        assert features['query_param_count'] == 2
        assert features['has_auth_header'] == True
        assert features['has_json_body'] == True
    
    def test_detect_anomalies_rule_based(self):
        """Test rule-based anomaly detection."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            },
            {
                'url': 'https://api.example.com/users?page=1&limit=10&sort=name&filter=active&search=test&category=admin&type=user&status=active&role=admin&permission=read&access=public&level=1&depth=2&size=large&format=json&output=detailed&include=all&exclude=none&fields=name,email,phone&order=asc&direction=up&sort_by=created_at&group_by=department&aggregate=count&function=sum&operation=select&query=complex&condition=where&clause=and&logic=or&comparison=equals&value=test&parameter=id&identifier=123&reference=abc&token=xyz&key=secret&password=admin&secret=hidden&credential=user&auth=basic&login=admin&user=root&admin=true&superuser=yes&privilege=all&right=write&permission=delete&access=private&level=admin&role=super&type=admin&status=active&category=user&group=admin&team=dev&department=it&company=test&organization=example&domain=test.com&subdomain=api&host=localhost&port=8080&protocol=https&scheme=http&path=/api/v1/users&endpoint=/users&resource=user&entity=person&object=account&record=profile&document=user&file=data&content=json&format=application/json&type=application/json&encoding=utf-8&charset=utf-8&language=en&locale=en_US&timezone=UTC&date=2023-01-01&time=12:00:00&timestamp=1672574400&epoch=1672574400&unix=1672574400&iso=2023-01-01T12:00:00Z&rfc=Mon, 01 Jan 2023 12:00:00 GMT&utc=2023-01-01T12:00:00Z&gmt=2023-01-01T12:00:00Z&local=2023-01-01T12:00:00Z&offset=+00:00&zone=UTC&dst=false&leap=false&year=2023&month=01&day=01&hour=12&minute=00&second=00&millisecond=000&microsecond=000000&nanosecond=000000000&weekday=0&week=1&quarter=1&yearday=1&isoweek=1&isoyear=2023&isoweekday=1&isocalendar=(2023, 1, 1)&ctime=1672574400&mtime=1672574400&atime=1672574400&size=1024&mode=644&uid=1000&gid=1000&dev=2049&ino=123456&nlink=1&blksize=4096&blocks=8&rdev=0&flags=0&gen=0&birthtime=1672574400&birthtime_ns=1672574400000000000&atime_ns=1672574400000000000&mtime_ns=1672574400000000000&ctime_ns=1672574400000000000&blksize_ns=4096000000000&blocks_ns=8000000000000&dev_ns=2049000000000&ino_ns=123456000000000&nlink_ns=1000000000000&rdev_ns=0&flags_ns=0&gen_ns=0&birthtime_ns=1672574400000000000',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        anomalies = self.ai_detector.detect_anomalies(requests)
        
        # Should detect the second request as anomalous due to excessive parameters
        assert len(anomalies) > 0
        assert any('excessive' in str(anomaly.get('reasons', [])).lower() or anomaly['anomaly_score'] > 0.5 for anomaly in anomalies)
    
    def test_classify_vulnerabilities_rule_based(self):
        """Test rule-based vulnerability classification."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            },
            {
                'url': 'https://api.example.com/users',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John\'; DROP TABLE users; --"}'
            }
        ]
        
        classifications = self.ai_detector.classify_vulnerabilities(requests)
        
        # Should detect SQL injection in the second request
        assert len(classifications) > 0
        assert any('sql_injection' in str(classification.get('vulnerability_type', '')) for classification in classifications)
    
    def test_calculate_risk_score(self):
        """Test risk score calculation."""
        request = {
            'url': 'https://api.example.com/admin/users?page=1&limit=100',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json', 'Authorization': 'Bearer admin_token'},
            'body': '{"name": "John", "email": "john@example.com", "password": "secret123"}'
        }
        
        risk_assessment = self.ai_detector.calculate_risk_score(request)
        
        assert 'risk_score' in risk_assessment
        assert 'breakdown' in risk_assessment
        assert 'risk_level' in risk_assessment
        assert 0 <= risk_assessment['risk_score'] <= 1
        assert risk_assessment['risk_level'] in ['Critical', 'High', 'Medium', 'Low', 'Minimal']
        
        # Should have high risk due to sensitive patterns
        assert risk_assessment['risk_score'] > 0.3
    
    def test_generate_fuzzing_suggestions(self):
        """Test fuzzing suggestion generation."""
        request = {
            'url': 'https://api.example.com/users?page=1&limit=10',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json', 'X-Custom-Header': 'value'},
            'body': '{"name": "John", "email": "john@example.com"}'
        }
        
        suggestions = self.ai_detector.generate_fuzzing_suggestions(request)
        
        assert isinstance(suggestions, list)
        assert len(suggestions) > 0
        
        for suggestion in suggestions:
            assert 'type' in suggestion
            assert 'description' in suggestion
            assert 'confidence' in suggestion
            assert 'payloads' in suggestion
            assert 0 <= suggestion['confidence'] <= 1
    
    def test_learn_from_results(self):
        """Test learning from scan results."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        results = [
            {
                'vulnerabilities': [
                    {'type': 'sql_injection', 'severity': 'High'}
                ]
            }
        ]
        
        initial_count = len(self.ai_detector.training_data['vulnerabilities'])
        self.ai_detector.learn_from_results(requests, results)
        
        # Should have added training data
        assert len(self.ai_detector.training_data['vulnerabilities']) > initial_count
    
    def test_get_model_status(self):
        """Test model status retrieval."""
        status = self.ai_detector.get_model_status()
        
        assert 'ml_available' in status
        assert 'config' in status
        assert 'models_loaded' in status
        assert 'vectorizers_loaded' in status
        assert 'scalers_loaded' in status
        assert 'training_data' in status
        
        assert isinstance(status['ml_available'], bool)
        assert isinstance(status['models_loaded'], list)
        assert isinstance(status['training_data'], dict)


class TestAISecurityChecker:
    """Test AI Security Checker plugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            'enabled': True,
            'models': {
                'anomaly_detection': {'enabled': True, 'threshold': 0.7, 'contamination': 0.1},
                'vulnerability_classification': {'enabled': True, 'threshold': 0.8, 'min_samples': 10},
                'risk_scoring': {'enabled': True, 'weights': {'endpoint_complexity': 0.3, 'parameter_count': 0.2, 'authentication': 0.3, 'data_sensitivity': 0.2}},
                'intelligent_fuzzing': {'enabled': True, 'max_suggestions': 50, 'confidence_threshold': 0.6}
            },
            'learning': {'enabled': True, 'auto_retrain': True, 'retrain_interval': 100, 'min_training_samples': 50},
            'fallback_to_rules': True
        }
        
        self.plugin = AISecurityChecker()
        self.plugin.configure(self.config)
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "AISecurityChecker"
        assert self.plugin.description == "AI-powered vulnerability detection using machine learning models"
        assert self.plugin.version == "1.0.0"
        assert self.plugin.enabled == True
        assert self.plugin.config == self.config
    
    def test_plugin_disabled(self):
        """Test plugin when disabled."""
        disabled_config = self.config.copy()
        disabled_config['enabled'] = False
        
        plugin = AISecurityChecker()
        plugin.configure(disabled_config)
        result = plugin.check("https://api.example.com", [])
        
        assert result.success == True
        assert len(result.vulnerabilities) == 0
        assert result.error is None
    
    def test_check_with_normal_requests(self):
        """Test plugin with normal requests."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        result = self.plugin.check("https://api.example.com", requests)
        
        assert isinstance(result, PluginResult)
        assert result.success == True
        assert result.plugin_name == "AISecurityChecker"
        assert isinstance(result.vulnerabilities, list)
    
    def test_check_with_suspicious_requests(self):
        """Test plugin with suspicious requests."""
        requests = [
            {
                'url': 'https://api.example.com/users?page=1&limit=10&sort=name&filter=active&search=test&category=admin&type=user&status=active&role=admin&permission=read&access=public&level=1&depth=2&size=large&format=json&output=detailed&include=all&exclude=none&fields=name,email,phone&order=asc&direction=up&sort_by=created_at&group_by=department&aggregate=count&function=sum&operation=select&query=complex&condition=where&clause=and&logic=or&comparison=equals&value=test&parameter=id&identifier=123&reference=abc&token=xyz&key=secret&password=admin&secret=hidden&credential=user&auth=basic&login=admin&user=root&admin=true&superuser=yes&privilege=all&right=write&permission=delete&access=private&level=admin&role=super&type=admin&status=active&category=user&group=admin&team=dev&department=it&company=test&organization=example&domain=test.com&subdomain=api&host=localhost&port=8080&protocol=https&scheme=http&path=/api/v1/users&endpoint=/users&resource=user&entity=person&object=account&record=profile&document=user&file=data&content=json&format=application/json&type=application/json&encoding=utf-8&charset=utf-8&language=en&locale=en_US&timezone=UTC&date=2023-01-01&time=12:00:00&timestamp=1672574400&epoch=1672574400&unix=1672574400&iso=2023-01-01T12:00:00Z&rfc=Mon, 01 Jan 2023 12:00:00 GMT&utc=2023-01-01T12:00:00Z&gmt=2023-01-01T12:00:00Z&local=2023-01-01T12:00:00Z&offset=+00:00&zone=UTC&dst=false&leap=false&year=2023&month=01&day=01&hour=12&minute=00&second=00&millisecond=000&microsecond=000000&nanosecond=000000000&weekday=0&week=1&quarter=1&yearday=1&isoweek=1&isoyear=2023&isoweekday=1&isocalendar=(2023, 1, 1)&ctime=1672574400&mtime=1672574400&atime=1672574400&size=1024&mode=644&uid=1000&gid=1000&dev=2049&ino=123456&nlink=1&blksize=4096&blocks=8&rdev=0&flags=0&gen=0&birthtime=1672574400&birthtime_ns=1672574400000000000&atime_ns=1672574400000000000&mtime_ns=1672574400000000000&ctime_ns=1672574400000000000&blksize_ns=4096000000000&blocks_ns=8000000000000&dev_ns=2049000000000&ino_ns=123456000000000&nlink_ns=1000000000000&rdev_ns=0&flags_ns=0&gen_ns=0&birthtime_ns=1672574400000000000',
                'method': 'POST',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John\'; DROP TABLE users; --"}'
            }
        ]
        
        result = self.plugin.check("https://api.example.com", requests)
        
        assert isinstance(result, PluginResult)
        assert result.success == True
        assert result.plugin_name == "AISecurityChecker"
        assert isinstance(result.vulnerabilities, list)
        
        # Should find some vulnerabilities due to suspicious patterns
        assert len(result.vulnerabilities) > 0
    
    def test_learn_from_results(self):
        """Test learning from results."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        results = [
            {
                'vulnerabilities': [
                    {'type': 'sql_injection', 'severity': 'High'}
                ]
            }
        ]
        
        # Should not raise an exception
        self.plugin.learn_from_results(requests, results)
    
    def test_get_model_status(self):
        """Test model status retrieval."""
        status = self.plugin.get_model_status()
        
        assert isinstance(status, dict)
        assert 'ml_available' in status
        assert 'config' in status
    
    def test_should_activate(self):
        """Test plugin activation logic."""
        requests = [
            {
                'url': 'https://api.example.com/users',
                'method': 'GET',
                'headers': {'Content-Type': 'application/json'},
                'body': '{"name": "John"}'
            }
        ]
        
        assert self.plugin.should_activate(requests) == True
        
        # Test with empty requests
        assert self.plugin.should_activate([]) == False
        
        # Test with disabled plugin
        disabled_plugin = AISecurityChecker()
        disabled_plugin.configure({'enabled': False})
        assert disabled_plugin.should_activate(requests) == False
    
    def test_error_handling(self):
        """Test error handling in plugin."""
        # Test with invalid request data
        result = self.plugin.check("https://api.example.com", [{'invalid': 'data'}])
        
        assert isinstance(result, PluginResult)
        # Should handle gracefully without crashing
        assert result.plugin_name == "AISecurityChecker"
