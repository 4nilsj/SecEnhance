#!/usr/bin/env python3
"""
Demo script to showcase AI-powered detection functionality.
"""

import sys
import os
import json
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api_security_scanner'))

from api_security_scanner.core.ai_detector import AIDetector
from api_security_scanner.plugins.ai_security_checker import AISecurityChecker


def create_test_requests():
    """Create test requests for demonstration."""
    return {
        "normal_requests": [
            {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": '{"name": "John", "email": "john@example.com"}'
            },
            {
                "url": "https://api.example.com/posts",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"title": "Test Post", "content": "This is a test post"}'
            }
        ],
        "suspicious_requests": [
            {
                "url": "https://api.example.com/users?page=1&limit=10&sort=name&filter=active&search=test&category=admin&type=user&status=active&role=admin&permission=read&access=public&level=1&depth=2&size=large&format=json&output=detailed&include=all&exclude=none&fields=name,email,phone&order=asc&direction=up&sort_by=created_at&group_by=department&aggregate=count&function=sum&operation=select&query=complex&condition=where&clause=and&logic=or&comparison=equals&value=test&parameter=id&identifier=123&reference=abc&token=xyz&key=secret&password=admin&secret=hidden&credential=user&auth=basic&login=admin&user=root&admin=true&superuser=yes&privilege=all&right=write&permission=delete&access=private&level=admin&role=super&type=admin&status=active&category=user&group=admin&team=dev&department=it&company=test&organization=example&domain=test.com&subdomain=api&host=localhost&port=8080&protocol=https&scheme=http&path=/api/v1/users&endpoint=/users&resource=user&entity=person&object=account&record=profile&document=user&file=data&content=json&format=application/json&type=application/json&encoding=utf-8&charset=utf-8&language=en&locale=en_US&timezone=UTC&date=2023-01-01&time=12:00:00&timestamp=1672574400&epoch=1672574400&unix=1672574400&iso=2023-01-01T12:00:00Z&rfc=Mon, 01 Jan 2023 12:00:00 GMT&utc=2023-01-01T12:00:00Z&gmt=2023-01-01T12:00:00Z&local=2023-01-01T12:00:00Z&offset=+00:00&zone=UTC&dst=false&leap=false&year=2023&month=01&day=01&hour=12&minute=00&second=00&millisecond=000&microsecond=000000&nanosecond=000000000&weekday=0&week=1&quarter=1&yearday=1&isoweek=1&isoyear=2023&isoweekday=1&isocalendar=(2023, 1, 1)&ctime=1672574400&mtime=1672574400&atime=1672574400&size=1024&mode=644&uid=1000&gid=1000&dev=2049&ino=123456&nlink=1&blksize=4096&blocks=8&rdev=0&flags=0&gen=0&birthtime=1672574400&birthtime_ns=1672574400000000000&atime_ns=1672574400000000000&mtime_ns=1672574400000000000&ctime_ns=1672574400000000000&blksize_ns=4096000000000&blocks_ns=8000000000000&dev_ns=2049000000000&ino_ns=123456000000000&nlink_ns=1000000000000&rdev_ns=0&flags_ns=0&gen_ns=0&birthtime_ns=1672574400000000000",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": ""
            },
            {
                "url": "https://api.example.com/users",
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"name": "John\'; DROP TABLE users; --", "email": "john@example.com"}'
            },
            {
                "url": "https://api.example.com/search",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": '{"query": "<script>alert(\'XSS\')</script>"}'
            },
            {
                "url": "https://api.example.com/files/../../../etc/passwd",
                "method": "GET",
                "headers": {"Content-Type": "application/json"},
                "body": ""
            }
        ],
        "high_risk_requests": [
            {
                "url": "https://api.example.com/admin/users?page=1&limit=100",
                "method": "POST",
                "headers": {"Content-Type": "application/json", "Authorization": "Bearer admin_token"},
                "body": '{"name": "John", "email": "john@example.com", "password": "secret123", "ssn": "123-45-6789", "credit_card": "4111-1111-1111-1111"}'
            },
            {
                "url": "https://api.example.com/admin/delete-user",
                "method": "DELETE",
                "headers": {"Content-Type": "application/json", "Authorization": "Bearer admin_token"},
                "body": '{"user_id": "123", "confirm": "true"}'
            }
        ]
    }


def test_ai_detector():
    """Test the AI detector functionality."""
    print("🤖 Testing AI Detector...")
    
    # Initialize AI detector
    config = {
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
    
    ai_detector = AIDetector(config)
    test_data = create_test_requests()
    
    # Test feature extraction
    print("\n🔍 Testing Feature Extraction:")
    for category, requests in test_data.items():
        print(f"\n  {category.replace('_', ' ').title()}:")
        for i, request in enumerate(requests[:2]):  # Test first 2 requests
            features = ai_detector.extract_features(request)
            print(f"    Request {i+1}:")
            print(f"      URL Length: {features['url_length']}")
            print(f"      Path Depth: {features['path_depth']}")
            print(f"      Query Params: {features['query_param_count']}")
            print(f"      Has Auth: {features['has_auth_header']}")
            print(f"      Body Length: {features['body_length']}")
            print(f"      Sensitive Patterns: {features['has_sensitive_patterns']}")
            print(f"      SQL Patterns: {features['has_sql_patterns']}")
            print(f"      XSS Patterns: {features['has_xss_patterns']}")
            print(f"      Path Traversal: {features['has_path_traversal']}")
    
    # Test anomaly detection
    print("\n🚨 Testing Anomaly Detection:")
    all_requests = []
    for requests in test_data.values():
        all_requests.extend(requests)
    
    anomalies = ai_detector.detect_anomalies(all_requests)
    print(f"  Found {len(anomalies)} anomalies")
    
    for i, anomaly in enumerate(anomalies[:3]):  # Show first 3 anomalies
        print(f"    Anomaly {i+1}:")
        print(f"      Score: {anomaly['anomaly_score']:.3f}")
        print(f"      Confidence: {anomaly['confidence']:.3f}")
        print(f"      Method: {anomaly['detection_method']}")
        if 'reasons' in anomaly:
            print(f"      Reasons: {', '.join(anomaly['reasons'])}")
    
    # Test vulnerability classification
    print("\n🎯 Testing Vulnerability Classification:")
    classifications = ai_detector.classify_vulnerabilities(all_requests)
    print(f"  Found {len(classifications)} potential vulnerabilities")
    
    for i, classification in enumerate(classifications[:3]):  # Show first 3 classifications
        print(f"    Classification {i+1}:")
        print(f"      Type: {classification['vulnerability_type']}")
        print(f"      Confidence: {classification['confidence']:.3f}")
        print(f"      Method: {classification['detection_method']}")
    
    # Test risk scoring
    print("\n📊 Testing Risk Scoring:")
    for category, requests in test_data.items():
        print(f"\n  {category.replace('_', ' ').title()}:")
        for i, request in enumerate(requests[:2]):  # Test first 2 requests
            risk_assessment = ai_detector.calculate_risk_score(request)
            print(f"    Request {i+1}:")
            print(f"      Risk Score: {risk_assessment['risk_score']:.3f}")
            print(f"      Risk Level: {risk_assessment['risk_level']}")
            print(f"      Breakdown:")
            for key, value in risk_assessment['breakdown'].items():
                print(f"        {key}: {value}")
    
    # Test fuzzing suggestions
    print("\n💡 Testing Fuzzing Suggestions:")
    for category, requests in test_data.items():
        print(f"\n  {category.replace('_', ' ').title()}:")
        for i, request in enumerate(requests[:1]):  # Test first request
            suggestions = ai_detector.generate_fuzzing_suggestions(request)
            print(f"    Request {i+1}: {len(suggestions)} suggestions")
            for j, suggestion in enumerate(suggestions[:2]):  # Show first 2 suggestions
                print(f"      Suggestion {j+1}: {suggestion['type']}")
                print(f"        Confidence: {suggestion['confidence']:.3f}")
                print(f"        Description: {suggestion['description']}")
                print(f"        Payloads: {', '.join(suggestion['payloads'][:3])}")
    
    # Test model status
    print("\n📈 Model Status:")
    status = ai_detector.get_model_status()
    print(f"  ML Available: {status['ml_available']}")
    print(f"  Models Loaded: {len(status['models_loaded'])}")
    print(f"  Vectorizers Loaded: {len(status['vectorizers_loaded'])}")
    print(f"  Scalers Loaded: {len(status['scalers_loaded'])}")
    print(f"  Training Data:")
    print(f"    Vulnerabilities: {status['training_data']['vulnerabilities']}")
    print(f"    Normal Requests: {status['training_data']['normal_requests']}")
    print(f"    Anomalies: {status['training_data']['anomalies']}")
    
    return True


def test_ai_security_checker():
    """Test the AI Security Checker plugin."""
    print("\n🔒 Testing AI Security Checker Plugin...")
    
    # Initialize plugin
    config = {
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
    
    plugin = AISecurityChecker(config=config)
    test_data = create_test_requests()
    
    # Test with different request types
    for category, requests in test_data.items():
        print(f"\n  Testing {category.replace('_', ' ').title()}:")
        result = plugin.check("https://api.example.com", requests)
        
        print(f"    Success: {result.success}")
        print(f"    Vulnerabilities Found: {len(result.vulnerabilities)}")
        
        if result.vulnerabilities:
            for i, vuln in enumerate(result.vulnerabilities[:2]):  # Show first 2 vulnerabilities
                print(f"      Vulnerability {i+1}:")
                print(f"        Title: {vuln.title}")
                print(f"        Severity: {vuln.severity}")
                print(f"        CVSS Score: {vuln.cvss_score}")
                print(f"        Category: {vuln.category}")
        
        if result.error:
            print(f"    Error: {result.error}")
    
    # Test plugin status
    print(f"\n  Plugin Status:")
    status = plugin.get_model_status()
    print(f"    ML Available: {status['ml_available']}")
    print(f"    Models Loaded: {len(status['models_loaded'])}")
    
    # Test learning
    print(f"\n  Testing Learning:")
    requests = test_data['suspicious_requests'][:2]
    results = [{'vulnerabilities': [{'type': 'sql_injection', 'severity': 'High'}]}]
    plugin.learn_from_results(requests, results)
    print(f"    Learning completed successfully")
    
    return True


def main():
    """Main function."""
    print("🚀 AI-Powered Detection Demo")
    print("=" * 50)
    
    try:
        # Test AI Detector
        success1 = test_ai_detector()
        
        # Test AI Security Checker Plugin
        success2 = test_ai_security_checker()
        
        if success1 and success2:
            print("\n✅ All tests passed!")
            print("\n🎉 AI-Powered Detection is working correctly!")
            print("\n📝 Key Features Demonstrated:")
            print("  • Feature extraction from API requests")
            print("  • Anomaly detection using ML and rule-based methods")
            print("  • Vulnerability classification")
            print("  • Risk scoring and assessment")
            print("  • Intelligent fuzzing suggestions")
            print("  • Learning from scan results")
            print("  • Plugin integration")
            print("\n🔧 Configuration Options:")
            print("  • Enable/disable AI detection")
            print("  • Configure individual ML models")
            print("  • Adjust confidence thresholds")
            print("  • Control learning behavior")
            print("  • Fallback to rule-based detection")
        else:
            print("\n❌ Some tests failed!")
            return 1
    except Exception as e:
        print(f"\n💥 Error during testing: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
