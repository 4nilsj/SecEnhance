#!/usr/bin/env python3
"""
AI Capabilities Test Script
Demonstrates AI-assisted threat discovery capabilities.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.ai_assisted_threat_discovery import AIAssistedThreatDiscovery
from src.debug_utils import setup_debug_logging

def test_cve_analysis():
    """Test CVE analysis capabilities."""
    print("=== Testing CVE Analysis ===")
    
    # Initialize AI discovery
    ai_discovery = AIAssistedThreatDiscovery(debug=True)
    
    # Test architecture
    architecture = {
        "name": "Test Web Application",
        "description": "Web application with user authentication and database",
        "components": [
            {
                "name": "Web Server",
                "type": "web_server",
                "description": "Apache web server",
                "technologies": ["Apache", "PHP"],
                "external": False
            },
            {
                "name": "Database",
                "type": "database",
                "description": "MySQL database",
                "technologies": ["MySQL"],
                "external": False
            }
        ],
        "data_flows": [
            {
                "from": "Web Server",
                "to": "Database",
                "protocol": "TCP",
                "data_type": "user_data",
                "encrypted": False
            }
        ],
        "trust_boundaries": [],
        "assets": []
    }
    
    try:
        # Run CVE analysis
        cve_results = ai_discovery.cve_analyzer.analyze_architecture_for_cves(architecture)
        print(f"✅ CVE analysis completed: {len(cve_results)} potential CVEs found")
        
        if cve_results:
            print("Top CVE matches:")
            for cve in cve_results[:3]:
                print(f"  - {cve['cve_id']}: {cve['title']} (Risk: {cve['relevance_score']:.2f})")
        
        return True
        
    except Exception as e:
        print(f"❌ CVE analysis failed: {e}")
        return False

def test_pattern_recognition():
    """Test architecture pattern recognition."""
    print("\n=== Testing Pattern Recognition ===")
    
    # Initialize AI discovery
    ai_discovery = AIAssistedThreatDiscovery(debug=True)
    
    # Test microservices architecture
    architecture = {
        "name": "Microservices Application",
        "description": "Distributed microservices with API gateway",
        "components": [
            {
                "name": "API Gateway",
                "type": "gateway",
                "description": "Kong API gateway",
                "technologies": ["Kong"],
                "external": False
            },
            {
                "name": "User Service",
                "type": "service",
                "description": "User management service",
                "technologies": ["Node.js"],
                "external": False
            },
            {
                "name": "Product Service",
                "type": "service",
                "description": "Product catalog service",
                "technologies": ["Python"],
                "external": False
            },
            {
                "name": "Database",
                "type": "database",
                "description": "PostgreSQL database",
                "technologies": ["PostgreSQL"],
                "external": False
            }
        ],
        "data_flows": [
            {
                "from": "API Gateway",
                "to": "User Service",
                "protocol": "HTTPS",
                "data_type": "auth_data",
                "encrypted": True
            },
            {
                "from": "API Gateway",
                "to": "Product Service",
                "protocol": "HTTPS",
                "data_type": "product_data",
                "encrypted": True
            }
        ],
        "trust_boundaries": [],
        "assets": []
    }
    
    try:
        # Run pattern recognition
        patterns = ai_discovery.pattern_recognizer.recognize_patterns(architecture)
        print(f"✅ Pattern recognition completed: {len(patterns)} patterns recognized")
        
        if patterns:
            print("Recognized patterns:")
            for pattern in patterns:
                print(f"  - {pattern['name']} (Confidence: {pattern['confidence']:.2f})")
        
        # Test threat prediction from patterns
        threats = ai_discovery.pattern_recognizer.predict_threats_from_patterns(patterns)
        print(f"✅ Threat prediction completed: {len(threats)} threats predicted")
        
        if threats:
            print("Predicted threats:")
            for threat in threats[:3]:
                print(f"  - {threat['threat']} (Risk: {threat['risk_score']:.2f})")
        
        return True
        
    except Exception as e:
        print(f"❌ Pattern recognition failed: {e}")
        return False

def test_nlp_analysis():
    """Test NLP analysis capabilities."""
    print("\n=== Testing NLP Analysis ===")
    
    # Initialize AI discovery
    ai_discovery = AIAssistedThreatDiscovery(debug=True)
    
    # Test design document
    design_doc = """
    The application is a web-based e-commerce platform that allows users to browse products,
    create accounts, and make purchases. The system uses a three-tier architecture with a web
    server, application server, and database. User authentication is handled through OAuth2,
    and sensitive data is encrypted using AES-256. The application processes credit card
    information and stores user profiles in a PostgreSQL database. File uploads are allowed
    for product images, and the system integrates with external payment gateways.
    """
    
    try:
        # Run NLP analysis
        nlp_results = ai_discovery.nlp_analyzer.analyze_design_document(design_doc)
        print("✅ NLP analysis completed")
        
        print(f"Security requirements found: {len(nlp_results['security_requirements'])}")
        print(f"Threat indicators found: {len(nlp_results['threat_indicators'])}")
        print(f"Data flows identified: {len(nlp_results['data_flows'])}")
        print(f"Components identified: {len(nlp_results['components'])}")
        
        # Test requirements extraction
        requirements = ai_discovery.nlp_analyzer.extract_requirements(design_doc)
        print(f"Requirements extracted: {len(requirements)}")
        
        return True
        
    except Exception as e:
        print(f"❌ NLP analysis failed: {e}")
        return False

def test_predictive_modeling():
    """Test predictive modeling capabilities."""
    print("\n=== Testing Predictive Modeling ===")
    
    # Initialize AI discovery
    ai_discovery = AIAssistedThreatDiscovery(debug=True)
    
    # Test architecture
    architecture = {
        "name": "Cloud-Native Application",
        "description": "Serverless application with external APIs",
        "components": [
            {
                "name": "Lambda Function",
                "type": "function",
                "description": "AWS Lambda function",
                "technologies": ["AWS Lambda", "Python"],
                "external": False
            },
            {
                "name": "External API",
                "type": "api",
                "description": "Third-party payment API",
                "technologies": ["Stripe API"],
                "external": True
            },
            {
                "name": "S3 Storage",
                "type": "service",
                "description": "File storage",
                "technologies": ["AWS S3"],
                "external": True
            }
        ],
        "data_flows": [
            {
                "from": "Lambda Function",
                "to": "External API",
                "protocol": "HTTPS",
                "data_type": "payment_data",
                "encrypted": True
            }
        ],
        "trust_boundaries": [],
        "assets": []
    }
    
    try:
        # Train models first
        print("Training predictive models...")
        training_results = ai_discovery.predictive_modeler.train_models()
        print(f"✅ Models trained: {training_results}")
        
        # Run prediction
        prediction = ai_discovery.predictive_modeler.predict_threats(architecture)
        print("✅ Predictive modeling completed")
        
        print(f"Predicted risk level: {prediction.get('risk_level', 'Unknown')}")
        print(f"Predicted threats: {prediction.get('predicted_threats', [])}")
        print(f"Confidence: {prediction.get('confidence', 0.0):.2f}")
        
        return True
        
    except Exception as e:
        print(f"❌ Predictive modeling failed: {e}")
        return False

def test_comprehensive_ai_analysis():
    """Test comprehensive AI analysis."""
    print("\n=== Testing Comprehensive AI Analysis ===")
    
    # Initialize AI discovery
    ai_discovery = AIAssistedThreatDiscovery(debug=True)
    
    # Test architecture
    architecture = {
        "name": "Modern Web Application",
        "description": "React frontend with Node.js backend and MongoDB database",
        "components": [
            {
                "name": "React Frontend",
                "type": "web_server",
                "description": "React SPA",
                "technologies": ["React", "JavaScript"],
                "external": False
            },
            {
                "name": "Node.js Backend",
                "type": "api",
                "description": "Express.js API server",
                "technologies": ["Node.js", "Express"],
                "external": False
            },
            {
                "name": "MongoDB",
                "type": "database",
                "description": "NoSQL database",
                "technologies": ["MongoDB"],
                "external": False
            },
            {
                "name": "Payment Gateway",
                "type": "api",
                "description": "External payment service",
                "technologies": ["Stripe"],
                "external": True
            }
        ],
        "data_flows": [
            {
                "from": "React Frontend",
                "to": "Node.js Backend",
                "protocol": "HTTPS",
                "data_type": "user_data",
                "encrypted": True
            },
            {
                "from": "Node.js Backend",
                "to": "MongoDB",
                "protocol": "TCP",
                "data_type": "user_data",
                "encrypted": False
            },
            {
                "from": "Node.js Backend",
                "to": "Payment Gateway",
                "protocol": "HTTPS",
                "data_type": "payment_data",
                "encrypted": True
            }
        ],
        "trust_boundaries": [
            {
                "name": "External Services",
                "components": ["Payment Gateway"],
                "description": "Third-party services"
            }
        ],
        "assets": [
            {
                "name": "User Data",
                "type": "data",
                "value": "high",
                "description": "Personal user information"
            }
        ]
    }
    
    try:
        # Run comprehensive analysis
        results = ai_discovery.comprehensive_threat_analysis(
            architecture=architecture,
            enable_cve_analysis=True,
            enable_pattern_recognition=True,
            enable_nlp_analysis=False,
            enable_predictive_modeling=True
        )
        
        print("✅ Comprehensive AI analysis completed")
        
        # Display results
        print(f"Total threats identified: {len(results['combined_threats'])}")
        print(f"Overall risk level: {results['risk_assessment']['overall_risk_level']}")
        print(f"AI confidence: {results['risk_assessment']['ai_confidence']:.2f}")
        
        print("\nTop AI-identified threats:")
        for threat in results['combined_threats'][:5]:
            ai_marker = " (AI)" if threat.get('ai_enhanced', False) else ""
            print(f"  - {threat['title']}{ai_marker} (Risk: {threat['risk_score']:.2f})")
        
        print(f"\nAI recommendations: {len(results['recommendations'])}")
        for rec in results['recommendations'][:3]:
            print(f"  - {rec}")
        
        return True
        
    except Exception as e:
        print(f"❌ Comprehensive AI analysis failed: {e}")
        return False

def main():
    """Run all AI capability tests."""
    print("🚀 Testing AI-Assisted Threat Discovery Capabilities")
    print("=" * 60)
    
    # Change to the threat_modeler directory
    os.chdir(Path(__file__).parent.parent)
    
    # Run tests
    tests = [
        ("CVE Analysis", test_cve_analysis),
        ("Pattern Recognition", test_pattern_recognition),
        ("NLP Analysis", test_nlp_analysis),
        ("Predictive Modeling", test_predictive_modeling),
        ("Comprehensive AI Analysis", test_comprehensive_ai_analysis)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name} Test...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} test passed")
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 AI Capabilities Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All AI capabilities tests passed! AI-assisted threat discovery is working correctly.")
        return 0
    else:
        print("⚠️  Some AI tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 