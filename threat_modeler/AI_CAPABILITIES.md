# AI-Assisted Threat Discovery

This document describes the advanced AI capabilities integrated into the Threat Modeling Tool for enhanced threat discovery and analysis.

## Overview

The AI-assisted threat discovery system combines multiple machine learning approaches to provide comprehensive threat analysis:

- **CVE Analysis**: Transformer models for vulnerability identification
- **Pattern Recognition**: ML-based architecture pattern detection
- **NLP Analysis**: Natural language processing for document analysis
- **Predictive Modeling**: ML models for threat prediction

## Architecture

```
AI-Assisted Threat Discovery
├── CVE Analyzer
│   ├── Transformer Models
│   ├── CVE Database Integration
│   └── Vulnerability Matching
├── Pattern Recognizer
│   ├── Architecture Pattern Database
│   ├── ML-based Pattern Matching
│   └── Threat Pattern Mapping
├── NLP Analyzer
│   ├── Document Analysis
│   ├── Requirement Extraction
│   └── Security Keyword Detection
└── Predictive Modeler
    ├── ML Models (Random Forest, Gradient Boosting)
    ├── Feature Engineering
    └── Threat Prediction
```

## CVE Analysis

### Overview
Uses transformer models trained on CVE databases to identify potential vulnerabilities in your architecture.

### Features
- **CVE Database Integration**: Connects to NVD API for latest vulnerability data
- **Transformer Models**: Uses sentence transformers for similarity matching
- **Technology Matching**: Identifies CVEs relevant to your technology stack
- **Risk Scoring**: Calculates relevance scores for each CVE match

### Usage
```python
from src.ai.cve_analyzer import CVEAnalyzer

analyzer = CVEAnalyzer(debug=True)
cve_results = analyzer.analyze_architecture_for_cves(architecture)
```

### Output
```json
{
  "cve_id": "CVE-2023-1234",
  "description": "SQL injection vulnerability in web application",
  "severity": "HIGH",
  "relevance_score": 0.85,
  "affected_components": ["Web Server", "Database"],
  "recommendations": [
    "Use parameterized queries",
    "Implement input validation"
  ]
}
```

## Architecture Pattern Recognition

### Overview
Identifies common architectural patterns and their associated threats using machine learning.

### Supported Patterns
- **Microservices**: Distributed services with API communication
- **Monolithic**: Single application with shared components
- **Serverless**: Event-driven functions without server management
- **Event-Driven**: Message-based asynchronous processing
- **Layered**: Horizontal layer organization
- **Client-Server**: Distributed client and server components
- **Peer-to-Peer**: Equal peer nodes with distributed data

### Features
- **Pattern Database**: Comprehensive pattern definitions with threats
- **ML-based Recognition**: Uses sentence transformers for pattern matching
- **Threat Prediction**: Predicts threats based on recognized patterns
- **Complexity Analysis**: Analyzes architecture complexity and security implications

### Usage
```python
from src.ai.pattern_recognizer import ArchitecturePatternRecognizer

recognizer = ArchitecturePatternRecognizer(debug=True)
patterns = recognizer.recognize_patterns(architecture)
threats = recognizer.predict_threats_from_patterns(patterns)
```

### Output
```json
{
  "pattern": "microservices",
  "name": "Microservices Architecture",
  "confidence": 0.92,
  "threats": [
    "service-to-service authentication",
    "API security",
    "distributed denial of service"
  ],
  "risk_score": 7.5,
  "mitigations": [
    "Implement service mesh for security",
    "Use API gateways with authentication"
  ]
}
```

## Natural Language Processing (NLP)

### Overview
Analyzes design documents and requirements using natural language processing to extract security-relevant information.

### Features
- **Document Analysis**: Extracts security requirements and threat indicators
- **Requirement Extraction**: Identifies functional and security requirements
- **Security Keyword Detection**: Finds security-relevant terms and concepts
- **Data Flow Extraction**: Identifies data flows from natural language descriptions

### Usage
```python
from src.ai.nlp_analyzer import NLPAnalyzer

analyzer = NLPAnalyzer(debug=True)
results = analyzer.analyze_design_document(document_text)
requirements = analyzer.extract_requirements(document_text)
```

### Output
```json
{
  "security_requirements": [
    "authentication: Implement OAuth2 authentication",
    "data_protection: Encrypt sensitive data using AES-256"
  ],
  "threat_indicators": [
    "high_risk: System processes customer data",
    "external_exposure: Application has public API endpoints"
  ],
  "data_flows": [
    "Web Server -> Database: user_data via TCP"
  ],
  "recommendations": [
    "Add explicit security requirements",
    "Implement threat modeling for identified risk areas"
  ]
}
```

## Predictive Threat Modeling

### Overview
Uses machine learning models to predict potential threats based on historical data and architectural patterns.

### Models
- **Random Forest**: For threat classification
- **Gradient Boosting**: For risk prediction
- **Logistic Regression**: For vulnerability prediction

### Features
- **Feature Engineering**: Extracts relevant features from architecture
- **Model Training**: Trains on synthetic and real-world data
- **Threat Prediction**: Predicts threats with confidence scores
- **Feedback Integration**: Updates models based on user feedback

### Usage
```python
from src.ai.predictive_modeler import PredictiveThreatModeler

modeler = PredictiveThreatModeler(debug=True)
modeler.train_models()  # Train models first
prediction = modeler.predict_threats(architecture)
```

### Output
```json
{
  "predicted_threats": ["sql_injection", "xss"],
  "risk_level": "medium",
  "confidence": 0.78,
  "recommendations": [
    "Implement input validation",
    "Use output encoding for user data"
  ]
}
```

## Comprehensive AI Analysis

### Overview
Combines all AI capabilities for comprehensive threat analysis.

### Features
- **Multi-Modal Analysis**: Combines CVE, pattern, NLP, and predictive analysis
- **Threat Synthesis**: Merges traditional and AI-identified threats
- **Risk Assessment**: Provides overall risk assessment with AI confidence
- **Intelligent Recommendations**: Generates AI-powered security recommendations

### Usage
```python
from src.ai_assisted_threat_discovery import AIAssistedThreatDiscovery

ai_discovery = AIAssistedThreatDiscovery(debug=True)
results = ai_discovery.comprehensive_threat_analysis(
    architecture=architecture,
    enable_cve_analysis=True,
    enable_pattern_recognition=True,
    enable_nlp_analysis=True,
    enable_predictive_modeling=True
)
```

### Output
```json
{
  "combined_threats": [
    {
      "id": "cve_cve-2023-1234",
      "title": "SQL Injection Vulnerability",
      "severity": "HIGH",
      "risk_score": 8.5,
      "combined_score": 9.2,
      "sources": ["cve_analysis", "pattern_recognition"],
      "ai_enhanced": true,
      "confidence": 0.85
    }
  ],
  "risk_assessment": {
    "overall_risk_level": "HIGH",
    "total_threats": 15,
    "high_severity_threats": 5,
    "ai_confidence": 0.82
  },
  "recommendations": [
    "Implement parameterized queries",
    "Use API gateways with authentication",
    "Add explicit security requirements"
  ]
}
```

## Installation and Setup

### Dependencies
The AI capabilities require additional dependencies:

```bash
pip install torch transformers sentence-transformers scikit-learn
pip install numpy pandas requests beautifulsoup4 nltk spacy gensim
```

### Model Download
Some models are downloaded automatically on first use:
- Sentence transformers: `all-MiniLM-L6-v2`
- spaCy model: `en_core_web_sm`
- NLTK data: punkt, averaged_perceptron_tagger, maxent_ne_chunker, stopwords

### Manual Model Download
```bash
# Download spaCy model
python -m spacy download en_core_web_sm

# Download NLTK data
python -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger'); nltk.download('maxent_ne_chunker'); nltk.download('stopwords')"
```

## Testing AI Capabilities

### Test Script
Run the comprehensive AI test suite:

```bash
python examples/test_ai_capabilities.py
```

### Individual Tests
```python
# Test CVE analysis
python -c "from examples.test_ai_capabilities import test_cve_analysis; test_cve_analysis()"

# Test pattern recognition
python -c "from examples.test_ai_capabilities import test_pattern_recognition; test_pattern_recognition()"

# Test NLP analysis
python -c "from examples.test_ai_capabilities import test_nlp_analysis; test_nlp_analysis()"

# Test predictive modeling
python -c "from examples.test_ai_capabilities import test_predictive_modeling; test_predictive_modeling()"
```

## Configuration

### AI Settings
Configure AI behavior in the code:

```python
# Enable/disable specific AI capabilities
ai_discovery = AIAssistedThreatDiscovery(debug=True)
results = ai_discovery.comprehensive_threat_analysis(
    architecture=architecture,
    enable_cve_analysis=True,      # CVE database analysis
    enable_pattern_recognition=True, # Architecture pattern recognition
    enable_nlp_analysis=True,      # Document analysis
    enable_predictive_modeling=True # ML-based prediction
)
```

### Model Configuration
```python
# CVE Analyzer
cve_analyzer = CVEAnalyzer(debug=True)
# Uses sentence transformer: 'all-MiniLM-L6-v2'

# Pattern Recognizer
pattern_recognizer = ArchitecturePatternRecognizer(debug=True)
# Uses sentence transformer: 'all-MiniLM-L6-v2'

# NLP Analyzer
nlp_analyzer = NLPAnalyzer(debug=True)
# Uses spaCy model: 'en_core_web_sm'

# Predictive Modeler
predictive_modeler = PredictiveThreatModeler(debug=True)
# Uses scikit-learn models: RandomForest, GradientBoosting, LogisticRegression
```

## Performance Considerations

### Model Loading
- Models are loaded on first use and cached in memory
- Initial loading may take 10-30 seconds depending on system
- Subsequent analyses are much faster

### Memory Usage
- Sentence transformers: ~100MB per model
- spaCy model: ~50MB
- scikit-learn models: ~10-50MB each
- Total memory usage: ~200-300MB

### Processing Time
- CVE analysis: 5-15 seconds
- Pattern recognition: 2-5 seconds
- NLP analysis: 1-3 seconds per document
- Predictive modeling: 1-2 seconds
- Comprehensive analysis: 10-25 seconds

## Troubleshooting

### Common Issues

1. **Model Download Failures**
   ```bash
   # Manual download
   python -m spacy download en_core_web_sm
   python -c "import nltk; nltk.download('punkt')"
   ```

2. **Memory Issues**
   ```python
   # Reduce model complexity
   from sentence_transformers import SentenceTransformer
   model = SentenceTransformer('all-MiniLM-L6-v2')  # Smaller model
   ```

3. **CVE API Issues**
   ```python
   # Use local cache
   cve_analyzer = CVEAnalyzer(debug=True)
   # Falls back to sample data if API unavailable
   ```

4. **Training Data Issues**
   ```python
   # Regenerate training data
   predictive_modeler = PredictiveThreatModeler(debug=True)
   predictive_modeler._generate_synthetic_data()
   ```

### Debug Mode
Enable debug mode for detailed logging:

```bash
python threat_modeler_cli.py --ai --debug -i architecture.yaml
```

## Future Enhancements

### Planned Features
- **Custom Model Training**: Train models on organization-specific data
- **Threat Intelligence Integration**: Real-time threat intelligence feeds
- **Advanced NLP**: More sophisticated document analysis
- **Model Explainability**: Explain AI predictions and recommendations
- **Continuous Learning**: Models that improve over time with feedback

### Research Areas
- **Graph Neural Networks**: For complex architecture analysis
- **Transformer Models**: For advanced threat prediction
- **Federated Learning**: For privacy-preserving model training
- **Adversarial ML**: For robust threat detection

## Contributing

### Adding New AI Capabilities
1. Create new module in `src/ai/`
2. Implement required interfaces
3. Add to `AIAssistedThreatDiscovery` class
4. Update documentation and tests

### Model Improvements
1. Collect feedback data
2. Retrain models with new data
3. Validate model performance
4. Deploy updated models

### Pattern Database
1. Add new architectural patterns
2. Define associated threats
3. Provide mitigation strategies
4. Update pattern recognition logic

## License

The AI capabilities are subject to the same license as the main tool. Some models may have their own licenses:

- **Sentence Transformers**: Apache 2.0
- **spaCy**: MIT
- **scikit-learn**: BSD
- **PyTorch**: BSD

## Support

For AI-related issues:
1. Check the troubleshooting section
2. Run the test script to verify functionality
3. Enable debug mode for detailed logging
4. Check model downloads and dependencies
5. Create an issue with detailed information 