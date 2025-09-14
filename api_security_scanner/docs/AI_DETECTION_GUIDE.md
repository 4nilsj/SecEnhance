# AI-Powered Detection Guide

## Overview

The API Security Scanner now includes advanced AI-powered detection capabilities that use machine learning models to identify vulnerabilities, anomalies, and security risks in API requests. This feature provides intelligent analysis that goes beyond traditional rule-based detection methods.

## Table of Contents

- [Features](#features)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [AI Detection Types](#ai-detection-types)
- [CLI Options](#cli-options)
- [Environment Variables](#environment-variables)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

## Features

### 🤖 Core AI Capabilities

1. **Anomaly Detection**: Identifies unusual patterns in API requests that may indicate security issues
2. **Vulnerability Classification**: Automatically classifies potential vulnerabilities (SQL injection, XSS, path traversal, etc.)
3. **Risk Scoring**: Calculates comprehensive risk scores based on multiple factors
4. **Intelligent Fuzzing**: Suggests targeted fuzzing approaches based on request analysis
5. **Learning**: Improves detection accuracy over time by learning from scan results

### 🔧 Configuration Options

- Enable/disable AI detection entirely
- Configure individual ML models
- Adjust confidence thresholds
- Control learning behavior
- Set model storage paths
- Fallback to rule-based detection

## Installation & Setup

### Prerequisites

The AI detection feature requires additional Python packages for machine learning capabilities:

```bash
pip install scikit-learn joblib numpy
```

### Optional Dependencies

For enhanced ML capabilities (optional):
```bash
pip install pandas matplotlib seaborn
```

### Verification

Test if AI detection is available:
```bash
python -c "from api_security_scanner.core.ai_detector import AIDetector; print('AI Detection available:', AIDetector().ml_available)"
```

## Configuration

### CLI Configuration

AI detection can be configured through command-line options:

```bash
# Enable AI detection (default: enabled)
python main.py scan -f collection.json --ai-detection

# Disable AI detection
python main.py scan -f collection.json --no-ai-detection

# Configure specific AI features
python main.py scan -f collection.json \
  --ai-anomaly-detection \
  --no-ai-vulnerability-classification \
  --ai-risk-scoring \
  --ai-intelligent-fuzzing \
  --ai-learning
```

### Environment Variables

Configure AI detection through environment variables:

```bash
# Enable/disable AI detection
export AI_DETECTION_ENABLED=true

# Configure individual models
export AI_ANOMALY_DETECTION_ENABLED=true
export AI_VULNERABILITY_CLASSIFICATION_ENABLED=true
export AI_RISK_SCORING_ENABLED=true
export AI_INTELLIGENT_FUZZING_ENABLED=true
export AI_LEARNING_ENABLED=true

# Model storage path
export AI_MODEL_STORAGE_PATH=/path/to/models
```

### Configuration File

Add AI detection settings to your configuration file:

```yaml
ai_detection:
  enabled: true
  models:
    anomaly_detection:
      enabled: true
      threshold: 0.7
      contamination: 0.1
    vulnerability_classification:
      enabled: true
      threshold: 0.8
      min_samples: 10
    risk_scoring:
      enabled: true
      weights:
        endpoint_complexity: 0.3
        parameter_count: 0.2
        authentication: 0.3
        data_sensitivity: 0.2
    intelligent_fuzzing:
      enabled: true
      max_suggestions: 50
      confidence_threshold: 0.6
  learning:
    enabled: true
    auto_retrain: true
    retrain_interval: 100
    min_training_samples: 50
  fallback_to_rules: true
  model_storage_path: "models"
```

## Usage

### Basic Usage

```bash
# Scan with AI detection enabled
python main.py scan -f collection.json

# Scan with specific AI features
python main.py scan -f collection.json \
  --ai-detection \
  --ai-anomaly-detection \
  --ai-vulnerability-classification
```

### Advanced Usage

```bash
# Scan with custom AI configuration
python main.py scan -f collection.json \
  --ai-detection \
  --ai-anomaly-detection \
  --ai-vulnerability-classification \
  --ai-risk-scoring \
  --ai-intelligent-fuzzing \
  --ai-learning
```

### Plugin Selection with AI

```bash
# Run only AI security checker
python main.py scan -f collection.json --plugins AISecurityChecker

# Run AI checker with other plugins
python main.py scan -f collection.json \
  --plugins AISecurityChecker,JWTSecurityChecker,SecurityHeadersChecker
```

## AI Detection Types

### 1. Anomaly Detection

Identifies unusual patterns in API requests:

**Features Analyzed:**
- URL length and complexity
- Parameter count and types
- Request body size and content
- Header patterns
- Authentication methods

**Detection Methods:**
- Machine Learning: Isolation Forest algorithm
- Rule-based: Pattern analysis and thresholds

**Example Output:**
```
🚨 Anomaly Detected
  Score: 0.85
  Confidence: 0.85
  Reasons: Unusually long URL, High number of query parameters, Contains sensitive patterns
```

### 2. Vulnerability Classification

Automatically classifies potential vulnerabilities:

**Supported Vulnerability Types:**
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Information Disclosure
- Authentication Bypass
- Command Injection

**Detection Methods:**
- Machine Learning: Random Forest classifier
- Rule-based: Pattern matching and signature detection

**Example Output:**
```
🎯 Vulnerability Classification
  Type: sql_injection
  Confidence: 0.92
  Method: ml_vulnerability_classification
```

### 3. Risk Scoring

Calculates comprehensive risk scores:

**Risk Factors:**
- Endpoint complexity
- Parameter count
- Authentication requirements
- Data sensitivity
- Security patterns

**Risk Levels:**
- Critical (0.8-1.0)
- High (0.6-0.8)
- Medium (0.4-0.6)
- Low (0.2-0.4)
- Minimal (0.0-0.2)

**Example Output:**
```
📊 Risk Assessment
  Risk Score: 0.73
  Risk Level: High
  Breakdown:
    endpoint_complexity: 0.9
    parameter_count: 1.0
    authentication: 0.2
    data_sensitivity: 1.0
```

### 4. Intelligent Fuzzing

Suggests targeted fuzzing approaches:

**Fuzzing Types:**
- Query parameter fuzzing
- JSON field fuzzing
- Header injection
- Method override

**Example Output:**
```
💡 Fuzzing Suggestions
  Type: query_parameter_fuzzing
  Confidence: 0.8
  Description: Fuzz query parameters with malicious payloads
  Payloads: ../etc/passwd, admin, test, null, undefined
```

## CLI Options

### AI Detection Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ai-detection` | Enable AI-powered detection | `true` |
| `--no-ai-detection` | Disable AI-powered detection | `false` |
| `--ai-anomaly-detection` | Enable anomaly detection | `true` |
| `--no-ai-anomaly-detection` | Disable anomaly detection | `false` |
| `--ai-vulnerability-classification` | Enable vulnerability classification | `true` |
| `--no-ai-vulnerability-classification` | Disable vulnerability classification | `false` |
| `--ai-risk-scoring` | Enable risk scoring | `true` |
| `--no-ai-risk-scoring` | Disable risk scoring | `false` |
| `--ai-intelligent-fuzzing` | Enable intelligent fuzzing | `true` |
| `--no-ai-intelligent-fuzzing` | Disable intelligent fuzzing | `false` |
| `--ai-learning` | Enable learning from results | `true` |
| `--no-ai-learning` | Disable learning from results | `false` |

## Environment Variables

### AI Detection Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AI_DETECTION_ENABLED` | Enable/disable AI detection | `true` |
| `AI_ANOMALY_DETECTION_ENABLED` | Enable/disable anomaly detection | `true` |
| `AI_VULNERABILITY_CLASSIFICATION_ENABLED` | Enable/disable vulnerability classification | `true` |
| `AI_RISK_SCORING_ENABLED` | Enable/disable risk scoring | `true` |
| `AI_INTELLIGENT_FUZZING_ENABLED` | Enable/disable intelligent fuzzing | `true` |
| `AI_LEARNING_ENABLED` | Enable/disable learning | `true` |
| `AI_MODEL_STORAGE_PATH` | Path for storing ML models | `models` |

## Examples

### Example 1: Basic AI Detection

```bash
# Scan with all AI features enabled
python main.py scan -f postman_collection.json --ai-detection
```

**Output:**
```
🤖 AI-Powered Detection Results:
  Anomalies Found: 3
  Vulnerabilities Classified: 5
  High Risk Requests: 2
  Fuzzing Suggestions: 8
```

### Example 2: Selective AI Features

```bash
# Only anomaly detection and risk scoring
python main.py scan -f openapi_spec.yaml \
  --ai-anomaly-detection \
  --ai-risk-scoring \
  --no-ai-vulnerability-classification \
  --no-ai-intelligent-fuzzing
```

### Example 3: AI with Custom Plugins

```bash
# AI detection with JWT and GraphQL plugins
python main.py scan -f collection.json \
  --ai-detection \
  --plugins AISecurityChecker,JWTSecurityChecker,GraphQLSecurityChecker
```

### Example 4: Environment Configuration

```bash
# Set environment variables
export AI_DETECTION_ENABLED=true
export AI_ANOMALY_DETECTION_ENABLED=true
export AI_VULNERABILITY_CLASSIFICATION_ENABLED=false
export AI_RISK_SCORING_ENABLED=true

# Run scan
python main.py scan -f collection.json
```

## Troubleshooting

### Common Issues

#### 1. ML Libraries Not Available

**Error:** `ML libraries not available. AI detection will use rule-based fallback.`

**Solution:**
```bash
pip install scikit-learn joblib numpy
```

#### 2. Model Loading Errors

**Error:** `Could not load existing models`

**Solution:**
- Check if the models directory exists and is writable
- Delete corrupted model files to force regeneration
- Ensure sufficient disk space

#### 3. Low Detection Accuracy

**Symptoms:** Few or no vulnerabilities detected

**Solutions:**
- Lower confidence thresholds in configuration
- Enable learning to improve models over time
- Check if rule-based fallback is working
- Verify input data quality

#### 4. Performance Issues

**Symptoms:** Slow scanning with AI enabled

**Solutions:**
- Disable unused AI features
- Reduce model complexity
- Use rule-based fallback for large datasets
- Increase system resources

### Debug Mode

Enable debug logging for AI detection:

```bash
python main.py scan -f collection.json --ai-detection -vv
```

### Model Status Check

Check AI model status:

```python
from api_security_scanner.core.ai_detector import AIDetector

detector = AIDetector()
status = detector.get_model_status()
print(f"ML Available: {status['ml_available']}")
print(f"Models Loaded: {status['models_loaded']}")
print(f"Training Data: {status['training_data']}")
```

## Advanced Configuration

### Custom Model Parameters

```python
# Custom AI detector configuration
config = {
    'enabled': True,
    'models': {
        'anomaly_detection': {
            'enabled': True,
            'threshold': 0.6,  # Lower threshold for more sensitive detection
            'contamination': 0.05  # Lower contamination for fewer false positives
        },
        'vulnerability_classification': {
            'enabled': True,
            'threshold': 0.7,  # Lower threshold for more classifications
            'min_samples': 5   # Lower minimum samples
        },
        'risk_scoring': {
            'enabled': True,
            'weights': {
                'endpoint_complexity': 0.4,  # Increase weight
                'parameter_count': 0.1,      # Decrease weight
                'authentication': 0.3,
                'data_sensitivity': 0.2
            }
        }
    },
    'learning': {
        'enabled': True,
        'auto_retrain': True,
        'retrain_interval': 50,  # Retrain more frequently
        'min_training_samples': 25  # Lower minimum samples
    }
}
```

### Custom Feature Extraction

Extend the AI detector with custom features:

```python
from api_security_scanner.core.ai_detector import AIDetector

class CustomAIDetector(AIDetector):
    def extract_features(self, request):
        features = super().extract_features(request)
        
        # Add custom features
        features['custom_pattern'] = self._detect_custom_pattern(request)
        features['business_logic_risk'] = self._assess_business_logic(request)
        
        return features
    
    def _detect_custom_pattern(self, request):
        # Custom pattern detection logic
        return 1 if 'custom_pattern' in request.get('body', '') else 0
    
    def _assess_business_logic(self, request):
        # Business logic risk assessment
        return 0.5  # Example risk score
```

### Integration with Custom Plugins

```python
from api_security_scanner.plugins.ai_security_checker import AISecurityChecker

class CustomAISecurityChecker(AISecurityChecker):
    def __init__(self, zap=None, target=None):
        super().__init__(zap, target)
        self.custom_config = self._load_custom_config()
    
    def _load_custom_config(self):
        # Load custom configuration
        return {
            'custom_thresholds': {
                'sql_injection': 0.9,
                'xss': 0.8,
                'path_traversal': 0.95
            }
        }
    
    def _classify_vulnerabilities(self, requests_data):
        vulnerabilities = super()._classify_vulnerabilities(requests_data)
        
        # Apply custom thresholds
        for vuln in vulnerabilities:
            if vuln.name in self.custom_config['custom_thresholds']:
                threshold = self.custom_config['custom_thresholds'][vuln.name]
                if vuln.cvss_score < threshold:
                    vulnerabilities.remove(vuln)
        
        return vulnerabilities
```

## Best Practices

### 1. Configuration Management

- Use environment variables for production deployments
- Keep configuration files in version control
- Document custom configurations
- Test configurations in development first

### 2. Performance Optimization

- Enable only needed AI features
- Use appropriate confidence thresholds
- Monitor system resources during scanning
- Consider rule-based fallback for large datasets

### 3. Model Management

- Regularly backup trained models
- Monitor model performance over time
- Retrain models with new data
- Clean up old model files

### 4. Security Considerations

- Validate AI detection results
- Use AI as supplement, not replacement for manual testing
- Review and verify high-confidence detections
- Keep ML models updated

## Support

For issues, questions, or contributions related to AI detection:

1. Check the troubleshooting section above
2. Review the test files for usage examples
3. Run the demo scripts to verify functionality
4. Check the GitHub issues for known problems
5. Create a new issue with detailed information

## Changelog

### Version 1.0.0
- Initial AI detection implementation
- Anomaly detection with ML and rule-based methods
- Vulnerability classification for common attack types
- Risk scoring with configurable weights
- Intelligent fuzzing suggestions
- Learning capabilities with model persistence
- Full CLI and environment variable support
- Comprehensive test suite
- Demo scripts and documentation
