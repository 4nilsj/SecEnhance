# AI Detection API Reference

## Overview

This document provides comprehensive API reference for the AI detection system components.

## Table of Contents

- [AIDetector Class](#aidetector-class)
- [AISecurityChecker Plugin](#aisecuritychecker-plugin)
- [Configuration Classes](#configuration-classes)
- [Data Classes](#data-classes)
- [Utility Functions](#utility-functions)

## AIDetector Class

### Class Definition

```python
class AIDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None)
```

### Constructor Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `config` | `Optional[Dict[str, Any]]` | Configuration dictionary | `None` |

### Methods

#### `extract_features(request: Dict[str, Any]) -> Dict[str, Any]`

Extracts features from an API request for ML analysis.

**Parameters:**
- `request`: Dictionary containing request data

**Returns:**
- Dictionary of extracted features

**Example:**
```python
detector = AIDetector()
features = detector.extract_features({
    'url': 'https://api.example.com/users?id=1',
    'method': 'GET',
    'headers': {'Authorization': 'Bearer token'},
    'body': '{"name": "test"}'
})
```

#### `detect_anomalies(requests_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]`

Detects anomalies in API requests using ML models.

**Parameters:**
- `requests_data`: List of request dictionaries

**Returns:**
- List of anomaly detection results

**Example:**
```python
anomalies = detector.detect_anomalies(requests_data)
for anomaly in anomalies:
    print(f"Anomaly Score: {anomaly['score']}")
    print(f"Confidence: {anomaly['confidence']}")
```

#### `classify_vulnerabilities(requests_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]`

Classifies potential vulnerabilities in API requests.

**Parameters:**
- `requests_data`: List of request dictionaries

**Returns:**
- List of vulnerability classifications

**Example:**
```python
vulnerabilities = detector.classify_vulnerabilities(requests_data)
for vuln in vulnerabilities:
    print(f"Type: {vuln['type']}")
    print(f"Confidence: {vuln['confidence']}")
```

#### `calculate_risk_scores(requests_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]`

Calculates risk scores for API requests.

**Parameters:**
- `requests_data`: List of request dictionaries

**Returns:**
- List of risk assessment results

**Example:**
```python
risks = detector.calculate_risk_scores(requests_data)
for risk in risks:
    print(f"Risk Score: {risk['score']}")
    print(f"Risk Level: {risk['level']}")
```

#### `generate_fuzzing_suggestions(requests_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]`

Generates intelligent fuzzing suggestions for API requests.

**Parameters:**
- `requests_data`: List of request dictionaries

**Returns:**
- List of fuzzing suggestions

**Example:**
```python
suggestions = detector.generate_fuzzing_suggestions(requests_data)
for suggestion in suggestions:
    print(f"Type: {suggestion['type']}")
    print(f"Payloads: {suggestion['payloads']}")
```

#### `learn_from_results(requests_data: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]]) -> bool`

Learns from scan results to improve future detection.

**Parameters:**
- `requests_data`: List of request dictionaries
- `vulnerabilities`: List of detected vulnerabilities

**Returns:**
- Boolean indicating success

**Example:**
```python
success = detector.learn_from_results(requests_data, vulnerabilities)
if success:
    print("Learning completed successfully")
```

#### `get_model_status() -> Dict[str, Any]`

Returns the current status of ML models.

**Returns:**
- Dictionary containing model status information

**Example:**
```python
status = detector.get_model_status()
print(f"ML Available: {status['ml_available']}")
print(f"Models Loaded: {status['models_loaded']}")
```

#### `save_models() -> bool`

Saves trained models to disk.

**Returns:**
- Boolean indicating success

**Example:**
```python
success = detector.save_models()
if success:
    print("Models saved successfully")
```

#### `load_models() -> bool`

Loads trained models from disk.

**Returns:**
- Boolean indicating success

**Example:**
```python
success = detector.load_models()
if success:
    print("Models loaded successfully")
```

## AISecurityChecker Plugin

### Class Definition

```python
class AISecurityChecker(BasePlugin):
    def __init__(self, zap=None, target=None)
```

### Constructor Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `zap` | `Optional[ZAP]` | ZAP instance | `None` |
| `target` | `Optional[str]` | Target URL | `None` |

### Methods

#### `configure(config: Dict[str, Any]) -> None`

Configures the plugin with AI detection settings.

**Parameters:**
- `config`: Configuration dictionary

**Example:**
```python
plugin = AISecurityChecker()
config = {
    'enabled': True,
    'models': {
        'anomaly_detection': {'enabled': True},
        'vulnerability_classification': {'enabled': True}
    }
}
plugin.configure(config)
```

#### `check(target_url: str, requests_data: List[Dict[str, Any]], auth_headers: Optional[Dict[str, str]] = None) -> PluginResult`

Performs AI-powered security checks on API requests.

**Parameters:**
- `target_url`: Target URL for scanning
- `requests_data`: List of request dictionaries
- `auth_headers`: Optional authentication headers

**Returns:**
- PluginResult containing detected vulnerabilities

**Example:**
```python
result = plugin.check(
    target_url="https://api.example.com",
    requests_data=requests_data,
    auth_headers={"Authorization": "Bearer token"}
)
print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
```

#### `should_activate(requests_data: List[Dict[str, Any]]) -> bool`

Determines if the plugin should be activated for the given requests.

**Parameters:**
- `requests_data`: List of request dictionaries

**Returns:**
- Boolean indicating if plugin should activate

**Example:**
```python
should_activate = plugin.should_activate(requests_data)
if should_activate:
    print("AI Security Checker will be activated")
```

#### `generate_poc(vulnerability_id: str) -> Optional[ProofOfConcept]`

Generates proof of concept for a vulnerability.

**Parameters:**
- `vulnerability_id`: ID of the vulnerability

**Returns:**
- ProofOfConcept object or None

**Example:**
```python
poc = plugin.generate_poc("vuln_123")
if poc:
    print(f"POC generated: {poc.evidence_description}")
```

## Configuration Classes

### AIDetectionConfig

```python
@dataclass
class AIDetectionConfig:
    enabled: bool = True
    models: Dict[str, Any] = field(default_factory=lambda: {
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
    })
    learning: Dict[str, Any] = field(default_factory=lambda: {
        'enabled': True,
        'auto_retrain': True,
        'retrain_interval': 100,
        'min_training_samples': 50
    })
    fallback_to_rules: bool = True
    model_storage_path: str = "models"
```

### Configuration Fields

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `enabled` | `bool` | Enable AI detection | `True` |
| `models` | `Dict[str, Any]` | Model configurations | See above |
| `learning` | `Dict[str, Any]` | Learning configurations | See above |
| `fallback_to_rules` | `bool` | Use rule-based fallback | `True` |
| `model_storage_path` | `str` | Path for model storage | `"models"` |

## Data Classes

### Vulnerability

```python
@dataclass
class Vulnerability:
    id: str
    name: str
    description: str
    risk: str
    cvss_score: float
    solution: str
    references: List[str]
    cwe_id: Optional[str]
    wasc_id: Optional[str]
    request: Optional[Dict[str, Any]]
    response: Optional[Dict[str, Any]]
    url: Optional[str]
    parameter: Optional[str]
    evidence: Optional[str]
    scan_id: Optional[str]
    timestamp: Optional[datetime]
```

### ProofOfConcept

```python
@dataclass
class ProofOfConcept:
    vulnerability_id: str
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    timestamp: datetime
    evidence_description: str
```

### PluginResult

```python
@dataclass
class PluginResult:
    plugin_name: str
    vulnerabilities: List[Vulnerability]
    execution_time: float
    success: bool
    error_message: Optional[str]
    metadata: Dict[str, Any]
```

## Utility Functions

### Feature Extraction Utilities

#### `_extract_url_features(request: Dict[str, Any]) -> Dict[str, Any]`

Extracts URL-related features from a request.

**Parameters:**
- `request`: Request dictionary

**Returns:**
- Dictionary of URL features

#### `_extract_method_features(request: Dict[str, Any]) -> Dict[str, Any]`

Extracts HTTP method-related features from a request.

**Parameters:**
- `request`: Request dictionary

**Returns:**
- Dictionary of method features

#### `_extract_header_features(request: Dict[str, Any]) -> Dict[str, Any]`

Extracts header-related features from a request.

**Parameters:**
- `request`: Request dictionary

**Returns:**
- Dictionary of header features

#### `_extract_body_features(request: Dict[str, Any]) -> Dict[str, Any]`

Extracts body-related features from a request.

**Parameters:**
- `request`: Request dictionary

**Returns:**
- Dictionary of body features

#### `_extract_security_features(request: Dict[str, Any]) -> Dict[str, Any]`

Extracts security-related features from a request.

**Parameters:**
- `request`: Request dictionary

**Returns:**
- Dictionary of security features

### Pattern Detection Utilities

#### `_detect_sql_patterns(text: str) -> bool`

Detects SQL injection patterns in text.

**Parameters:**
- `text`: Text to analyze

**Returns:**
- Boolean indicating SQL injection patterns

#### `_detect_xss_patterns(text: str) -> bool`

Detects XSS patterns in text.

**Parameters:**
- `text`: Text to analyze

**Returns:**
- Boolean indicating XSS patterns

#### `_detect_path_traversal_patterns(text: str) -> bool`

Detects path traversal patterns in text.

**Parameters:**
- `text`: Text to analyze

**Returns:**
- Boolean indicating path traversal patterns

#### `_detect_command_injection_patterns(text: str) -> bool`

Detects command injection patterns in text.

**Parameters:**
- `text`: Text to analyze

**Returns:**
- Boolean indicating command injection patterns

### Risk Assessment Utilities

#### `_calculate_endpoint_complexity(url: str) -> float`

Calculates endpoint complexity score.

**Parameters:**
- `url`: URL to analyze

**Returns:**
- Complexity score (0-1)

#### `_assess_authentication_risk(headers: Dict[str, str]) -> float`

Assesses authentication-related risk.

**Parameters:**
- `headers`: Request headers

**Returns:**
- Authentication risk score (0-1)

#### `_evaluate_data_sensitivity(body: str, headers: Dict[str, str]) -> float`

Evaluates data sensitivity risk.

**Parameters:**
- `body`: Request body
- `headers`: Request headers

**Returns:**
- Data sensitivity score (0-1)

## Error Handling

### Common Exceptions

#### `AIDetectionError`

Base exception for AI detection errors.

```python
class AIDetectionError(Exception):
    pass
```

#### `ModelLoadError`

Raised when ML models fail to load.

```python
class ModelLoadError(AIDetectionError):
    pass
```

#### `FeatureExtractionError`

Raised when feature extraction fails.

```python
class FeatureExtractionError(AIDetectionError):
    pass
```

#### `ConfigurationError`

Raised when configuration is invalid.

```python
class ConfigurationError(AIDetectionError):
    pass
```

### Error Handling Examples

```python
try:
    detector = AIDetector(config)
    features = detector.extract_features(request)
except ConfigurationError as e:
    print(f"Configuration error: {e}")
except FeatureExtractionError as e:
    print(f"Feature extraction error: {e}")
except AIDetectionError as e:
    print(f"AI detection error: {e}")
```

## Performance Considerations

### Memory Usage

- Models are loaded once and reused
- Feature vectors are cached when possible
- Large datasets are processed in batches

### Processing Time

- Feature extraction is optimized for speed
- ML models use efficient algorithms
- Parallel processing for independent operations

### Scalability

- Models can be trained on large datasets
- Batch processing for multiple requests
- Streaming processing for very large datasets

## Best Practices

### Configuration

- Use environment variables for production
- Keep configuration files in version control
- Test configurations in development first

### Error Handling

- Always handle exceptions gracefully
- Log errors for debugging
- Provide fallback mechanisms

### Performance

- Monitor memory usage
- Use appropriate batch sizes
- Consider rule-based fallback for large datasets

### Security

- Validate input data
- Sanitize feature vectors
- Secure model storage

## Examples

### Basic Usage

```python
from api_security_scanner.core.ai_detector import AIDetector

# Initialize detector
detector = AIDetector()

# Extract features
features = detector.extract_features(request)

# Detect anomalies
anomalies = detector.detect_anomalies([request])

# Classify vulnerabilities
vulnerabilities = detector.classify_vulnerabilities([request])

# Calculate risk scores
risks = detector.calculate_risk_scores([request])
```

### Advanced Usage

```python
from api_security_scanner.plugins.ai_security_checker import AISecurityChecker

# Initialize plugin
plugin = AISecurityChecker()

# Configure plugin
config = {
    'enabled': True,
    'models': {
        'anomaly_detection': {'enabled': True, 'threshold': 0.6},
        'vulnerability_classification': {'enabled': True, 'threshold': 0.7}
    }
}
plugin.configure(config)

# Perform security check
result = plugin.check(target_url, requests_data)

# Process results
for vulnerability in result.vulnerabilities:
    print(f"Vulnerability: {vulnerability.name}")
    print(f"Risk: {vulnerability.risk}")
    print(f"CVSS Score: {vulnerability.cvss_score}")
```

### Custom Configuration

```python
# Custom AI detector configuration
config = {
    'enabled': True,
    'models': {
        'anomaly_detection': {
            'enabled': True,
            'threshold': 0.5,  # Lower threshold for more sensitive detection
            'contamination': 0.05  # Lower contamination for fewer false positives
        },
        'vulnerability_classification': {
            'enabled': True,
            'threshold': 0.6,  # Lower threshold for more classifications
            'min_samples': 5   # Lower minimum samples
        }
    },
    'learning': {
        'enabled': True,
        'auto_retrain': True,
        'retrain_interval': 50,  # Retrain more frequently
        'min_training_samples': 25  # Lower minimum samples
    }
}

detector = AIDetector(config)
```

## Support

For additional help:

- Check the [AI Detection Guide](AI_DETECTION_GUIDE.md) for user documentation
- Review the [AI Detection Architecture](AI_DETECTION_ARCHITECTURE.md) for technical details
- Run the test suite: `python -m pytest tests/test_ai_detection.py`
- Try the demo scripts: `python test_ai_detection_demo_simple.py`
