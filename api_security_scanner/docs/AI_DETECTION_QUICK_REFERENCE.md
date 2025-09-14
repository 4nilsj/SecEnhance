# AI Detection Quick Reference

## Quick Start

### Enable AI Detection
```bash
python main.py scan -f collection.json --ai-detection
```

### Disable AI Detection
```bash
python main.py scan -f collection.json --no-ai-detection
```

### Run Only AI Plugin
```bash
python main.py scan -f collection.json --plugins AISecurityChecker
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--ai-detection` | Enable AI detection (default) |
| `--no-ai-detection` | Disable AI detection |
| `--ai-anomaly-detection` | Enable anomaly detection |
| `--no-ai-anomaly-detection` | Disable anomaly detection |
| `--ai-vulnerability-classification` | Enable vulnerability classification |
| `--no-ai-vulnerability-classification` | Disable vulnerability classification |
| `--ai-risk-scoring` | Enable risk scoring |
| `--no-ai-risk-scoring` | Disable risk scoring |
| `--ai-intelligent-fuzzing` | Enable intelligent fuzzing |
| `--no-ai-intelligent-fuzzing` | Disable intelligent fuzzing |
| `--ai-learning` | Enable learning from results |
| `--no-ai-learning` | Disable learning |

## Environment Variables

```bash
export AI_DETECTION_ENABLED=true
export AI_ANOMALY_DETECTION_ENABLED=true
export AI_VULNERABILITY_CLASSIFICATION_ENABLED=true
export AI_RISK_SCORING_ENABLED=true
export AI_INTELLIGENT_FUZZING_ENABLED=true
export AI_LEARNING_ENABLED=true
export AI_MODEL_STORAGE_PATH=/path/to/models
```

## Common Use Cases

### 1. Basic AI Detection
```bash
python main.py scan -f collection.json
```

### 2. Anomaly Detection Only
```bash
python main.py scan -f collection.json \
  --ai-anomaly-detection \
  --no-ai-vulnerability-classification \
  --no-ai-risk-scoring \
  --no-ai-intelligent-fuzzing
```

### 3. High-Sensitivity Detection
```bash
python main.py scan -f collection.json \
  --ai-detection \
  --ai-anomaly-detection \
  --ai-vulnerability-classification \
  --ai-risk-scoring
```

### 4. AI with Other Plugins
```bash
python main.py scan -f collection.json \
  --ai-detection \
  --plugins AISecurityChecker,JWTSecurityChecker,GraphQLSecurityChecker
```

## Configuration Examples

### Minimal Configuration
```yaml
ai_detection:
  enabled: true
  fallback_to_rules: true
```

### Full Configuration
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

## Detection Types

### Anomaly Detection
- **Purpose**: Find unusual patterns
- **Output**: Anomaly scores and reasons
- **Example**: Unusually long URLs, excessive parameters

### Vulnerability Classification
- **Purpose**: Classify attack types
- **Output**: Vulnerability types and confidence
- **Example**: SQL injection, XSS, path traversal

### Risk Scoring
- **Purpose**: Calculate risk levels
- **Output**: Risk scores (0-1) and levels
- **Example**: Critical, High, Medium, Low, Minimal

### Intelligent Fuzzing
- **Purpose**: Suggest test payloads
- **Output**: Fuzzing suggestions and payloads
- **Example**: Query parameter fuzzing, JSON field fuzzing

## Troubleshooting

### ML Libraries Not Available
```bash
pip install scikit-learn joblib numpy
```

### Check AI Status
```python
from api_security_scanner.core.ai_detector import AIDetector
detector = AIDetector()
print(f"ML Available: {detector.ml_available}")
```

### Debug Mode
```bash
python main.py scan -f collection.json --ai-detection -vv
```

### Model Status
```python
status = detector.get_model_status()
print(f"Models: {status['models_loaded']}")
print(f"Training Data: {status['training_data']}")
```

## Performance Tips

### For Large Datasets
- Use `--no-ai-learning` to disable learning
- Enable only needed features
- Use rule-based fallback

### For High Accuracy
- Enable learning with `--ai-learning`
- Lower confidence thresholds
- Use all detection types

### For Fast Scanning
- Disable unused features
- Use `--no-ai-intelligent-fuzzing`
- Consider rule-based fallback

## Output Examples

### Anomaly Detection
```
🚨 Anomaly Detected
  Score: 0.85
  Confidence: 0.85
  Reasons: Unusually long URL, High number of query parameters
```

### Vulnerability Classification
```
🎯 Vulnerability Classification
  Type: sql_injection
  Confidence: 0.92
  Method: ml_vulnerability_classification
```

### Risk Assessment
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

### Fuzzing Suggestions
```
💡 Fuzzing Suggestions
  Type: query_parameter_fuzzing
  Confidence: 0.8
  Payloads: ../etc/passwd, admin, test, null, undefined
```

## Best Practices

1. **Start Simple**: Begin with default settings
2. **Monitor Performance**: Watch system resources
3. **Validate Results**: Review AI detections
4. **Use Learning**: Enable learning for improvement
5. **Backup Models**: Keep model backups
6. **Test Configurations**: Test in development first

## Support

- **Documentation**: See `AI_DETECTION_GUIDE.md`
- **Architecture**: See `AI_DETECTION_ARCHITECTURE.md`
- **Tests**: Run `python -m pytest tests/test_ai_detection.py`
- **Demo**: Run `python test_ai_detection_demo_simple.py`
- **Issues**: Check GitHub issues for known problems
