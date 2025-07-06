# JWT Security Tester — Reports Guide

## Report Types
- **HTML**: Colorful, detailed, easy to read
- **JSON**: For automation/integration

## Location
- Saved in `reports/` by default
- Filename can be set with `--output <file>`

## HTML Report Structure
- **Header**: Title, date, summary
- **Token Details**: Header, payload, signature, claims
- **Vulnerabilities**: List with severity, description, and reproduction steps
- **Summary Cards**: Risk level, counts by severity
- **Batch Mode**: Includes stats and per-token results

## JSON Report Structure
- Mirrors the internal results structure
- Includes all test results, vulnerabilities, and summary

## Example: HTML Report
- Open in browser for full color and collapsible sections

## Example: JSON Report
```json
{
  "batch_report": {
    "title": "JWT Security Batch Analysis",
    "generated_date": "2024-07-06T10:00:00",
    "tokens_tested": 10,
    "invalid_tokens": 2,
    "results": [ ... ],
    "errors": [ ... ]
  }
}
```

## Interpreting Results
- **Critical**: Immediate action required
- **High**: Serious risk, fix soon
- **Medium**: Should be addressed
- **Low**: Informational

## Customization
- Edit `config/default_config.json` to change report options

## More
- See [../README.md](../README.md) for overview
- See [USAGE.md](USAGE.md) for CLI usage
- See [API_REFERENCE.md](API_REFERENCE.md) for API usage 