# Examples

This directory contains example files for testing the API Security Scanner.

## Files

### sample_postman_collection.json
A sample Postman Collection v2.1 with various API endpoints including:
- User management endpoints (GET, POST)
- Authentication endpoint
- Proper headers and request bodies

### sample_openapi.yaml
A sample OpenAPI 3.0 specification with:
- User management API
- Authentication endpoints
- Proper schemas and security definitions
- Multiple servers (production and staging)

## Usage Examples

### Test with Postman Collection
```bash
python main.py scan -f examples/sample_postman_collection.json
```

### Test with OpenAPI Spec
```bash
python main.py scan -f examples/sample_openapi.yaml
```

### Test with Authentication
```bash
python main.py scan -f examples/sample_postman_collection.json \
  --auth-type header --auth-name "X-API-Key" --auth-value "test-key-123"
```

### Test with Custom Plugins Only
```bash
python main.py scan -f examples/sample_postman_collection.json --no-zap
```

### Generate Reports
```bash
python main.py scan -f examples/sample_postman_collection.json \
  --export reports/sample-scan.html \
  --export-json reports/sample-scan.json \
  --performance-stats
```

## Creating Your Own Examples

### Postman Collection
1. Export your Postman collection as JSON (v2.1 format)
2. Place it in this directory
3. Use the `-f` flag to scan it

### OpenAPI Specification
1. Create or export your OpenAPI spec as YAML or JSON
2. Place it in this directory
3. Use the `-f` flag to scan it

### Curl Commands
You can test individual curl commands directly:
```bash
python main.py scan -u "curl -X GET https://api.example.com/users"
```

## Notes

- The example files use placeholder URLs (`https://api.example.com`)
- Replace with actual API endpoints for real testing
- Ensure you have proper authentication credentials for protected endpoints
- The scanner will attempt to make actual HTTP requests to the specified URLs
