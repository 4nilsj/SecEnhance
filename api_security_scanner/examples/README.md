# API Collection Examples

This directory contains example API collection files for testing the API Security Scanner.

## Available Collections

### Postman Collections

#### `sample_postman_collection.json`
Basic Postman collection demonstrating:
- User management endpoints (GET, POST)
- Authentication endpoints
- Variable usage (`{{base_url}}`)
- Different HTTP methods and headers

#### `test_collection.json`
Comprehensive Postman collection featuring:
- Public endpoints (health check, public data)
- User management (registration, login, profile)
- Admin endpoints (user administration)
- File operations (upload, download)
- Various authentication methods
- Complex request bodies and parameters

### OpenAPI Specifications

#### `sample_openapi.yaml`
Basic OpenAPI 3.0 specification with:
- User management operations
- Authentication endpoints
- Request/response schemas
- Security schemes (Bearer, API Key)

#### `test_openapi.yaml`
Comprehensive OpenAPI specification including:
- System endpoints (health check)
- Public API endpoints
- User registration and authentication
- Profile management
- Admin operations
- File upload/download
- Complete schema definitions
- Security configurations

## Usage Examples

### Test with Postman Collection
```bash
python -m api_security_scanner.cli.main scan --file examples/sample_postman_collection.json
```

### Test with OpenAPI Specification
```bash
python -m api_security_scanner.cli.main scan --file examples/sample_openapi.yaml
```

### Test with Authentication
```bash
python -m api_security_scanner.cli.main scan \
  --file examples/test_collection.json \
  --auth-type header \
  --auth-name Authorization \
  --auth-value "Bearer your-token-here"
```

### Run Demo Script
```bash
python demo_api_collections.py
```

## Collection Features

### Security Testing Scenarios

These collections are designed to test various security aspects:

1. **Authentication Testing**
   - Bearer token validation
   - API key authentication
   - Session management
   - Authorization levels

2. **Input Validation**
   - JSON payload validation
   - Parameter injection testing
   - File upload security
   - Query parameter handling

3. **Authorization Testing**
   - Role-based access control
   - Admin privilege escalation
   - Resource access control
   - Permission validation

4. **Data Security**
   - Sensitive data exposure
   - Information disclosure
   - Data validation
   - Error handling

### Endpoint Categories

- **Public Endpoints**: No authentication required
- **User Endpoints**: Basic user authentication
- **Admin Endpoints**: Administrative privileges required
- **File Operations**: File upload/download security
- **System Endpoints**: Health checks and monitoring

## Customization

### Modifying Collections

To test against your own APIs:

1. **Update URLs**: Replace placeholder URLs with your actual endpoints
2. **Add Authentication**: Include proper authentication headers/tokens
3. **Customize Requests**: Modify request bodies and parameters
4. **Add Endpoints**: Include additional endpoints specific to your API

### Variable Substitution

Collections use variables for flexibility:

- `{{base_url}}`: Base API URL
- `{{auth_token}}`: Authentication token
- `{{admin_token}}`: Admin authentication token
- `{{user_id}}`: User identifier
- `{{file_id}}`: File identifier

## Security Considerations

### Testing Environment

- Use test/staging environments for security scanning
- Avoid scanning production systems without proper authorization
- Ensure test data doesn't contain sensitive information
- Use appropriate authentication tokens for testing

### Collection Security

- Remove sensitive data from collections before sharing
- Use environment variables for authentication tokens
- Regularly update test credentials
- Validate collection integrity before scanning

## Troubleshooting

### Common Issues

1. **DNS Resolution**: Ensure target URLs are accessible
2. **Authentication**: Verify tokens and credentials are valid
3. **Collection Format**: Check JSON/YAML syntax validity
4. **Network Access**: Confirm firewall and network connectivity

### Debug Mode

Enable verbose output for troubleshooting:

```bash
python -m api_security_scanner.cli.main scan \
  --file examples/sample_postman_collection.json \
  -vv
```

## Contributing

To add new example collections:

1. Follow the existing naming convention
2. Include comprehensive endpoint coverage
3. Add proper documentation
4. Test with the scanner before submitting
5. Update this README with collection details

## Support

For issues with these example collections or the scanner:

1. Check the main project documentation
2. Review the API Collection Testing Guide
3. Run the demo scripts for reference
4. Create an issue in the project repository