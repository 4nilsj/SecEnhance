# JWT Security Tester — API Reference

## Overview
The REST API allows programmatic analysis of JWTs. Powered by Flask, supports CORS.

## Running the API
```
python src/jwt_api.py
```

## Endpoints

### `GET /status`
- **Description:** Health check
- **Response:** `{ "status": "ok" }`

### `POST /analyze`
- **Description:** Analyze a JWT
- **Request:**
  ```json
  { "token": "<jwt>" }
  ```
- **Response:**
  ```json
  {
    "results": { ... },
    "summary": { ... }
  }
  ```
- **Errors:** Returns `{ "error": "..." }` on failure

### `POST /analyze-batch` *(if implemented)*
- **Description:** Analyze multiple JWTs
- **Request:**
  ```json
  { "tokens": ["jwt1", "jwt2", ...] }
  ```
- **Response:**
  ```json
  { "results": [ ... ] }
  ```

## Example: Analyze a Token
```
curl -X POST http://localhost:5000/analyze -H "Content-Type: application/json" -d '{"token": "<jwt>"}'
```

## CORS
- Enabled by default for all origins

## More
- See [../README.md](../README.md) for overview
- See [USAGE.md](USAGE.md) for CLI usage
- See [CONFIGURATION.md](CONFIGURATION.md) for config details 