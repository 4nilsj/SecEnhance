# JWT Security Tester — Configuration Guide

## Default Config File
- Location: `config/default_config.json`
- Structure:
```json
{
  "defaults": {
    "debug": false,
    "output_format": "html",
    "max_attempts": 1000,
    "workers": 4,
    "timeout": 30
  },
  "api": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false,
    "cors_enabled": true
  },
  "testing": {
    "enable_cve_tests": true,
    "enable_dictionary_attack": true,
    "enable_claim_fuzzing": true,
    "enable_timestamp_tampering": true,
    "enable_jwks_validation": true
  },
  "reporting": {
    "include_poc": false,
    "include_reproduction_steps": true,
    "color_output": true,
    "progress_bars": true,
    "save_reports": true,
    "reports_directory": "reports"
  },
  "security": {
    "common_secrets_file": "config/common_secrets.txt",
    "max_token_size": 8192,
    "allowed_algorithms": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
    "forbidden_algorithms": ["none"]
  }
}
```

## Overriding Config

- **CLI flags** (highest priority):
  - `--max-attempts`, `--workers`, `--debug`, etc.
- **Environment variables** (medium priority):
  - `JWT_DEBUG`, `JWT_MAX_ATTEMPTS`, `JWT_API_PORT`, etc.
- **Config file** (lowest priority):
  - Edit `config/default_config.json` or use `--config <file>`

## Environment Variables
- `JWT_DEBUG=true`
- `JWT_MAX_ATTEMPTS=2000`
- `JWT_API_PORT=9000`
- ...and more (see code for full list)

## Secrets File
- Location: `config/common_secrets.txt`
- Used for dictionary attacks
- One secret per line

## Example: Custom Config
```sh
python src/jwt_security_tester.py --config my_config.json --token "<jwt>"
```

## Example: Environment Override
```sh
set JWT_DEBUG=true
python src/jwt_security_tester.py --token "<jwt>"
```

## More
- See [../README.md](../README.md) for overview
- See [USAGE.md](USAGE.md) for CLI usage
- See [API_REFERENCE.md](API_REFERENCE.md) for API usage 