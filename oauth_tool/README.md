# OAuth/OIDC Security Testing Tool

A comprehensive CLI and interactive tool for analyzing and testing OAuth 2.0 and OpenID Connect (OIDC) flows for security vulnerabilities and misconfigurations.

## Features

- **Discovery & Metadata Analysis**: Fetch and analyze .well-known/openid-configuration and JWKS endpoints.
- **Authorization Flow Simulation**: Simulate Authorization Code, Implicit, Hybrid, and PKCE flows.
- **Token Handling**: Request, decode, and validate access, ID, and refresh tokens.
- **Vulnerability Checks**: Detect common OAuth/OIDC attacks and misconfigurations.
- **Fuzzing & Manipulation**: Fuzz and manipulate parameters and tokens.
- **Reporting**: Generate detailed security reports.
- **CLI & Interactive Mode**: Use via command-line or step-by-step interactive mode.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python src/oauth_oidc_tester.py --issuer https://example.com --client-id myclient --redirect-uri http://localhost:8080/callback
```

For full options, run:

```bash
python src/oauth_oidc_tester.py --help
```

## Security Notice

**Use this tool only on systems and applications you own or have explicit permission to test.**

## License

This tool is provided for educational and security research purposes. 