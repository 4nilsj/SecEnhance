# JWT Security Testing Tool

A comprehensive CLI tool for analyzing and testing JWT token security with advanced attack capabilities.

## Features

### 🔍 Core Analysis
- **Token Structure Analysis**: Decode and analyze JWT header, payload, and signature
- **Algorithm Confusion Testing**: Test for algorithm switching vulnerabilities
- **Signature Verification**: Test with various secrets and keys
- **Claim Validation**: Check for missing or insecure claims
- **Token Tampering**: Test various tampering techniques
- **Replay Attack Testing**: Check for replay attack vulnerabilities

### 🚨 CVE-Specific Tests
- **CVE-2015-2951**: alg=none signature bypass vulnerability
- **CVE-2016-10555**: RS/HS256 public key mismatch vulnerability
- **CVE-2018-0114**: Key injection vulnerability
- **CVE-2019-20933/CVE-2020-28637**: Blank password vulnerability
- **CVE-2020-28042**: Null signature vulnerability
- **CVE-2022-21449**: Psychic Signature ECDSA vulnerability

### 🎯 Advanced Testing
- **Claim Fuzzing**: Test claim values with various payloads
- **Timestamp Tampering**: Test timestamp manipulation attacks
- **Dictionary Attack**: High-speed secret cracking with wordlists
- **JWKS Validation**: Test against JSON Web Key Sets
- **Key Generation**: Generate RSA and ECDSA key pairs
- **Token Forging**: Create custom JWT tokens

### 📊 Reporting
- **Comprehensive Reports**: Detailed JSON reports with all test results
- **Risk Assessment**: Categorized vulnerabilities by severity
- **Batch Processing**: Test multiple tokens from files
- **Interactive Mode**: Real-time testing with user input

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Test a single token
python src/jwt_security_tester.py --token "your.jwt.token"

# Test with secret
python src/jwt_security_tester.py --token "your.jwt.token" --secret "your_secret"

# Test with public key for RS/ES algorithms
python src/jwt_security_tester.py --token "your.jwt.token" --public-key "path/to/public.pem"
```

### Specific Tests

```bash
# Run only CVE tests
python src/jwt_security_tester.py --token "your.jwt.token" --test cve

# Run claim fuzzing
python src/jwt_security_tester.py --token "your.jwt.token" --test fuzzing

# Run timestamp tampering tests
python src/jwt_security_tester.py --token "your.jwt.token" --test timestamps

# Run dictionary attack
python src/jwt_security_tester.py --token "your.jwt.token" --test dictionary --wordlist wordlist.txt

# Test JWKS validation
python src/jwt_security_tester.py --token "your.jwt.token" --test jwks --jwks-url "https://example.com/.well-known/jwks.json"
```

### Key Generation

```bash
# Generate RSA and ECDSA key pairs
python src/jwt_security_tester.py --test generate-keys --key-size 2048 --curve P-256
```

### Token Forging

```bash
# Forge a new token based on existing payload
python src/jwt_security_tester.py --token "original.jwt.token" --test forge --secret "new_secret"
```

### Batch Processing

```bash
# Test multiple tokens from file
python src/jwt_security_tester.py --file tokens.txt --output batch_report.json
```

### Interactive Mode

```bash
# Run in interactive mode
python src/jwt_security_tester.py
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--token` | JWT token to test |
| `--secret` | Secret key for signature verification |
| `--public-key` | Public key for RS/ES algorithm testing |
| `--jwks-url` | JWKS URL for key validation |
| `--wordlist` | Wordlist file for dictionary attack |
| `--file` | File containing JWT tokens (one per line) |
| `--output` | Output file for report |
| `--test` | Specific test to run (see test options below) |
| `--max-attempts` | Maximum attempts for dictionary attack (default: 1000) |
| `--key-size` | RSA key size for generation (default: 2048) |
| `--curve` | ECDSA curve for generation (default: P-256) |

### Test Options

- `structure`: Token structure analysis
- `algorithm`: Algorithm confusion testing
- `signature`: Signature verification
- `claims`: Claim validation
- `tampering`: Token tampering
- `replay`: Replay attack testing
- `cve`: All CVE-specific tests
- `fuzzing`: Claim fuzzing
- `timestamps`: Timestamp tampering
- `dictionary`: Dictionary attack
- `jwks`: JWKS validation
- `generate-keys`: Generate key pairs
- `forge`: Forge new tokens
- `all`: All tests (default)

## Examples

### Example 1: Basic Security Test
```bash
python src/jwt_security_tester.py --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

### Example 2: CVE Testing with Public Key
```bash
python src/jwt_security_tester.py --token "your.jwt.token" --test cve --public-key "public.pem"
```

### Example 3: Dictionary Attack
```bash
python src/jwt_security_tester.py --token "your.jwt.token" --test dictionary --wordlist common_passwords.txt --max-attempts 5000
```

### Example 4: Generate Keys and Test
```bash
# Generate keys
python src/jwt_security_tester.py --test generate-keys

# Test with generated public key
python src/jwt_security_tester.py --token "your.jwt.token" --public-key "rsa_public_2048.pem"
```

## Output

The tool generates comprehensive JSON reports including:

- **Test Summary**: Overall risk assessment and vulnerability counts
- **Detailed Results**: Results from each test category
- **CVE Analysis**: Specific CVE test results with exploit details
- **Recommendations**: Security recommendations and mitigations
- **Timestamps**: Test execution timestamps

## Security Considerations

⚠️ **Important**: This tool is for security testing and research purposes only. Only use it on systems you own or have explicit permission to test.

## Dependencies

- `PyJWT`: JWT token handling
- `cryptography`: Key generation and cryptographic operations
- `requests`: HTTP requests for JWKS validation

## License

This tool is provided for educational and security research purposes. 