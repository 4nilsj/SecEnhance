# JWT Security Tester — Usage Guide

## Basic Usage

Analyze a single JWT:
```
python src/jwt_security_tester.py --token "<jwt>"
```

Analyze tokens from a file:
```
python src/jwt_security_tester.py --file tokens.txt --output batch_report.html
```

Dictionary attack:
```
python src/jwt_security_tester.py --token "<jwt>" --test dictionary --wordlist my_wordlist.txt
```

Generate keys:
```
python src/jwt_security_tester.py --test generate-keys --key-size 2048
```

## All CLI Options

- `--token <JWT>`: Analyze a single JWT
- `--file <file>`: Analyze tokens from file (one per line)
- `--test <type>`: Specify test (structure, algorithm, signature, claims, tampering, replay, cve, fuzzing, timestamps, dictionary, jwks, jwks-spoofing, generate-keys, forge, all)
- `--output <file>`: Save report (HTML/JSON)
- `--config <file>`: Use custom config
- `--max-attempts <n>`: Max attempts for dictionary attack
- `--workers <n>`: Parallel workers for batch
- `--debug`: Enable debug logging
- `--version`, `--help`: Info and help

## Test Types

- `structure`: Analyze JWT structure
- `algorithm`: Algorithm confusion tests
- `signature`: Signature verification
- `claims`: Claim validation
- `tampering`: Token tampering
- `replay`: Replay attack
- `cve`: Run all CVE-specific tests
- `fuzzing`: Claim fuzzing
- `timestamps`: Timestamp tampering
- `dictionary`: Dictionary attack
- `jwks`: JWKS validation
- `jwks-spoofing`: JWKS spoofing
- `generate-keys`: Generate RSA/ECDSA key pairs
- `forge`: Forge a token
- `all`: Run all tests

## Advanced Scenarios

- **Batch mode with custom workers:**
  ```
  python src/jwt_security_tester.py --file tokens.txt --workers 8
  ```
- **Custom config:**
  ```
  python src/jwt_security_tester.py --config my_config.json --token "<jwt>"
  ```
- **Environment variable override:**
  ```
  set JWT_DEBUG=true
  python src/jwt_security_tester.py --token "<jwt>"
  ```
- **Save JSON report:**
  ```
  python src/jwt_security_tester.py --token "<jwt>" --output result.json
  ```

## Interactive Mode

Run without arguments to enter interactive mode.

## Exit Codes
- `0`: Success
- `1`: Error or invalid input

## More
- See [../README.md](../README.md) for overview
- See [CONFIGURATION.md](CONFIGURATION.md) for config details
- See [API_REFERENCE.md](API_REFERENCE.md) for API usage 