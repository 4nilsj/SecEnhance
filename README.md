# GraphQL Security Scanner

A comprehensive, Python-based security testing tool designed to detect vulnerabilities in GraphQL APIs. This tool performs automated scanning for common security issues including Injection, Broken Access Control (IDOR), Information Leakage, and Denial of Service (DoS) risks.

## Features

- **Injection Scanning**: automated fuzzing for SQL, NoSQL, and Command Injection vulnerabilities.
- **Access Control (IDOR) Testing**: Differential analysis using secondary session cookies to detect unauthorized access to resources.
- **Information Leakage**: Detects Stack Traces, Introspection, and Type Leaking via Interfaces.
- **Denial of Service (DoS)**: Checks for Query Depth, Cyclic Fragments, Batching, and Alias Overloading.
- **Reporting**: Generates visually attractive **HTML Reports** with PoC (Proof of Concept) and Remediation advice, as well as JSON/Text output.
- **Customization**: Supports custom headers, cookies, query fuzzing, and cURL command importing.

## Installation

### Prerequisites
- Python 3.8+
- `pip` (Python Package Manager)

### Steps

1.  **Clone the Repository** (or download source):
    ```bash
    git clone <repository-url>
    cd Antigravity
    ```

2.  **Create a Virtual Environment** (Recommended):
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

The tool is run via the command line using the `graphql_scanner.cli` module.

### Basic Scan
Perform a standard security scan against a target URL.
```bash
python -m graphql_scanner.cli --url http://target.com/graphql
```

### Authentication
Authenticate using cookies or custom headers.
```bash
# Using Cookies
python -m graphql_scanner.cli --url http://target.com/graphql --cookie "session=abc12345"

# Using Headers (e.g., Bearer Token)
python -m graphql_scanner.cli --url http://target.com/graphql --header "Authorization: Bearer <token>"
```

### IDOR / Broken Access Control
Test for IDOR by providing a **Secondary User's Cookie** (`--cookie-b`). The tool will check if the secondary user can access resources owned by the primary user (implied by the default/primary state).
```bash
python -m graphql_scanner.cli --url http://target.com/graphql --cookie "session=USER_A" --cookie-b "session=USER_B"
```

### Generating Reports
Save the results to a file. The format is determined by the file extension.
- **HTML (Recommended)**: Interactive visual report with PoC.
- **JSON**: For machine parsing.
- **TXT**: Plain text summary.

```bash
python -m graphql_scanner.cli --url http://target.com/graphql --output report.html
```

### Advanced Options
- **Import from cURL**: Copy a request from browser DevTools as cURL and import it.
  ```bash
  python -m graphql_scanner.cli --curl "curl 'http://...'"
  ```
- **Custom Query Fuzzing**: Fuzz specific arguments in a provided query/mutation.
  ```bash
  python -m graphql_scanner.cli --url ... --data 'mutation { login(username:"test") { token } }' --fuzz-query
  ```

## Troubleshooting

### 1. "Connection Refused" or "Failed to connect"
- **Cause**: The target server is not running or the URL is incorrect.
- **Solution**: Ensure your GraphQL server (or the mock server) is running and accessible.
  - To run the included mock server: `python tests/mock_server.py`

### 2. "Introspection Disabled"
- **Cause**: The server has disabled GraphQL Introspection, preventing the scanner from mapping the schema.
- **Solution**: The scanner will skip schema-dependent checks (like automatic field fuzzing) but general checks (like DoS probing) may still run. You can manually fuzz specific queries using `--data`.

### 3. "Module not found" error
- **Cause**: Dependencies are not installed or the virtual environment is not active.
- **Solution**: Run `pip install -r requirements.txt` and ensure your venv is active (`source venv/bin/activate`).

### 4. IDOR Check returns "SAFE" unexpectedly
- **Cause**: The scanner might not have found fields with `id` arguments, or the resources tested (e.g., ID "1") are publicly accessible.
- **Solution**: The IDOR scanner uses a heuristic logic. For better results, ensure the schema involves fields that take an `ID` argument.

## Development / Testing

A **Mock Server** is included to test the scanner's capabilities safely.

1.  Start the server:
    ```bash
    python tests/mock_server.py
    ```
    (Runs on `http://127.0.0.1:5000/graphql`)

2.  Run the scanner against it:
    ```bash
    python -m graphql_scanner.cli --url http://127.0.0.1:5000/graphql --output report.html
    ```
