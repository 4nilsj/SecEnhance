from typing import Dict, Any
from graphql_scanner.core.client import GraphQLClient

def check_stack_trace(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Stack Trace Leakage...")
    # Trigger an error by sending invalid type or malformed query
    # Case 1: Syntax Error
    try:
        # Invalid syntax
        result = client.query("query { invalid syntax }")
        if "errors" in result:
            err_str = str(result["errors"])
            if is_stack_trace(err_str):
                 return {
                    "vulnerability": "Stack Trace Leakage",
                    "severity": "Low (Info Leak)",
                    "status": "VULNERABLE",
                    "description": "Server reveals stack traces on syntax errors."
                }
    except:
        pass

    # Case 2: Runtime Error (if possible)
    # We can try submitting a string to an Int argument if we knew one.
    # For now, generic syntax error is a good baseline check.
    
    return {
        "vulnerability": "Stack Trace Leakage",
        "status": "SAFE",
        "description": "No stack traces found in errors."
    }

def is_stack_trace(error_text: str) -> bool:
    keywords = [
        "Traceback (most recent call last)",
        "File \"",
        "line ",
        "in module",
        "at Object.",
        "at Function.",
        "System.Exception",
        "java.lang."
    ]
    count = 0
    for k in keywords:
        if k in error_text:
            count += 1
    
    return count >= 2 or "Traceback" in error_text
