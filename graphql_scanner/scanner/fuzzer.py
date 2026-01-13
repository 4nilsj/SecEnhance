from typing import Dict, Any, List
import re
from graphql_scanner.core.client import GraphQLClient
from graphql_scanner.scanner.injection import PAYLOADS, ERROR_SIGNATURES

def check_custom_query_fuzzing(client: GraphQLClient, query_string: str) -> List[Dict[str, Any]]:
    print("[-] Fuzzing provided Custom Query/Mutation...")
    results = []
    
    # 1. Check for Variables in Query (e.g., $var)
    # This is complex to parse perfectly without a parser, but we can do simple string replace if we assume standard JSON vars.
    # HOWEVER, usually user provides query AND variables.
    # If we only have query body with hardcoded strings like `id: "123"`, we can try to regex replace "123" with payload.
    
    # Regex for finding string arguments: argumentName: "value"
    # Matches: ignore spaces, find 'arg:', space?, quote, content, quote
    # We will try to inject into these values.
    
    # Simple regex finding quoted string arguments:  : \s* "([^"]+)"
    # Risk: might match things that are not args. But for fuzzer it's okay to try invalid queries.
    
    potential_injection_points = list(re.finditer(r':\s*"([^"]+)"', query_string))
    
    if not potential_injection_points:
         return [{
            "vulnerability": "Custom Query Fuzzer",
            "status": "SKIPPED",
            "description": "No obvious hardcoded string arguments found to fuzz in the provided query."
        }]
    
    # Limit injection points
    potential_injection_points = potential_injection_points[:5]
    
    for match in potential_injection_points:
        original_value = match.group(1)
        full_match = match.group(0) # e.g. : "123"
        
        for payload in PAYLOADS:
            # Replace the FIRST occurrence of this specific match? 
            # If multiple same args exist, reckless replace might break.
            # Using span to replace exactly this one instance.
            
            start, end = match.span()
            # We construct new query string by slicing
            # : "PAYLOAD"
            # match.start() is index of ':'
            # match.group(1) start/end are content inside quotes.
            
            # We want to replace content inside quotes.
            # re.finditer returns match objects. Group 1 is the content.
            span_start, span_end = match.span(1)
            
            fuzzed_query = query_string[:span_start] + payload + query_string[span_end:]
            
            try:
                result = client.query(fuzzed_query)
                if isinstance(result, dict) and "errors" in result:
                    error_str = str(result["errors"])
                    for sig in ERROR_SIGNATURES:
                        if sig.lower() in error_str.lower():
                            results.append({
                                "vulnerability": f"Custom Query Injection ({sig})",
                                "severity": "High",
                                "status": "VULNERABLE",
                                "description": f"Custom query argument '{original_value}' triggered DB error with payload: {payload}",
                                "details": error_str[:100]
                            })
                            # Stop after finding one bug for this arg
                            break
            except Exception:
                pass
                
    if not results:
         results.append({
            "vulnerability": "Custom Query Fuzzer",
            "status": "SAFE",
            "description": "Fuzzed custom query arguments but triggered no specific errors."
        })
        
    return results
