from typing import Dict, Any, List
from graphql_scanner.core.client import GraphQLClient

COMMON_DIRECTIVES = [
    "@admin",
    "@internal",
    "@debug",
    "@cached",
    "@deprecated",
    "@auth",
    "@test"
]

def check_custom_directives(client: GraphQLClient) -> List[Dict[str, Any]]:
    print("[-] Checking for Hidden Custom Directives...")
    results = []
    
    # We try to apply directives to __typename or a known field
    base_query = "query { __typename %s }"
    
    for directive in COMMON_DIRECTIVES:
        query = base_query % directive
        try:
            result = client.query(query)
            
            # If we get "data", it means the directive IS valid and accepted (and probably did nothing or something hidden)
            # If we get "Unknown directive", it doesn't exist.
            
            if isinstance(result, dict):
                if "errors" in result:
                    errors = str(result["errors"])
                    if "Unknown directive" in errors:
                        continue # Not existing
                        
                    # If error is "Directive ... may not be used on FIELD", it EXISTS but wrong location.
                    # That is a finding!
                    if "may not be used on" in errors:
                         results.append({
                            "vulnerability": f"Hidden Directive Found: {directive}",
                            "severity": "Medium (Logic)",
                            "status": "VULNERABLE",
                            "description": f"Directive {directive} exists but location was wrong.",
                            "details": errors[:100]
                        })
                         continue
                
                if "data" in result:
                     results.append({
                        "vulnerability": f"Hidden Directive Found: {directive}",
                        "severity": "Medium (Logic)",
                        "status": "VULNERABLE",
                        "description": f"Server accepted directive {directive} without error.",
                    })
                    
        except Exception:
            pass
            
    if not results:
        results.append({
            "vulnerability": "Custom Directives",
            "status": "SAFE",
            "description": "No common internal directives accepted."
        })
        
    return results
