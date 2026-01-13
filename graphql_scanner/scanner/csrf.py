from typing import Dict, Any
from graphql_scanner.core.client import GraphQLClient

def check_get_method_support(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for GET Method Support (CSRF Potential)...")
    # 1. Check if we can execute a query via GET
    query = "{ __typename }"
    try:
        result = client.query(query, method="GET")
        
        # If success, check if it's a mutation-capable endpoint
        # We can't easily test mutation via GET without a known mutation.
        # But supporting GET for queries is a prerequisite or a sign.
        # Actually, if the server accepts GET for queries, it helps performance but CSRF risk is higher if it also accepts mutations.
        
        if isinstance(result, dict) and "data" in result:
             return {
                "vulnerability": "GET Method Support",
                "severity": "Low (Potential CSRF)",
                "status": "WARNING",
                "description": "Server accepts GraphQL queries via GET. Verify if mutations are also allowed via GET.",
            }
        
    except Exception:
        pass
        
    return {
        "vulnerability": "GET Method Support",
        "status": "SAFE",
        "description": "Server does not accept queries via GET."
    }

def check_post_urlencoded(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for POST x-www-form-urlencoded Support...")
    data = "query={ __typename }"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        # We use send_request to control body and headers precisely
        result = client.send_request(data=data, headers=headers, method="POST")
        
        if isinstance(result, dict) and "data" in result:
             return {
                "vulnerability": "POST urlencoded Support",
                "severity": "High (CSRF)",
                "status": "VULNERABLE",
                "description": "Server accepts x-www-form-urlencoded. This allows CSRF attacks from simple HTML forms.",
            }
    except Exception:
        pass

    return {
        "vulnerability": "POST urlencoded Support",
        "status": "SAFE",
        "description": "Server does not accept x-www-form-urlencoded."
    }
