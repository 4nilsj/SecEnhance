from typing import Dict, Any, Optional
from graphql_scanner.core.client import GraphQLClient
from graphql_scanner.introspection.fetcher import fetch_schema

def check_introspection(client: GraphQLClient) -> Dict[str, Any]:
    """
    Checks if introspection is enabled and returns the result.
    
    Args:
        client: The GraphQLClient.
        
    Returns:
        Dict containing status and details.
    """
    print("[-] Checking if Introspection is enabled...")
    schema = fetch_schema(client)
    
    if schema:
        return {
            "vulnerability": "Introspection Enabled",
            "severity": "Low (Information Disclosure)",
            "description": "GraphQL Introspection is enabled. This allows attackers to map the API schema.",
            "status": "VULNERABLE",
            "details": f"Found {len(schema.get('__schema', {}).get('types', []))} types."
        }
    else:
        return {
            "vulnerability": "Introspection Enabled",
            "status": "SAFE",
            "description": "Introspection query failed or is disabled."
        }
