from typing import Dict, Any
from graphql_scanner.core.client import GraphQLClient

def generate_nested_query(depth: int) -> str:
    """Generates a deeply nested recursive query."""
    query = "__typename"
    for _ in range(depth):
        query = f"__typename {{ {query} }}"
    return f"query DeepNesting {{ {query} }}"

async def check_complexity(client: GraphQLClient, max_depth: int = 100) -> Dict[str, Any]:
    # ...
    query = generate_nested_query(max_depth)
    
    try:
        result = await client.query(query)
        
        if "errors" in result:
             # Check if error message mentions depth or complexity
            errors = str(result["errors"])
            if "depth" in errors.lower() or "complexity" in errors.lower():
                 return {
                    "vulnerability": "Query Depth Limit",
                    "status": "SAFE",
                    "description": "Server appears to limit query depth."
                }
        
        return {
            "vulnerability": "Query Depth Limit",
            "severity": "Medium (DOS)",
            "status": "WARNING",
            "description": f"Server accepted a query with depth {max_depth}. It might be vulnerable to DOS.",
            "details": "No depth limit error returned."
        }

    except Exception as e:
        return {
            "vulnerability": "Query Depth Limit",
            "status": "UNKNOWN",
            "description": f"Request failed: {str(e)}"
        }
