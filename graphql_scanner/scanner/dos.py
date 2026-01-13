from typing import Dict, Any, List
from graphql_scanner.core.client import GraphQLClient

async def check_alias_overloading(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Alias Overloading...")
    count = 100
    aliases = [f"a{i}: __typename" for i in range(count)]
    query = f"queryAliases {{ {', '.join(aliases)} }}"
    
    try:
        result = await client.query(query)
        # If we get result with 100 aliases, it might be vulnerable or just processing heavy
        if isinstance(result, dict) and "data" in result:
             return {
                "vulnerability": "Alias Overloading",
                "severity": "Medium (DoS)",
                "status": "WARNING",
                "description": f"Server processed {count} aliases in a single query.",
                "query": query,
                "response": result
            }
        elif isinstance(result, dict) and "errors" in result:
             # Check if error mentions alias limit
             return {
                "vulnerability": "Alias Overloading",
                "status": "SAFE",
                "description": "Server returned errors, possibly limiting aliases."
            }
        return {"vulnerability": "Alias Overloading", "status": "UNKNOWN", "description": "Unexpected response."}
    except Exception as e:
        return {"vulnerability": "Alias Overloading", "status": "UNKNOWN", "description": str(e)}

async def check_batch_queries(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Batch Queries...")
    count = 10
    queries = [{"query": "query { __typename }"} for _ in range(count)]
    
    try:
        result = await client.batch_query(queries)
        if isinstance(result, list) and len(result) == count:
             return {
                "vulnerability": "Batch Queries",
                "severity": "Medium (DoS)",
                "status": "VULNERABLE",
                "description": "Server supports batch queries (Array of operations).",
                "query": queries,
                "response": result
            }
        return {
            "vulnerability": "Batch Queries",
            "status": "SAFE",
            "description": "Server does not appear to support batch queries (did not return array)."
        }
    except Exception as e:
         # If it fails (e.g. 500 or 400 because it doesn't like arrays), it's safe from standard batching
         return {"vulnerability": "Batch Queries", "status": "SAFE", "description": "Request failed or rejected batch format."}

async def check_field_duplication(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Field Duplication...")
    count = 500
    fields = "__typename " * count
    query = f"query {{ {fields} }}"
    
    try:
        result = await client.query(query)
        if isinstance(result, dict) and "data" in result:
             return {
                "vulnerability": "Field Duplication",
                "severity": "Low (DoS)",
                "status": "WARNING",
                "description": f"Server accepted {count} duplicate fields.",
                "query": query,
                "response": result
            }
        return {"vulnerability": "Field Duplication", "status": "SAFE", "description": "Server rejected or failed to process."}
    except Exception as e:
        return {"vulnerability": "Field Duplication", "status": "UNKNOWN", "description": str(e)}

async def check_directive_overloading(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Directives Overloading...")
    count = 50
    directives = "@skip(if: false) " * count
    query = f"query {{ __typename {directives} }}"
    
    try:
        result = await client.query(query)
        if isinstance(result, dict) and "data" in result:
            return {
                "vulnerability": "Directives Overloading",
                "severity": "Low (DoS)",
                "status": "WARNING",
                "description": f"Server processed {count} directives on a single field.",
                "query": query,
                "response": result
            }
        return {"vulnerability": "Directives Overloading", "status": "SAFE", "description": "Server rejected."}
    except Exception as e:
        return {"vulnerability": "Directives Overloading", "status": "UNKNOWN", "description": str(e)}

async def check_circular_fragments(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Circular Fragment Spreads...")
    # ... (skipping long query string for brevity in targetContent but it must match exactly)
    
    try:
        # We need a type to query on. __Type is usually available.
        # But top level query needs to return that type. 
        # Standard introspection query returns __schema { types ... }
        # So we can try to query __schema { types { ...A } }
        
        real_query = """
        query CircularCheck {
            __schema {
                types {
                    ...A
                }
            }
        }
        
        fragment A on __Type {
            name
            ...B
        }
        
        fragment B on __Type {
            name
            ...A
        }
        """
        
        result = await client.query(real_query)
        
        if isinstance(result, dict) and "errors" in result:
            errors = str(result["errors"])
            if "spread" in errors.lower() or "cycle" in errors.lower() or "recursion" in errors.lower():
                 return {
                    "vulnerability": "Circular Fragments",
                    "status": "SAFE",
                    "description": "Server detected and blocked circular fragments."
                }
        
        # If no error or generic error, it might be vulnerable depending on if it crashed or just timed out
        # If it returns data, it means it didn't recurse infinitely (maybe limited depth)
        if isinstance(result, dict) and "data" in result:
             return {
                "vulnerability": "Circular Fragments",
                "status": "SAFE",
                "description": "Server handled the query without error (likely depth limited)."
            }

        return {"vulnerability": "Circular Fragments", "status": "UNKNOWN", "description": "Unexpected response."}

    except Exception as e:
         return {"vulnerability": "Circular Fragments", "status": "UNKNOWN", "description": str(e)}
