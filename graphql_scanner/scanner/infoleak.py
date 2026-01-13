from typing import Dict, Any, List
from graphql_scanner.core.client import GraphQLClient

async def check_tracing_enabled(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Tracing/Debug mode...")
    try:
        result = await client.query("{ __typename }")
        if isinstance(result, dict) and "extensions" in result:
            ext = result["extensions"]
            if "tracing" in ext or "debug" in ext:
                 return {
                    "vulnerability": "Tracing/Debug Enabled",
                    "severity": "Low (Info Leak)",
                    "status": "VULNERABLE",
                    "description": "Response contains 'extensions' with tracing/debug info.",
                    "query": "{ __typename }",
                    "response": result
                }
    except Exception:
        pass
    
    return {
        "vulnerability": "Tracing/Debug Enabled",
        "status": "SAFE",
        "description": "Tracing info not found."
    }

async def check_field_suggestions(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Field Suggestions...")
    try:
        # Send a typo
        result = await client.query("{ __typenam }")
        if isinstance(result, dict) and "errors" in result:
            errors = str(result["errors"])
            if "did you mean" in errors.lower():
                 return {
                    "vulnerability": "Field Suggestions",
                    "severity": "Low (Info Leak)",
                    "status": "VULNERABLE",
                    "description": "Server suggests field names on errors ('Did you mean...')."
                }
    except Exception:
        pass
        
    return {
        "vulnerability": "Field Suggestions",
        "status": "SAFE",
        "description": "No suggestions found in errors."
    }

async def check_graphiql(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for GraphiQL/Playground...")
    # ...
    targets = [client.url]
    if client.url.endswith("/graphql"):
        targets.append(client.url.replace("/graphql", "/graphiql"))
        targets.append(client.url.replace("/graphql", "/playground"))
    
    found = []
    for target in targets:
        try:
             # Request with Accept: text/html
             res = await client.send_request(method="GET", headers={"Accept": "text/html"}, payload=None)
             # If res is text and contains "GraphiQL" or "Playground"
             if isinstance(res, str) and ("GraphiQL" in res or "Playground" in res):
                 found.append(target)
        except:
            pass
            
    if found:
        return {
            "vulnerability": "GraphiQL/Playground Exposed",
            "severity": "Low (Info Leak)",
            "status": "VULNERABLE",
            "description": f"Found interfaces at: {', '.join(found)}",
            "details": f"Checked paths: {', '.join(targets)}"
        }
        
    return {
        "vulnerability": "GraphiQL/Playground Exposed",
        "status": "SAFE",
        "description": "No common specific UI endpoints found."
    }
