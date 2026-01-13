from typing import List, Dict, Any, Optional
from graphql_scanner.core.client import GraphQLClient

async def check_idor(client_a: GraphQLClient, client_b: Optional[GraphQLClient], schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("[-] Checking for IDOR / Broken Access Control...")
    results = []
    
    if not schema or not client_b:
        return [{
            "vulnerability": "IDOR Checks",
            "status": "SKIPPED",
            "description": "Skipped due to missing Schema or Secondary Cookie (--cookie-b)."
        }]

    # 1. Identify Fields with Arguments (Potentially checking specific resources)
    # We look for fields like `user(id: ID)`
    
    query_type_name = schema.get("__schema", {}).get("queryType", {}).get("name", "Query")
    types = schema.get("__schema", {}).get("types", [])
    query_type = next((t for t in types if t["name"] == query_type_name), None)
    
    if not query_type: return []
    
    fields_to_test = []
    for field in query_type.get("fields", []):
        # Heuristic: fields with 'id' argument or return types like 'User' are interesting
        has_id_arg = any(arg["name"] == "id" for arg in field.get("args", []))
        if has_id_arg:
            fields_to_test.append(field)
            
    fields_to_test = fields_to_test[:5] # Limit checks
    
    # 2. Differential Testing
    # We assume '1' is a valid ID for 'user' (from previous mocks/knowledge) or we just blindly test '1'.
    # A real tool would need to crawling first to find valid IDs users own.
    # Here we will just fuzz ID '1' and '2'.
    
    test_id = "1" 
    
    for field in fields_to_test:
        field_name = field["name"]
        
        # Test Query with Client A (Expected Owner?)
        query = f'query {{ {field_name}(id: "{test_id}") {{ __typename }} }}'
        
        try:
            # A's response (Baseline)
            # res_a = await client_a.query(query) 
            # Ideally we check if A can access it.
            
            # B's response (Attacker)
            res_b = await client_b.query(query)
            
            # Analyze B's access
            if isinstance(res_b, dict):
                if "errors" in res_b:
                    # B got error -> Good Access Control (potentially)
                    pass 
                elif "data" in res_b and res_b["data"].get(field_name):
                     # B got data!
                     # Vulnerability: resource accessible by secondary user.
                     # Caveat: Maybe it's public data?
                     # We flag as Warning/Potential IDOR.
                     results.append({
                        "vulnerability": "Potential IDOR / Access Control",
                        "severity": "High",
                        "status": "VULNERABLE",
                        "description": f"Field '{field_name}' (id: {test_id}) was accessible by Secondary User (Client B).",
                        "details": f"Response data: {str(res_b['data'])[:50]}...",
                        "query": query,
                        "response": res_b
                    })
                 
        except Exception:
            pass

    if not results:
         results.append({
            "vulnerability": "IDOR Checks",
            "status": "SAFE",
            "description": "No obvious Access Control issues found with tested IDs."
        })

    return results

