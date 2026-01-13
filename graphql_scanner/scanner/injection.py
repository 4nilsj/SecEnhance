from typing import Dict, Any, List, Optional
from graphql_scanner.core.client import GraphQLClient

# Common SQL/NoSQL Injection payloads
PAYLOADS = [
    "'", 
    "' OR '1'='1", 
    "\"", 
    "\" OR \"1\"=\"1", 
    "1 OR 1=1", 
    "sleep(5)",
    "'; --",
    ") OR ('1'='1",
    "admin' --",
    # NoSQL
    "{" + "\"$ne\": null" + "}", 
    "{" + "\"$gt\": \"\"" + "}", 
    "|| 1==1"
]

ERROR_SIGNATURES = [
    "SQL syntax",
    "mysql_fetch",
    "Syntax error",
    "Unclosed quotation mark",
    "ORA-",
    "PostgreSQL query",
    "MongoError",
    "sqlite3.OperationalError",
    "quoted string",
]

def check_injection(client: GraphQLClient, schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("[-] Checking for Injection Vulnerabilities (SQL/NoSQL)...")
    results = []
    
    if not schema:
         return [{
            "vulnerability": "Injection Checks",
            "status": "SKIPPED",
            "description": "Schema not available (Introspection disabled or failed). Cannot fuzz fields."
        }]

    # 1. Identify query fields with arguments
    # We iterate over Query type fields
    try:
        query_type_name = schema.get("__schema", {}).get("queryType", {}).get("name", "Query")
        types = schema.get("__schema", {}).get("types", [])
        query_type = next((t for t in types if t["name"] == query_type_name), None)
        
        if not query_type:
             return [{"vulnerability": "Injection Checks", "status": "SKIPPED", "description": "Could not find Query type."}]

        mutation_type_name = schema.get("__schema", {}).get("mutationType", {}).get("name", "Mutation")
        mutation_type = next((t for t in types if t["name"] == mutation_type_name), None)

        fields_to_test = []
        
        # Add Query Fields
        for field in query_type.get("fields", []):
            if field.get("args"):
                fields_to_test.append(field)
                
        # Add Mutation Fields
        if mutation_type:
            for field in mutation_type.get("fields", []):
                if field.get("args"):
                    # Mark as mutation for context (optional, but good for logging)
                    field["_is_mutation"] = True 
                    fields_to_test.append(field)
        
        if not fields_to_test:
             return [{"vulnerability": "Injection Checks", "status": "SAFE", "description": "No fields with arguments found to test."}]
             
        # Limit testing to avoid massive scans in this demo
        # We prioritize mutations if available as they are critical
        fields_to_test = sorted(fields_to_test, key=lambda x: x.get("_is_mutation", False), reverse=True)[:5] 
        
        detected = False
        
        for field in fields_to_test:
            field_name = field["name"]
            # Construct a basic query. We need to know subfields if it returns an object.
            # Simplified: just ask for __typename
            
            for arg in field["args"]:
                arg_name = arg["name"]
                
                # Fuzz this argument
                for payload in PAYLOADS:
                    # Construct query: queryOrMutation { field(arg: "payload") { __typename } }
                    operation_type = "mutation" if field.get("_is_mutation") else "query"
                    # Note: We assume string args for simplicity in this scanner
                    query = f'{operation_type} {{ {field_name}({arg_name}: "{payload}") {{ __typename }} }}'
                    
                    try:
                        result = client.query(query)
                        if "errors" in result:
                            error_str = str(result["errors"])
                            # Check for DB errors
                            for sig in ERROR_SIGNATURES:
                                if sig.lower() in error_str.lower():
                                    is_false_positive = False
                                    # Differential Analysis
                                    safe_payload = "safe_string"
                                    safe_query = f'{operation_type} {{ {field_name}({arg_name}: "{safe_payload}") {{ __typename }} }}'
                                    try:
                                        safe_result = client.query(safe_query)
                                        if isinstance(safe_result, dict) and "errors" in safe_result:
                                             is_false_positive = True
                                    except Exception:
                                        pass

                                    if is_false_positive:
                                        results.append({
                                            "vulnerability": f"Injection ({sig}) - Low Confidence",
                                            "severity": "High",
                                            "status": "WARNING",
                                            "description": f"Field '{field_name}' arg '{arg_name}' triggered error, but SAFE payload also failed.",
                                            "details": error_str[:100] + "...",
                                            "query": query,
                                            "response": result
                                        })
                                    else:
                                        results.append({
                                            "vulnerability": f"Injection ({sig})",
                                            "severity": "High",
                                            "status": "VULNERABLE",
                                            "description": f"Field '{field_name}' arg '{arg_name}' triggered DB error with payload: {payload}",
                                            "details": error_str[:100] + "...",
                                            "query": query,
                                            "response": result
                                        })
                                    detected = True
                                    break
                    except Exception:
                        pass
                    
                # if detected: break # Removed to scan all payloads
            # if detected: break # Removed to scan all args
        # if detected: break # Removed to scan all fields
            
        if not detected:
             results.append({
                "vulnerability": "Injection Checks",
                "status": "SAFE", 
                "description": "No specific DB errors triggered by injection payloads."
            })
            
    except Exception as e:
         results.append({"vulnerability": "Injection Checks", "status": "ERROR", "description": str(e)})

    return results
