import asyncio
from typing import Dict, Any, List, Optional, Union
from graphql_scanner.core.client import GraphQLClient

# Common SQL/NoSQL Injection payloads
SQL_PAYLOADS = ["'", "' OR '1'='1", "\"", "\" OR \"1\"=\"1", "1 OR 1=1", "sleep(5)", "'; --", ") OR ('1'='1", "admin' --"]
NOSQL_PAYLOADS = ["{\"$ne\": null}", "{\"$gt\": \"\"}", "|| 1==1"]

# Type-aware payloads (Advanced Fuzzing)
TYPE_PAYLOADS = {
    "Int": [999999999, 0, -1, 2147483648, -2147483649], # Overflows and boundary values
    "Float": [0.0, -1.0, 1e37, "3.14"], # Scientific notation and string representation
    "Boolean": [None, "true", "0", 1],
    "String": SQL_PAYLOADS + NOSQL_PAYLOADS
}

ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "Syntax error", "Unclosed quotation mark", "ORA-", 
    "PostgreSQL query", "MongoError", "sqlite3.OperationalError", "quoted string",
    "Integer Overflow", "out of range", "too large for column"
]

PAYLOADS = SQL_PAYLOADS + NOSQL_PAYLOADS

async def check_injection(client: GraphQLClient, schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("[-] Checking for Injection & Advanced Fuzzing (Async)...")
    results = []
    
    if not schema:
         return [{"vulnerability": "Injection Checks", "status": "SKIPPED", "description": "Schema not available."}]

    try:
        types = schema.get("__schema", {}).get("types", [])
        query_type_name = schema.get("__schema", {}).get("queryType", {}).get("name", "Query")
        mutation_type_name = schema.get("__schema", {}).get("mutationType", {}).get("name", "Mutation")
        
        query_type = next((t for t in types if t["name"] == query_type_name), None)
        mutation_type = next((t for t in types if t["name"] == mutation_type_name), None)

        fields_to_test = []
        if query_type: fields_to_test.extend([(f, "query") for f in query_type.get("fields", []) if f.get("args")])
        if mutation_type: fields_to_test.extend([(f, "mutation") for f in mutation_type.get("fields", []) if f.get("args")])

        # Limit for demo, prioritizing mutations
        fields_to_test = sorted(fields_to_test, key=lambda x: x[1] == "mutation", reverse=True)[:10]

        async def fuzz_field_arg(field, op_type, arg):
            arg_name = arg["name"]
            arg_type_info = arg["type"]
            
            # Extract base type name
            base_type = _get_base_type_name(arg_type_info)
            payloads = TYPE_PAYLOADS.get(base_type, SQL_PAYLOADS + NOSQL_PAYLOADS)
            
            field_results = []
            for payload in payloads:
                # Format payload based on type
                formatted_payload = payload
                if base_type == "String" and isinstance(payload, str):
                    formatted_payload = f'"{payload}"'
                elif payload is None:
                    formatted_payload = "null"
                elif isinstance(payload, bool):
                    formatted_payload = str(payload).lower()
                
                query = f'{op_type} {{ {field["name"]}({arg_name}: {formatted_payload}) {{ __typename }} }}'
                
                try:
                    res = await client.query(query)
                    if isinstance(res, dict) and "errors" in res:
                        error_str = str(res["errors"])
                        for sig in ERROR_SIGNATURES:
                            if sig.lower() in error_str.lower():
                                # Differential check
                                is_fp = await _is_false_positive(client, field, op_type, arg_name, base_type)
                                
                                field_results.append({
                                    "vulnerability": f"Injection/Fuzzing ({sig})" + (" - Low Confidence" if is_fp else ""),
                                    "severity": "High",
                                    "status": "WARNING" if is_fp else "VULNERABLE",
                                    "description": f"Field '{field['name']}' arg '{arg_name}' type '{base_type}' triggered error with payload: {payload}",
                                    "query": query,
                                    "response": res
                                })
                                break # Found a signature, move to next payload for this arg
                except:
                    pass
            return field_results

        tasks = []
        for field, op_type in fields_to_test:
            for arg in field["args"]:
                tasks.append(fuzz_field_arg(field, op_type, arg))

        # Run all fuzzing tasks in parallel!
        batch_results = await asyncio.gather(*tasks)
        for r_list in batch_results:
            results.extend(r_list)

        if not results:
            results.append({"vulnerability": "Injection/Fuzzing Checks", "status": "SAFE", "description": "No vulnerabilities found."})

    except Exception as e:
        results.append({"vulnerability": "Injection Checks", "status": "ERROR", "description": str(e)})

    return results

def _get_base_type_name(type_info: Dict[str, Any]) -> str:
    """Recursively find the base type name (e.g., String, Int)."""
    if type_info.get("name"):
        return type_info["name"]
    if type_info.get("ofType"):
        return _get_base_type_name(type_info["ofType"])
    return "String"

async def _is_false_positive(client, field, op_type, arg_name, base_type) -> bool:
    """Perform differential analysis to check for false positives."""
    safe_values = {"Int": 1, "Float": 1.0, "Boolean": True, "String": '"safe_val"'}
    safe_val = safe_values.get(base_type, '"safe_val"')
    query = f'{op_type} {{ {field["name"]}({arg_name}: {safe_val}) {{ __typename }} }}'
    try:
        res = await client.query(query)
        return isinstance(res, dict) and "errors" in res
    except:
        return True
