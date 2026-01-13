from typing import Dict, Any, List, Optional
from graphql_scanner.core.client import GraphQLClient

async def check_input_validation(client: GraphQLClient, schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("[-] Checking for Input Validation (Int Limits / Logic)...")
    results = []
    
    if not schema:
         return [{
            "vulnerability": "Input Validation",
            "status": "SKIPPED",
            "description": "Schema not available."
        }]

    try:
        query_type_name = schema.get("__schema", {}).get("queryType", {}).get("name", "Query")
        mutation_type_name = schema.get("__schema", {}).get("mutationType", {}).get("name", "Mutation")
        
        types = schema.get("__schema", {}).get("types", [])
        query_type = next((t for t in types if t["name"] == query_type_name), None)
        mutation_type = next((t for t in types if t["name"] == mutation_type_name), None)
        
        fields_to_test = []
        if query_type:
            for field in query_type.get("fields", []):
                if field.get("args"):
                    fields_to_test.append(field)
                    
        if mutation_type:
             for field in mutation_type.get("fields", []):
                if field.get("args"):
                    field["_is_mutation"] = True
                    fields_to_test.append(field)
        
        fields_to_test = sorted(fields_to_test, key=lambda x: x.get("_is_mutation", False), reverse=True)[:5] # Limit scan
        
        # Payloads for Integers and Strings
        # Note: In a real tool, we'd check the Argument TYPE (Int, String, ID) to select payload.
        # For simplicity, we try common edge cases.
        
        INT_PAYLOADS = [
            2147483648, # MAX_INT 32 + 1
            -1, 
            999999999999999999999999, # Huge number
        ]
        
        # Logic: If we send a huge int to a field expecting ID or Int, does it crash or return 500?
        # Only testing one field for demo.
        
        for field in fields_to_test:
            field_name = field["name"]
            for arg in field["args"]:
                arg_name = arg["name"]
                
                # Test Int Limits
                for payload in INT_PAYLOADS:
                    operation_type = "mutation" if field.get("_is_mutation") else "query"
                    query = f'{operation_type} {{ {field_name}({arg_name}: {payload}) {{ __typename }} }}'
                    try:
                        result = await client.query(query)
                        if isinstance(result, dict) and "errors" in result:
                            err = str(result["errors"])
                            # Look for numeric overflow or generic exceptions
                            if "overflow" in err.lower() or "too large" in err.lower():
                                 pass # Handled
                            elif "exception" in err.lower() or "500" in err:
                                 results.append({
                                    "vulnerability": "Integer Overflow / Unhandled Input",
                                    "severity": "Low",
                                    "status": "WARNING",
                                    "description": f"Field '{field_name}' arg '{arg_name}' triggered error with payload {payload}",
                                    "details": err[:100]
                                })
                    except:
                        pass
        
    except Exception as e:
         results.append({"vulnerability": "Input Validation", "status": "ERROR", "description": str(e)})

    return results

async def check_large_payload(client: GraphQLClient) -> Dict[str, Any]:
    print("[-] Checking for Large Payload Handling...")
    # Send a query with a massive string in a variable or alias
    # Using aliases is easier to simulate without valid schema args
    
    count = 2000 # Not too huge to avoid freezing own machine, but enough to tempt regex/allocators
    padding = "A" * count
    
    query = f"query {{ __typename # {padding} \n }}" 
    
    try:
        # Just check status. If it times out or 500s.
        result = await client.query(query)
        return {
            "vulnerability": "Large Payload",
            "status": "SAFE",
            "description": "Server handled large payload query."
        }
    except Exception as e:
         return {
            "vulnerability": "Large Payload",
            "status": "WARNING",
            "description": "Request failed with large payload. Possible DoS vector.",
            "details": str(e)
        }

