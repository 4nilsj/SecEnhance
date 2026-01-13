from typing import Dict, Any, List, Optional
from graphql_scanner.core.client import GraphQLClient

async def check_interface_leaks(client: GraphQLClient, schema: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    print("[-] Checking for Interface/Union Implementation Leaks...")
    results = []
    
    if not schema:
         return [{
            "vulnerability": "Interface/Logic Check",
            "status": "SKIPPED",
            "description": "Schema not available."
        }]

    try:
        types = schema.get("__schema", {}).get("types", [])
        
        # Look for Interfaces
        interfaces = [t for t in types if t.get("kind") == "INTERFACE"]
        
        leaked_types = []
        
        for iface in interfaces:
            possible_types = iface.get("possibleTypes", [])
            if not possible_types:
                continue
                
            for pt in possible_types:
                t_name = pt.get("name")
                # Heuristic: If type name contains "Admin", "Internal", "Hidden" 
                # but is attached to a generic Interface like "User" or "Node"
                
                check_terms = ["admin", "internal", "privileged", "staff", "sudo"]
                if any(term in t_name.lower() for term in check_terms):
                    leaked_types.append(f"{t_name} implements {iface.get('name')}")
        
        if leaked_types:
            results.append({
                "vulnerability": "Type Leakage via Interface",
                "severity": "Low (Info Leak)",
                "status": "WARNING",
                "description": f"Found sensitive types implementing public interfaces: {', '.join(leaked_types[:5])}"
            })
        else:
             results.append({
                "vulnerability": "Interface/Logic Check",
                "status": "SAFE",
                "description": "No sensitive types found implementing interfaces."
            })
            
    except Exception as e:
         results.append({"vulnerability": "Interface/Logic Check", "status": "ERROR", "description": str(e)})

    return results
