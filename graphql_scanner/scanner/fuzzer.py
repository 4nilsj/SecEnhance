import asyncio
import re
from typing import Dict, Any, List
from graphql_scanner.core.client import GraphQLClient
from graphql_scanner.scanner.injection import PAYLOADS, ERROR_SIGNATURES

async def check_custom_query_fuzzing(client: GraphQLClient, query_string: str) -> List[Dict[str, Any]]:
    print("[-] Fuzzing provided Custom Query/Mutation (Async)...")
    results = []
    
    potential_injection_points = list(re.finditer(r':\s*"([^"]+)"', query_string))
    
    if not potential_injection_points:
         return [{
            "vulnerability": "Custom Query Fuzzer",
            "status": "SKIPPED",
            "description": "No obvious hardcoded string arguments found to fuzz in the provided query."
        }]
    
    potential_injection_points = potential_injection_points[:5]
    
    async def fuzz_point(match):
        point_results = []
        original_value = match.group(1)
        span_start, span_end = match.span(1)
        
        for payload in PAYLOADS:
            fuzzed_query = query_string[:span_start] + payload + query_string[span_end:]
            try:
                result = await client.query(fuzzed_query)
                if isinstance(result, dict) and "errors" in result:
                    error_str = str(result["errors"])
                    for sig in ERROR_SIGNATURES:
                        if sig.lower() in error_str.lower():
                            point_results.append({
                                "vulnerability": f"Custom Query Injection ({sig})",
                                "severity": "High",
                                "status": "VULNERABLE",
                                "description": f"Custom query argument '{original_value}' triggered error with payload: {payload}",
                                "details": error_str[:100]
                            })
                            return point_results # Found one, move to next point
            except:
                pass
        return point_results

    tasks = [fuzz_point(m) for m in potential_injection_points]
    batch_results = await asyncio.gather(*tasks)
    for res in batch_results:
        results.extend(res)
                
    if not results:
         results.append({
            "vulnerability": "Custom Query Fuzzer",
            "status": "SAFE",
            "description": "Fuzzed custom query arguments but triggered no specific errors."
        })
        
    return results
