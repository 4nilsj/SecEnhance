import typer
from rich.console import Console
from rich.table import Table
from typing import Optional, List
import json
from graphql_scanner.core.client import GraphQLClient
from graphql_scanner.scanner.introspection import check_introspection, fetch_schema
from graphql_scanner.scanner.complexity import check_complexity
from graphql_scanner.scanner.dos import (
    check_alias_overloading,
    check_batch_queries,
    check_field_duplication,
    check_directive_overloading,
    check_circular_fragments
)
from graphql_scanner.scanner.csrf import (
    check_get_method_support,
    check_post_urlencoded
)
from graphql_scanner.scanner.infoleak import (
    check_tracing_enabled,
    check_field_suggestions,
    check_graphiql
)
from graphql_scanner.scanner.injection import check_injection
from graphql_scanner.scanner.errors import check_stack_trace
from graphql_scanner.scanner.validation import check_input_validation, check_large_payload
from graphql_scanner.scanner.directives import check_custom_directives
from graphql_scanner.scanner.logic import check_interface_leaks
from graphql_scanner.scanner.logic import check_interface_leaks
from graphql_scanner.scanner.fuzzer import check_custom_query_fuzzing
from graphql_scanner.scanner.idor import check_idor
from graphql_scanner.report_generator import generate_html_report
from graphql_scanner.utils import parse_curl

app = typer.Typer()
console = Console()

@app.command()
def scan(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Target GraphQL URL"),
    cookies: Optional[str] = typer.Option(None, "--cookie", "-c", help="Cookies for authentication (e.g., 'session=123')"),
    cookie_b: Optional[str] = typer.Option(None, "--cookie-b", help="Secondary Cookies for IDOR/Access Control testing"),
    headers: Optional[List[str]] = typer.Option(None, "--header", "-H", help="Custom headers (e.g., 'Authorization: Bearer 123'). Can be used multiple times."),
    curl: Optional[str] = typer.Option(None, "--curl", help="Parse options from a cURL command string"),
    data: Optional[str] = typer.Option(None, "--data", "-d", help="Custom query/mutation string to scan (fuzzes arguments within it)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save results (e.g. results.json or results.txt)"),
    fuzz_query: bool = typer.Option(False, "--fuzz-query", help="Enable fuzzing of custom query provided via cURL data"),
    depth: int = typer.Option(100, "--depth", "-D", help="Max depth for complexity check")
):
    """
    Scan a GraphQL endpoint for security vulnerabilities.
    """
    # Header Parsing
    custom_headers = {}
    if headers:
        for h in headers:
            if ":" in h:
                key, val = h.split(":", 1)
                custom_headers[key.strip()] = val.strip()

    custom_query_string = None 
    
    # Priority: CLI > cURL
    if data:
        custom_query_string = data
        fuzz_query = True
        console.print("[bold blue]Custom query provided via --data. Enabling fuzzing.[/bold blue]")

    # cURL Parsing logic
    if curl:
        try:
            console.print("[bold yellow]Parsing cURL command...[/bold yellow]")
            curl_data = parse_curl(curl)
            
            if not url: url = curl_data["url"]
            if not cookies: cookies = curl_data["cookies"]
            
            curl_headers = curl_data.get("headers", {})
            curl_headers.update(custom_headers)
            custom_headers = curl_headers
            
            # Check for data (query) in cURL
            if curl_data.get("data") and not custom_query_string:
                 custom_query_string = curl_data["data"]
                 console.print("[bold blue]Detected custom query in cURL data. Will use for Mutation/Fuzzing checks if enabled.[/bold blue]")
                 fuzz_query = True
            
        except Exception as e:
            console.print(f"[bold red]Failed to parse cURL command: {e}[/bold red]")
            raise typer.Exit(code=1)

    if not url:
        console.print("[bold red]Error: Missing --url or --curl argument.[/bold red]")
        raise typer.Exit(code=1)
    
    console.print(f"[bold green]Starting scan against {url}[/bold green]")
    
    try:
        client = GraphQLClient(url, cookies, headers=custom_headers)
        client_b = None
        if cookie_b:
             client_b = GraphQLClient(url, cookie_b, headers=custom_headers)
             console.print(f"[bold blue]Secondary Client initialized for IDOR testing.[/bold blue]")
    except Exception as e:
        console.print(f"[bold red]Failed to initialize client: {e}[/bold red]")
        raise typer.Exit(code=1)

    results = []

    # 0. Custom Query Fuzzing (if provided)
    if fuzz_query and custom_query_string:
         results.extend(check_custom_query_fuzzing(client, custom_query_string))
    
    # 1. Introspection (Fetch Schema first as it's needed for Injection)
    console.print("[-] Fetching Schema for Analysis...")
    schema = fetch_schema(client) # Reuse check_introspection internal logic or just call check and reuse
    
    # We run check_introspection to get the report
    results.append(check_introspection(client))
    
    # 2. Complexity
    results.append(check_complexity(client, max_depth=depth))
    
    # 3. DoS Checks
    results.append(check_alias_overloading(client))
    results.append(check_batch_queries(client))
    results.append(check_field_duplication(client))
    results.append(check_directive_overloading(client))
    results.append(check_circular_fragments(client))
    
    # 4. CSRF Checks
    results.append(check_get_method_support(client))
    results.append(check_post_urlencoded(client))
    
    # 5. Info Leak Checks
    results.append(check_tracing_enabled(client))
    results.append(check_field_suggestions(client))
    results.append(check_graphiql(client))
    
    # 6. Injection Checks
    injection_results = check_injection(client, schema)
    results.extend(injection_results)
    
    # 7. Error Checks
    results.append(check_stack_trace(client))

    # 8. Input Validation Checks
    results.extend(check_input_validation(client, schema))
    results.append(check_large_payload(client))

    # 9. Directives Checks
    results.extend(check_custom_directives(client))

    # 10. Logic Checks
    results.extend(check_interface_leaks(client, schema))
    
    # 11. IDOR Checks
    if client_b:
        results.extend(check_idor(client, client_b, schema))
    
    # Display Results
    table = Table(title="Scan Results")
    table.add_column("Vulnerability", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Severity", style="red")
    table.add_column("Description", style="white")

    for res in results:
        severity = res.get("severity", "-")
        table.add_row(
            res["vulnerability"],
            res["status"],
            severity,
            res["description"]
        )

    console.print(table)
    
    if output:
        try:
            if output.endswith(".json"):
                 with open(output, "w") as f:
                     json.dump(results, f, indent=4)
                 console.print(f"[bold green]Results saved to {output}[/bold green]")
            elif output.endswith(".html"):
                 html_content = generate_html_report(results, url)
                 with open(output, "w") as f:
                     f.write(html_content)
                 console.print(f"[bold green]HTML Report saved to {output}[/bold green]")
            else:
                 # Text format
                 with open(output, "w") as f:
                     f.write("GraphQL Vulnerability Scan Results\n")
                     f.write("==================================\n\n")
                     for res in results:
                         f.write(f"Vulnerability: {res['vulnerability']}\n")
                         f.write(f"Status: {res['status']}\n")
                         f.write(f"Severity: {res.get('severity', '-')}\n")
                         f.write(f"Description: {res['description']}\n")
                         if "details" in res:
                             f.write(f"Details: {res['details']}\n")
                         f.write("-" * 40 + "\n")
                 console.print(f"[bold green]Results saved to {output}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Failed to save output to file: {e}[/bold red]")

if __name__ == "__main__":
    app()
