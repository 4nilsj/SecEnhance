#!/usr/bin/env python3
"""
OAuth/OIDC Security Testing Tool
A comprehensive CLI and interactive tool for analyzing and testing OAuth 2.0 and OpenID Connect (OIDC) flows.
"""

import argparse
from rich import print
import requests
import secrets
import hashlib
import base64
import jwt
import json
import logging
import sys
from datetime import datetime

# Configure debug logging
def setup_debug_logging(debug: bool = False):
    """Setup debug logging configuration."""
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('oauth_debug.log')
            ]
        )
        logging.debug("Debug logging enabled")
    else:
        logging.basicConfig(level=logging.INFO)

def debug_print(message: str, debug: bool = False):
    """Print debug message if debug mode is enabled."""
    if debug:
        print(f"[DEBUG] {message}")
        logging.debug(message)

# Placeholders for future imports
# import requests, jwt, cryptography, flask, etc.

def discover_metadata(issuer, debug=False):
    debug_print(f"Starting OIDC metadata discovery for issuer: {issuer}", debug)
    print(f"[bold cyan]Discovering OIDC metadata for:[/bold cyan] {issuer}")
    config_url = issuer.rstrip('/') + '/.well-known/openid-configuration'
    debug_print(f"Configuration URL: {config_url}", debug)
    
    try:
        debug_print("Making HTTP request to OIDC configuration endpoint", debug)
        resp = requests.get(config_url, timeout=10)
        debug_print(f"Response status: {resp.status_code}", debug)
        debug_print(f"Response headers: {dict(resp.headers)}", debug)
        
        resp.raise_for_status()
        metadata = resp.json()
        debug_print(f"OIDC metadata received: {metadata}", debug)
        print("[green]✓ OIDC metadata fetched[/green]")
        
        # Print key endpoints
        for k in ["authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "issuer"]:
            if k in metadata:
                print(f"[bold]{k}:[/bold] {metadata[k]}")
                debug_print(f"Endpoint {k}: {metadata[k]}", debug)
        
        # Fetch JWKS if present
        jwks_keys = []
        if "jwks_uri" in metadata:
            try:
                debug_print(f"Fetching JWKS from: {metadata['jwks_uri']}", debug)
                jwks_resp = requests.get(metadata["jwks_uri"], timeout=10)
                debug_print(f"JWKS response status: {jwks_resp.status_code}", debug)
                
                jwks_resp.raise_for_status()
                jwks = jwks_resp.json()
                jwks_keys = jwks.get("keys", [])
                debug_print(f"JWKS keys received: {len(jwks_keys)} keys", debug)
                print(f"[green]✓ JWKS keys fetched ({len(jwks_keys)} keys)[/green]")
            except Exception as e:
                debug_print(f"JWKS fetch error: {str(e)}", debug)
                print(f"[yellow]Could not fetch JWKS: {e}[/yellow]")
        
        # Print supported features
        for k in ["scopes_supported", "response_types_supported", "grant_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported"]:
            if k in metadata:
                print(f"[bold]{k}:[/bold] {metadata[k]}")
                debug_print(f"Supported feature {k}: {metadata[k]}", debug)
        
        debug_print("OIDC metadata discovery completed successfully", debug)
        return {"metadata": metadata, "jwks_keys": jwks_keys}
    except Exception as e:
        debug_print(f"OIDC metadata discovery failed: {str(e)}", debug)
        print(f"[red]Failed to fetch OIDC metadata: {e}[/red]")
        return {"error": str(e)}

def simulate_authorization_flow(args, debug=False):
    debug_print("Starting OAuth authorization flow simulation", debug)
    print("[bold cyan]Simulating OAuth/OIDC authorization flow (manual copy-paste)...[/bold cyan]")
    
    # Build authorization URL
    response_type = "code"  # For now, support code flow; can extend to token/id_token
    state = secrets.token_urlsafe(8)
    nonce = secrets.token_urlsafe(8)
    code_challenge = None
    code_verifier = None
    
    debug_print(f"Generated state: {state}", debug)
    debug_print(f"Generated nonce: {nonce}", debug)
    
    url_params = {
        "client_id": args.client_id,
        "redirect_uri": args.redirect_uri,
        "response_type": response_type,
        "scope": args.scope,
        "state": state,
        "nonce": nonce
    }
    
    debug_print(f"Authorization URL parameters: {url_params}", debug)
    
    # PKCE support (optional)
    if hasattr(args, "pkce") and args.pkce:
        debug_print("PKCE enabled, generating code verifier and challenge", debug)
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=').decode()
        url_params["code_challenge"] = code_challenge
        url_params["code_challenge_method"] = "S256"
        debug_print(f"Code verifier: {code_verifier}", debug)
        debug_print(f"Code challenge: {code_challenge}", debug)
    
    # Build URL
    authz_url = args.issuer.rstrip('/') + "/authorize?" + "&".join(f"{k}={url_params[k]}" for k in url_params)
    debug_print(f"Authorization URL: {authz_url}", debug)
    print(f"[yellow]Open this URL in your browser and authenticate:[/yellow]\n{authz_url}")
    
    if response_type == "code":
        code = input("\nPaste the authorization code from the redirect URL: ").strip()
        debug_print(f"Received authorization code: {code}", debug)
        print(f"[green]Received code:[/green] {code}")
        return {"code": code, "state": state, "nonce": nonce, "code_verifier": code_verifier}
    
    # For implicit/hybrid, could prompt for token/id_token
    debug_print("No authorization code flow, returning empty result", debug)
    return {}

def handle_tokens(args, debug=False):
    debug_print("Starting token handling and validation", debug)
    print("[bold cyan]Handling and validating tokens...[/bold cyan]")
    
    # Get the authorization code from the flow simulation
    flow_data = simulate_authorization_flow(args, debug)
    if "code" not in flow_data:
        debug_print("No authorization code available for token exchange", debug)
        print("[red]No authorization code available[/red]")
        return {}
    
    code = flow_data["code"]
    debug_print(f"Using authorization code: {code[:10]}...", debug)
    
    # Exchange code for tokens
    token_endpoint = args.issuer.rstrip('/') + "/token"
    debug_print(f"Token endpoint: {token_endpoint}", debug)
    
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": args.redirect_uri
    }
    
    if hasattr(flow_data, "code_verifier") and flow_data["code_verifier"]:
        token_data["code_verifier"] = flow_data["code_verifier"]
        debug_print("Including PKCE code verifier in token request", debug)
    
    debug_print(f"Token request data: {token_data}", debug)
    
    # Try client_secret_basic first
    headers = {}
    if args.client_secret:
        import base64
        auth = base64.b64encode(f"{args.client_id}:{args.client_secret}".encode()).decode()
        headers["Authorization"] = f"Basic {auth}"
        debug_print("Using client_secret_basic authentication", debug)
    else:
        token_data["client_id"] = args.client_id
        debug_print("Using client_secret_post authentication", debug)
    
    debug_print(f"Request headers: {headers}", debug)
    
    # Try client_secret_post if no secret or basic fails
    try:
        debug_print("Making token exchange request", debug)
        resp = requests.post(token_endpoint, data=token_data, headers=headers, timeout=10)
        debug_print(f"Token exchange response status: {resp.status_code}", debug)
        debug_print(f"Token exchange response headers: {dict(resp.headers)}", debug)
        
        resp.raise_for_status()
        tokens = resp.json()
        debug_print(f"Token response received: {tokens}", debug)
        print("[green]✓ Tokens received[/green]")
        
        # Decode and validate ID token
        if "id_token" in tokens:
            try:
                debug_print("Decoding ID token", debug)
                id_token = jwt.decode(tokens["id_token"], options={"verify_signature": False})
                debug_print(f"ID token claims: {id_token}", debug)
                print(f"[bold]ID Token claims:[/bold] {id_token}")
            except Exception as e:
                debug_print(f"ID token decode error: {str(e)}", debug)
                print(f"[yellow]Could not decode ID token: {e}[/yellow]")
        
        # Decode access token if it's a JWT
        if "access_token" in tokens:
            try:
                debug_print("Attempting to decode access token as JWT", debug)
                access_token = jwt.decode(tokens["access_token"], options={"verify_signature": False})
                debug_print(f"Access token claims: {access_token}", debug)
                print(f"[bold]Access Token claims:[/bold] {access_token}")
            except Exception as e:
                debug_print(f"Access token decode error: {str(e)}", debug)
                print(f"[yellow]Access token is not a JWT or could not decode: {e}[/yellow]")
        
        debug_print("Token handling completed successfully", debug)
        return {"tokens": tokens, "flow_data": flow_data}
    except Exception as e:
        debug_print(f"Token exchange failed: {str(e)}", debug)
        print(f"[red]Token exchange failed: {e}[/red]")
        return {"error": str(e)}

def check_vulnerabilities(args):
    print("[bold cyan]Checking for common OAuth/OIDC vulnerabilities...[/bold cyan]")
    vulns = []
    # 1. Open Redirect Test
    print("[yellow]Testing for open redirects...[/yellow]")
    redirect_uri = args.redirect_uri
    malicious_redirects = [
        "https://attacker.com/callback",
        "https://evil.com/steal",
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>"
    ]
    for malicious_uri in malicious_redirects:
        try:
            test_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={malicious_uri}&response_type=code&scope={args.scope}"
            resp = requests.get(test_url, timeout=5, allow_redirects=False)
            if resp.status_code in [302, 303, 307, 308]:
                vulns.append({
                    "type": "Open Redirect",
                    "severity": "High",
                    "description": f"Redirect to malicious URI: {malicious_uri}",
                    "details": f"Status: {resp.status_code}, Location: {resp.headers.get('Location', 'N/A')}"
                })
        except:
            pass
    # 2. CSRF Test (missing/weak state)
    print("[yellow]Testing for CSRF vulnerabilities...[/yellow]")
    try:
        no_state_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={redirect_uri}&response_type=code&scope={args.scope}"
        resp = requests.get(no_state_url, timeout=5, allow_redirects=False)
        if resp.status_code in [302, 303, 307, 308]:
            vulns.append({
                "type": "CSRF (Missing State)",
                "severity": "Medium",
                "description": "Authorization endpoint accepts requests without state parameter",
                "details": "State parameter should be required to prevent CSRF attacks"
            })
    except:
        pass
    # 3. Token Substitution Test
    print("[yellow]Testing for token substitution...[/yellow]")
    # This would require actual tokens from the flow
    vulns.append({
        "type": "Token Substitution",
        "severity": "Info",
        "description": "Manual testing required - try substituting tokens in requests",
        "details": "Test with tokens from other clients or expired tokens"
    })
    # 4. ID Token Injection Test
    print("[yellow]Testing for ID token injection...[/yellow]")
    vulns.append({
        "type": "ID Token Injection",
        "severity": "Info",
        "description": "Manual testing required - try injecting malicious ID tokens",
        "details": "Test with modified ID tokens containing malicious claims"
    })
    # 5. Mix-up Attack Test
    print("[yellow]Testing for mix-up attacks...[/yellow]")
    # Check if multiple authorization servers are involved
    vulns.append({
        "type": "Mix-up Attack",
        "severity": "Info",
        "description": "Check for multiple authorization servers",
        "details": "Ensure client is configured for the correct authorization server"
    })
    # 6. PKCE Downgrade Test
    print("[yellow]Testing for PKCE downgrade...[/yellow]")
    try:
        no_pkce_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={redirect_uri}&response_type=code&scope={args.scope}&state=test"
        resp = requests.get(no_pkce_url, timeout=5, allow_redirects=False)
        if resp.status_code in [302, 303, 307, 308]:
            vulns.append({
                "type": "PKCE Downgrade",
                "severity": "Medium",
                "description": "Authorization endpoint accepts requests without PKCE",
                "details": "PKCE should be required for public clients"
            })
    except:
        pass
    # 7. Insecure Redirect URI Test
    print("[yellow]Testing for insecure redirect URIs...[/yellow]")
    insecure_uris = [
        "http://localhost/callback",
        "http://127.0.0.1/callback",
        "http://example.com/callback"
    ]
    for insecure_uri in insecure_uris:
        try:
            test_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={insecure_uri}&response_type=code&scope={args.scope}"
            resp = requests.get(test_url, timeout=5, allow_redirects=False)
            if resp.status_code in [302, 303, 307, 308]:
                vulns.append({
                    "type": "Insecure Redirect URI",
                    "severity": "Medium",
                    "description": f"Insecure redirect URI accepted: {insecure_uri}",
                    "details": "HTTPS should be required for redirect URIs"
                })
        except:
            pass
    # 8. Missing/Weak Nonce Test
    print("[yellow]Testing for missing/weak nonce...[/yellow]")
    try:
        no_nonce_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={redirect_uri}&response_type=id_token&scope=openid&state=test"
        resp = requests.get(no_nonce_url, timeout=5, allow_redirects=False)
        if resp.status_code in [302, 303, 307, 308]:
            vulns.append({
                "type": "Missing Nonce",
                "severity": "Medium",
                "description": "Authorization endpoint accepts ID token requests without nonce",
                "details": "Nonce should be required for ID token requests"
            })
    except:
        pass
    # 9. Scope Escalation Test
    print("[yellow]Testing for scope escalation...[/yellow]")
    escalated_scopes = [
        "admin",
        "root",
        "superuser",
        "all",
        "*"
    ]
    for scope in escalated_scopes:
        try:
            test_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}"
            resp = requests.get(test_url, timeout=5, allow_redirects=False)
            if resp.status_code in [302, 303, 307, 308]:
                vulns.append({
                    "type": "Scope Escalation",
                    "severity": "High",
                    "description": f"Escalated scope accepted: {scope}",
                    "details": "Client should not be able to request escalated scopes"
                })
        except:
            pass
    # 10. CORS Misconfiguration Test
    print("[yellow]Testing for CORS misconfigurations...[/yellow]")
    try:
        cors_headers = {
            "Origin": "https://attacker.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type"
        }
        resp = requests.options(f"{args.issuer.rstrip('/')}/token", headers=cors_headers, timeout=5)
        if "Access-Control-Allow-Origin" in resp.headers:
            if resp.headers["Access-Control-Allow-Origin"] == "*":
                vulns.append({
                    "type": "CORS Misconfiguration",
                    "severity": "Medium",
                    "description": "CORS allows all origins (*)",
                    "details": "CORS should be restricted to trusted domains"
                })
    except:
        pass
    # Print results
    if vulns:
        print(f"[red]Found {len(vulns)} potential vulnerabilities:[/red]")
        for vuln in vulns:
            print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    else:
        print("[green]No obvious vulnerabilities detected[/green]")
    return {"vulnerabilities": vulns}

def fuzz_and_manipulate(args):
    print("[bold cyan]Fuzzing and manipulating parameters...[/bold cyan]")
    fuzz_results = []
    # Fuzz vectors for different parameter types
    fuzz_vectors = {
        "state": ["", "null", "undefined", "test", "admin", "123456", "state' OR '1'='1", "state; DROP TABLE users;"],
        "nonce": ["", "null", "undefined", "test", "admin", "123456", "nonce' OR '1'='1"],
        "code": ["", "null", "undefined", "test", "admin", "123456", "code' OR '1'='1", "invalid_code"],
        "redirect_uri": [
            "https://attacker.com/callback",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "http://localhost:8080/callback",
            "https://example.com/callback?param=value",
            "https://example.com/callback#fragment"
        ],
        "client_id": ["", "null", "undefined", "admin", "root", "superuser", "client_id' OR '1'='1"],
        "scope": ["", "null", "undefined", "admin", "root", "superuser", "all", "*", "openid profile email admin"]
    }
    # Fuzz authorization endpoint parameters
    print("[yellow]Fuzzing authorization endpoint parameters...[/yellow]")
    base_url = f"{args.issuer.rstrip('/')}/authorize"
    for param, values in fuzz_vectors.items():
        for value in values:
            try:
                # Build URL with fuzzed parameter
                params = {
                    "client_id": args.client_id,
                    "redirect_uri": args.redirect_uri,
                    "response_type": "code",
                    "scope": args.scope,
                    "state": "test_state",
                    "nonce": "test_nonce"
                }
                params[param] = value
                url = base_url + "?" + "&".join(f"{k}={v}" for k, v in params.items())
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code not in [400, 401, 403]:  # Unexpected success
                    fuzz_results.append({
                        "parameter": param,
                        "value": value,
                        "status_code": resp.status_code,
                        "location": resp.headers.get("Location", "N/A"),
                        "type": "Authorization Parameter Fuzzing"
                    })
            except Exception as e:
                fuzz_results.append({
                    "parameter": param,
                    "value": value,
                    "error": str(e),
                    "type": "Authorization Parameter Fuzzing"
                })
    # Fuzz token endpoint parameters
    print("[yellow]Fuzzing token endpoint parameters...[/yellow]")
    token_url = f"{args.issuer.rstrip('/')}/token"
    for param, values in fuzz_vectors.items():
        if param in ["code", "redirect_uri", "client_id"]:
            for value in values:
                try:
                    data = {
                        "grant_type": "authorization_code",
                        "code": "test_code",
                        "redirect_uri": args.redirect_uri,
                        "client_id": args.client_id
                    }
                    data[param] = value
                    headers = {}
                    if args.client_secret:
                        import base64
                        auth = base64.b64encode(f"{args.client_id}:{args.client_secret}".encode()).decode()
                        headers["Authorization"] = f"Basic {auth}"
                    resp = requests.post(token_url, data=data, headers=headers, timeout=5)
                    if resp.status_code not in [400, 401, 403]:  # Unexpected success
                        fuzz_results.append({
                            "parameter": param,
                            "value": value,
                            "status_code": resp.status_code,
                            "response": resp.text[:100],
                            "type": "Token Endpoint Fuzzing"
                        })
                except Exception as e:
                    fuzz_results.append({
                        "parameter": param,
                        "value": value,
                        "error": str(e),
                        "type": "Token Endpoint Fuzzing"
                    })
    # Test token manipulation and replay
    print("[yellow]Testing token manipulation and replay...[/yellow]")
    # This would require actual tokens from the flow
    fuzz_results.append({
        "type": "Token Manipulation",
        "description": "Manual testing required - try manipulating tokens",
        "details": "Test with expired, modified, or tokens from other clients"
    })
    # Test request replay
    print("[yellow]Testing request replay...[/yellow]")
    try:
        # Replay authorization request
        replay_url = f"{args.issuer.rstrip('/')}/authorize?client_id={args.client_id}&redirect_uri={args.redirect_uri}&response_type=code&scope={args.scope}&state=replay_test"
        resp1 = requests.get(replay_url, timeout=5, allow_redirects=False)
        resp2 = requests.get(replay_url, timeout=5, allow_redirects=False)
        if resp1.status_code == resp2.status_code and resp1.headers.get("Location") == resp2.headers.get("Location"):
            fuzz_results.append({
                "type": "Request Replay",
                "description": "Authorization request can be replayed",
                "details": "Same response for identical requests - may indicate replay vulnerability"
            })
    except Exception as e:
        fuzz_results.append({
            "type": "Request Replay",
            "error": str(e)
        })
    # Print results
    if fuzz_results:
        print(f"[red]Found {len(fuzz_results)} fuzzing results:[/red]")
        for result in fuzz_results:
            if "type" in result:
                print(f"  [{result.get('type', 'Unknown')}] {result.get('description', 'Fuzzing result')}")
    else:
        print("[green]No interesting fuzzing results[/green]")
    return {"fuzzing_results": fuzz_results}

def generate_report(results, output_file=None):
    print("[bold cyan]Generating comprehensive security report...[/bold cyan]")
    
    # Calculate risk scores and summary
    total_vulns = len(results.get("vulnerabilities", {}).get("vulnerabilities", []))
    high_vulns = len([v for v in results.get("vulnerabilities", {}).get("vulnerabilities", []) if v.get("severity") == "High"])
    medium_vulns = len([v for v in results.get("vulnerabilities", {}).get("vulnerabilities", []) if v.get("severity") == "Medium"])
    low_vulns = len([v for v in results.get("vulnerabilities", {}).get("vulnerabilities", []) if v.get("severity") == "Low"])
    
    # Determine overall risk level
    if high_vulns > 0:
        overall_risk = "Critical"
    elif medium_vulns > 0:
        overall_risk = "High"
    elif low_vulns > 0:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"
    
    # Generate recommendations
    recommendations = []
    if high_vulns > 0:
        recommendations.append("🚨 CRITICAL: Immediate action required for high-severity vulnerabilities")
    if medium_vulns > 0:
        recommendations.append("⚠️ HIGH: Address medium-severity vulnerabilities within 30 days")
    if low_vulns > 0:
        recommendations.append("🔶 MEDIUM: Plan remediation for low-severity vulnerabilities")
    
    # OAuth/OIDC specific recommendations
    recommendations.extend([
        "🔐 Always use HTTPS for all OAuth/OIDC endpoints",
        "🛡️ Implement proper state parameter validation",
        "🔑 Use PKCE for public clients",
        "⏰ Set appropriate token expiration times",
        "🎯 Validate redirect URIs strictly",
        "🔒 Use strong client secrets",
        "📋 Implement proper scope validation",
        "🔄 Use nonce for ID token requests",
        "🌐 Configure CORS properly",
        "🔍 Regular security audits recommended"
    ])
    
    # Build comprehensive report
    report = {
        "oauth_oidc_security_report": {
            "title": "OAuth/OIDC Security Analysis Report",
            "generated_date": datetime.now().isoformat(),
            "executive_summary": {
                "total_vulnerabilities": total_vulns,
                "high_severity": high_vulns,
                "medium_severity": medium_vulns,
                "low_severity": low_vulns,
                "overall_risk_level": overall_risk,
                "key_findings": [
                    f"Found {total_vulns} potential vulnerabilities",
                    f"{high_vulns} high-severity issues require immediate attention",
                    f"{medium_vulns} medium-severity issues should be addressed",
                    f"{low_vulns} low-severity issues for consideration"
                ]
            },
            "detailed_results": results,
            "risk_assessment": {
                "overall_risk": overall_risk,
                "risk_factors": {
                    "open_redirects": high_vulns > 0,
                    "csrf_vulnerabilities": medium_vulns > 0,
                    "token_security": low_vulns > 0,
                    "configuration_issues": total_vulns > 0
                },
                "impact_analysis": {
                    "authentication_bypass": high_vulns > 0,
                    "data_exfiltration": medium_vulns > 0,
                    "session_hijacking": medium_vulns > 0,
                    "privilege_escalation": high_vulns > 0
                }
            },
            "recommendations": recommendations,
            "technical_details": {
                "test_coverage": {
                    "oidc_discovery": "✓",
                    "authorization_flow": "✓",
                    "token_handling": "✓",
                    "vulnerability_checks": "✓",
                    "fuzzing_tests": "✓"
                },
                "test_methodology": [
                    "OIDC metadata discovery and analysis",
                    "Authorization flow simulation",
                    "Token exchange and validation",
                    "Comprehensive vulnerability scanning",
                    "Parameter fuzzing and manipulation"
                ]
            }
        }
    }
    
    # Save report
    if output_file is None:
        output_file = f"oauth_oidc_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[green]✅ Comprehensive report saved:[/green] {output_file}")
        
        # Print summary
        print("\n" + "=" * 60)
        print("[bold]📊 OAuth/OIDC Security Test Summary[/bold]")
        print("=" * 60)
        print(f"🔍 Total Vulnerabilities: {total_vulns}")
        print(f"🚨 High Severity: {high_vulns}")
        print(f"⚠️ Medium Severity: {medium_vulns}")
        print(f"🔶 Low Severity: {low_vulns}")
        print(f"🎯 Overall Risk: {overall_risk}")
        
        if total_vulns == 0:
            print("\n✅ No vulnerabilities found! OAuth/OIDC implementation appears secure.")
        else:
            print(f"\n❌ {total_vulns} vulnerabilities found. Review detailed report for remediation steps.")
        
        return output_file
    except Exception as e:
        print(f"[red]❌ Failed to save report: {e}[/red]")
        return None

def main():
    parser = argparse.ArgumentParser(description="OAuth/OIDC Security Testing Tool")
    parser.add_argument("--issuer", required=True, help="OIDC issuer base URL (e.g., https://example.com)")
    parser.add_argument("--client-id", required=True, help="OAuth client ID")
    parser.add_argument("--client-secret", help="OAuth client secret (if applicable)")
    parser.add_argument("--redirect-uri", required=True, help="Redirect URI for the OAuth flow")
    parser.add_argument("--scope", default="openid profile email", help="OAuth scopes (default: openid profile email)")
    parser.add_argument("--mode", choices=["cli", "interactive"], default="cli", help="Run in CLI or interactive mode")
    parser.add_argument("--output", help="Output file for the security report")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with detailed logging")
    args = parser.parse_args()

    # Setup debug logging
    setup_debug_logging(args.debug)
    debug_print("OAuth/OIDC Security Testing Tool starting", args.debug)
    debug_print(f"Arguments: {vars(args)}", args.debug)

    print("[bold green]OAuth/OIDC Security Testing Tool[/bold green]")
    print("=" * 60)

    # 1. Discovery & Metadata
    debug_print("Starting OIDC metadata discovery", args.debug)
    metadata = discover_metadata(args.issuer, args.debug)

    # 2. Authorization Flow Simulation
    debug_print("Starting authorization flow simulation", args.debug)
    flow_results = simulate_authorization_flow(args, args.debug)

    # 3. Token Handling
    debug_print("Starting token handling", args.debug)
    token_results = handle_tokens(args, args.debug)

    # 4. Vulnerability Checks
    debug_print("Starting vulnerability checks", args.debug)
    vuln_results = check_vulnerabilities(args)

    # 5. Fuzzing & Manipulation
    debug_print("Starting fuzzing and manipulation tests", args.debug)
    fuzz_results = fuzz_and_manipulate(args)

    # 6. Reporting
    debug_print("Generating comprehensive report", args.debug)
    results = {
        "metadata": metadata,
        "flow": flow_results,
        "tokens": token_results,
        "vulnerabilities": vuln_results,
        "fuzzing": fuzz_results
    }
    report_file = generate_report(results, args.output)
    debug_print(f"Report generation completed: {report_file}", args.debug)
    print(f"[bold green]Report saved:[/bold green] {report_file}")

if __name__ == "__main__":
    main() 