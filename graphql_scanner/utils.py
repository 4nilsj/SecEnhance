import shlex
import argparse
from typing import Dict, Any, Optional

def parse_curl(curl_command: str) -> Dict[str, Any]:
    """
    Parses a simple cURL command to extract URL, method, headers, and data.
    """
    if not curl_command.strip().startswith("curl"):
        raise ValueError("Command must start with 'curl'")

    # Split command using shlex to handle quotes correctly
    try:
        args = shlex.split(curl_command)
    except Exception as e:
        raise ValueError(f"Failed to parse cURL command args: {e}")

    # Remove 'curl'
    if args and args[0] == "curl":
        args = args[1:]

    # Use argparse to parse known cURL arguments
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("url", nargs="?")
    parser.add_argument("-X", "--request", dest="method", default="GET")
    parser.add_argument("-H", "--header", action="append", dest="headers", default=[])
    parser.add_argument("-b", "--cookie", dest="cookie", default=None)
    parser.add_argument("-d", "--data", "--data-raw", "--data-binary", dest="data", default=None)
    
    # We parse known args, and ignore unknowns for simplicity (real curl has many flags)
    try:
        parsed_args, unknown = parser.parse_known_args(args)
    except Exception as e:
        raise ValueError(f"Failed to parse arguments: {e}")

    url = parsed_args.url
    # Sometimes URL is not a positional arg but just sitting there if we didn't specify it properly? 
    # Argparse usually grabs the first positional as URL.
    # If users put flags before URL, argparse handles it if defined.
    
    # If URL is missing in parsed args (maybe parsed as unknown if mixed strangely), 
    # try to find a standalone string starting with http/https in unknown
    if not url:
        for arg in unknown:
            if arg.startswith("http"):
                url = arg
                break
    
    if not url:
        raise ValueError("Could not find URL in cURL command")

    headers = {}
    for h in parsed_args.headers:
        if ":" in h:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()

    # Handle Cookie header specifically or -b flag
    cookies = parsed_args.cookie
    
    # If Cookie header exists, it overrides/merges with -b? 
    # For now, let's prioritize explicit -b, otherwise look in headers.
    if "Cookie" in headers and not cookies:
        cookies = headers.pop("Cookie") # Remove from headers to avoid dupes if client handles cookies separately
    
    return {
        "url": url,
        "method": parsed_args.method,
        "headers": headers,
        "cookies": cookies,
        "data": parsed_args.data
    }
