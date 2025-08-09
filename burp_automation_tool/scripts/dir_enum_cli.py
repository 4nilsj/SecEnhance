#!/usr/bin/env python3
"""
Directory Enumeration CLI (Dirb/DirBuster-like)

Features:
- Concurrent enumeration of directories and files
- Optional extensions (e.g., -e php,txt,html)
- Include/exclude HTTP status filters
- Redirect handling, timeouts, custom headers and user-agent
- Output to JSON and/or plaintext

Example:
  python scripts/dir_enum_cli.py https://target.tld/ -w wordlist.txt -e php,txt -t 30 \
    --status 200,204,301,302,401,403 --output artifacts/enum
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import urllib.request
import urllib.error

DEFAULT_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 8

BUILTIN_WORDS = [
    "admin", "login", "logout", "api", "v1", "v2", "test", "backup", "config",
    "uploads", "static", "assets", "images", "css", "js", ".git", ".env",
]

@dataclass
class Finding:
    url: str
    status: int
    length: Optional[int]
    location: Optional[str]


def _http_request(url: str, method: str, headers: Dict[str, str], timeout: int, follow_redirects: bool) -> Tuple[int, Optional[int], Optional[str]]:
    req = urllib.request.Request(url, method=method, headers=headers)
    opener = urllib.request.build_opener()
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPErrorProcessor):
            def http_response(self, request, response):
                return response
            https_response = http_response
        opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, 'status', resp.getcode())
            length = resp.headers.get('Content-Length')
            loc = resp.headers.get('Location')
            return int(status), int(length) if length and length.isdigit() else None, loc
    except urllib.error.HTTPError as e:
        status = e.code
        length = e.headers.get('Content-Length') if e.headers else None
        loc = e.headers.get('Location') if e.headers else None
        return int(status), int(length) if length and str(length).isdigit() else None, loc
    except urllib.error.URLError:
        return -1, None, None


def _candidate_urls(base: str, word: str, exts: List[str], add_dirs: bool) -> List[str]:
    urls: List[str] = []
    # Ensure base ends with '/'
    b = base if base.endswith('/') else base + '/'
    # Files with extensions
    for ext in exts or [""]:
        suffix = ("." + ext.strip('.')) if ext else ""
        urls.append(urljoin(b, word + suffix))
    # Directories (trailing slash)
    if add_dirs:
        urls.append(urljoin(b, word + '/'))
    return urls


def load_words(path: Optional[str]) -> List[str]:
    if not path:
        return BUILTIN_WORDS
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    words: List[str] = []
    with p.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            words.append(line)
    return words


def enumerate_targets(base: str, words: List[str], exts: List[str], threads: int, method: str,
                      statuses: Optional[set[int]], exclude_statuses: Optional[set[int]], timeout: int,
                      follow_redirects: bool, headers: Dict[str, str], include_dirs: bool) -> List[Finding]:
    findings: List[Finding] = []
    seen: set[str] = set()

    def task(url: str) -> Optional[Finding]:
        if url in seen:
            return None
        seen.add(url)
        st, ln, loc = _http_request(url, method, headers, timeout, follow_redirects)
        if st < 0:
            return None
        if statuses and st not in statuses:
            return None
        if exclude_statuses and st in exclude_statuses:
            return None
        return Finding(url=url, status=st, length=ln, location=loc)

    candidates: List[str] = []
    for w in words:
        candidates.extend(_candidate_urls(base, w, exts, add_dirs=include_dirs))

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(task, u) for u in candidates]
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            if res:
                findings.append(res)
    return findings


def write_output(findings: List[Finding], out_prefix: Optional[str]) -> None:
    if not out_prefix:
        for f in findings:
            line = f"{f.status}\t{f.length or '-'}\t{f.url}"
            if f.location:
                line += f" -> {f.location}"
            print(line)
        return
    out_dir = Path(out_prefix).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    txt_path = Path(f"{out_prefix}.txt")
    json_path = Path(f"{out_prefix}.json")
    with txt_path.open('w', encoding='utf-8') as tf:
        for f in findings:
            line = f"{f.status}\t{f.length or '-'}\t{f.url}"
            if f.location:
                line += f" -> {f.location}"
            tf.write(line + "\n")
    with json_path.open('w', encoding='utf-8') as jf:
        json.dump([f.__dict__ for f in findings], jf, indent=2)
    print(f"Wrote {txt_path} and {json_path}")


def parse_statuses(s: Optional[str]) -> Optional[set[int]]:
    if not s:
        return None
    vals = set()
    for part in s.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            vals.add(int(part))
        except ValueError:
            pass
    return vals


def main(argv=None):
    ap = argparse.ArgumentParser(description="Directory enumeration CLI")
    ap.add_argument('url', help='Base URL, e.g., https://target.tld/app/')
    ap.add_argument('-w', '--wordlist', help='Path to wordlist file')
    ap.add_argument('-e', '--extensions', default='', help='Comma-separated extensions, e.g., php,txt,html')
    ap.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS, help='Number of threads (default 20)')
    ap.add_argument('-m', '--method', default='GET', choices=['GET','HEAD'], help='HTTP method (default GET)')
    ap.add_argument('--status', help='Include only these statuses (comma-separated). Default common positives.')
    ap.add_argument('--exclude-status', help='Exclude these statuses (comma-separated)')
    ap.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Timeout seconds (default 8)')
    ap.add_argument('--no-redirects', action='store_true', help='Do not follow redirects')
    ap.add_argument('--ua', '--user-agent', dest='user_agent', default='DirEnumCLI/1.0', help='User-Agent')
    ap.add_argument('-H', '--header', action='append', default=[], help='Custom header, e.g., "Authorization: Bearer X"')
    ap.add_argument('--output', help='Output prefix (without extension), e.g., artifacts/enum/scan1')
    ap.add_argument('--no-dirs', action='store_true', help='Do not probe directory variants (trailing slash)')

    args = ap.parse_args(argv)

    exts = [x.strip() for x in args.extensions.split(',') if x.strip()]
    words = load_words(args.wordlist)
    statuses = parse_statuses(args.status) or DEFAULT_STATUSES
    exclude = parse_statuses(args.exclude_status)

    headers: Dict[str, str] = {"User-Agent": args.user_agent}
    for h in args.header:
        if ':' in h:
            k, v = h.split(':', 1)
            headers[k.strip()] = v.strip()

    findings = enumerate_targets(
        base=args.url,
        words=words,
        exts=exts,
        threads=args.threads,
        method=args.method,
        statuses=statuses,
        exclude_statuses=exclude,
        timeout=args.timeout,
        follow_redirects=not args.no_redirects,
        headers=headers,
        include_dirs=not args.no_dirs,
    )

    findings.sort(key=lambda f: (f.status, f.url))
    write_output(findings, args.output)


if __name__ == '__main__':
    main()