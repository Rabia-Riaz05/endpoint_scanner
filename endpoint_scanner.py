#!/usr/bin/env python3

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl

import requests
from bs4 import BeautifulSoup

# ----------------- Configuration -----------------
USER_AGENT = "EndpointScanner/1.0 (+https://example.com)"
REQUEST_TIMEOUT = 10
DEFAULT_THREADS = 10
MAX_CRAWL = 500  # safety cap on discovered URLs

# simple SQL error signatures
SQL_ERRORS = [
    'you have an error in your sql syntax',
    'mysql_fetch',
    'syntax error',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
]

# payloads (non-destructive): marker for reflection tests
XSS_MARKER = 'INJECTED_MARKER_12345'
XSS_PAYLOAD = XSS_MARKER
SQLI_TEST = "' OR '1'='1"
OPENREDIRECT_TEST_URL = 'https://example.com/'

# ----------------- Helpers -----------------

def norm_url(base, link):
    try:
        return urljoin(base, link)
    except Exception:
        return None


def same_origin(a, b):
    pa = urlparse(a)
    pb = urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def safe_get(url, params=None, allow_redirects=True):
    headers = {'User-Agent': USER_AGENT}
    try:
        r = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects)
        return r
    except Exception as e:
        return None

# ----------------- Discovery -----------------

def discover(domain, scheme='http', depth=2, threads=10):
    """Crawl starting from root of domain and return discovered endpoints (URLs and form actions).
    Only follows same-origin links. Depth-limited breadth-first.
    """
    if not domain.startswith('http'):
        start = f"{scheme}://{domain}"
    else:
        start = domain
    seen = set()
    to_crawl = [start]
    discovered = set()

    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    for d in range(depth):
        if not to_crawl:
            break
        next_level = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(fetch_and_extract, session, url, start): url for url in to_crawl}
            for fut in as_completed(futures):
                base = futures[fut]
                try:
                    urls, forms = fut.result()
                except Exception:
                    continue
                for u in urls:
                    if len(discovered) >= MAX_CRAWL:
                        break
                    if u not in seen and same_origin(start, u):
                        seen.add(u)
                        next_level.append(u)
                        discovered.add(u)
                for form in forms:
                    discovered.add(form)
                if len(discovered) >= MAX_CRAWL:
                    break
        to_crawl = next_level
    # ensure start is included
    discovered.add(start)
    return sorted(discovered)


def fetch_and_extract(session, url, origin):
    urls = set()
    forms = set()
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        text = r.text
        soup = BeautifulSoup(text, 'html.parser')
        # links
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            full = norm_url(url, href)
            if full:
                urls.add(full.split('#')[0])
        # forms
        for f in soup.find_all('form'):
            action = f.get('action') or ''
            method = (f.get('method') or 'get').lower()
            action_url = norm_url(url, action) or url
            # include as endpoint with marker for form and method
            forms.add(f"{method.upper()} {action_url}")
    except Exception:
        pass
    return urls, forms

# ----------------- Checks -----------------

def check_endpoint(url):
    """Run safe checks on single endpoint. Returns dict with findings."""
    result = {
        'endpoint': url,
        'xss': None,
        'sqli': None,
        'open_redirect': None,
        'http_status': None,
        'notes': []
    }

    # parse
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))

    # baseline request
    r0 = safe_get(url)
    if r0 is None:
        result['notes'].append('request_failed')
        return result
    result['http_status'] = r0.status_code
    base_text = r0.text or ''

    # --- XSS (reflected) check: inject marker into each param and look for reflection ---
    if q:
        for key in list(q.keys()):
            q2 = q.copy()
            q2[key] = XSS_PAYLOAD
            r = safe_get(base, params=q2)
            if r and XSS_MARKER in (r.text or ''):
                result['xss'] = {'type': 'reflected', 'param': key, 'payload': XSS_PAYLOAD}
                break
    else:
        # try simple path-based reflection by appending marker
        test_url = url.rstrip('/') + '/' + XSS_PAYLOAD
        r = safe_get(test_url)
        if r and XSS_MARKER in (r.text or ''):
            result['xss'] = {'type': 'reflected_path', 'payload': XSS_PAYLOAD}

    # --- SQLi check: append basic sqli to params or as path ---
    sqli_found = False
    if q:
        for key in list(q.keys()):
            q2 = q.copy()
            q2[key] = SQLI_TEST
            r = safe_get(base, params=q2)
            if r:
                body = (r.text or '').lower()
                if any(err in body for err in SQL_ERRORS):
                    result['sqli'] = {'param': key, 'evidence': 'error_string'}
                    sqli_found = True
                    break
                # boolean-based check
                r_true = safe_get(base, params={**q2})
                r_false = safe_get(base, params={**q2, key: SQLI_TEST + 'randomjunk'})
                if r_true and r_false and r_true.status_code == r_false.status_code and r_true.text != r_false.text:
                    result['sqli'] = {'param': key, 'evidence': 'boolean_difference'}
                    sqli_found = True
                    break
    else:
        # try path injection
        test = base + SQLI_TEST
        r = safe_get(test)
        if r and any(err in (r.text or '').lower() for err in SQL_ERRORS):
            result['sqli'] = {'param': None, 'evidence': 'error_string'}
            sqli_found = True

    # --- Open redirect check: replace common redirect params to point to example.com and see if final URL is external ---
    redirect_params = ['url', 'next', 'ReturnUrl', 'redirect', 'r', 'dest']
    openredir_found = False
    if q:
        for rp in redirect_params:
            if rp in q:
                q2 = q.copy()
                q2[rp] = OPENREDIRECT_TEST_URL
                r = safe_get(base, params=q2, allow_redirects=False)
                # check for immediate Location header
                if r is not None and (300 <= r.status_code < 400) and 'location' in r.headers:
                    loc = r.headers['location']
                    if urlparse(loc).netloc and urlparse(loc).netloc != parsed.netloc:
                        result['open_redirect'] = {'param': rp, 'location': loc}
                        openredir_found = True
                        break
                # follow and check
                r2 = safe_get(base, params=q2, allow_redirects=True)
                if r2 and urlparse(r2.url).netloc != parsed.netloc:
                    result['open_redirect'] = {'param': rp, 'final_url': r2.url}
                    openredir_found = True
                    break

    # mark clean/none
    if not result['xss']:
        result['xss'] = None
    if not result['sqli']:
        result['sqli'] = None
    if not result['open_redirect']:
        result['open_redirect'] = None

    return result

# ----------------- Reporting -----------------

def save_json(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump({'created': int(time.time()), 'results': results}, f, indent=2)


def save_html(results, filename):
    html_rows = []
    for r in results:
        html_rows.append(f"<tr><td>{escape(r['endpoint'])}</td><td>{escape(str(r['http_status']))}</td><td>{escape(json.dumps(r['xss']))}</td><td>{escape(json.dumps(r['sqli']))}</td><td>{escape(json.dumps(r['open_redirect']))}</td></tr>")
    html = f"""<!doctype html>
<html>
<head><meta charset='utf-8'><title>Endpoint Scan Results</title>
<style>table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;font-family:monospace}}</style></head>
<body>
<h1>Endpoint Scan Results</h1>
<table>
<tr><th>Endpoint</th><th>HTTP</th><th>XSS</th><th>SQLi</th><th>Open Redirect</th></tr>
{''.join(html_rows)}
</table>
</body>
</html>"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

# ----------------- CLI -----------------

def main():
    parser = argparse.ArgumentParser(description='Discover endpoints and perform safe web checks (XSS, SQLi, Open-Redirect)')
    parser.add_argument('--domains', required=True, help='Comma-separated domains or starting URLs (e.g. example.com or https://example.com)')
    parser.add_argument('--scheme', default='http', choices=['http', 'https'], help='Default scheme if domain provided')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default 2)')
    parser.add_argument('--threads', type=int, default=DEFAULT_THREADS, help='Concurrency for checks (default 10)')
    parser.add_argument('--out', help='Output JSON filename')
    parser.add_argument('--html', help='Output HTML filename')
    parser.add_argument('--max', type=int, default=200, help='Max endpoints to test')

    args = parser.parse_args()

    domains = [d.strip() for d in args.domains.split(',') if d.strip()]
    all_endpoints = set()
    for d in domains:
        print(f"[+] Discovering endpoints for {d} (depth {args.depth})...")
        eps = discover(d, scheme=args.scheme, depth=args.depth, threads=args.threads)
        print(f"    found {len(eps)} endpoints")
        for e in eps:
            all_endpoints.add(e)
        if len(all_endpoints) >= args.max:
            break

    endpoints = sorted(list(all_endpoints))[:args.max]
    print(f"[+] Testing {len(endpoints)} endpoints with {args.threads} threads")

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_endpoint, ep): ep for ep in endpoints}
        for fut in as_completed(futures):
            ep = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {'endpoint': ep, 'error': str(e)}
            print(f"- {ep} => xss={res.get('xss') is not None}, sqli={res.get('sqli') is not None}, openredir={res.get('open_redirect') is not None}")
            results.append(res)

    if args.out:
        save_json(results, args.out)
        print(f"[+] JSON saved to {args.out}")
    if args.html:
        save_html(results, args.html)
        print(f"[+] HTML saved to {args.html}")


if __name__ == '__main__':
    main()
