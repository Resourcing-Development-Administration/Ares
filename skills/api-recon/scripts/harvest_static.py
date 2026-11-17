#!/usr/bin/env python3
"""
harvest_static.py — Harvest API endpoints from static assets of a web application.

Crawls the target's HTML, discovers linked JS/CSS files, downloads them, and
extracts endpoint patterns. Combines output from extract_route_map.py logic.

Usage: python harvest_static.py <base_url> [--depth N] [--out harvest.json] [--timeout 30]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

# Script/link tags we care about
_ASSET_EXTENSIONS = {".js", ".mjs", ".ts"}
_IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico"}

# Endpoint patterns (same as extract_route_map)
_ENDPOINT_RE = [
    re.compile(r"""(?:fetch|axios\.\w+)\s*\(\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
    re.compile(r"""`(\/api\/[a-zA-Z0-9_/${}.:-]{2,})`"""),
    re.compile(r"""path\s*:\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{3,})[`'"]"""),
    re.compile(r"""[`'"](\/api\/v\d+\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
]

_METHOD_RE = re.compile(r"""\b(GET|POST|PUT|PATCH|DELETE)\b""", re.IGNORECASE)


class LinkParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.scripts: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr_dict = dict(attrs)
        if tag == "script":
            src = attr_dict.get("src", "")
            if src:
                self.scripts.append(urllib.parse.urljoin(self.base_url, src))
        elif tag == "link":
            href = attr_dict.get("href", "")
            rel = attr_dict.get("rel", "")
            if href and "stylesheet" not in rel:
                ext = Path(urllib.parse.urlparse(href).path).suffix.lower()
                if ext in _ASSET_EXTENSIONS:
                    self.links.append(urllib.parse.urljoin(self.base_url, href))


def _fetch(url: str, timeout: int) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Ares/harvest-static 1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"[harvest_static] fetch {url}: {exc}", file=sys.stderr)
        return None


def _extract_endpoints(js: str) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for lineno, line in enumerate(js.splitlines(), 1):
        for pattern in _ENDPOINT_RE:
            for m in pattern.finditer(line):
                ep = m.group(1)
                if len(ep) < 3:
                    continue
                ep = re.sub(r"/\d{2,}", "/{id}", ep)
                ep = re.sub(r"/[0-9a-f-]{36}(?=/|$)", "/{id}", ep)
                if ep in seen:
                    continue
                seen.add(ep)
                method_m = _METHOD_RE.search(line)
                out.append({
                    "endpoint": ep,
                    "method": method_m.group(1).upper() if method_m else "UNKNOWN",
                    "line": lineno,
                })
    return out


def harvest(base_url: str, depth: int = 1, timeout: int = 30) -> dict:
    t0 = time.time()
    # Fetch root HTML
    html = _fetch(base_url, timeout)
    if not html:
        return {"error": f"could not fetch {base_url}", "endpoints": []}

    parser = LinkParser(base_url)
    parser.feed(html)
    js_urls = list(dict.fromkeys(parser.scripts + parser.links))

    # Inline script extraction
    all_endpoints: list[dict] = []
    seen_global: set[str] = set()

    for ep in _extract_endpoints(html):
        k = (ep["endpoint"], ep["method"])
        if k not in seen_global:
            seen_global.add(k)
            ep["source"] = base_url
            all_endpoints.append(ep)

    # Download and parse JS assets
    for js_url in js_urls[:50]:  # cap at 50 files
        ext = Path(urllib.parse.urlparse(js_url).path).suffix.lower()
        if ext in _IGNORE_EXTENSIONS:
            continue
        js = _fetch(js_url, timeout)
        if not js:
            continue
        for ep in _extract_endpoints(js):
            k = (ep["endpoint"], ep["method"])
            if k not in seen_global:
                seen_global.add(k)
                ep["source"] = js_url
                all_endpoints.append(ep)

    return {
        "base_url": base_url,
        "js_files_scanned": len(js_urls),
        "total_endpoints": len(all_endpoints),
        "duration_s": round(time.time() - t0, 2),
        "endpoints": all_endpoints,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Harvest API endpoints from static assets")
    parser.add_argument("url", help="Base URL of the target application")
    parser.add_argument("--depth", type=int, default=1, help="Link-follow depth (default: 1)")
    parser.add_argument("--out", "-o", default="-", help="Output JSON file (- for stdout)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    args = parser.parse_args()

    result = harvest(args.url, depth=args.depth, timeout=args.timeout)

    out_json = json.dumps(result, indent=2)
    if args.out == "-":
        print(out_json)
    else:
        Path(args.out).write_text(out_json)
        print(f"[harvest_static] {result['total_endpoints']} endpoints → {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
