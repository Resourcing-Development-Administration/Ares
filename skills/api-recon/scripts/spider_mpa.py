#!/usr/bin/env python3
"""
spider_mpa.py — Multi-Page Application (MPA) spider.

Crawls a traditional server-rendered MPA (not SPA) by following HTML links,
discovering forms, and extracting API endpoints from inline JS. Unlike harvest_static
which downloads asset files, this follows navigation links up to a given depth.

Usage: python spider_mpa.py <base_url> [--depth 3] [--out spider.json] [--timeout 15]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser
from pathlib import Path

_ENDPOINT_RE = [
    re.compile(r"""(?:fetch|axios\.\w+)\s*\(\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
    re.compile(r"""[`'"](\/api\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
    re.compile(r"""\baction\s*=\s*['"](\/[^'"?#]{2,})[`'"]"""),
]

_DEFAULT_HEADERS = {
    "User-Agent": "Ares/spider-mpa 1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class MpaParser(HTMLParser):
    def __init__(self, base_url: str, current_url: str):
        super().__init__()
        self.base_url = base_url
        self.current_url = current_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._in_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr = dict(attrs)
        if tag == "a":
            href = attr.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                abs_url = urllib.parse.urljoin(self.current_url, href)
                if abs_url.startswith(self.base_url):
                    self.links.append(abs_url.split("#")[0])
        elif tag == "form":
            self._in_form = {
                "action": urllib.parse.urljoin(self.current_url, attr.get("action", self.current_url)),
                "method": attr.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._in_form is not None:
            self._in_form["inputs"].append({
                "name": attr.get("name", ""),
                "type": attr.get("type", "text"),
                "value": attr.get("value", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form is not None:
            self.forms.append(self._in_form)
            self._in_form = None


def _fetch(url: str, timeout: int) -> str | None:
    try:
        req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" not in ct and "text/plain" not in ct:
                return None
            return resp.read(1 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"[spider_mpa] {url}: {exc}", file=sys.stderr)
        return None


def _extract_inline_endpoints(html: str) -> list[str]:
    out: list[str] = []
    for pattern in _ENDPOINT_RE:
        for m in pattern.finditer(html):
            ep = m.group(1)
            if 2 < len(ep) < 200:
                out.append(ep)
    return out


def spider(base_url: str, max_depth: int = 3, timeout: int = 15) -> dict:
    base_url = base_url.rstrip("/")
    t0 = time.time()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(base_url, 0)])

    all_pages: list[dict] = []
    all_forms: list[dict] = []
    all_endpoints: list[str] = []
    endpoint_seen: set[str] = set()

    while queue:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        html = _fetch(url, timeout)
        if html is None:
            continue

        parser = MpaParser(base_url, url)
        parser.feed(html)

        page_endpoints = _extract_inline_endpoints(html)
        for ep in page_endpoints:
            if ep not in endpoint_seen:
                endpoint_seen.add(ep)
                all_endpoints.append(ep)

        all_pages.append({
            "url": url,
            "depth": depth,
            "links": len(parser.links),
            "forms": len(parser.forms),
            "inline_endpoints": len(page_endpoints),
        })
        all_forms.extend(parser.forms)

        for link in parser.links:
            if link not in visited:
                queue.append((link, depth + 1))

    return {
        "base_url": base_url,
        "pages_crawled": len(all_pages),
        "total_forms": len(all_forms),
        "total_endpoints": len(all_endpoints),
        "duration_s": round(time.time() - t0, 2),
        "pages": all_pages,
        "forms": all_forms,
        "inline_endpoints": all_endpoints,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Spider a multi-page application")
    parser.add_argument("url", help="Base URL of the target MPA")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--out", "-o", default="-")
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    result = spider(args.url, max_depth=args.depth, timeout=args.timeout)
    out_json = json.dumps(result, indent=2)
    if args.out == "-":
        print(out_json)
    else:
        Path(args.out).write_text(out_json)
        print(f"[spider_mpa] {result['pages_crawled']} pages, {result['total_endpoints']} endpoints → {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
