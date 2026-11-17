#!/usr/bin/env python3
"""
extract_route_map.py — Extract API route maps from bundled JavaScript files.

Parses JS bundles (webpack, Rollup, Vite) to find route definitions, API calls,
and endpoint patterns. Outputs a structured JSON route map.

Usage: python extract_route_map.py <bundle.js> [--out routes.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Common patterns for API endpoint strings in JS bundles
_ENDPOINT_PATTERNS = [
    # fetch/axios calls: fetch("/api/users"), axios.get("/v1/items")
    re.compile(r"""(?:fetch|axios\.\w+|api\.\w+)\s*\(\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
    # Template literals with /api prefix: `/api/${id}/items`
    re.compile(r"""`(\/api\/[a-zA-Z0-9_/${}.:-]{2,})`"""),
    # Router.get/post/put/patch/delete("/path")
    re.compile(r"""router\.\w+\s*\(\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
    # React Router / Vue Router: path: "/users/:id"
    re.compile(r"""path\s*:\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{3,})[`'"]"""),
    # app.get/post/etc (Express-style in SSR bundles)
    re.compile(r"""app\.\w+\s*\(\s*[`'"](\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
    # OpenAPI spec references
    re.compile(r"""[`'"](\/api\/v\d+\/[a-zA-Z0-9_/{}:.-]{2,})[`'"]"""),
]

# Method hints near an endpoint
_METHOD_HINT = re.compile(
    r"""\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b""", re.IGNORECASE
)

# Webpack chunk separators
_CHUNK_SEP = re.compile(r"""(?:__webpack_require__|webpackChunkName|/\*\* @module)""")


def _normalize_endpoint(ep: str) -> str:
    """Normalize dynamic segments: /users/123 → /users/{id}"""
    ep = re.sub(r"/\d{2,}", "/{id}", ep)
    ep = re.sub(r"/[0-9a-f]{24,}(?=/|$)", "/{id}", ep)  # MongoDB IDs
    ep = re.sub(r"/[0-9a-f-]{36}(?=/|$)", "/{id}", ep)   # UUIDs
    return ep


def _extract_from_chunk(chunk: str) -> list[dict]:
    routes: list[dict] = []
    seen: set[str] = set()
    lines = chunk.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern in _ENDPOINT_PATTERNS:
            for m in pattern.finditer(line):
                ep = m.group(1)
                if len(ep) < 3 or ep.endswith(".js") or ep.endswith(".css"):
                    continue
                norm = _normalize_endpoint(ep)
                key = norm
                if key in seen:
                    continue
                seen.add(key)
                # Look for method hint on the same line
                method_m = _METHOD_HINT.search(line)
                method = method_m.group(1).upper() if method_m else "UNKNOWN"
                routes.append({
                    "endpoint": norm,
                    "raw": ep,
                    "method": method,
                    "line": lineno,
                })
    return routes


def extract_route_map(js_path: str) -> dict:
    content = Path(js_path).read_text(errors="replace")
    # Split by webpack chunk boundaries for better attribution
    chunks = _CHUNK_SEP.split(content)
    all_routes: list[dict] = []
    seen_global: set[str] = set()
    for chunk in chunks:
        for route in _extract_from_chunk(chunk):
            k = (route["endpoint"], route["method"])
            if k not in seen_global:
                seen_global.add(k)
                all_routes.append(route)

    # Group by prefix
    prefixes: dict[str, list[dict]] = {}
    for r in all_routes:
        parts = r["endpoint"].split("/")
        prefix = "/".join(parts[:3]) if len(parts) >= 3 else r["endpoint"]
        prefixes.setdefault(prefix, []).append(r)

    return {
        "source": js_path,
        "total_routes": len(all_routes),
        "routes": all_routes,
        "by_prefix": {k: v for k, v in sorted(prefixes.items())},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract API route map from JS bundle")
    parser.add_argument("bundle", help="Path to JS bundle file")
    parser.add_argument("--out", "-o", default="-", help="Output JSON file (- for stdout)")
    args = parser.parse_args()

    result = extract_route_map(args.bundle)

    out_json = json.dumps(result, indent=2)
    if args.out == "-":
        print(out_json)
    else:
        Path(args.out).write_text(out_json)
        print(f"[extract_route_map] wrote {result['total_routes']} routes → {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
