#!/usr/bin/env python3
"""
build_perm_tree.py — Build a permission tree from discovered API endpoints.

Takes a route map (from extract_route_map.py, harvest_static.py, or spider_mpa.py)
and builds a hierarchical permission tree showing which HTTP methods are allowed
at each path, categorized by probable RBAC role.

Usage: python build_perm_tree.py routes.json [--out perm_tree.json] [--format text|json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# RBAC heuristics: path prefixes → probable role requirement
_ROLE_HINTS: list[tuple[str, str]] = [
    ("/admin/", "admin"),
    ("/api/admin/", "admin"),
    ("/internal/", "admin"),
    ("/management/", "admin"),
    ("/v1/admin/", "admin"),
    ("/v2/admin/", "admin"),
    ("/api/v1/admin/", "admin"),
    ("/api/v2/admin/", "admin"),
    ("/auth/", "unauthenticated"),
    ("/login", "unauthenticated"),
    ("/register", "unauthenticated"),
    ("/public/", "unauthenticated"),
    ("/health", "unauthenticated"),
    ("/metrics", "monitoring"),
    ("/actuator/", "monitoring"),
    ("/debug/", "developer"),
    ("/swagger", "developer"),
    ("/openapi", "developer"),
    ("/api-docs", "developer"),
    ("/user/", "user"),
    ("/profile/", "user"),
    ("/account/", "user"),
    ("/api/", "user"),
    ("/v1/", "user"),
    ("/v2/", "user"),
]

# Methods that likely require write permission
_WRITE_METHODS = frozenset(["POST", "PUT", "PATCH", "DELETE"])
# Methods that are read-only
_READ_METHODS = frozenset(["GET", "HEAD", "OPTIONS"])


def _infer_role(path: str) -> str:
    for prefix, role in _ROLE_HINTS:
        if path.startswith(prefix) or path.lower().startswith(prefix):
            return role
    return "user"


def _infer_privilege(method: str, path: str) -> str:
    if method in _WRITE_METHODS:
        if any(kw in path for kw in ("/admin", "/delete", "/ban", "/reset", "/grant")):
            return "elevated_write"
        return "write"
    return "read"


def build_perm_tree(routes: list[dict]) -> dict:
    """
    Build permission tree from a list of route dicts with 'endpoint' and 'method' keys.
    """
    # Group by normalized path
    by_path: dict[str, dict] = {}
    for route in routes:
        path = route.get("endpoint") or route.get("path") or ""
        method = (route.get("method") or "UNKNOWN").upper()
        if path not in by_path:
            by_path[path] = {
                "path": path,
                "methods": [],
                "role": _infer_role(path),
                "privileges": set(),
            }
        node = by_path[path]
        if method not in node["methods"]:
            node["methods"].append(method)
        node["privileges"].add(_infer_privilege(method, path))

    # Convert to tree structure
    tree: dict = {"children": {}, "paths": []}

    for path, node in sorted(by_path.items()):
        node["privileges"] = sorted(node["privileges"])
        # Insert into tree
        parts = [p for p in path.split("/") if p]
        cur = tree
        for i, part in enumerate(parts):
            if part not in cur["children"]:
                cur["children"][part] = {"children": {}, "paths": []}
            if i == len(parts) - 1:
                cur["children"][part]["paths"].append(node)
            else:
                cur = cur["children"][part]

    # Summary by role
    by_role: dict[str, list] = defaultdict(list)
    for node in by_path.values():
        by_role[node["role"]].append(node)

    # Security observations
    observations: list[str] = []
    admin_paths = by_role.get("admin", [])
    if admin_paths:
        observations.append(f"{len(admin_paths)} admin endpoint(s) found — verify access control")
    unauth_paths = by_role.get("unauthenticated", [])
    write_unauth = [p for p in unauth_paths if any(m in _WRITE_METHODS for m in p["methods"])]
    if write_unauth:
        observations.append(f"{len(write_unauth)} unauthenticated write endpoint(s) found — potential CSRF/SSRF risk")
    debug_paths = by_role.get("developer", [])
    if debug_paths:
        observations.append(f"{len(debug_paths)} debug/documentation endpoint(s) exposed — check production deployment")

    return {
        "total_paths": len(by_path),
        "by_role": {role: [n["path"] for n in nodes] for role, nodes in by_role.items()},
        "observations": observations,
        "tree": tree,
        "flat": sorted(by_path.values(), key=lambda n: n["path"]),
    }


def _print_text(tree: dict) -> None:
    print(f"Total paths: {tree['total_paths']}")
    print()
    print("By role:")
    for role, paths in sorted(tree["by_role"].items()):
        print(f"  {role} ({len(paths)}):")
        for p in sorted(paths)[:20]:
            print(f"    {p}")
        if len(paths) > 20:
            print(f"    ... and {len(paths) - 20} more")
    print()
    if tree["observations"]:
        print("Security observations:")
        for obs in tree["observations"]:
            print(f"  ! {obs}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build permission tree from route map")
    parser.add_argument("routes", help="JSON file with routes (from extract_route_map, harvest_static, etc.)")
    parser.add_argument("--out", "-o", default="-")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    data = json.loads(Path(args.routes).read_text())
    # Support multiple input formats
    routes = (
        data if isinstance(data, list)
        else data.get("routes") or data.get("endpoints") or data.get("inline_endpoints") or []
    )
    # Normalize string endpoints
    routes = [r if isinstance(r, dict) else {"endpoint": r, "method": "UNKNOWN"} for r in routes]

    result = build_perm_tree(routes)

    if args.format == "text":
        _print_text(result)
        return

    out_json = json.dumps(result, indent=2, default=list)
    if args.out == "-":
        print(out_json)
    else:
        Path(args.out).write_text(out_json)
        print(f"[build_perm_tree] {result['total_paths']} paths → {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
