"""
Parsers mínimos de manifiestos de dependencias, para alimentar consultas a
OSV.dev. Cubre los casos más comunes de un server MCP (Python/Node); no
pretende ser un resolvedor de lockfiles completo.
"""
from __future__ import annotations
import json
import os
import re


def _find(source_path: str, filename: str) -> str | None:
    if os.path.isfile(source_path) and os.path.basename(source_path) == filename:
        return source_path
    candidate = os.path.join(source_path, filename)
    return candidate if os.path.isfile(candidate) else None


def parse_requirements_txt(path: str) -> list[dict]:
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if m:
                out.append({"name": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
            else:
                m2 = re.match(r"^([A-Za-z0-9_.\-]+)", line)
                if m2:
                    out.append({"name": m2.group(1), "version": None, "ecosystem": "PyPI"})
    return out


def parse_package_lock(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    out = []
    if "packages" in data:  # lockfileVersion 2/3
        for pkg_path, info in data["packages"].items():
            if not pkg_path or not isinstance(info, dict):
                continue
            name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
            version = info.get("version")
            if name and version:
                out.append({"name": name, "version": version, "ecosystem": "npm"})
    elif "dependencies" in data:  # lockfileVersion 1
        def walk(deps: dict):
            for name, info in deps.items():
                if isinstance(info, dict) and info.get("version"):
                    out.append({"name": name, "version": info["version"], "ecosystem": "npm"})
                if isinstance(info, dict) and info.get("dependencies"):
                    walk(info["dependencies"])
        walk(data["dependencies"])
    return out


def parse_package_json(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, range_spec in (data.get(section) or {}).items():
            version = re.sub(r"^[~^>=<\s]+", "", str(range_spec)) or None
            if version and not re.match(r"^\d", version):  # rango tipo "*" o "workspace:" -> sin versión fiable
                version = None
            out.append({"name": name, "version": version, "ecosystem": "npm"})
    return out


def discover_packages(source_path: str) -> list[dict]:
    """Detecta manifiestos conocidos bajo source_path y devuelve la lista combinada
    de {name, version, ecosystem} lista para OSV. Prioriza lockfiles (versión exacta)
    sobre manifiestos declarativos (rango)."""
    packages: list[dict] = []
    seen = set()

    def add_all(items: list[dict]):
        for p in items:
            key = (p["ecosystem"], p["name"])
            if key in seen:
                continue
            seen.add(key)
            packages.append(p)

    pkg_lock = _find(source_path, "package-lock.json")
    if pkg_lock:
        add_all(parse_package_lock(pkg_lock))
    pkg_json = _find(source_path, "package.json")
    if pkg_json:
        add_all(parse_package_json(pkg_json))

    reqs = _find(source_path, "requirements.txt")
    if reqs:
        add_all(parse_requirements_txt(reqs))

    return packages
