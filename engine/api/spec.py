"""
Carga de endpoints desde OpenAPI 3.x / Swagger 2 (JSON o YAML) y colecciones Postman v2.x, o
descubrimiento automático del spec en rutas comunes. Todo lo que viene del spec es NO CONFIABLE
(lo sirve el target): topes de cantidad y profundidad, nunca se ejecuta nada de él.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field

import yaml

MAX_ENDPOINTS = 400
SPEC_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api/openapi.json", "/api-docs",
              "/swagger/v1/swagger.json", "/openapi.yaml", "/api/v1/openapi.json", "/docs/openapi.json"]
_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


@dataclass
class Endpoint:
    method: str
    path: str                                   # con {param}
    params: list[dict] = field(default_factory=list)   # {name, in, required, schema}
    body_schema: dict | None = None
    secured: bool | None = None                 # None = el spec no lo dice
    summary: str = ""

    @property
    def path_params(self): return [p for p in self.params if p["in"] == "path"]
    @property
    def key(self): return f"{self.method} {self.path}"


def _deref(node, root, depth=0):
    if depth > 8 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        cur = root
        for part in ref[2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(cur, dict) else None
        return _deref(cur, root, depth + 1) if cur is not None else {}
    return node


def parse_openapi(doc: dict) -> list[Endpoint]:
    out: list[Endpoint] = []
    base = ""
    if "swagger" in doc:
        base = doc.get("basePath", "") or ""
    elif doc.get("servers"):
        from urllib.parse import urlparse
        u = (doc["servers"][0] or {}).get("url", "")
        base = urlparse(u).path if "://" in u else (u if u.startswith("/") else "")
    global_sec = doc.get("security")
    for path, item in (doc.get("paths") or {}).items():
        item = _deref(item, doc)
        if not isinstance(item, dict):
            continue
        shared = [_deref(p, doc) for p in item.get("parameters", []) or []]
        for m in _METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            params = []
            for p in shared + [_deref(x, doc) for x in op.get("parameters", []) or []]:
                if isinstance(p, dict) and p.get("name"):
                    params.append({"name": p["name"], "in": p.get("in", "query"), "required": bool(p.get("required")),
                                   "schema": _deref(p.get("schema") or {"type": p.get("type", "string")}, doc)})
            body = None
            rb = _deref(op.get("requestBody") or {}, doc)
            if isinstance(rb, dict):
                content = rb.get("content") or {}
                js = content.get("application/json") or next(iter(content.values()), None)
                if isinstance(js, dict):
                    body = _deref(js.get("schema") or {}, doc)
            for p in op.get("parameters", []) or []:
                pp = _deref(p, doc)
                if isinstance(pp, dict) and pp.get("in") == "body":
                    body = _deref(pp.get("schema") or {}, doc)
            sec = op.get("security", global_sec)
            secured = None if sec is None else bool(sec)   # security: [] = público explícito
            out.append(Endpoint(m.upper(), (base.rstrip("/") + path) if base else path, params, body, secured,
                                op.get("summary", "") or ""))
            if len(out) >= MAX_ENDPOINTS:
                return out
    return out


def parse_postman(doc: dict) -> list[Endpoint]:
    out: list[Endpoint] = []

    def walk(items):
        for it in items or []:
            if "item" in it:
                walk(it["item"])
            req = it.get("request")
            if not isinstance(req, dict) or len(out) >= MAX_ENDPOINTS:
                continue
            url = req.get("url")
            if isinstance(url, str):
                path = re.sub(r"^[a-z]+://[^/]+", "", url).split("?")[0] or "/"
                path = re.sub(r"\{\{[^}]+\}\}", "", path) or "/"
                query = []
            else:
                parts = (url or {}).get("path", []) or []
                path = "/" + "/".join(str(p) for p in parts)
                query = (url or {}).get("query", []) or []
            path = re.sub(r"/:([A-Za-z_]\w*)", r"/{\1}", path)
            params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                      for n in re.findall(r"\{(\w+)\}", path)]
            params += [{"name": q.get("key"), "in": "query", "required": False, "schema": {"type": "string"}}
                       for q in query if q.get("key")]
            out.append(Endpoint((req.get("method") or "GET").upper(), path, params, None, None, it.get("name", "")))
    walk(doc.get("item"))
    return out


def parse_spec_text(text: str) -> list[Endpoint]:
    try:
        doc = json.loads(text)
    except Exception:
        doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        return []
    if "paths" in doc:
        return parse_openapi(doc)
    if "item" in doc:
        return parse_postman(doc)
    return []


async def load_endpoints(target, source: str | None) -> tuple[list[Endpoint], str]:
    """(endpoints, origen). source: ruta local, URL, o None -> autodescubrir."""
    import os
    if source:
        if os.path.isfile(source):
            return parse_spec_text(open(source, encoding="utf-8").read()), f"archivo {source}"
        r = await target.request("GET", source, auth="a", raw_url=source.startswith("http"))
        return (parse_spec_text(r["text"]) if r["status"] == 200 else []), f"url {source}"
    for p in SPEC_PATHS:
        r = await target.request("GET", p, auth="a")
        if r["status"] == 200 and r["text"][:1] in ("{", "o", "s", "-", "#") and ("paths" in r["text"] or "swagger" in r["text"]):
            eps = parse_spec_text(r["text"])
            if eps:
                return eps, f"autodescubierto en {p}"
    return [], "no se encontró spec"


def sample_value(schema: dict | None, name: str = ""):
    s = schema or {}
    if s.get("enum"):
        return s["enum"][0]
    if "default" in s:
        return s["default"]
    t = s.get("type", "string")
    if t in ("integer", "number"):
        return s.get("minimum", 1)
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        return {}
    return "1" if re.search(r"id$|_id$", name, re.I) else "test"
