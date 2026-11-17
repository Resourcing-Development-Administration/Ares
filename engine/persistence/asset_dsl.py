"""
Asset DSL — query language for filtering assets.
Parses expressions like: domain=example.com AND status=200 OR technology=nginx
Port of ARTEX db/asset_dsl.go.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# ── Field registry ────────────────────────────────────────────────────────────

STRING_FIELDS: dict[str, str] = {
    "domain": "domain", "root_domain": "root_domain",
    "ip": "ip", "url": "url", "page_title": "page_title",
    "title": "page_title", "icp": "icp",
    "service_name": "service_name", "app_name": "app_name",
    "bundle_id": "bundle_id", "category": "category",
    "app_icp": "app_icp", "method": "method",
    "service_type": "service_type", "record_type": "record_type",
}

ARRAY_FIELDS: dict[str, str] = {
    "technology": "technologies", "technologies": "technologies",
    "tech": "technologies",
}

NUMERIC_FIELDS: dict[str, str] = {
    "port": "port", "status_code": "status_code", "status": "status_code",
}

KNOWN_FIELDS = set(STRING_FIELDS) | set(ARRAY_FIELDS) | set(NUMERIC_FIELDS)


# ── AST ───────────────────────────────────────────────────────────────────────

@dataclass
class Expr:
    field: str    # empty = bare text search
    op: str       # "=", "!=", ">", ">=", "<", "<="
    value: str


@dataclass
class AstNode:
    kind: str             # "and" | "or" | "leaf"
    children: list["AstNode"]
    expr: Expr | None


# ── Tokenizer ─────────────────────────────────────────────────────────────────

_FIELD_OP_RE = re.compile(r'([a-z_][a-z0-9_]*)\s*(==|!=|>=|<=|>|<|=)\s*', re.IGNORECASE)
_QUOTED_RE = re.compile(r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\'')
_KEYWORD_RE = re.compile(r'\b(AND|OR)\b', re.IGNORECASE)
_PAREN_RE = re.compile(r'[()]')
_BARE_RE = re.compile(r'\S+')


def _tokenize(text: str) -> list[tuple[str, str]]:
    """Return list of (type, value) tokens."""
    tokens: list[tuple[str, str]] = []
    i = 0
    text = text.strip()
    n = len(text)
    while i < n:
        # skip whitespace
        if text[i].isspace():
            i += 1
            continue

        # keyword AND/OR
        m = _KEYWORD_RE.match(text, i)
        if m and (m.start() == i):
            tokens.append((m.group(0).upper(), m.group(0)))
            i = m.end()
            continue

        # paren
        if text[i] in "()":
            tokens.append(("LPAREN" if text[i] == "(" else "RPAREN", text[i]))
            i += 1
            continue

        # quoted string
        m = _QUOTED_RE.match(text, i)
        if m:
            tokens.append(("VALUE", m.group(0)[1:-1]))
            i = m.end()
            continue

        # field=value
        m = _FIELD_OP_RE.match(text, i)
        if m and m.group(1).lower() in KNOWN_FIELDS:
            field = m.group(1).lower()
            op = m.group(2)
            i = m.end()
            # read value token (quoted or bare)
            mq = _QUOTED_RE.match(text, i)
            if mq:
                val = mq.group(0)[1:-1]
                i = mq.end()
            else:
                mb = _BARE_RE.match(text, i)
                val = mb.group(0) if mb else ""
                if mb:
                    i = mb.end()
            tokens.append(("FIELD_OP", f"{field}{op}{val}"))
            continue

        # bare token
        m = _BARE_RE.match(text, i)
        if m:
            tokens.append(("BARE", m.group(0)))
            i = m.end()
            continue

        i += 1

    return tokens


# ── Simple recursive-descent parser ──────────────────────────────────────────

class DslParser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> tuple[str, str] | None:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def _next(self) -> tuple[str, str] | None:
        t = self._peek()
        self._pos += 1
        return t

    def parse(self) -> AstNode | None:
        return self._parse_or()

    def _parse_or(self) -> AstNode | None:
        left = self._parse_and()
        while self._peek() and self._peek()[0] == "OR":
            self._next()
            right = self._parse_and()
            if left and right:
                left = AstNode("or", [left, right], None)
        return left

    def _parse_and(self) -> AstNode | None:
        left = self._parse_atom()
        while self._peek() and self._peek()[0] == "AND":
            self._next()
            right = self._parse_atom()
            if left and right:
                left = AstNode("and", [left, right], None)
        return left

    def _parse_atom(self) -> AstNode | None:
        t = self._peek()
        if t is None:
            return None
        if t[0] == "LPAREN":
            self._next()
            node = self._parse_or()
            if self._peek() and self._peek()[0] == "RPAREN":
                self._next()
            return node
        if t[0] == "FIELD_OP":
            self._next()
            raw = t[1]
            for op in ("==", "!=", ">=", "<=", ">", "<", "="):
                idx = raw.find(op)
                if idx != -1:
                    field = raw[:idx]
                    val = raw[idx + len(op):]
                    return AstNode("leaf", [], Expr(field, op, val))
        if t[0] == "BARE":
            self._next()
            return AstNode("leaf", [], Expr("", "=", t[1]))
        return None


def parse(dsl: str) -> AstNode | None:
    """Parse a DSL query string into an AST."""
    tokens = _tokenize(dsl)
    if not tokens:
        return None
    return DslParser(tokens).parse()


def to_filter(node: AstNode | None) -> dict:
    """Convert AST to a simplified filter dict for use by asset stores."""
    if node is None:
        return {}
    if node.kind == "leaf" and node.expr:
        return {"field": node.expr.field, "op": node.expr.op, "value": node.expr.value}
    if node.kind in ("and", "or"):
        return {node.kind: [to_filter(c) for c in node.children if c is not None]}
    return {}


def evaluate(node: AstNode | None, asset: dict[str, Any]) -> bool:
    """Evaluate a DSL AST against an asset dict. Returns True if the asset matches."""
    if node is None:
        return True
    if node.kind == "leaf" and node.expr:
        return _eval_expr(node.expr, asset)
    if node.kind == "and":
        return all(evaluate(c, asset) for c in node.children)
    if node.kind == "or":
        return any(evaluate(c, asset) for c in node.children)
    return True


def _eval_expr(expr: Expr, asset: dict[str, Any]) -> bool:
    if not expr.field:
        needle = expr.value.lower()
        return any(needle in str(v).lower() for v in asset.values() if isinstance(v, (str, int, float)))

    col = (STRING_FIELDS.get(expr.field)
           or ARRAY_FIELDS.get(expr.field)
           or NUMERIC_FIELDS.get(expr.field, expr.field))
    val = asset.get(col) or asset.get(expr.field)
    if val is None:
        return False

    target = expr.value
    op = expr.op

    if isinstance(val, list):
        return any(str(item).lower() == target.lower() for item in val)

    if expr.field in NUMERIC_FIELDS:
        try:
            n, t = int(val), int(target)
            if op in ("=", "=="): return n == t
            if op == "!=": return n != t
            if op == ">": return n > t
            if op == ">=": return n >= t
            if op == "<": return n < t
            if op == "<=": return n <= t
        except (ValueError, TypeError):
            return False

    if op in ("=", "=="): return str(val).lower() == target.lower()
    if op == "!=": return str(val).lower() != target.lower()
    return str(val).lower() == target.lower()
