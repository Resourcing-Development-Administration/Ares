"""
Normalización segura de JSON Schema para todo el engine -- única fuente de
verdad para "¿qué parámetros tiene este tool?", en vez de que cada test
mire `schema.get("properties", {})` a mano (lo que hacía TODO el código
hasta ahora) y se pierda cualquier parámetro declarado dentro de
`oneOf`/`anyOf`/`allOf`/`$ref` -- composición MUY común en schemas reales
(ej. "options: oneOf[{type A}, {type B}]"), no una rareza académica.
Sin esto, esos parámetros son INVISIBLES para fuzzing/injection/path
traversal/BOLA -- una zona ciega real, confirmada al auditar la herramienta.

Segunda razón de ser, igual de importante: el INPUT que normalizamos viene
de un server bajo auditoría, es decir, NO CONFIABLE por definición -- un
server hostil puede declarar un schema diseñado para atacar al escáner, no
al usuario del escáner:
  - `$ref` circular (A -> B -> A): sin guardas, recursión infinita.
  - `oneOf`/`anyOf` con fan-out exponencial anidado: igual que un "billion
    laughs" de XML, pero en JSON Schema.
  - Anidamiento de miles de niveles: agota la pila de Python.
Por eso toda función acá tiene límites explícitos (profundidad, nodos
visitados, tiempo) y SIEMPRE devuelve algo usable en vez de colgarse o
tirar una excepción -- un server hostil no debe poder tumbar a Ares mismo.
"""
from __future__ import annotations

MAX_DEPTH = 12          # anidamiento razonable de un schema real; más que esto es sospechoso
MAX_NODES = 4000        # tope total de sub-schemas visitados por normalize_schema()
MAX_PROPERTIES = 500    # tope de parámetros que cualquier test itera por tool


class _Budget:
    """Contador compartido de nodos visitados en una sola llamada a
    normalize_schema() -- cuando se agota, se corta la recursión ahí mismo
    (resultado parcial, nunca una excepción ni un colgado)."""
    __slots__ = ("nodes",)

    def __init__(self):
        self.nodes = 0

    def consume(self) -> bool:
        self.nodes += 1
        return self.nodes <= MAX_NODES


def _resolve_ref(ref: str, root: dict):
    """Solo refs LOCALES tipo '#/definitions/Foo' o '#/$defs/Foo' -- un
    server hostil no necesita que sigamos una URL externa para su ataque,
    y seguir URLs externas abriría una SSRF nueva dentro del propio
    normalizador. Devuelve None si no se puede resolver (ref externo,
    malformado, o no encontrado) -- nunca levanta excepción."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _flatten(schema, root: dict, budget: _Budget, depth: int, seen_refs: frozenset) -> dict:
    """Devuelve {"properties": {...}, "required": [...]} para UN nodo de
    schema, resolviendo $ref/allOf/oneOf/anyOf recursivamente. oneOf/anyOf
    se tratan como UNIÓN de propiedades (cualquier rama es un input válido
    posible -- para fuzzing/análisis de superficie de ataque, más cobertura
    es más seguro que menos) y ninguna de sus propiedades se marca
    'required' globalmente (porque el campo puede ser requerido en una
    rama y no existir en otra)."""
    if depth > MAX_DEPTH or not budget.consume() or not isinstance(schema, dict):
        return {"properties": {}, "required": []}

    properties: dict = {}
    required: list[str] = []

    ref = schema.get("$ref")
    if ref:
        if ref in seen_refs:
            return {"properties": {}, "required": []}  # ciclo detectado, cortar acá
        resolved = _resolve_ref(ref, root)
        if resolved is not None:
            sub = _flatten(resolved, root, budget, depth + 1, seen_refs | {ref})
            properties.update(sub["properties"])
            required.extend(sub["required"])
        # un $ref no resuelto no es un error fatal -- simplemente no aporta propiedades

    own_props = schema.get("properties")
    if isinstance(own_props, dict):
        for i, (pname, pschema) in enumerate(own_props.items()):
            if i >= MAX_PROPERTIES or not budget.consume():
                break
            properties[pname] = pschema if isinstance(pschema, dict) else {}
    own_required = schema.get("required")
    if isinstance(own_required, list):
        required.extend(r for r in own_required if isinstance(r, str))

    for combinator in ("allOf", "oneOf", "anyOf"):
        branches = schema.get(combinator)
        if not isinstance(branches, list):
            continue
        for branch in branches[:MAX_PROPERTIES]:
            if not budget.consume():
                break
            sub = _flatten(branch, root, budget, depth + 1, seen_refs)
            properties.update({k: v for k, v in sub["properties"].items() if k not in properties})
            if combinator == "allOf":
                required.extend(sub["required"])
            # oneOf/anyOf: NO propagamos required (ver docstring)

    return {"properties": properties, "required": required}


def normalize_schema(schema: dict | None) -> dict:
    """Punto de entrada único: dado el input_schema crudo de un tool (tal
    cual lo devuelve el server bajo auditoría, NO CONFIABLE), devuelve
    {"properties": {nombre: sub-schema}, "required": [nombres]} ya
    resueltos a través de $ref/allOf/oneOf/anyOf, con duplicados
    eliminados y límites de profundidad/nodos aplicados. Nunca levanta
    excepción ni se cuelga, sea cual sea la forma del schema de entrada."""
    if not isinstance(schema, dict):
        return {"properties": {}, "required": []}
    budget = _Budget()
    result = _flatten(schema, schema, budget, 0, frozenset())
    result["required"] = sorted(set(result["required"]))
    return result


def pathology_report(schema: dict | None) -> dict | None:
    """Heurística separada de normalize_schema() a propósito: normalize_schema
    SIEMPRE devuelve algo usable (nunca falla), pero acá queremos ADEMÁS
    señalar explícitamente cuando un schema parece diseñado para atacar al
    propio escáner (no al usuario del MCP) -- billion-laughs vía oneOf/anyOf
    anidado, referencias circulares, o anidamiento extremo. Devuelve None si
    el schema parece normal, o un dict {"reasons": [...], "node_count_estimate": N}
    si se detecta algo sospechoso. Usado por recon.schema_dos_indicators."""
    if not isinstance(schema, dict):
        return None
    reasons = []
    budget = _Budget()
    result = _flatten(schema, schema, budget, 0, frozenset())

    if budget.nodes >= MAX_NODES:
        reasons.append(f"el schema tiene {budget.nodes}+ sub-nodos (tope de análisis {MAX_NODES}) -- "
                        f"fan-out o anidamiento muy por encima de lo que declara cualquier tool legítimo")

    def _max_depth(node, root, depth=0, seen=frozenset(), budget2=None, cap=MAX_DEPTH + 4):
        if depth > cap or not isinstance(node, dict):
            return depth
        if budget2 is not None and not budget2.consume():
            return depth
        best = depth
        ref = node.get("$ref")
        if ref and ref not in seen:
            resolved = _resolve_ref(ref, root)
            if resolved is not None:
                best = max(best, _max_depth(resolved, root, depth + 1, seen | {ref}, budget2, cap))
        for combinator in ("allOf", "oneOf", "anyOf"):
            for branch in (node.get(combinator) or [])[:50]:
                best = max(best, _max_depth(branch, root, depth + 1, seen, budget2, cap))
        for pschema in (node.get("properties") or {}).values():
            best = max(best, _max_depth(pschema, root, depth + 1, seen, budget2, cap))
        return best

    depth_budget = _Budget()
    depth = _max_depth(schema, schema, 0, frozenset(), depth_budget, MAX_DEPTH + 4)
    if depth > MAX_DEPTH:
        reasons.append(f"anidamiento efectivo de {depth} niveles (tope sano {MAX_DEPTH}) -- "
                        f"posible intento de agotar la pila/tiempo del analizador")

    total_branches = 0
    def _count_combinators(node, depth=0, budget3=None, cap=MAX_DEPTH + 2):
        nonlocal total_branches
        if depth > cap or not isinstance(node, dict) or (budget3 and not budget3.consume()):
            return
        for combinator in ("allOf", "oneOf", "anyOf"):
            branches = node.get(combinator)
            if isinstance(branches, list):
                total_branches += len(branches)
                for b in branches[:200]:
                    _count_combinators(b, depth + 1, budget3, cap)
    cb_budget = _Budget()
    _count_combinators(schema, 0, cb_budget, MAX_DEPTH + 2)
    if total_branches > 200:
        reasons.append(f"{total_branches} ramas oneOf/anyOf/allOf combinadas en todo el schema -- "
                        f"fan-out consistente con un intento de 'billion laughs' vía JSON Schema")

    if not reasons:
        return None
    return {"reasons": reasons, "node_count_estimate": budget.nodes, "max_depth_estimate": depth,
            "combinator_branch_count": total_branches}
