"""
Metadatos de riesgo / frameworks / confianza de los tests api.* -- se inyectan en las MISMAS tablas
que usa MCP (engine/core/risk.py, frameworks.py, confidence.py) para que Finding.severity/risk/
frameworks funcionen igual, sin duplicar la lógica de scoring.
"""
from engine.core import risk, frameworks as fw, confidence as cf

_BI = lambda f, r, c, p: {"financial": f, "reputational": r, "compliance": c, "privacy": p}  # noqa: E731

# id -> (vector CVSS base, business_impact, esfuerzo, confianza, [tags])
_ROWS = {
    "api.sensitive_paths": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", _BI("high", "high", "high", "high"), ("low", "Quitar/proteger el recurso expuesto."), cf.VERIFIED, [("api", "API8:2023")]),
    "api.security_headers": ("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", _BI("low", "low", "low", "low"), ("trivial", "Agregar los headers en el gateway/framework."), cf.HEURISTIC, [("api", "API8:2023")]),
    "api.cors": ("AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", _BI("high", "high", "medium", "high"), ("low", "Allowlist explícita de orígenes; nunca reflejar Origin con credenciales."), cf.VERIFIED, [("api", "API8:2023")]),
    "api.auth_required": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", _BI("high", "high", "high", "high"), ("medium", "Exigir autenticación en todos los endpoints no públicos."), cf.VERIFIED, [("api", "API2:2023"), ("api", "API5:2023")]),
    "api.bola": ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", _BI("high", "high", "high", "high"), ("medium", "Validar propiedad del objeto en cada acceso por id, server-side."), cf.VERIFIED, [("api", "API1:2023")]),
    "api.verbose_errors": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", _BI("low", "medium", "medium", "low"), ("trivial", "Manejador global de errores con mensajes genéricos; debug apagado."), cf.HEURISTIC, [("api", "API8:2023")]),
    "api.injection_probe": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", _BI("high", "high", "high", "high"), ("medium", "Consultas parametrizadas / validación de entrada."), cf.VERIFIED, [("api", "API8:2023")]),
    "api.method_tampering": ("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", _BI("low", "low", "low", "low"), ("trivial", "Deshabilitar TRACE y métodos no usados."), cf.VERIFIED, [("api", "API8:2023")]),
    "api.rate_limit": ("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L", _BI("medium", "medium", "low", "low"), ("medium", "Rate limiting por cliente/identidad (y lockout en login)."), cf.HEURISTIC, [("api", "API4:2023")]),
    "api.jwt": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", _BI("high", "high", "high", "high"), ("low", "Rechazar alg=none, secreto fuerte (>=256 bits) o asimétricas, exigir exp."), cf.VERIFIED, [("api", "API2:2023")]),
    "api.mass_assignment": ("AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N", _BI("high", "medium", "medium", "medium"), ("medium", "Allowlist de campos por endpoint (DTO), nunca bindear el body entero al modelo."), cf.HEURISTIC, [("api", "API3:2023")]),
    "gql.introspection": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", _BI("low", "low", "low", "low"), ("trivial", "Deshabilitar introspección en producción."), cf.VERIFIED, [("api", "API9:2023"), ("api", "API8:2023")]),
    "gql.field_suggestions": ("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", _BI("low", "low", "low", "low"), ("trivial", "Desactivar las sugerencias 'Did you mean' en producción."), cf.VERIFIED, [("api", "API8:2023")]),
    "gql.depth_limit": ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", _BI("high", "medium", "low", "low"), ("low", "Límite de profundidad/complejidad de consulta."), cf.VERIFIED, [("api", "API4:2023")]),
    "gql.alias_batching": ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", _BI("medium", "low", "low", "low"), ("low", "Limitar aliases y desactivar el batching de arrays (o contarlos para el rate limit)."), cf.HEURISTIC, [("api", "API4:2023"), ("api", "API6:2023")]),
    "gql.unauth_queries": ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", _BI("high", "high", "high", "high"), ("medium", "Autorización por campo/resolver; no depender solo del endpoint."), cf.HEURISTIC, [("api", "API2:2023"), ("api", "API5:2023")]),
    "gql.get_mutations": ("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", _BI("high", "medium", "medium", "low"), ("low", "Rechazar mutaciones por GET (405) y exigir Content-Type JSON."), cf.VERIFIED, [("api", "API8:2023")]),
}


def install():
    for tid, (vec, bi, eff, conf, tags) in _ROWS.items():
        risk._TABLE.setdefault(tid, {"vector": vec, "business_impact": bi, "remediation_effort": eff})
        cf.CONFIDENCE_MAP.setdefault(tid, conf)
        fw.FRAMEWORK_MAP.setdefault(tid, [fw._api(code) for _, code in tags])


install()
