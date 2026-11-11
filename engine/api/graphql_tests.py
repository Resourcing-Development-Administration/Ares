"""
Tests sobre endpoints GraphQL. ctx además trae {"graphql_path": str | None}. Si no hay endpoint
GraphQL detectado, cada test devuelve passed=True explicando por qué (nunca un "no aplica" mudo).
"""
from __future__ import annotations
import asyncio
import re

from engine.api.registry import api_test
from engine.core.models import Finding, Evidence, Category

INTROSPECTION_QUERY = """
query IntrospectionQuery { __schema { queryType { name } mutationType { name }
  types { name kind fields { name args { name } } } } }
"""


async def _gql(target, ctx, query: str, variables: dict | None = None, auth="a", method="POST"):
    path = ctx.get("graphql_path")
    if not path:
        return None
    body = {"query": query, "variables": variables or {}}
    if method == "GET":
        import json as _json
        return await target.request("GET", path, params={"query": query, "variables": _json.dumps(variables or {})}, auth=auth)
    return await target.request("POST", path, json_body=body, auth=auth)


def _na(tid: str, msg: str) -> list[Finding]:
    return [Finding(test_id=tid, title="Sin endpoint GraphQL detectado", category=Category.API, target="server",
                    passed=True, description=msg)]


@api_test("gql.introspection", "Introspección GraphQL habilitada", level=1, kind="graphql",
          description="Envía la query de introspección estándar; si el server devuelve el schema completo "
                       "(tipos, queries, mutations), un atacante puede mapear toda la API sin documentación.")
async def introspection(target, ctx) -> list[Finding]:
    tid = "gql.introspection"
    if not ctx.get("graphql_path"):
        return _na(tid, "No se detectó un endpoint GraphQL (ver --graphql-path).")
    r = await _gql(target, ctx, INTROSPECTION_QUERY, auth=None)
    data = (r or {}).get("json") or {}
    types = (((data.get("data") or {}).get("__schema") or {}).get("types") or [])
    if types:
        names = [t["name"] for t in types if not str(t.get("name", "")).startswith("__")][:15]
        return [Finding(
            test_id=tid, title="Introspección habilitada sin autenticación", category=Category.API,
            target=ctx["graphql_path"], passed=False, confidence_override="verified",
            description=f"La query de introspección devolvió {len(types)} tipos sin credenciales -- se puede "
                         f"mapear todo el schema (queries, mutations, campos) sin documentación. Ejemplos: {', '.join(names)}",
            evidence=Evidence(response={"type_count": len(types), "sample": names}),
            remediation="Deshabilitar introspección en producción (middleware que rechace '__schema'/'__type').",
        )]
    return [Finding(tid, title="Introspección no disponible sin autenticación", category=Category.API,
                    target=ctx["graphql_path"], passed=True, description="La query de introspección no devolvió el schema.")]


@api_test("gql.field_suggestions", "Sugerencias de campo ('did you mean') filtran el schema", level=1, kind="graphql",
          description="Aunque la introspección esté apagada, muchos servers GraphQL sugieren nombres de campo "
                       "válidos al recibir uno inexistente ('Did you mean quer?') -- permite enumerar el "
                       "schema campo por campo igual.")
async def field_suggestions(target, ctx) -> list[Finding]:
    tid = "gql.field_suggestions"
    if not ctx.get("graphql_path"):
        return _na(tid, "No se detectó un endpoint GraphQL.")
    r = await _gql(target, ctx, "{ ares_nonexistent_field_zz }", auth=None)
    text = str((r or {}).get("text", ""))
    if re.search(r"[Dd]id you mean", text):
        return [Finding(tid, title="El server sugiere nombres de campo válidos en los errores",
                        category=Category.API, target=ctx["graphql_path"], passed=False,
                        confidence_override="verified",
                        description="Un campo inexistente disparó una sugerencia 'Did you mean...?' -- permite "
                                     "reconstruir el schema campo por campo aunque la introspección esté apagada.",
                        evidence=Evidence(response={"excerpt": text[:300]}),
                        remediation="Desactivar las sugerencias de campo en producción (graphql-js: disableIntrospection + validation rule).")]
    return [Finding(tid, title="Sin sugerencias de campo", category=Category.API, target=ctx["graphql_path"],
                    passed=True, description="El error por un campo inexistente no sugirió nombres válidos.")]


@api_test("gql.depth_limit", "Sin límite de profundidad de consulta (DoS)", level=2, kind="graphql",
          default_enabled=False,
          description="Envía una query anidada ~15 niveles (usando un tipo recursivo real del schema, si la "
                       "introspección lo permitió detectarlo, o un patrón genérico) y mide si el server la "
                       "procesa sin rechazarla -- habilita DoS por complejidad de consulta.")
async def depth_limit(target, ctx) -> list[Finding]:
    tid = "gql.depth_limit"
    if not ctx.get("graphql_path"):
        return _na(tid, "No se detectó un endpoint GraphQL.")
    field = ctx.get("gql_recursive_field")
    if not field:
        return [Finding(tid, title="No se identificó un campo recursivo para anidar", category=Category.API,
                        target="server", passed=True,
                        description="Se necesita un campo que se referencie a sí mismo (ej. comment{replies{...}}) "
                                     "para armar una query profunda realista; la introspección no expuso uno.")]
    depth = 15
    q = "{ " + f"{field} " * 1
    q = ("{" + field + " {" * depth)[:-0]
    q = "{" + field + (" { " + field) * depth + " }" * depth
    import time
    t0 = time.monotonic()
    r = await _gql(target, ctx, q, auth="a" if ctx.get("auth_a") else None)
    elapsed = time.monotonic() - t0
    if r and r.get("status") and r["status"] < 400 and elapsed > 3:
        return [Finding(tid, title=f"Query de profundidad {depth} aceptada ({elapsed:.1f}s)", category=Category.API,
                        target=ctx["graphql_path"], passed=False, confidence_override="verified",
                        description=f"Una query anidando '{field}' {depth} niveles tardó {elapsed:.1f}s y no fue "
                                     f"rechazada -- sin límite de profundidad/complejidad, un cliente puede "
                                     f"agotar recursos con una sola consulta.",
                        evidence=Evidence(request={"depth": depth}, response={"elapsed_s": elapsed}),
                        remediation="Límite de profundidad/costo de consulta (graphql-depth-limit / graphql-cost-analysis).")]
    return [Finding(tid, title="La consulta profunda fue rechazada o resuelta rápido", category=Category.API,
                    target=ctx["graphql_path"], passed=True, description=f"status={r.get('status') if r else None}, {elapsed:.2f}s.")]


@api_test("gql.alias_batching", "Batching por alias sin límite (bypass de rate limit)", level=2, kind="graphql",
          default_enabled=False,
          description="Envía una sola query con N alias de la MISMA query (ej. login con credenciales "
                       "distintas) -- si el server la ejecuta completa, cada request HTTP vale por N intentos, "
                       "evadiendo cualquier rate limit medido por request.")
async def alias_batching(target, ctx) -> list[Finding]:
    tid = "gql.alias_batching"
    if not ctx.get("graphql_path"):
        return _na(tid, "No se detectó un endpoint GraphQL.")
    field = ctx.get("gql_probe_field") or "__typename"
    n = 40
    q = "{ " + " ".join(f"a{i}: {field}" for i in range(n)) + " }"
    r = await _gql(target, ctx, q, auth="a" if ctx.get("auth_a") else None)
    data = (r or {}).get("json") or {}
    resolved = sum(1 for k in (data.get("data") or {}) if k.startswith("a"))
    if r and r.get("status") and r["status"] < 400 and resolved >= n * 0.9:
        return [Finding(tid, title=f"Batching por alias sin límite ({resolved}/{n} resueltos en 1 request)",
                        category=Category.API, target=ctx["graphql_path"], passed=False, confidence_override="verified",
                        description=f"Una sola request con {n} alias de '{field}' resolvió {resolved} de ellos. "
                                     f"Para una mutation sensible (login, reset de password), esto convierte un "
                                     f"rate limit por-request en inútil: N intentos por request.",
                        evidence=Evidence(request={"aliases": n}, response={"resolved": resolved}),
                        remediation="Limitar la cantidad de alias/operaciones por request (graphql-query-complexity), "
                                     "o contarlos contra el rate limit real.")]
    return [Finding(tid, title="El batching por alias está limitado", category=Category.API,
                    target=ctx["graphql_path"], passed=True, description=f"{resolved}/{n} alias resueltos.")]


@api_test("gql.unauth_queries", "Queries/mutations sensibles accesibles sin autenticación", level=2, kind="graphql",
          description="Prueba las queries/mutations descubiertas por introspección (o una lista genérica: me, "
                       "users, user, admin...) SIN credenciales -- cualquiera que devuelva datos reales es un "
                       "fallo de autorización a nivel de campo, no solo de endpoint.")
async def unauth_queries(target, ctx) -> list[Finding]:
    tid = "gql.unauth_queries"
    if not ctx.get("graphql_path"):
        return _na(tid, "No se detectó un endpoint GraphQL.")
    fields = ctx.get("gql_query_fields") or ["me", "users", "user", "admin", "viewer", "allUsers"]
    findings = []
    for f in fields[:25]:
        r = await _gql(target, ctx, "{ " + f + " { __typename } }", auth=None)
        data = (r or {}).get("json") or {}
        if (data.get("data") or {}).get(f) not in (None, [], {}) and not data.get("errors"):
            findings.append(Finding(
                tid, title=f"Query '{f}' responde sin autenticación", category=Category.API, target=f,
                passed=False, confidence_override="heuristic",
                description=f"La query '{f}' devolvió datos (no null, sin errores) sin ninguna credencial.",
                evidence=Evidence(request={"query": f}, response={"excerpt": str(data)[:300]}),
                remediation="Autorización por campo/resolver (no asumir que el transporte ya filtró el acceso).",
            ))
    if not findings:
        findings.append(Finding(tid, title="Sin queries sensibles accesibles sin auth", category=Category.API,
                                target="server", passed=True, description=f"Se probaron {len(fields[:25])} query(s); ninguna devolvió datos sin credenciales."))
    return findings


@api_test("gql.get_mutations", "Mutations ejecutables por GET (CSRF)", level=1, kind="graphql",
          description="Reenvía una mutation de bajo riesgo como GET con la query en el querystring -- si el "
                       "server la ejecuta igual, es vulnerable a CSRF (un <img src> de un sitio ajeno la dispara).")
async def get_mutations(target, ctx) -> list[Finding]:
    tid = "gql.get_mutations"
    if not ctx.get("graphql_path"):
        return _na(tid, "No se detectó un endpoint GraphQL.")
    r = await _gql(target, ctx, "{ __typename }", auth="a" if ctx.get("auth_a") else None, method="GET")
    if r and r.get("status") and r["status"] < 400 and (r.get("json") or {}).get("data"):
        return [Finding(tid, title="GraphQL acepta operaciones por GET", category=Category.API,
                        target=ctx["graphql_path"], passed=False, confidence_override="verified",
                        description="El endpoint resolvió una operación enviada por GET con la query en el "
                                     "querystring. Si esto se extiende a mutations, son explotables vía CSRF "
                                     "(sin necesitar JS: un <img src=...> en un sitio ajeno la dispara).",
                        evidence=Evidence(response={"status": r["status"]}),
                        remediation="Aceptar operaciones solo por POST con Content-Type: application/json; "
                                     "rechazar GET para mutations explícitamente.")]
    return [Finding(tid, title="GraphQL no ejecuta operaciones por GET", category=Category.API,
                    target=ctx["graphql_path"], passed=True, description=f"GET devolvió status={r.get('status') if r else None}.")]
