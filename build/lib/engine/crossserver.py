"""
Correlación cross-server: todo lo demás en Ares audita UN server a la vez,
incluso `full` (que corre varios en paralelo pero cada uno aislado). Esto
cierra parte del hueco documentado en el roadmap (MCP09:2025 Shadow MCP
Servers / Tool Shadowing, y la mitad "cross-server" de la cadena de
exfiltración que supplychain.exfiltration_chain solo mira dentro de un
mismo server) -- corre DESPUÉS de que varios ScanReport ya existen (ej. modo
`full` con 2+ targets) y busca patrones que solo aparecen al mirar el
conjunto:

1. Tool Shadowing: un tool en el server B tiene nombre idéntico o casi
   idéntico a uno del server A (confusión directa: el agente puede invocar
   el del server equivocado), O la descripción de un tool en B menciona
   literalmente el nombre de un tool de OTRO server conectado con lenguaje
   directivo ("usar X en vez de", "siempre llamar a") -- el patrón de
   ataque documentado donde un server malicioso manipula, vía su propia
   descripción, cómo el agente interactúa con tools de servers legítimos.

2. Cadena de exfiltración cross-server: supplychain.exfiltration_chain
   busca lector+emisor DENTRO de un mismo server; acá se busca lo mismo
   pero ENTRE servers distintos -- un patrón invisible para cualquier scan
   de un solo target, y el motivo típico por el que "cada MCP individual
   pasa el audit" pero el conjunto conectado sigue siendo explotable.

No depende del modelo Finding/Category (esto no es un ScanReport de un solo
target) -- devuelve un dict plano, para no forzar el modelo de datos a
soportar algo que estructuralmente es distinto (N-a-N entre targets).
"""
from __future__ import annotations
import re

from engine.supplychain.similarity import jaro_winkler
from engine.core.models import Finding, Evidence, Category
from engine.core.risk import build_vector, base_vector_for

SHADOW_SIMILARITY_THRESHOLD = 0.90  # más alto que tool_squatting (0.82): acá cruza servers,
                                     # con distinta procedencia/confianza -- exigimos más parecido
                                     # antes de gatear, para no ahogar el hallazgo en ruido.

READER_RE = re.compile(r"read|file|env|secret|config|credential|key|token|password", re.IGNORECASE)
SENDER_RE = re.compile(r"send|post|http|request|webhook|email|upload|exfil|transmit|notify", re.IGNORECASE)
DIRECTIVE_RE = re.compile(
    r"(?i)(always|instead of|en vez de|siempre (usar|llamar)|use .{0,15} instead|prefer .{0,20} over|do not use)"
)


def _tools_by_server(reports: dict[str, list[dict]]) -> list[tuple[str, dict]]:
    """reports: {server_name: tools_enumerated}. Devuelve [(server_name, tool), ...] plano."""
    out = []
    for server_name, tools in reports.items():
        for t in tools or []:
            out.append((server_name, t))
    return out


def _find_tool_shadowing(reports: dict[str, list[dict]]) -> list[dict]:
    flat = _tools_by_server(reports)
    findings = []

    # 1) nombres idénticos o casi idénticos entre servers DISTINTOS
    for i in range(len(flat)):
        server_a, tool_a = flat[i]
        for j in range(i + 1, len(flat)):
            server_b, tool_b = flat[j]
            if server_a == server_b:
                continue
            name_a, name_b = tool_a["name"], tool_b["name"]
            if name_a == name_b:
                findings.append({
                    "kind": "exact_name_collision",
                    "severity": "high",
                    "servers": [server_a, server_b],
                    "tools": [name_a, name_b],
                    "detail": f"'{name_a}' existe idéntico en '{server_a}' Y '{server_b}' -- el agente no "
                              f"tiene forma de saber a cuál le está hablando salvo por metadata de sesión; "
                              f"un server malicioso puede registrar el mismo nombre que uno legítimo para "
                              f"interceptar invocaciones destinadas al otro.",
                })
                continue
            sim = jaro_winkler(name_a.lower(), name_b.lower())
            if sim >= SHADOW_SIMILARITY_THRESHOLD:
                findings.append({
                    "kind": "near_name_collision",
                    "severity": "medium",
                    "servers": [server_a, server_b],
                    "tools": [name_a, name_b],
                    "detail": f"'{name_a}' ({server_a}) y '{name_b}' ({server_b}) tienen similitud "
                              f"{sim:.3f} entre servers distintos -- riesgo de que el agente invoque el "
                              f"del server equivocado.",
                })

    # 2) una descripción menciona, con lenguaje directivo, el nombre de un tool de OTRO server
    all_names_by_server = {s: {t["name"] for t in tools or []} for s, tools in reports.items()}
    for server_name, tool in flat:
        desc = tool.get("description", "") or ""
        if not DIRECTIVE_RE.search(desc):
            continue
        for other_server, other_names in all_names_by_server.items():
            if other_server == server_name:
                continue
            for other_name in other_names:
                if other_name and other_name in desc:
                    findings.append({
                        "kind": "directive_cross_reference",
                        "severity": "critical",
                        "servers": [server_name, other_server],
                        "tools": [tool["name"], other_name],
                        "detail": f"La descripción de '{tool['name']}' (server '{server_name}') menciona con "
                                  f"lenguaje directivo el tool '{other_name}' del server '{other_server}' -- "
                                  f"patrón de Tool Shadowing: un server puede intentar reprogramar cómo el "
                                  f"agente usa tools de OTRO server legítimo ya conectado, solo con texto en "
                                  f"su propia descripción.",
                    })

    return findings


def _find_cross_server_exfil_chains(reports: dict[str, list[dict]]) -> list[dict]:
    readers = []  # (server, tool_name)
    senders = []
    for server_name, tools in reports.items():
        for t in tools or []:
            blob = t["name"] + " " + (t.get("description", "") or "")
            if READER_RE.search(blob):
                readers.append((server_name, t["name"]))
            if SENDER_RE.search(blob):
                senders.append((server_name, t["name"]))

    chains = []
    for r_server, r_tool in readers:
        for s_server, s_tool in senders:
            if r_server == s_server:
                continue  # eso ya lo cubre supplychain.exfiltration_chain (dentro de un mismo server)
            chains.append({
                "kind": "cross_server_exfil_chain",
                "severity": "high",
                "servers": [r_server, s_server],
                "tools": [r_tool, s_tool],
                "detail": f"Tool lector '{r_tool}' en '{r_server}' + tool emisor '{s_tool}' en '{s_server}' "
                          f"-- un agente con ambos servers conectados en la misma sesión puede encadenarlos "
                          f"para exfiltrar datos, aunque cada server individualmente 'pase' su propio scan "
                          f"(ninguno ve al otro).",
            })
    return chains


def cross_server_findings(reports: dict[str, list[dict]]) -> list[Finding]:
    """Versión Finding-real de analyze_cross_server(), para que esto deje de ser un
    dict suelto que solo se imprime en terminal -- confirmado que `full` nunca lo pasaba
    por calculate_score/PolicyEngine/SARIF, ni siquiera cuando el propio código ya lo
    marcaba severity='critical' (directive_cross_reference): una corrida de CI con
    --sarif-out jamás veía esto en el code scanning de GitHub, y ninguna policy BLOCK
    podía gatillar por acá. Se corre como un ScanReport propio (target_name='(correlación
    cross-server)'), mismo pipeline que cualquier otro -- ver cli/main.py::cmd_full y
    webui/app.py."""
    if len(reports) < 2:
        return []

    findings = []
    for item in _find_tool_shadowing(reports):
        kind = item["kind"]
        servers, tools = item["servers"], item["tools"]
        # override de CVSS por kind -- mismo patrón que supplychain.tool_squatting (pisa I
        # cuando hay cross-intent): acá "directive_cross_reference" es la única variante
        # donde se confirmó TEXTO que intenta reprogramar el comportamiento del agente
        # hacia otro server (impacto de integridad real), las otras dos son colisión de
        # nombre (riesgo de confusión, no de manipulación activa).
        if kind == "directive_cross_reference":
            vector = build_vector(base_vector_for("crossserver.tool_shadowing"), AC="L", I="H")
        elif kind == "exact_name_collision":
            vector = build_vector(base_vector_for("crossserver.tool_shadowing"), AC="L")
        else:
            vector = base_vector_for("crossserver.tool_shadowing")
        findings.append(Finding(
            test_id="crossserver.tool_shadowing",
            title=f"Tool shadowing entre servers: '{tools[0]}' ({servers[0]}) / '{tools[1]}' ({servers[1]})",
            category=Category.SUPPLYCHAIN,
            target=f"{servers[0]} + {servers[1]}",
            description=item["detail"],
            cvss_vector_override=vector,
            evidence=Evidence(response=item),
            passed=False,
            remediation="Maximizar distancia léxica entre tools de servers distintos conectados en la "
                         "misma sesión; si la descripción de un tool referencia un tool de OTRO server "
                         "con lenguaje directivo, tratarlo como indicio de tool poisoning y auditar ese "
                         "server de origen.",
            references=["https://owasp.org/www-project-mcp-top-10/"],
        ))

    for item in _find_cross_server_exfil_chains(reports):
        servers, tools = item["servers"], item["tools"]
        findings.append(Finding(
            test_id="crossserver.exfiltration_chain",
            title=f"Cadena de exfiltración cross-server: '{tools[0]}' ({servers[0]}) -> '{tools[1]}' ({servers[1]})",
            category=Category.SUPPLYCHAIN,
            target=f"{servers[0]} + {servers[1]}",
            description=item["detail"],
            evidence=Evidence(response=item),
            passed=False,
            remediation="Requerir confirmación humana explícita antes de que datos leídos de un server "
                         "se pasen a una tool de red/envío de OTRO server conectado en la misma sesión -- "
                         "cada server individualmente puede 'pasar' su propio scan y la combinación seguir "
                         "siendo explotable.",
            references=["https://owasp.org/www-project-mcp-top-10/"],
        ))

    if not findings:
        findings.append(Finding(
            test_id="crossserver.tool_shadowing", title="Sin indicios de tool shadowing ni exfiltración cross-server",
            category=Category.SUPPLYCHAIN, target="(correlación cross-server)",
            description=f"Ningún patrón de shadowing o cadena cross-server entre los {len(reports)} servers analizados.",
            passed=True,
        ))
    return findings


def analyze_cross_server(reports: dict[str, list[dict]]) -> dict:
    """reports: {server_name: tools_enumerated} de 2+ targets ya escaneados
    (ej. de un batch `full`). Devuelve tool shadowing + cadenas cross-server."""
    if len(reports) < 2:
        return {"applicable": False, "reason": "se necesitan 2+ servers en la misma corrida para correlacionar.",
                "tool_shadowing": [], "cross_server_exfil_chains": []}

    shadowing = _find_tool_shadowing(reports)
    chains = _find_cross_server_exfil_chains(reports)
    return {
        "applicable": True,
        "servers_analyzed": list(reports.keys()),
        "tool_shadowing": shadowing,
        "cross_server_exfil_chains": chains,
        "summary": (
            f"{len(shadowing)} indicio(s) de tool shadowing (MCP09:2025), "
            f"{len(chains)} cadena(s) de exfiltración cross-server entre los "
            f"{len(reports)} servers analizados en conjunto."
        ),
    }
