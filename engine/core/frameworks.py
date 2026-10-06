"""
Mapeo de cada test a los frameworks de seguridad reconocidos que le aplican.
Esta es la ÚNICA fuente de verdad para estos tags: los tests NO los declaran
ellos mismos (así no quedan desactualizados sueltos por archivo); Finding los
expone vía la propiedad `frameworks`, y report/SARIF los leen desde ahí.

Frameworks usados y por qué:

- OWASP MCP Top 10 (2025) — el Top 10 oficial y numerado dedicado
  específicamente a Model Context Protocol (owasp.org/www-project-mcp-top-10,
  MCP01:2025..MCP10:2025). Es el más específico al dominio de los cuatro.
- OWASP Top 10 for LLM Applications (2025) — lista oficial numerada y
  estable para riesgos de aplicaciones con LLM en general (no específica a MCP).
- OWASP API Security Top 10 (2023) — aplica porque un server MCP sobre
  http/sse es, en los hechos, una API.
- MITRE ATLAS — matriz de tácticas/técnicas adversarias contra sistemas de
  IA. Se citan técnicas puntuales SOLO donde hay un ID confirmado y estable
  al momento de escribir esto (AML.T0011.002, AML.T0085.001, AML.T0086); para
  el resto se usa la táctica general. ATLAS es un documento vivo -- cruzar
  contra https://atlas.mitre.org antes de citarlo en un informe formal.
  (Nota: AML.T0085.001 y AML.T0086 reemplazan los IDs AML.T0061/AML.T0062
  usados en una versión anterior de este archivo -- ATLAS renumeró estas
  técnicas tras la ola de técnicas "agentic" agregada en 2026; verificado
  contra d3fend.mitre.org, que las mapea 1:1 desde ATLAS.)
- OWASP GenAI Security Project — "Agentic AI Threats and Mitigations":
  guía emergente, todavía no un Top-10 cerrado y numerado como los otros
  tres. Se cita por nombre de amenaza, no por ID, y solo para lo que el
  MCP Top 10 no cubre todavía.

Huecos conocidos (documentados, no fabricados), revisados contra el texto
oficial de cada categoría (owasp.org/www-project-mcp-top-10) al cerrar esta
ronda:

- MCP08:2025 (Lack of Audit and Telemetry): cobertura PARCIAL, inherente al
  modelo black-box -- recon.audit_logging solo puede verificar si el server
  DECLARA soporte de logging (capability), nunca si realmente audita cada
  llamada (eso requeriría acceso a los logs del lado del server, que un
  escáner externo no tiene). Techo real del enfoque, no negligencia.
- MCP09:2025 (Shadow MCP Servers): CERRADO -- antes solo corría en modo
  `full` (2+ targets) y quedaba como un dict suelto impreso en terminal, sin
  pasar por score/policy/SARIF. Ahora es un Finding real
  (crossserver.tool_shadowing) con el mismo pipeline que cualquier otro.
  Sigue requiriendo 2+ targets en la misma corrida -- un solo server no
  puede "hacerse sombra a sí mismo".
- MCP10:2025 (Context Injection & Over-Sharing): CERRADO -- tres ángulos
  complementarios, ninguno redundante: crossserver.exfiltration_chain (datos
  cruzando el aislamiento entre servers DISTINTOS en la misma sesión),
  auth.resource_object_level (BOLA en resources -- un id sin aislar DENTRO
  de una sesión), y auth.cross_session_context_bleed (bleed ENTRE
  sesiones/tenants del MISMO server: planta un canario con una credencial y
  confirma con una segunda credencial independiente si aparece sin que
  nadie se lo haya dado -- requiere --auth-token-b, opt-in e intrusivo).
  Los tres juntos cubren servidor propio / resource individual / sesión-
  tenant distinta -- las tres superficies donde "contexto compartido que
  debería estar aislado" puede filtrarse según el documento oficial.
"""
from __future__ import annotations

OWASP_MCP_URL = "https://owasp.org/www-project-mcp-top-10/"
OWASP_LLM_URL = "https://genai.owasp.org/llm-top-10/"
OWASP_API_URL = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
ATLAS_URL = "https://atlas.mitre.org/matrices/ATLAS"
OWASP_AGENTIC_URL = "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/"

OWASP_MCP = {
    "MCP01:2025": "Token Mismanagement & Secret Exposure",
    "MCP02:2025": "Privilege Escalation via Scope Creep",
    "MCP03:2025": "Tool Poisoning",
    "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05:2025": "Command Injection & Execution",
    # el nombre oficial es "Intent Flow Subversion" (inyección indirecta vía contexto
    # recuperado -- resources/tool outputs -- que secuestra el plan/objetivo del agente,
    # no "prompt injection" genérico) -- corregido tras leer el documento real del repo
    # OWASP/www-project-mcp-top-10 (2025/MCP06-2025–Intent-Flow-Subversion.md); el nombre
    # anterior acá era una paráfrasis imprecisa, nunca inventada pero tampoco verificada
    # contra la fuente primaria al momento de escribirse.
    "MCP06:2025": "Intent Flow Subversion",
    "MCP07:2025": "Insufficient Authentication & Authorization",
    "MCP08:2025": "Lack of Audit and Telemetry",
    "MCP09:2025": "Shadow MCP Servers",
    "MCP10:2025": "Context Injection & Over-Sharing",
}

OWASP_LLM = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

OWASP_API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# técnicas ATLAS con ID confirmado (no todo ATLAS, solo lo verificado). Verificado
# directamente contra dist/ATLAS.yaml de mitre-atlas/atlas-data (v5.6.0, no un resumen
# de terceros) -- las 8 agregadas en esta ronda son demostrablemente más precisas que
# las tácticas genéricas que reemplazan/complementan, y AML.T0110 nombra Model Context
# Protocol (MCP) EXPLÍCITAMENTE en su propia descripción oficial -- la técnica ATLAS
# más específica a MCP que existe hoy.
ATLAS_TECHNIQUES = {
    "poisoned-tool": ("AML.T0011.002", "Poisoned AI Agent Tool"),
    "tool-poisoning-mcp": ("AML.T0110", "AI Agent Tool Poisoning"),  # cita MCP por nombre en su descripción oficial
    "agent-tools": ("AML.T0085.001", "AI Agent Tools"),
    "tool-invocation": ("AML.T0053", "AI Agent Tool Invocation"),  # distinto de agent-tools: esto es Ares/un adversario invocando, no un agente vivo siendo inducido a invocar
    "exfil-via-tool": ("AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
    "supply-chain-rug-pull": ("AML.T0109", "AI Supply Chain Rug Pull"),  # match literal de nombre con adv.rug_pull
    "credential-harvesting-tool": ("AML.T0098", "AI Agent Tool Credential Harvesting"),
    "data-destruction-tool": ("AML.T0101", "Data Destruction via AI Agent Tool Invocation"),
    "discover-tool-definitions": ("AML.T0084.001", "Tool Definitions"),  # sub-técnica de AML.T0084 Discover AI Agent Configuration
    "context-poisoning": ("AML.T0080", "AI Agent Context Poisoning"),
    "unsecured-credentials": ("AML.T0055", "Unsecured Credentials"),
    "agentic-resource-consumption": ("AML.T0034.002", "Agentic Resource Consumption"),  # sub-técnica de AML.T0034 Cost Harvesting
    "prompt-injection": ("AML.T0051", "LLM Prompt Injection"),
    "prompt-injection-indirect": ("AML.T0051.001", "LLM Prompt Injection: Indirect"),  # sub-técnica -- "inyección vía canales de datos que el LLM ingesta", exactamente line jumping/tool poisoning
}

# fallback a nivel táctica cuando no hay técnica puntual confirmada
ATLAS_TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "credential-access": "Credential Access",
    "collection": "Collection",
    "ml-attack-staging": "ML Attack Staging",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

AGENTIC_THREATS = {
    "excessive-agency": "Excessive Agency",
    "resource-exhaustion": "Resource Exhaustion / Denial of Service",
    "human-in-the-loop-bypass": "Human-in-the-Loop Bypass",
}


def _tag(framework: str, id_: str | None, name: str, url: str) -> dict:
    return {"framework": framework, "id": id_, "name": name, "url": url}


def _mcp(code): return _tag("OWASP-MCP", code, OWASP_MCP[code], OWASP_MCP_URL)
def _llm(code): return _tag("OWASP-LLM", code, OWASP_LLM[code], OWASP_LLM_URL)
def _api(code): return _tag("OWASP-API", code, OWASP_API[code], OWASP_API_URL)
def _atlas_t(key):
    tid, name = ATLAS_TECHNIQUES[key]
    # link a la página de la técnica puntual, no al matrix genérico -- antes de esto
    # las ~10 técnicas citadas compartían el mismo link a la matriz completa.
    return _tag("ATLAS", tid, name, f"https://atlas.mitre.org/techniques/{tid}")
def _atlas(key): return _tag("ATLAS", None, ATLAS_TACTICS[key], ATLAS_URL)
def _agentic(key): return _tag("AGENTIC", key, AGENTIC_THREATS[key], OWASP_AGENTIC_URL)


FRAMEWORK_MAP: dict[str, list[dict]] = {
    # + discover-tool-definitions (AML.T0084.001, sub-técnica de "Discover AI Agent
    # Configuration"): es LITERALMENTE lo que hace este test -- enumerar qué tools tiene
    # el agente -- más preciso que el tag genérico de táctica "reconnaissance" solo.
    "recon.enumerate": [_atlas("reconnaissance"), _atlas_t("discover-tool-definitions")],
    "recon.suspicious_descriptions": [_mcp("MCP03:2025"), _llm("LLM01:2025"), _atlas_t("poisoned-tool"),
                                        _atlas_t("tool-poisoning-mcp"), _atlas_t("prompt-injection-indirect")],
    "recon.excessive_permissions": [_mcp("MCP02:2025"), _llm("LLM06:2025"), _agentic("excessive-agency")],
    "recon.audit_logging": [_mcp("MCP08:2025")],

    "static.schema_permissive": [_api("API8:2023")],
    "static.no_schema": [_api("API8:2023")],
    "static.known_cve_check": [_mcp("MCP04:2025"), _llm("LLM03:2025")],
    "static.typosquatting_check": [_mcp("MCP04:2025"), _llm("LLM03:2025"), _atlas_t("poisoned-tool"), _atlas_t("tool-poisoning-mcp")],

    # tool-invocation (AML.T0053) en vez de agent-tools (AML.T0085.001): T0053 es Ares/un
    # adversario invocando tools directamente con argumentos maliciosos; T0085.001 es
    # específicamente "prompt the AI SERVICE to invoke tools" -- un agente vivo siendo
    # inducido, que es el escenario de adv.live_agent_injection, no de un fuzzer directo.
    "dynamic.fuzz_tools": [_llm("LLM05:2025"), _api("API8:2023"), _atlas_t("tool-invocation")],
    "dynamic.command_injection_confirmed": [_mcp("MCP05:2025"), _llm("LLM05:2025"), _atlas_t("tool-invocation")],
    "dynamic.path_traversal_confirmed": [_api("API8:2023"), _atlas("collection")],
    "dynamic.fuzz_resources": [_api("API8:2023"), _atlas("collection")],
    # credential-harvesting-tool (AML.T0098) reemplaza la táctica genérica "credential-access":
    # T0098 es match exacto -- "use access to an AI agent... to retrieve data from available
    # agent tools to collect credentials", la descripción casi textual de este test.
    "dynamic.credential_harvest_paths": [_mcp("MCP01:2025"), _llm("LLM02:2025"), _atlas_t("credential-harvesting-tool")],
    # LLM10:2025 (Unbounded Consumption) faltaba acá -- es EXACTAMENTE lo que describe
    # (consumo sin límite de recursos/tiempo de cómputo), no un tag nuevo inventado, una
    # ausencia corregida tras revisar que los 10 códigos de OWASP_LLM tuvieran al menos
    # un test que los citara.
    # + agentic-resource-consumption (AML.T0034.002, sub-técnica de "Cost Harvesting"):
    # más preciso y más actual (modificada 2026-03) que la táctica genérica.
    "dynamic.rate_limit": [_api("API4:2023"), _llm("LLM10:2025"), _agentic("resource-exhaustion"), _atlas_t("agentic-resource-consumption")],
    "orchestrator.test_unresponsive": [_api("API4:2023"), _llm("LLM10:2025"), _agentic("resource-exhaustion"), _atlas_t("agentic-resource-consumption")],
    "orchestrator.target_unresponsive_sustained": [_api("API4:2023"), _llm("LLM10:2025"), _agentic("resource-exhaustion"), _atlas_t("agentic-resource-consumption")],
    "orchestrator.connection_failed": [_mcp("MCP07:2025"), _api("API8:2023")],

    # prompt-injection-indirect (AML.T0051.001) reemplaza la táctica genérica "ml-attack-staging":
    # match preciso -- "indirect injection via data channels ingested by the LLM", exactamente
    # el payload reflejado desde un tool/resource que este test busca.
    "adv.injection_passthrough": [_mcp("MCP06:2025"), _llm("LLM01:2025"), _atlas_t("prompt-injection-indirect")],
    "adv.ssrf_exfil": [_api("API7:2023"), _llm("LLM02:2025"), _atlas_t("exfil-via-tool")],
    "adv.confused_deputy": [_mcp("MCP02:2025"), _api("API1:2023"), _llm("LLM06:2025")],
    # data-destruction-tool (AML.T0101): match exacto de nombre y descripción -- antes este
    # test no tenía NINGÚN tag de ATLAS.
    "adv.destructive_no_confirmation": [_llm("LLM06:2025"), _agentic("human-in-the-loop-bypass"), _atlas_t("data-destruction-tool")],
    "adv.live_agent_injection": [_mcp("MCP06:2025"), _llm("LLM01:2025"), _atlas_t("agent-tools"), _atlas_t("prompt-injection")],
    # + LLM04:2025 (Data and Model Poisoning): un tool/schema que cambia DESPUÉS de la
    # aprobación inicial del usuario es, conceptualmente, la misma clase de ataque que
    # "poisoning" -- la definición en la que el agente confía deja de ser la que el
    # usuario aprobó, sin que nada se lo avise. Faltaba este tag, no es un test nuevo.
    # + supply-chain-rug-pull (AML.T0109): match LITERAL de nombre -- "AI Supply Chain Rug
    # Pull" es, palabra por palabra, lo que este test detecta.
    "adv.rug_pull": [_mcp("MCP03:2025"), _llm("LLM03:2025"), _llm("LLM04:2025"), _atlas_t("supply-chain-rug-pull")],
    "adv.stateful_chain_exfil": [_mcp("MCP06:2025"), _llm("LLM02:2025"), _atlas_t("exfil-via-tool"), _atlas_t("context-poisoning")],

    "auth.unauthenticated_access": [_mcp("MCP07:2025"), _api("API2:2023"), _atlas("initial-access")],
    "auth.weak_credentials": [_mcp("MCP07:2025"), _api("API2:2023"), _atlas("credential-access")],
    "auth.authz_object_level": [_mcp("MCP02:2025"), _api("API1:2023")],
    "auth.resource_object_level": [_mcp("MCP02:2025"), _mcp("MCP10:2025"), _api("API1:2023")],
    # la pieza de MCP10 que faltaba por completo: fuga confirmada ENTRE sesiones/tenants
    # distintos de la MISMA conexión, no solo un id dentro de una sesión.
    "auth.cross_session_context_bleed": [_mcp("MCP10:2025"), _llm("LLM02:2025"), _api("API1:2023"), _atlas("collection")],
    "auth.oauth_metadata_security": [_mcp("MCP07:2025"), _api("API2:2023")],

    "exposure.certificate_type": [_mcp("MCP07:2025"), _api("API8:2023")],
    "exposure.transport_security": [_mcp("MCP07:2025"), _api("API8:2023")],
    "exposure.cors_misconfig": [_mcp("MCP07:2025"), _api("API8:2023")],
    # API8:2023 (Security Misconfiguration), no API9:2023 (Improper Inventory
    # Management -- ese es sobre versiones/endpoints no documentados, un
    # problema de PROCESO, no de que un servicio pensado para ser interno
    # resuelva a una IP pública). Corregido tras revisión cruzada contra la
    # descripción oficial de OWASP.
    "exposure.network_reachability": [_api("API8:2023")],
    "exposure.session_id_entropy": [_mcp("MCP07:2025"), _api("API2:2023")],

    # unsecured-credentials (AML.T0055) reemplaza la táctica genérica: match exacto de nombre.
    "supplychain.secret_exposure": [_mcp("MCP01:2025"), _llm("LLM02:2025"), _atlas_t("unsecured-credentials")],
    "supplychain.tool_squatting": [_mcp("MCP03:2025"), _llm("LLM03:2025"), _atlas_t("poisoned-tool"), _atlas_t("tool-poisoning-mcp")],
    "supplychain.exfiltration_chain": [_llm("LLM02:2025"), _atlas_t("exfil-via-tool")],
    "supplychain.malicious_patterns": [_mcp("MCP03:2025"), _llm("LLM01:2025"), _atlas_t("poisoned-tool"), _atlas_t("tool-poisoning-mcp")],
    "supplychain.dependency_vulnerabilities": [_mcp("MCP04:2025"), _llm("LLM03:2025")],
    "supplychain.source_sast": [_mcp("MCP05:2025"), _llm("LLM05:2025"), _api("API8:2023")],

    # MCP09:2025 (Shadow MCP Servers) -- antes "cubierto" solo por un dict suelto que
    # cmd_full imprimía en terminal sin pasar por score/policy/SARIF (ver
    # engine/crossserver.py::cross_server_findings, que lo convierte en Finding real).
    "crossserver.tool_shadowing": [_mcp("MCP09:2025"), _llm("LLM01:2025"), _atlas_t("poisoned-tool"), _atlas_t("tool-poisoning-mcp")],
    # también tagueado MCP10:2025 (Context Injection & Over-Sharing): una cadena de
    # exfiltración ENTRE servers conectados en la misma sesión es, en los términos
    # exactos del documento oficial de MCP10 ("context reused across agents/workflows
    # that should remain isolated"), el mismo patrón -- datos cruzando un límite de
    # aislamiento que debería existir entre servers de confianza distinta.
    "crossserver.exfiltration_chain": [_mcp("MCP09:2025"), _mcp("MCP10:2025"), _llm("LLM02:2025"), _atlas_t("exfil-via-tool")],
}


def get_frameworks_for(test_id: str) -> list[dict]:
    return FRAMEWORK_MAP.get(test_id, [])
