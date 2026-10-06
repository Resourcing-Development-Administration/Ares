"""
Nivel de confianza por test, para que un hallazgo no se lea como "explotación
confirmada" cuando en realidad es una heurística (regex/keyword/similitud).

- VERIFIED: el finding se basa en un hecho observado directamente (el server
  ejecutó el canario, el schema literalmente carece de la restricción, el
  header de CORS realmente refleja el origin, la CVE está confirmada en una
  base pública) — no requiere juicio humano adicional para confiar en él.
- HEURISTIC: el finding es una señal (keyword, regex, similitud de nombre,
  tamaño de respuesta) que amerita revisión manual antes de actuar — puede
  ser falso positivo.

Única fuente de verdad por test_id, igual patrón que engine/core/frameworks.py.
"""
from __future__ import annotations

VERIFIED = "verified"
HEURISTIC = "heuristic"
DEFAULT = HEURISTIC  # ante la duda, no sobre-prometer certeza

CONFIDENCE_MAP: dict[str, str] = {
    "recon.enumerate": VERIFIED,
    "recon.audit_logging": VERIFIED,
    "recon.suspicious_descriptions": HEURISTIC,
    "recon.excessive_permissions": HEURISTIC,

    "static.schema_permissive": VERIFIED,
    "static.no_schema": VERIFIED,
    "static.known_cve_check": HEURISTIC,  # version/name autoreportados por el target bajo auditoría, no una fuente independiente
    "static.typosquatting_check": HEURISTIC,  # similitud de nombre, no confirmación de que sea malicioso

    "dynamic.fuzz_tools": VERIFIED,
    "dynamic.command_injection_confirmed": VERIFIED,
    "dynamic.path_traversal_confirmed": VERIFIED,
    "dynamic.fuzz_resources": VERIFIED,
    "dynamic.credential_harvest_paths": VERIFIED,  # firma de contenido real (clave SSH/AWS/config MCP), no inferencia
    "dynamic.rate_limit": VERIFIED,
    "orchestrator.test_unresponsive": VERIFIED,  # el timeout es un hecho observado, no una heurística
    "orchestrator.target_unresponsive_sustained": VERIFIED,
    "orchestrator.connection_failed": VERIFIED,  # el rechazo de conexión es un hecho observado (TLS/red/transport)

    "adv.injection_passthrough": HEURISTIC,
    "adv.ssrf_exfil": HEURISTIC,
    "adv.confused_deputy": HEURISTIC,
    "adv.destructive_no_confirmation": VERIFIED,
    "adv.rug_pull": VERIFIED,  # comparación factual de hash, no heurística
    "adv.stateful_chain_exfil": VERIFIED,  # ejecución real de la cadena con canario, no inferencia por coexistencia
    "adv.live_agent_injection": HEURISTIC,  # el finding confirmado se marca "verified" vía confidence_override

    "auth.unauthenticated_access": VERIFIED,
    "auth.weak_credentials": VERIFIED,
    "auth.authz_object_level": HEURISTIC,  # respuesta distinta no prueba por sí sola una fuga real
    "auth.resource_object_level": HEURISTIC,  # mismo motivo, sobre resources en vez de tools
    "auth.cross_session_context_bleed": VERIFIED,  # canario plantado con una sesión y leído con otra -- ejecución real, no inferencia
    "auth.oauth_metadata_security": VERIFIED,  # observación directa de headers/metadata reales

    "exposure.certificate_type": VERIFIED,  # observación directa del certificado servido + validación real de cadena
    "exposure.transport_security": VERIFIED,
    "exposure.cors_misconfig": VERIFIED,
    "exposure.network_reachability": VERIFIED,
    "exposure.session_id_entropy": VERIFIED,

    "supplychain.secret_exposure": HEURISTIC,
    "supplychain.tool_squatting": HEURISTIC,
    "supplychain.exfiltration_chain": HEURISTIC,
    "crossserver.tool_shadowing": HEURISTIC,  # similitud de nombre / regex directivo, no confirmación de intención maliciosa real
    "crossserver.exfiltration_chain": HEURISTIC,  # coexistencia lector+emisor entre servers, no ejecución real encadenada
    "supplychain.malicious_patterns": HEURISTIC,
    "supplychain.dependency_vulnerabilities": VERIFIED,
    "supplychain.source_sast": VERIFIED,  # patrón/taint sobre código fuente real, hecho observado directamente
}


def get_confidence_for(test_id: str) -> str:
    return CONFIDENCE_MAP.get(test_id, DEFAULT)
