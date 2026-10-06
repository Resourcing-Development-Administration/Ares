"""
Modelo de riesgo por test_id -- única fuente de verdad, mismo patrón que
frameworks.py/confidence.py. Reemplaza la severidad "puesta a mano" por un
cálculo trazable a dos estándares reconocidos:

- CVSS v3.1 (FIRST.org) para severidad técnica y "facilidad de explotación"
  (los cuatro sub-componentes AV/AC/PR/UI, en texto plano vía
  engine/core/cvss.py::exploitability_plain_language).
- OWASP Risk Rating Methodology (https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
  para el rating de riesgo agregado: Likelihood × Impact -> Note/Low/Medium/
  High/Critical (la matriz 3x3 exacta que publica OWASP), y para las
  categorías de impacto al negocio (financial/reputational/compliance/
  privacy) que ese mismo documento define.

Lo único que NO es un estándar externo -- y se marca así explícitamente --
es `remediation_effort`: una estimación propia de Ares de cuánto esfuerzo de
ingeniería típicamente requiere el fix, para poder priorizar (alto riesgo +
fix trivial = lo primero que arreglás).

Cada test puede ajustar el vector CVSS baseline por instancia (ej. severidad
distinta si el payload fue aceptado vs rechazado) pasando `cvss_vector` al
construir el Finding -- ver Finding.cvss_vector_override en engine/core/models.py.
"""
from __future__ import annotations
from engine.core.cvss import calculate_base_score, severity_from_score, parse_vector, _AV, _AC, _PR_UNCHANGED, _UI, _CIA

_IMPACT_RANK = {"low": 0, "medium": 1, "high": 2}
_RANK_IMPACT = {v: k for k, v in _IMPACT_RANK.items()}


def build_vector(base_vector: str, **overrides: str) -> str:
    """Parte de un vector baseline y pisa componentes puntuales, ej.
    build_vector(CVSS_VECTORS['adv.injection_passthrough'], I='L')."""
    m = parse_vector(base_vector)
    m.update(overrides)
    return f"AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/UI:{m['UI']}/S:{m['S']}/C:{m['C']}/I:{m['I']}/A:{m['A']}"


def _exploitability_subscore(vector: str) -> float:
    m = parse_vector(vector)
    return 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _PR_UNCHANGED[m["PR"]] * _UI[m["UI"]]


def _technical_impact_label(vector: str) -> str:
    m = parse_vector(vector)
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    isc = 1 - (1 - c) * (1 - i) * (1 - a)
    if isc <= 0:
        return "low"
    if isc < 0.5:
        return "medium"
    return "high"


def likelihood_from(vector: str, confidence: str) -> str:
    """Likelihood según OWASP Risk Rating: qué tan probable es que esto se
    descubra y explote en la práctica. Se deriva de la facilidad de
    explotación real (CVSS exploitability sub-score) -- pero un hallazgo
    'heuristic' (señal, no confirmación) nunca puede rendir 'high': no hay
    evidencia de que sea explotable de verdad todavía, solo una sospecha."""
    sub = _exploitability_subscore(vector)
    label = "high" if sub >= 3.0 else "medium" if sub >= 1.3 else "low"
    if confidence == "heuristic" and label == "high":
        return "medium"
    return label


# Matriz oficial de OWASP Risk Rating Methodology (Likelihood x Impact -> severidad).
_OWASP_MATRIX = {
    ("low", "low"): "Note", ("low", "medium"): "Low", ("low", "high"): "Medium",
    ("medium", "low"): "Low", ("medium", "medium"): "Medium", ("medium", "high"): "High",
    ("high", "low"): "Medium", ("high", "medium"): "High", ("high", "high"): "Critical",
}


def owasp_risk_rating(likelihood: str, impact: str) -> str:
    return _OWASP_MATRIX[(likelihood, impact)]


def _worst(*labels: str) -> str:
    return _RANK_IMPACT[max(_IMPACT_RANK[l] for l in labels)]


# --- tabla por test_id --------------------------------------------------------
# vector: baseline CVSS v3.1 (sin 'CVSS:3.1/'); business_impact: los 4 factores
# de OWASP Risk Rating (financial/reputational/compliance/privacy), low/medium/high;
# remediation_effort: estimación propia de Ares (trivial/low/medium/high) + rationale.

_TABLE: dict[str, dict] = {
    "recon.enumerate": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "business_impact": {"financial": "low", "reputational": "low", "compliance": "low", "privacy": "low"},
        "remediation_effort": ("trivial", "Es solo enumeración; no hay nada que arreglar por sí sola."),
    },
    "recon.suspicious_descriptions": {
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
        "business_impact": {"financial": "medium", "reputational": "high", "compliance": "medium", "privacy": "medium"},
        "remediation_effort": ("low", "Editar la descripción del tool y agregar un lint/CI check que la bloquee a futuro."),
    },
    "recon.audit_logging": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "business_impact": {"financial": "low", "reputational": "low", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("medium", "Instrumentar logging de invocaciones de tools/cambios de contexto -- infraestructura, no un flag."),
    },
    "recon.excessive_permissions": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("medium", "Requiere sandboxing/allowlist real, no solo renombrar el tool."),
    },
    "static.no_schema": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "business_impact": {"financial": "low", "reputational": "low", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("trivial", "Declarar JSON Schema explícito para los parámetros."),
    },
    "static.known_cve_check": {
        # Aproximación: el feed no trae el vector CVSS completo publicado por CVE (solo el score), así que
        # esto es un baseline representativo de la clase de vulnerabilidad (RCE/path traversal en server MCP
        # oficial), no el vector exacto de cada CVE puntual -- el score real publicado queda en la descripción.
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("trivial", "Actualizar el server a la versión con fix publicado (ver campo 'remediation')."),
    },
    "static.typosquatting_check": {
        "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "high", "compliance": "medium", "privacy": "medium"},
        "remediation_effort": ("trivial", "Confirmar la fuente real del paquete; desinstalar si es un typosquat confirmado."),
    },
    "static.schema_permissive": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "business_impact": {"financial": "low", "reputational": "low", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("trivial", "Agregar enum/pattern/maxLength/additionalProperties=false."),
    },
    "dynamic.command_injection_confirmed": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Sacar shell=True/exec del path de código; requiere revisar cada invocación de subprocess."),
    },
    "dynamic.path_traversal_confirmed": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("low", "Resolver y validar la ruta contra un directorio base permitido (patrón conocido)."),
    },
    "dynamic.credential_harvest_paths": {
        # Scope Changed: a diferencia de leer /etc/passwd (reconocimiento), una credencial real robada
        # (clave SSH, AWS, token de OTRO server MCP) se usa para pivotear FUERA del server bajo prueba.
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("low", "Mismo fix que path traversal (allowlist de directorio base), pero urgente -- ya hay una credencial real potencialmente comprometida, rotarla."),
    },
    "dynamic.fuzz_resources": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("low", "Mismo fix que path traversal, aplicado al resolver de resources/templates."),
    },
    "dynamic.fuzz_tools": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "business_impact": {"financial": "low", "reputational": "medium", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("trivial", "Capturar excepciones y devolver mensajes de error genéricos al cliente."),
    },
    "dynamic.rate_limit": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "low", "privacy": "low"},
        "remediation_effort": ("medium", "Implementar throttling por sesión/cliente -- infraestructura, no un one-liner."),
    },
    # no es un test de los que corren contra el target por su propio id -- lo emite el
    # orquestador cuando CUALQUIER test se corta por timeout (ver engine/orchestrator.py).
    # Mismo vector que dynamic.rate_limit (A:L, resource-exhaustion): la diferencia es la
    # dirección -- ahí Ares agota al target, acá el target logra agotar/colgar a Ares.
    "orchestrator.test_unresponsive": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "business_impact": {"financial": "low", "reputational": "medium", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("medium", "Investigar por qué esa ruta no responde; re-ejecutar aislado con "
                                           "--test-timeout-s más alto antes de confiar en un score limpio."),
    },
    # emitido por el circuit breaker (ScanConfig.max_consecutive_timeouts) cuando VARIOS tests
    # seguidos se cuelgan -- severidad más alta que un timeout aislado porque implica que la
    # corrida quedó incompleta, no solo que un test puntual falló.
    "orchestrator.target_unresponsive_sustained": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        "business_impact": {"financial": "medium", "reputational": "high", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("medium", "Investigar por qué el server dejó de responder de forma sostenida "
                                           "antes de confiar en el score de esta corrida (incompleta)."),
    },
    # emitido por el orquestador cuando NO hubo sesión y el fallo no fue un 401 legítimo (TLS
    # rechazado, DNS/conexión/timeout). No es una vuln del server en sí: es que la corrida quedó
    # INCOMPLETA y su score/veredicto no son válidos como postura. Se califica alto a propósito
    # para que un scan que no se conectó nunca pase como "limpio"; el veredicto además lo fuerza
    # policy.yaml (BLOCK en production). I:H = la integridad del resultado del scan está comprometida.
    "orchestrator.connection_failed": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "business_impact": {"financial": "low", "reputational": "high", "compliance": "high", "privacy": "low"},
        "remediation_effort": ("low", "Conectarse de verdad (p.ej. --ca-bundle para una CA interna) y "
                                       "re-ejecutar; no confiar en el score hasta que la corrida sea completa."),
    },
    "adv.confused_deputy": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "medium", "privacy": "medium"},
        "remediation_effort": ("medium", "Acotar params de identificación/paths a un namespace explícito."),
    },
    "adv.destructive_no_confirmation": {
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("trivial", "Agregar parámetro confirm/dry_run obligatorio y hacerlo cumplir server-side."),
    },
    "adv.injection_passthrough": {
        # baseline = caso "aceptado" (is_error=false); el test pisa a I:L cuando es solo un eco de rechazo.
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "business_impact": {"financial": "medium", "reputational": "high", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("medium", "Nunca mezclar instrucciones y datos; requiere marcar contenido externo como no confiable en el system prompt del agente."),
    },
    "adv.live_agent_injection": {
        # Scope Changed a propósito: el impacto confirmado cruza de "datos leídos" a
        # "ejecución de un tool que nadie pidió" -- el caso canónico de scope-change de CVSS.
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("high", "Requiere rediseñar el trust boundary entre datos leídos y acciones del agente en toda la arquitectura."),
    },
    "adv.stateful_chain_exfil": {
        # Scope Changed: como adv.ssrf_exfil -- la cadena cruza de "leer datos" a "un tool de
        # envío los acepta", el mismo patrón de cruce de scope que justifica S:C.
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Requiere un punto de control explícito (confirmación humana o segmentación de contexto) entre tools lectores y emisores, no un fix de una línea."),
    },
    "adv.rug_pull": {
        # el tool cambió de definición entre dos corridas sin ninguna señal al usuario --
        # el caso de libro es "benigno en la revisión, malicioso en la actualización".
        "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Pinnear definiciones de tools por hash y alertar/bloquear ante cualquier cambio no revisado."),
    },
    "adv.ssrf_exfil": {
        # Scope Changed: SSRF es el ejemplo de libro de cruce de scope (de la red pública a la interna).
        "vector": "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "medium"},
        "remediation_effort": ("low", "Allowlist de dominios/esquemas permitidos + bloquear rangos de IP privados/link-local."),
    },
    "auth.unauthenticated_access": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("low", "Exigir bearer/API key/mTLS antes de aceptar initialize/tools-list."),
    },
    "auth.weak_credentials": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("trivial", "Rotar a secretos generados criptográficamente; nunca tokens estáticos/adivinables."),
    },
    "auth.authz_object_level": {
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Requiere agregar una verificación explícita de ownership/scope por request, no un flag."),
    },
    "auth.resource_object_level": {
        # mismo vector que auth.authz_object_level -- mismo bug, otra superficie del protocolo.
        "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Agregar la misma verificación de ownership/scope en 'resources/read' que en las tools."),
    },
    "auth.cross_session_context_bleed": {
        # S:C (Scope Changed): el impacto cruza la frontera de OTRA sesión/tenant, no solo
        # del llamador actual -- y confirmado por canario (ejecución real), no heurística,
        # por eso C:H sin I/A (es una fuga de confidencialidad confirmada, no de integridad).
        "vector": "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("high", "Aislar el estado/contexto por sesión/tenant autenticado a nivel de "
                                          "arquitectura -- no es un fix de una línea, suele requerir separar "
                                          "el almacenamiento/caché compartido."),
    },
    "auth.oauth_metadata_security": {
        "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "high", "privacy": "medium"},
        "remediation_effort": ("medium", "Implementar RFC 9728 en el resource server y/o exigir PKCE en el authorization server -- config del proveedor de identidad, no del código de la tool."),
    },
    "exposure.transport_security": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("trivial", "Servir exclusivamente sobre TLS -- config de infraestructura, no código."),
    },
    "exposure.certificate_type": {
        # Un cert self-signed / de cadena desconocida / expirado habilita MITM activo: un atacante
        # en la ruta puede presentar su propio cert y el cliente que "igual confía" no lo distingue.
        # AC:H porque requiere posición de red (on-path); C:H/I:L por el mismo motivo que transport sin TLS.
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("low", "Emitir el certificado desde una CA en la que los clientes confíen (pública "
                                       "o interna), o -- si la CA es interna -- auditar pasando --ca-bundle con ella."),
    },
    "exposure.cors_misconfig": {
        # baseline = wildcard; el test pisa C:H/I:H cuando además refleja el origin con credentials=true.
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "medium", "privacy": "medium"},
        "remediation_effort": ("trivial", "Restringir Access-Control-Allow-Origin a una allowlist explícita."),
    },
    "exposure.network_reachability": {
        # AC:H a propósito -- esto es contextual (clasifica blast radius), no un ataque en sí;
        # sin esto, la fórmula de likelihood lo trata como "trivialmente explotable" y lo infla.
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "business_impact": {"financial": "low", "reputational": "low", "compliance": "low", "privacy": "low"},
        "remediation_effort": ("medium", "Si no necesita estar público, moverlo detrás de VPN/allowlist de IPs."),
    },
    "exposure.session_id_entropy": {
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "medium", "privacy": "high"},
        "remediation_effort": ("trivial", "Generar el session ID con secrets.token_hex(32) o equivalente CSPRNG -- un cambio de una línea."),
    },
    "supplychain.dependency_vulnerabilities": {
        # fallback -- cuando OSV.dev SÍ publica CVSS real para la CVE puntual, ESE prevalece
        # (ver engine/supplychain/tests.py); esto solo aplica si OSV no tiene CVSS.
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("low", "Actualizar a la versión con fix publicado (ver campo 'remediation' del finding)."),
    },
    "supplychain.exfiltration_chain": {
        "vector": "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Requerir confirmación humana antes de pasar datos de un tool lector a uno de red/envío."),
    },
    "supplychain.malicious_patterns": {
        "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N",
        "business_impact": {"financial": "medium", "reputational": "high", "compliance": "medium", "privacy": "medium"},
        "remediation_effort": ("medium", "Revisar manualmente y, si es real, tratar como tool comprometida (rotar/retirar)."),
    },
    "supplychain.secret_exposure": {
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "medium"},
        "remediation_effort": ("trivial", "Rotar el secreto expuesto ya, y sacarlo de descripciones/schemas a un vault."),
    },
    "supplychain.source_sast": {
        # baseline = severity WARNING/INFO de semgrep; el test pisa I:H cuando semgrep marcó ERROR
        # (command injection/eval/exec/deserialización insegura -- clases de impacto alto).
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("medium", "Depende del hallazgo puntual: sanitizar el sink señalado o reemplazar la API insegura -- ver la línea exacta en el finding."),
    },
    "supplychain.tool_squatting": {
        # baseline = sin intención cruzada; el test pisa I:H cuando SÍ hay cross-intent (destructivo vs lectura).
        "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "medium", "compliance": "low", "privacy": "low"},
        "remediation_effort": ("low", "Renombrar para maximizar distancia léxica entre tools de intención distinta."),
    },
    "crossserver.tool_shadowing": {
        # baseline = colisión de nombre casi-idéntica (near_name_collision); el test pisa
        # AC/I según el kind puntual -- ver engine/crossserver.py::cross_server_findings().
        # S:C (Scope Changed) porque el impacto cruza el límite de confianza de OTRO
        # server conectado, no solo del server que originó el finding -- distinto de
        # supplychain.tool_squatting (mismo server, mismo límite de confianza).
        "vector": "AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "business_impact": {"financial": "medium", "reputational": "high", "compliance": "medium", "privacy": "low"},
        "remediation_effort": ("low", "Maximizar distancia léxica entre tools de servers distintos; auditar "
                                        "el server de origen si hay lenguaje directivo cross-server."),
    },
    "crossserver.exfiltration_chain": {
        # mismo vector que supplychain.exfiltration_chain, pero S:C (Scope Changed): acá el
        # lector y el emisor viven en servers DISTINTOS -- ningún scan de un solo target
        # puede verlo, por diseño cruza el límite de confianza entre dos servers conectados.
        "vector": "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "business_impact": {"financial": "high", "reputational": "high", "compliance": "high", "privacy": "high"},
        "remediation_effort": ("medium", "Requerir confirmación humana antes de pasar datos leídos de un "
                                           "server a una tool de red/envío de OTRO server conectado."),
    },
}

_DEFAULT_ENTRY = {
    "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
    "business_impact": {"financial": "low", "reputational": "low", "compliance": "low", "privacy": "low"},
    "remediation_effort": ("medium", "test_id sin perfil de riesgo registrado -- revisar manualmente."),
}


def base_vector_for(test_id: str) -> str:
    """El vector CVSS baseline de un test_id, para que el propio test lo use como
    punto de partida de build_vector() cuando necesita ajustar un componente
    puntual según lo que observó en esa instancia."""
    return _TABLE.get(test_id, _DEFAULT_ENTRY)["vector"]


def risk_for(
    test_id: str,
    confidence: str = "heuristic",
    cvss_vector_override: str | None = None,
    business_impact_override: dict | None = None,
    category: str | None = None,
) -> dict:
    entry = _TABLE.get(test_id, _DEFAULT_ENTRY)
    vector = cvss_vector_override or entry["vector"]
    try:
        score = calculate_base_score(vector)
    except ValueError:
        # Red de seguridad: un cvss_vector_override mal formado (ej. un vector CVSS v4.0 real
        # de una fuente externa como OSV.dev -- calculate_base_score es v3.1-only) NUNCA debe
        # tumbar el scan ENTERO por un solo finding. Bug real encontrado corriendo Ares contra
        # un target vivo (supplychain.dependency_vulnerabilities con una CVE que OSV reporta en
        # v4.0) -- se cae al vector baseline de la tabla, que siempre es v3.1 válido por
        # construcción, en vez de propagar la excepción hacia arriba.
        vector = entry["vector"]
        score = calculate_base_score(vector)
    cvss_severity = severity_from_score(score)

    technical_impact = _technical_impact_label(vector)
    business = {**entry["business_impact"], **(business_impact_override or {})}
    impact_label = _worst(technical_impact, *business.values())
    likelihood = likelihood_from(vector, confidence)

    return {
        "cvss_vector": vector,
        "cvss_score": score,
        "cvss_severity": cvss_severity,
        "business_impact": business,
        "technical_impact": technical_impact,
        "likelihood": likelihood,
        "impact": impact_label,
        "risk_rating": owasp_risk_rating(likelihood, impact_label),
        "remediation_effort": entry["remediation_effort"][0],
        "remediation_effort_rationale": entry["remediation_effort"][1],
        "aivss": aivss_for(score, category, confidence) if category else None,
    }


# --- AIVSS (OWASP AI Vulnerability Scoring System, aivss.owasp.org) ----------
# Score COMPLEMENTARIO, no reemplaza CVSS+OWASP Risk Rating (esos siguen siendo
# la severidad "oficial" del finding -- sección 7 del manual). AIVSS extiende
# CVSS con contexto agéntico: qué tan autónomo es el agente, cuánto usa
# herramientas, y cuán no-determinista es su comportamiento amplifican el
# impacto real de un hallazgo DENTRO de un agente, distinto a software
# tradicional. Fórmula publicada:
#   AARS  = (10 - CVSS_base) x (factor_sum / 10) x threat_multiplier
#   AIVSS = (CVSS_base + AARS) x mitigation_factor
#
# Aproximación declarada explícitamente (is_approximation=True en el output):
# Ares no tiene forma de observar mitigaciones reales del target ni un AARS
# calculado por un tercero independiente (a diferencia del CVSS base, que sí
# tiene una fórmula pública 100% verificable desde el vector) -- por eso
# mitigation_factor queda fijo en 1.0 (sin mitigaciones conocidas asumidas,
# el escenario conservador) y factor_sum se toma como el PROMEDIO (no la
# suma literal) de los 3 factores agénticos 0-10 por categoría de test, para
# que la normalización /10 de la fórmula quede acotada 0-1 como se espera.
_AGENTIC_FACTORS = {
    # (autonomía, uso_de_herramientas, no_determinismo), cada uno 0-10 -- cuánto
    # amplifica el contexto agéntico el impacto de ESTA categoría si se explota
    # dentro de un agente real. No es igual un schema permisivo (static) que
    # una inyección que un agente real puede obedecer (adversarial).
    "recon": (1, 2, 1),
    "static": (1, 1, 1),
    "dynamic": (4, 6, 4),
    "adversarial": (8, 8, 7),
    "auth": (5, 6, 4),
    "exposure": (3, 3, 3),
    "supplychain": (6, 7, 6),
}

_AIVSS_THREAT_MULTIPLIER = {"verified": 1.0, "heuristic": 0.6}  # heuristic = amenaza sin confirmar, se amortigua


def aivss_for(cvss_base: float, category: str, confidence: str) -> dict:
    autonomy, tool_use, nondeterminism = _AGENTIC_FACTORS.get(category, (3, 3, 3))
    factor_avg = (autonomy + tool_use + nondeterminism) / 3.0
    threat_multiplier = _AIVSS_THREAT_MULTIPLIER.get(confidence, 0.6)
    mitigation_factor = 1.0  # sin mitigaciones conocidas asumidas -- ver nota arriba

    aars = (10 - cvss_base) * (factor_avg / 10) * threat_multiplier
    score = max(0.0, min(10.0, (cvss_base + aars) * mitigation_factor))

    return {
        "score": round(score, 1),
        "cvss_base": cvss_base,
        "aars": round(aars, 2),
        "agentic_factors": {"autonomy": autonomy, "tool_use": tool_use, "nondeterminism": nondeterminism},
        "threat_multiplier": threat_multiplier,
        "mitigation_factor": mitigation_factor,
        "is_approximation": True,
        "note": "Aproximación declarada (AARS/mitigation_factor no son observables del target real) -- "
                "score complementario, NO reemplaza el CVSS+OWASP Risk Rating oficial de este finding.",
    }
