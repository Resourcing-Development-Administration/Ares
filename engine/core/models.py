"""
Modelos de datos centrales del engine.
Todo módulo de prueba (recon/static/dynamic/adversarial) produce objetos Finding.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid
import json

from engine.core.frameworks import get_frameworks_for
from engine.core.confidence import get_confidence_for
from engine.core.risk import risk_for

_RISK_RATING_TO_SEVERITY = {
    "Note": "info", "Low": "low", "Medium": "medium", "High": "high", "Critical": "critical",
}


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    RECON = "recon"
    STATIC = "static"
    DYNAMIC = "dynamic"
    ADVERSARIAL = "adversarial"
    AUTH = "auth"
    EXPOSURE = "exposure"
    SUPPLYCHAIN = "supplychain"


@dataclass
class Evidence:
    """Evidencia cruda de una prueba: lo que se envió y lo que se recibió."""
    request: Any = None
    response: Any = None
    notes: str = ""
    raw: Optional[str] = None  # dump crudo si aplica (stdout, payload, etc.)

    def to_dict(self) -> dict:
        def safe(x):
            try:
                json.dumps(x)
                return x
            except (TypeError, ValueError):
                return str(x)
        return {
            "request": safe(self.request),
            "response": safe(self.response),
            "notes": self.notes,
            "raw": self.raw,
        }


@dataclass
class Finding:
    """Un hallazgo individual producido por un test.

    `severity` y `risk` YA NO se eligen a mano por test: se calculan desde
    engine/core/risk.py (CVSS v3.1 + OWASP Risk Rating Methodology) a partir
    del test_id y, cuando un test necesita expresar matiz por-instancia (ej.
    "el payload fue aceptado" vs "fue rechazado y solo citado en un error"),
    pasando `cvss_vector_override` con un vector ajustado -- ver
    engine/core/risk.py::build_vector()."""
    test_id: str                    # identificador del test que lo generó, ej "adv.prompt_injection.tool_output"
    title: str
    category: Category
    target: str                     # tool/resource/prompt afectado, o "server" en general
    description: str
    evidence: Evidence = field(default_factory=Evidence)
    passed: bool = True              # True = no se encontró problema, False = vulnerable/hallazgo confirmado
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Reducción de ruido (engine/reporting/suppress.py): un finding suprimido NUNCA se
    # borra ni se oculta del reporte -- sigue visible en HTML/JSON para auditoría -- pero
    # se excluye del conteo que alimenta score/policy_verdict. Dos motivos posibles:
    # allowlist explícita del usuario (.ares_allowlist.yml) o --min-confidence verified
    # descartando heurísticas. Nunca se setea a mano desde un test.
    suppressed: bool = False
    suppressed_reason: Optional[str] = None

    @property
    def frameworks(self) -> list[dict]:
        """Tags de OWASP LLM Top 10 / OWASP API Security Top 10 / MITRE ATLAS (táctica) /
        amenazas agentic de OWASP GenAI, resueltos por test_id. Ver engine/core/frameworks.py."""
        return get_frameworks_for(self.test_id)

    confidence_override: Optional[str] = None  # setealo desde el test cuando ESA instancia puntual
                                                 # se confirmó por un medio más fuerte que el default
                                                 # del test_id (ej. callback OOB real en adv.ssrf_exfil)

    @property
    def confidence(self) -> str:
        """"verified" (hecho observado directamente) o "heuristic" (señal que amerita
        revisión manual). Ver engine/core/confidence.py. confidence_override pisa el
        default del test_id cuando ESTA instancia puntual tiene evidencia más fuerte."""
        return self.confidence_override or get_confidence_for(self.test_id)

    cvss_vector_override: Optional[str] = None  # vector CVSS v3.1 ajustado para ESTA instancia puntual
                                                  # (ej. C:H en vez de C:L porque acá sí hubo credentials=true)
    business_impact_override: Optional[dict] = None  # pisa factores puntuales de impacto al negocio
                                                        # (ej. {"reputational": "low"}) cuando la evidencia
                                                        # de ESTA instancia es más débil que el caso típico

    @property
    def risk(self) -> dict:
        """Riesgo completo: vector/score CVSS v3.1, facilidad de explotación (sub-componentes
        CVSS en texto plano vía engine/core/cvss.py), impacto al negocio y rating agregado
        (OWASP Risk Rating Methodology: Likelihood x Impact), esfuerzo de remediación
        (estimación propia de Ares), y AIVSS complementario (aproximación declarada, no
        reemplaza el rating oficial). Ver engine/core/risk.py."""
        return risk_for(
            self.test_id, confidence=self.confidence,
            cvss_vector_override=self.cvss_vector_override,
            business_impact_override=self.business_impact_override,
            category=self.category.value,
        )

    @property
    def severity(self) -> Severity:
        """Derivada del risk rating (OWASP), no elegida a mano. Un finding con passed=True
        ("no se encontró nada") siempre es INFO, sin importar qué diga la tabla de riesgo."""
        if self.passed:
            return Severity.INFO
        return Severity(_RISK_RATING_TO_SEVERITY[self.risk["risk_rating"]])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "test_id": self.test_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "description": self.description,
            "passed": self.passed,
            "remediation": self.remediation,
            "references": self.references,
            "frameworks": self.frameworks,
            "confidence": self.confidence,
            "risk": self.risk if not self.passed else None,
            "evidence": self.evidence.to_dict(),
            "timestamp": self.timestamp,
            "suppressed": self.suppressed,
            "suppressed_reason": self.suppressed_reason,
        }


@dataclass
class TestMeta:
    """Metadata que describe un test disponible (para selección en UI/CLI)."""
    id: str
    name: str
    category: Category
    description: str
    default_enabled: bool = True
    requires_network: bool = False   # si el test puede hacer llamadas externas reales (SSRF, exfil, etc.)


@dataclass
class AuthConfig:
    """Credenciales explícitas a usar contra el target (transporte http/sse).
    type: "none" | "bearer" | "apikey" | "custom"
    header_name: solo aplica a "apikey"/"custom" (ej. "X-API-Key")."""
    type: str = "none"
    token: Optional[str] = None
    header_name: Optional[str] = None

    def to_headers(self) -> dict:
        if self.type == "bearer" and self.token:
            return {"Authorization": f"Bearer {self.token}"}
        if self.type in ("apikey", "custom") and self.token:
            return {(self.header_name or "X-API-Key"): self.token}
        return {}


@dataclass
class ScanConfig:
    """Config de una corrida: qué tests correr, contra qué target."""
    target_name: str
    transport: str                  # "stdio" | "sse" | "http"
    connection: dict                 # params de conexión (command/args, o url/headers)
    selected_tests: list[str] = field(default_factory=list)  # test ids seleccionados; vacío = todos los default
    max_fuzz_cases_per_tool: int = 25
    allow_network_side_effects: bool = False  # gate explícito para tests "requires_network"
    auth: Optional[AuthConfig] = None         # credenciales explícitas (http/sse)
    secondary_auth: Optional[AuthConfig] = None  # una SEGUNDA identidad/tenant válida contra el mismo
                                                   # server (http/sse) -- habilita auth.cross_session_context_bleed:
                                                   # plantar un canario con `auth` y buscarlo con esta otra
                                                   # sesión confirma fuga de contexto entre sesiones/tenants
                                                   # (MCP10:2025), no solo que el server "funciona".
    environment: str = "production"           # "production" | "development", usado por el policy engine
    source_path: Optional[str] = None         # ruta local del código fuente del server, para supplychain.dependency_vulnerabilities
    ca_bundle: Optional[str] = None           # ruta a un bundle de CA (PEM) para validar el certificado TLS del
                                                # server en transporte http/sse -- para auditar un server con CA
                                                # interna/corporativa sin desactivar la verificación. None = trust
                                                # store por defecto (certifi), con fallback a la env var SSL_CERT_FILE
                                                # resuelto en la CLI (ver engine/core/tls.py::resolve_ca_bundle).
    trust_presented_cert: bool = False         # http/sse: si la conexión falla por TLS no confiable (self-signed /
                                                # CA desconocida) y NO se dio --ca-bundle, traer el certificado que
                                                # el server presenta y FIJARLO (pinning TOFU) para completar el
                                                # handshake y poder correr las pruebas. NO valida identidad (el
                                                # dictamen del cert sigue marcándolo self-signed/riesgo) -- solo
                                                # permite auditar un target con cert interno sin frenar. Opt-in.
    request_delay_ms: int = 0                 # pausa entre llamadas a tools, para no saturar targets sensibles
    oob_callback_host: Optional[str] = None   # "host:puerto" reachable por el target, para confirmar SSRF por callback real
    baseline_path: Optional[str] = None       # reporte.json anterior; habilita el diff de findings Y adv.rug_pull
    allowlist_path: Optional[str] = None      # .ares_allowlist.yml -- suprime findings conocidos/aceptados (no los borra, ver engine/reporting/suppress.py)
    min_confidence: str = "heuristic"         # "heuristic" (default, todo cuenta) | "verified" (solo hechos observados gatean score/policy)
    live_agent_provider: str = "auto"         # "auto" | "anthropic" | "openai" | "ollama" | "all" -- ver engine/adversarial/live_agent_tests.py
    package_name: Optional[str] = None        # nombre de paquete declarado (npm/pypi) para static.typosquatting_check
    test_timeout_s: float = 60.0              # fail-closed: un test que no termina en este plazo se corta y se registra como error de ESE test, sin tumbar el scan
    verbose: bool = False                     # emite un evento "tool_call" por cada list_tools/call_tool/read_resource real, no solo el resumen por test
    max_consecutive_timeouts: int = 3         # circuit breaker: confirmado empíricamente que un solo tool que nunca responde
                                                # (ej. un server activamente hostil) hace que CADA test que lo toca se cuelgue
                                                # los test_timeout_s completos por separado -- 4 tests de la batería default ya
                                                # se comieron 4 minutos reales contra el mismo target antes de este fix. Tras N
                                                # timeouts CONSECUTIVOS el resto de los tests seleccionados se saltan de una, en
                                                # vez de seguir pagando el timeout completo test por test. 0 = sin límite (comportamiento viejo).
    sandbox_subprocess: bool = True           # aislamiento REAL de proceso (RLIMIT vía prlimit, ver engine/core/sandbox.py)
                                                # para el subprocess stdio del target -- default-on, --no-sandbox lo apaga.
    sandbox_mem_mb: int = 512                 # tope de memoria virtual (RLIMIT_AS) del proceso del target
    sandbox_cpu_s: int = 120                   # tope de tiempo de CPU (RLIMIT_CPU) del proceso del target
    sandbox_nproc: Optional[int] = None        # tope de procesos/threads (RLIMIT_NPROC) -- None (default) lo calcula
                                                 # dinámicamente como "lo que el usuario ya tiene corriendo + margen"
                                                 # (ver engine/core/sandbox.py: NPROC_HEADROOM). RLIMIT_NPROC es un
                                                 # tope sobre el TOTAL de procesos del usuario en el host, no por
                                                 # proceso hijo -- un número absoluto fijo rompe cualquier corrida
                                                 # real (confirmado: 64 fijo tumbaba la suite de tests enterita).
    sandbox_nofile: int = 256                    # tope de file descriptors abiertos (RLIMIT_NOFILE)
    max_text_for_analysis: Optional[int] = None  # override de engine.core.limits.MAX_TEXT_FOR_ANALYSIS (None = default del módulo)
    max_response_content: Optional[int] = None   # override de engine.core.limits.MAX_RESPONSE_CONTENT (None = default del módulo)
    reset_session_on_timeout: bool = True     # tras un timeout, cierra la sesión/subprocess vieja (que puede haber quedado
                                                # en un estado envenenado, o -- si es stdio -- seguir viva consumiendo
                                                # recursos del host) y abre una nueva para el resto de los tests. Si la
                                                # reconexión falla, el resto corre con target=None (mismo camino limpio
                                                # que una conexión inicial rechazada).


@dataclass
class ScanReport:
    scan_id: str
    target_name: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    tools_enumerated: list[dict] = field(default_factory=list)
    resources_enumerated: list[dict] = field(default_factory=list)
    prompts_enumerated: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    score: Optional[dict] = None            # {score, grade, verdict_text} -- ver engine/reporting/scoring.py
    policy_verdict: Optional[dict] = None   # {overall, by_finding} -- ver engine/policy/engine.py
    auth_impact: Optional[dict] = None      # {mitigated_by_auth, not_mitigated_by_auth} -- ver engine/compare.py
    baseline_diff: Optional[dict] = None    # {new, resolved, persisting} -- ver engine/baseline.py
    ares_version: str = ""

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target_name": self.target_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tools_enumerated": self.tools_enumerated,
            "resources_enumerated": self.resources_enumerated,
            "prompts_enumerated": self.prompts_enumerated,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "summary": self.summary(),
            "score": self.score,
            "policy_verdict": self.policy_verdict,
            "auth_impact": self.auth_impact,
            "baseline_diff": self.baseline_diff,
            "ares_version": self.ares_version,
        }

    def summary(self) -> dict:
        by_sev = {s.value: 0 for s in Severity}
        confirmed = 0
        suppressed = 0
        for f in self.findings:
            if f.passed:
                continue
            if f.suppressed:
                suppressed += 1
                continue
            by_sev[f.severity.value] += 1
            confirmed += 1
        return {
            "total_tests_run": len(self.findings),
            "confirmed_findings": confirmed,
            "by_severity": by_sev,
            "suppressed_findings": suppressed,
        }
