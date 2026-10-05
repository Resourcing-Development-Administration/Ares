"""
Calculador de CVSS v3.1 Base Score -- implementa la fórmula oficial publicada
por FIRST.org (https://www.first.org/cvss/v3.1/specification-document,
sección 7.1), no una aproximación. Mismo cálculo que usa cualquier
calculadora oficial de CVSS.

Scope Changed (S:C) SÍ se usa activamente -- varios tests en
engine/core/risk.py lo modelan explícitamente (adv.ssrf_exfil,
adv.rug_pull, adv.live_agent_injection, adv.stateful_chain_exfil,
supplychain.exfiltration_chain) para los casos de libro de cruce de scope
de seguridad en el sentido estricto de CVSS (ej. SSRF: de la red pública a
la interna). Por eso el chequeo "Impact <= 0 -> score 0" de más abajo se
hace sobre Impact ya calculado, no sobre ISCBase -- son equivalentes para
Scope Unchanged, pero no para Scope Changed.
"""
from __future__ import annotations
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/"
    r"S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])$"
)


def parse_vector(vector: str) -> dict:
    """Acepta el vector con o sin el prefijo 'CVSS:3.1/'."""
    v = vector if vector.startswith("CVSS:3.1/") else f"CVSS:3.1/{vector}"
    m = _VECTOR_RE.match(v)
    if not m:
        raise ValueError(f"vector CVSS v3.1 inválido o incompleto: {vector!r}")
    return m.groupdict()


def _roundup(value: float) -> float:
    """Función 'Roundup' oficial de CVSS: redondea hacia arriba al primer decimal,
    trabajando en enteros escalados para evitar errores de punto flotante."""
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000
    return (int_value // 10000 + 1) / 10


def calculate_base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    av = _AV[m["AV"]]
    ac = _AC[m["AC"]]
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    ui = _UI[m["UI"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    # El texto oficial de la sección 7.1 dice "If Impact <= 0, Base Score = 0"
    # -- sobre Impact (ya multiplicado por su fórmula de Scope), NO sobre
    # ISCBase. Para Scope Unchanged ambos chequeos coinciden (Impact = 6.42 x
    # ISCBase, mismo signo), pero para Scope Changed la fórmula (7.52 x
    # (ISCBase - 0.029) - ...) puede dar Impact <= 0 con ISCBase > 0 chico --
    # chequear ISCBase ahí habría devuelto un score > 0 donde el spec exige 0.
    # (En la práctica, con los bins categóricos N/L/H de CVSS, el único ISCBase
    # no-cero posible es >= 0.22, fuera de esa zona de riesgo -- pero el
    # cálculo queda spec-correct igual, sin depender de qué vectores use Ares hoy.)
    if impact <= 0:
        return 0.0

    if scope_changed:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base_score = _roundup(min(impact + exploitability, 10))

    return round(base_score, 1)


def severity_from_score(score: float) -> str:
    """Tabla oficial de calificación cualitativa de CVSS v3.1 (Qualitative Severity Rating Scale)."""
    if score == 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def severity_from_vector(vector: str) -> "Severity":  # noqa: F821 -- import diferido para evitar ciclo
    from engine.core.models import Severity
    return Severity(severity_from_score(calculate_base_score(vector)))


_PLAIN_AV = {"N": "red (Internet/red)", "A": "red adyacente", "L": "acceso local", "P": "acceso físico"}
_PLAIN_AC = {"L": "baja", "H": "alta"}
_PLAIN_PR = {"N": "ninguno", "L": "bajo (usuario autenticado normal)", "H": "alto (admin)"}
_PLAIN_UI = {"N": "ninguna", "R": "requiere que un usuario haga algo"}


def exploitability_plain_language(vector: str) -> dict:
    """Traduce los sub-componentes de explotabilidad de CVSS a texto plano --
    esto es lo que responde 'facilidad de explotación', con la fuente exacta
    (el propio vector) siempre visible al lado."""
    m = parse_vector(vector)
    return {
        "attack_vector": _PLAIN_AV[m["AV"]],
        "attack_complexity": _PLAIN_AC[m["AC"]],
        "privileges_required": _PLAIN_PR[m["PR"]],
        "user_interaction": _PLAIN_UI[m["UI"]],
    }
