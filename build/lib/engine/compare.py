"""
Corre el mismo scan dos veces -- una con las credenciales configuradas, otra
completamente sin auth -- y diffea los findings confirmados para responder
la pregunta central: "¿la autenticación protege realmente algo, o el server
se comporta igual esté o no esté logueado?"
"""
from __future__ import annotations
import copy

from engine.core.models import ScanConfig, ScanReport
from engine.orchestrator import run_scan


def _finding_key(f) -> tuple:
    return (f.test_id, f.target)


async def run_auth_comparison(config: ScanConfig, progress_cb=None) -> tuple[ScanReport, ScanReport]:
    """Devuelve (report_con_auth, report_sin_auth). Si config.auth es None (ya
    era una corrida sin auth), la segunda corrida es idéntica y auth_impact
    quedará vacío -- señal honesta de que no había nada que comparar."""

    def emit(event):
        if progress_cb:
            progress_cb({**event, "phase": "with_auth"})

    report_with_auth = await run_scan(config, progress_cb=emit)

    config_no_auth = copy.deepcopy(config)
    config_no_auth.auth = None
    config_no_auth.connection = {k: v for k, v in config.connection.items() if k not in ("auth", "headers")}

    def emit2(event):
        if progress_cb:
            progress_cb({**event, "phase": "without_auth"})

    report_without_auth = await run_scan(config_no_auth, progress_cb=emit2)

    with_keys = {_finding_key(f) for f in report_with_auth.findings if not f.passed}
    without_keys = {_finding_key(f) for f in report_without_auth.findings if not f.passed}

    mitigated_by_auth = sorted([f"{t}::{tg}" for t, tg in (without_keys - with_keys)])
    not_mitigated_by_auth = sorted([f"{t}::{tg}" for t, tg in (without_keys & with_keys)])
    only_with_auth = sorted([f"{t}::{tg}" for t, tg in (with_keys - without_keys)])

    auth_impact = {
        "mitigated_by_auth": mitigated_by_auth,
        "not_mitigated_by_auth": not_mitigated_by_auth,
        "only_visible_with_auth": only_with_auth,
        "summary": (
            f"{len(mitigated_by_auth)} hallazgo(s) desaparecen al autenticarse (auth SÍ los mitiga); "
            f"{len(not_mitigated_by_auth)} hallazgo(s) persisten igual con o sin auth (auth NO los mitiga)."
        ),
    }
    report_with_auth.auth_impact = auth_impact
    report_without_auth.auth_impact = auth_impact
    return report_with_auth, report_without_auth
