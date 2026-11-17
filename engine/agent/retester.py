"""
Sesión dedicada de re-test de un finding específico.
Verifica si un hallazgo sigue siendo reproducible (reproduced/fixed/inconclusive).

Port de ARTEX agent/retester.go.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from engine.core.models import Finding
    from engine.agent.llmpool import LLMPool

class RetestVerdict(str, Enum):
    REPRODUCED   = "reproduced"    # finding confirmado reproducible
    FIXED        = "fixed"         # ya no es reproducible (posiblemente parchado)
    INCONCLUSIVE = "inconclusive"  # no se pudo determinar

@dataclass
class RetestResult:
    finding_id: str
    verdict: RetestVerdict
    evidence: str           # output de herramientas que evidencian el veredicto
    steps_taken: list[str]  # pasos ejecutados en el re-test
    agent_notes: str = ""

async def retest_finding(
    finding: "Finding",
    pool: "LLMPool",
    target_url: str,
    timeout_s: int = 120,
    progress_cb=None,
) -> RetestResult:
    """Ejecuta una sesión de re-test dedicada para un finding específico.

    Usa el LLM para determinar cómo re-testear el finding específico
    y luego lo ejecuta, reportando el veredicto.
    """
    finding_id = getattr(finding, 'test_id', str(id(finding)))

    # Construir prompt de re-test
    system = (
        "Eres un agente de re-test de seguridad. Tu ÚNICA misión es verificar si un "
        "hallazgo específico sigue siendo reproducible. No explores otros vectores. "
        "Responde al final con uno de: REPRODUCED / FIXED / INCONCLUSIVE y el porqué."
    )

    user_msg = f"""Re-testa este hallazgo:

FINDING: {getattr(finding, 'title', 'Unknown')}
SEVERIDAD: {getattr(finding, 'severity', 'unknown')}
DESCRIPCIÓN: {getattr(finding, 'description', 'No description')}
TARGET: {target_url}
TEST ID: {finding_id}

Pasos:
1. Intenta reproducir el hallazgo con la misma técnica
2. Documenta el resultado exacto (request + response)
3. Determina: ¿sigue siendo reproducible?
4. Responde: REPRODUCED | FIXED | INCONCLUSIVE"""

    steps = [f"Iniciando re-test de {finding_id}"]
    if progress_cb:
        await progress_cb({"type": "retest_started", "finding_id": finding_id})

    try:
        response = await asyncio.wait_for(
            pool.chat(
                messages=[{"role": "user", "content": user_msg}],
                system=system,
                max_tokens=2000,
            ),
            timeout=timeout_s,
        )

        # Parsear veredicto de la respuesta
        resp_upper = response.upper()
        if "REPRODUCED" in resp_upper:
            verdict = RetestVerdict.REPRODUCED
        elif "FIXED" in resp_upper:
            verdict = RetestVerdict.FIXED
        else:
            verdict = RetestVerdict.INCONCLUSIVE

        steps.append(f"LLM re-test completado: {verdict.value}")

        if progress_cb:
            await progress_cb({"type": "retest_complete", "finding_id": finding_id, "verdict": verdict.value})

        return RetestResult(
            finding_id=finding_id,
            verdict=verdict,
            evidence=response[:3000],
            steps_taken=steps,
        )

    except asyncio.TimeoutError:
        return RetestResult(
            finding_id=finding_id,
            verdict=RetestVerdict.INCONCLUSIVE,
            evidence="Timeout durante el re-test",
            steps_taken=steps + ["TIMEOUT"],
        )
    except Exception as e:
        return RetestResult(
            finding_id=finding_id,
            verdict=RetestVerdict.INCONCLUSIVE,
            evidence=f"Error durante re-test: {e}",
            steps_taken=steps + [f"ERROR: {e}"],
        )
