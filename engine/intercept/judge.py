"""
LLM intercept judge — evaluación post-gate antes de ejecutar un test.

Hace 8 preguntas cerradas (sí/no) al LLM y toma una decisión binaria
allow/block. Fail-closed: si el LLM falla, bloquea por default.
Equivalente al judge.go de ARTEX.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from typing import Literal

JUDGE_QUESTIONS = [
    "¿El test está dentro del scope declarado?",
    "¿El host/IP es un target autorizado?",
    "¿El test es reversible (no destructivo)?",
    "¿El nivel de intrusividad es aceptable para este entorno?",
    "¿El payload NO contiene credenciales o secretos hardcodeados?",
    "¿El test NO podría afectar a terceros fuera del scope?",
    "¿El rate sería aceptable para un sistema de producción?",
    "¿Está documentado el propósito del test?",
    "¿El test NO podría causar indisponibilidad del servicio?",
    "¿El test NO exfiltra ni expone datos reales de usuarios?",
    "¿El test NO provoca pérdida permanente de datos?",
]

# Preguntas cuya respuesta esperada es "no" para que el test sea seguro.
# Las anteriores esperan "sí"; estas invierten la lógica.
_INVERTED_QUESTIONS: set[int] = set()  # actualmente ninguna — todas esperan "sí"


@dataclass
class JudgeDecision:
    action: Literal["allow", "block"]
    reason: str
    answers: dict[str, str]  # {pregunta: "yes"|"no"|"error"}
    blocked_on: list[str]    # preguntas que fallaron


class InterceptJudge:
    """Juez LLM que evalúa si un test puede ejecutarse.

    Fail-closed: si el LLM no responde o responde de forma ambigua,
    la decisión es "block".
    """

    def __init__(self, pool: "LLMPool") -> None:
        self._pool = pool

    async def evaluate(
        self,
        test_id: str,
        target_url: str,
        test_description: str,
        scope: list[str] | None = None,
        environment: str = "production",
    ) -> JudgeDecision:
        """Evalúa si el test puede ejecutarse. Fail-closed."""
        try:
            return await self._run_evaluation(
                test_id=test_id,
                target_url=target_url,
                test_description=test_description,
                scope=scope,
                environment=environment,
            )
        except Exception as exc:
            return JudgeDecision(
                action="block",
                reason=f"judge LLM error (fail-closed): {exc}",
                answers={q: "error" for q in JUDGE_QUESTIONS},
                blocked_on=["LLM failure"],
            )

    async def _run_evaluation(
        self,
        test_id: str,
        target_url: str,
        test_description: str,
        scope: list[str] | None,
        environment: str,
    ) -> JudgeDecision:
        scope_str = ", ".join(scope) if scope else "(sin scope declarado)"
        numbered = "\n".join(f"{i+1}. {q}" for i, q in enumerate(JUDGE_QUESTIONS))

        prompt = f"""Sos un juez de seguridad evaluando si un test puede ejecutarse.
Respondé SOLO con JSON válido — un objeto con una clave por número de pregunta ("1" a "11"),
cada valor exactamente "yes" o "no". Sin texto adicional.
Para cada pregunta responde únicamente con 'sí' o 'no'. El test solo se aprueba si TODAS las respuestas son 'sí'.

Contexto:
- test_id: {test_id}
- target: {target_url}
- scope: {scope_str}
- entorno: {environment}
- descripción: {test_description}

Preguntas:
{numbered}

Respuesta (solo JSON):"""

        messages = [{"role": "user", "content": prompt}]
        response = await self._pool.chat(messages, max_tokens=256)

        raw = ""
        content = response.get("content", "")
        if isinstance(content, str):
            raw = content
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    raw += block.get("text", "")
                elif isinstance(block, str):
                    raw += block

        answers = _parse_answers(raw)
        blocked_on = []
        for i, q in enumerate(JUDGE_QUESTIONS):
            key = str(i + 1)
            answer = answers.get(key, "error")
            expected = "no" if i in _INVERTED_QUESTIONS else "yes"
            if answer != expected:
                blocked_on.append(q)

        if blocked_on:
            return JudgeDecision(
                action="block",
                reason=f"judge bloqueó: {len(blocked_on)} pregunta(s) fallida(s)",
                answers={JUDGE_QUESTIONS[i]: answers.get(str(i + 1), "error")
                         for i in range(len(JUDGE_QUESTIONS))},
                blocked_on=blocked_on,
            )

        return JudgeDecision(
            action="allow",
            reason="todas las verificaciones pasaron",
            answers={JUDGE_QUESTIONS[i]: answers.get(str(i + 1), "error")
                     for i in range(len(JUDGE_QUESTIONS))},
            blocked_on=[],
        )


def _parse_answers(raw: str) -> dict[str, str]:
    """Parsea la respuesta JSON del LLM. Tolerante a markdown code fences."""
    text = raw.strip()
    # strip ```json ... ``` fences
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text, flags=re.IGNORECASE)
    text = text.strip()
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            return {}
        normalized: dict[str, str] = {}
        for k, v in data.items():
            key = str(k).strip()
            val = str(v).strip().lower()
            if val in ("yes", "sí", "si", "true", "1"):
                normalized[key] = "yes"
            elif val in ("no", "false", "0"):
                normalized[key] = "no"
            else:
                normalized[key] = "error"
        return normalized
    except (json.JSONDecodeError, ValueError):
        return {}
