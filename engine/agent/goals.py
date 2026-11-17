"""
Descomposición de metas via LLM y extracción de constraints operacionales.
Port de ARTEX agent/goals.go.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from engine.agent.llmpool import LLMPool

@dataclass
class OperatorConstraints:
    """Constraints deny/allow extraídas del goal del operador."""
    deny: list[str] = field(default_factory=list)   # técnicas/endpoints prohibidos
    allow: list[str] = field(default_factory=list)  # técnicas explícitamente permitidas
    scope_notes: list[str] = field(default_factory=list)

    def to_prompt_text(self) -> str:
        lines = []
        if self.deny:
            lines.append("PROHIBIDO: " + "; ".join(self.deny))
        if self.allow:
            lines.append("PERMITIDO EXPLÍCITAMENTE: " + "; ".join(self.allow))
        if self.scope_notes:
            lines.append("NOTAS DE SCOPE: " + "; ".join(self.scope_notes))
        return "\n".join(lines)

@dataclass
class GoalDecomposition:
    original_goal: str
    target: str
    sub_goals: list[str]           # lista ordenada de sub-objetivos
    constraints: OperatorConstraints
    is_ambiguous: bool = False      # True si el goal es demasiado vago
    ambiguity_reason: str = ""

# Gate de ambigüedad: goals con menos de N tokens o sin target concreto
MIN_GOAL_TOKENS = 5
MIN_GOAL_LEN = 20

def goal_is_ambiguous(goal: str) -> tuple[bool, str]:
    """Retorna (ambiguous, reason). True si el goal es demasiado vago."""
    if len(goal.strip()) < MIN_GOAL_LEN:
        return True, f"Goal demasiado corto (mín {MIN_GOAL_LEN} chars)"
    tokens = goal.split()
    if len(tokens) < MIN_GOAL_TOKENS:
        return True, f"Goal demasiado vago (mín {MIN_GOAL_TOKENS} palabras)"
    # Debe mencionar algún target concreto
    has_target = bool(re.search(r'(https?://|[\w.-]+\.[a-z]{2,}|/api/|endpoint|servidor|server)', goal, re.I))
    if not has_target:
        return True, "El goal no menciona un target o endpoint concreto"
    return False, ""

async def decompose_goal(goal: str, pool: "LLMPool") -> GoalDecomposition:
    """Descompone un goal en sub-objetivos usando LLM.

    También extrae constraints deny/allow que el operador haya indicado en el goal.
    """
    ambiguous, reason = goal_is_ambiguous(goal)

    # Extraer target del goal (regex simple)
    target_match = re.search(r'https?://[\w./-]+|[\w-]+\.[\w.-]+(?:/[\w/-]*)?', goal)
    target = target_match.group() if target_match else goal.split()[0] if goal.split() else ""

    if ambiguous:
        return GoalDecomposition(
            original_goal=goal, target=target, sub_goals=[goal],
            constraints=OperatorConstraints(), is_ambiguous=True, ambiguity_reason=reason
        )

    prompt = f"""Analiza este objetivo de prueba de seguridad y extrae:
1. Lista de sub-objetivos concretos (máx 5, en orden de ejecución)
2. Constraints deny/allow explícitos que el operador haya mencionado

OBJETIVO: {goal}

Responde en JSON con esta estructura:
{{
  "sub_goals": ["sub-objetivo 1", "sub-objetivo 2", ...],
  "deny": ["técnica o endpoint prohibido", ...],
  "allow": ["técnica explícitamente permitida", ...],
  "scope_notes": ["nota de scope", ...]
}}"""

    try:
        import json
        response = await pool.chat([{"role": "user", "content": prompt}], max_tokens=800)
        # Extraer JSON de la respuesta
        m = re.search(r'\{.*\}', response, re.DOTALL)
        if m:
            data = json.loads(m.group())
            return GoalDecomposition(
                original_goal=goal, target=target,
                sub_goals=data.get("sub_goals", [goal]),
                constraints=OperatorConstraints(
                    deny=data.get("deny", []),
                    allow=data.get("allow", []),
                    scope_notes=data.get("scope_notes", []),
                )
            )
    except Exception:
        pass

    # Fallback: sin descomposición
    return GoalDecomposition(
        original_goal=goal, target=target, sub_goals=[goal],
        constraints=OperatorConstraints()
    )
