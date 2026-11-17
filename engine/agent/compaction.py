"""
Compactación LLM de nodos fríos del grafo de exploración.
Genera digests en background para reducir el contexto del agente.

Port de ARTEX agent/compaction.go.
"""
from __future__ import annotations
import asyncio
import logging
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from engine.agent.llmpool import LLMPool
    from engine.agent.coldgraph import ColdGraph, GraphNode

log = logging.getLogger(__name__)

COMPACTION_SYSTEM = (
    "Eres un resumidor de hallazgos de seguridad. Se te da un grupo de nodos de un "
    "grafo de exploración que ya no están activos. Resume la información relevante "
    "en 2-3 párrafos concisos. Preserva: hosts/IPs, vulnerabilidades encontradas, "
    "paths probados y resultados clave. Descarta: detalles redundantes, errores de red "
    "temporales, outputs verbosos sin hallazgos."
)

class Compactor:
    """Compacta grupos de nodos fríos usando LLM en background.

    Corre como tarea asyncio paralela al loop planner/worker.
    No bloquea la ejecución del agente.
    """

    def __init__(self, pool: "LLMPool", graph: "ColdGraph", max_concurrent: int = 2):
        self._pool = pool
        self._graph = graph
        self._sem = asyncio.Semaphore(max_concurrent)
        self._running = False
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        """Inicia el compactor en background."""
        if not self._running:
            self._running = True
            self._task = asyncio.create_task(self._compaction_loop())

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    async def _compaction_loop(self) -> None:
        """Loop de compactación: cada 30s busca nodos fríos sin digest."""
        while self._running:
            try:
                await asyncio.sleep(30)
                groups = self._graph.connected_cold_groups()
                if not groups:
                    continue
                # Compactar hasta 3 grupos por ciclo
                tasks = [self._compact_group(g) for g in groups[:3]]
                await asyncio.gather(*tasks, return_exceptions=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("Compaction loop error: %s", e)

    async def _compact_group(self, nodes: list["GraphNode"]) -> None:
        async with self._sem:
            if not nodes: return
            # Construir texto del grupo
            parts = [f"[{n.kind.upper()}] {n.id}: {n.content[:500]}" for n in nodes]
            content = "\n\n".join(parts)

            try:
                digest = await self._pool.chat(
                    messages=[{"role": "user", "content": f"Resume estos nodos de exploración:\n\n{content}"}],
                    system=COMPACTION_SYSTEM,
                    max_tokens=500,
                )
                node_ids = [n.id for n in nodes]
                self._graph.apply_digest(node_ids, digest)
                log.debug("Compacted %d nodes → %d chars", len(nodes), len(digest))
            except Exception as e:
                log.warning("Failed to compact group: %s", e)

    async def compact_now(self) -> int:
        """Compactación inmediata (síncrona). Retorna número de grupos compactados."""
        groups = self._graph.connected_cold_groups()
        if not groups: return 0
        tasks = [self._compact_group(g) for g in groups]
        await asyncio.gather(*tasks, return_exceptions=True)
        return len(groups)
