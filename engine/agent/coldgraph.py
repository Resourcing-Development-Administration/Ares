"""
Algoritmos de gestión del grafo de exploración: clasificación hot/cold,
agrupamiento por conectividad, compresión de nodos fríos.

Port de ARTEX agent/coldgraph.go — algoritmos puros, sin DB ni LLM.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict

@dataclass
class GraphNode:
    id: str
    kind: str           # "domain" | "url" | "ip" | "finding" | "service"
    content: str        # contenido del nodo
    access_count: int = 0
    last_access: float = 0.0
    is_hot: bool = True
    digest: str = ""    # digest LLM si fue compactado

class ColdGraph:
    """Gestiona la clasificación hot/cold de nodos del grafo de exploración.

    Nodos HOT: accedidos recientemente, en el contexto activo del agente.
    Nodos COLD: no accedidos en N rondas, candidatos a compactación.
    """

    HOT_ROUNDS = 3  # rounds sin acceso para pasar a cold

    def __init__(self):
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, set[str]] = defaultdict(set)  # id → {id_vecinos}
        self._round = 0
        self._last_access_round: dict[str, int] = {}

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.id] = node
        self._last_access_round[node.id] = self._round

    def add_edge(self, from_id: str, to_id: str) -> None:
        self._edges[from_id].add(to_id)
        self._edges[to_id].add(from_id)

    def access_node(self, node_id: str) -> GraphNode | None:
        node = self._nodes.get(node_id)
        if node:
            node.access_count += 1
            node.last_access = self._round
            self._last_access_round[node_id] = self._round
            node.is_hot = True
        return node

    def advance_round(self) -> list[str]:
        """Avanza una ronda y retorna IDs de nodos que se volvieron fríos."""
        self._round += 1
        newly_cold = []
        for nid, node in self._nodes.items():
            rounds_since = self._round - self._last_access_round.get(nid, 0)
            if rounds_since >= self.HOT_ROUNDS and node.is_hot:
                node.is_hot = False
                newly_cold.append(nid)
        return newly_cold

    def cold_nodes(self) -> list[GraphNode]:
        return [n for n in self._nodes.values() if not n.is_hot and not n.digest]

    def hot_nodes(self) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.is_hot]

    def connected_cold_groups(self) -> list[list[GraphNode]]:
        """Agrupa nodos fríos por conectividad (para compresión conjunta)."""
        cold_ids = {n.id for n in self.cold_nodes()}
        visited = set()
        groups = []

        for nid in cold_ids:
            if nid in visited: continue
            # BFS dentro de cold nodes
            group = []
            queue = [nid]
            while queue:
                curr = queue.pop()
                if curr in visited or curr not in cold_ids: continue
                visited.add(curr)
                group.append(self._nodes[curr])
                for neighbor in self._edges.get(curr, set()):
                    if neighbor in cold_ids and neighbor not in visited:
                        queue.append(neighbor)
            if group:
                groups.append(group)

        # Rescue singletons: nodos fríos aislados se agrupan con su parent más cercano
        return groups

    def apply_digest(self, node_ids: list[str], digest: str) -> None:
        """Aplica un digest LLM a un grupo de nodos fríos."""
        for nid in node_ids:
            if nid in self._nodes:
                self._nodes[nid].digest = digest

    def stats(self) -> dict:
        total = len(self._nodes)
        hot = sum(1 for n in self._nodes.values() if n.is_hot)
        cold_undigested = sum(1 for n in self._nodes.values() if not n.is_hot and not n.digest)
        cold_digested = sum(1 for n in self._nodes.values() if not n.is_hot and n.digest)
        return {"total": total, "hot": hot, "cold_undigested": cold_undigested, "cold_digested": cold_digested, "round": self._round}
