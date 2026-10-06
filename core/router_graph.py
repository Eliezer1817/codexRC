#!/usr/bin/env python3
# ============================================================
# codexRC - ROUTER GRAPH (v0.98.0)
# ------------------------------------------------------------
# Representacion grafo de la superficie HTTP descubierta:
#
#   ROUTER -> ROUTE -> HANDLER -> PARAMETER / MIDDLEWARE / AUTH
#
# Cada edge lleva evidencia (archivo + linea): EVIDENCE-FIRST
# DISCOVERY (REGLA 7 de v0.98.0). Esto NO es un Hunter: solo
# almacena y expone estructura para que otros motores la consuman.
# ============================================================
from typing import Any, Dict, List, Optional


class RouterGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._auto = 0

    def _new_id(self, prefix: str) -> str:
        self._auto += 1
        return f"{prefix}_{self._auto:04d}"

    def add_node(self, kind: str, label: str, **extra: Any) -> str:
        nid = self._new_id(kind)
        self.nodes[nid] = {"id": nid, "kind": kind, "label": label, **extra}
        return nid

    def add_edge(self, src: str, dst: str, relation: str,
                 file: Optional[str] = None, line: Optional[int] = None,
                 evidence: Optional[str] = None) -> None:
        self.edges.append({
            "from": src, "to": dst, "relation": relation,
            "file": file, "line": line, "evidence": evidence,
        })

    def edges_from(self, node_id: str) -> List[Dict[str, Any]]:
        return [e for e in self.edges if e["from"] == node_id]

    def edges_to(self, node_id: str) -> List[Dict[str, Any]]:
        return [e for e in self.edges if e["to"] == node_id]

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": list(self.nodes.values()), "edges": self.edges}
