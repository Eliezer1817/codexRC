#!/usr/bin/env python3
"""FIN-STATE-TRANSITIONS (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 5.

Construye el grafo de transiciones de estado que el CODIGO declara
como legitimas, para despues poder decir si una transicion OBSERVADA
(durante una prueba dinamica, lab o live-read-only) es esperada o no.

Evidencia (unica fuente, nada se asume):
  Un bloque "if ($status == 'X') { ... $status = 'Y'; ... }" en el
  mismo handler es una transicion declarada por la aplicacion: desde
  'X' hacia 'Y'. Sin ese patron, NO se asume que la transicion exista
  ni que este prohibida: simplemente no hay evidencia de que el codigo
  la contemple.

Grafo:
  nodos  = todos los valores de estado vistos (en condiciones O en
           asignaciones) para una variable STATUS.
  edges  = {from, to, var, file, line, handler, evidence}

classify_transition(graph, from_state, to_state):
  Busca un edge con ese origen/destino exacto.
    - si existe: {"expected": True, "evidence": [...]}
    - si NO existe: {"expected": False, "evidence": []}
      y quien llama puede generar STATE-TRANSITION-CANDIDATE con el
      formato pedido:
        {"from": from_state, "action": accion, "to": to_state,
         "expected": False, "observed": True}

Uso:
    python3 core/fin_state_transitions.py <dir_plugin> [--json]
"""
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import fin_param_graph as fpg  # noqa: E402
from core import fin_param_infer as fpi  # noqa: E402
from core import gates_audit as ga  # noqa: E402

IF_STATUS_EQ_RE = re.compile(r"if\s*\(\s*\$(\w+)\s*==\s*['\"](\w+)['\"]")
ASSIGN_STATUS_RE = re.compile(r"\$(\w+)\s*=\s*['\"](\w+)['\"]\s*;")
WINDOW = 10  # lineas dentro del bloque if donde se busca la asignacion


def build_graph(root: str,
                 handlers: Optional[List[Dict[str, Any]]] = None
                 ) -> Dict[str, Any]:
    if handlers is None:
        handlers = ga.audit(root).get("handlers", [])

    nodes: set = set()
    edges: List[Dict[str, Any]] = []
    seen = set()

    for h in handlers:
        got = fpg._handler_body(root, h)
        if not got:
            continue
        body, callback_file, callback_line, handler_name = got
        lines = body.splitlines()

        for i, line in enumerate(lines):
            m = IF_STATUS_EQ_RE.search(line)
            if not m:
                continue
            var, from_state = m.groups()
            cls = fpi._classify(var)
            if not cls or cls["tipo"] != "STATUS":
                continue
            ventana = lines[i:i + WINDOW]
            for j, wline in enumerate(ventana):
                am = ASSIGN_STATUS_RE.search(wline)
                if not am or am.group(1) != var:
                    continue
                to_state = am.group(2)
                if to_state == from_state:
                    continue  # no-op declarado, no es una transicion
                linea_real = callback_line + i
                key = (callback_file, var, from_state, to_state)
                nodes.add(from_state)
                nodes.add(to_state)
                if key in seen:
                    continue
                seen.add(key)
                edges.append({
                    "from": from_state, "to": to_state, "var": var,
                    "file": callback_file, "line": linea_real,
                    "handler": handler_name,
                    "evidence": "%s -> %s" % (line.strip(), wline.strip()),
                })
                break  # una asignacion encontrada alcanza para este if

    return {"plugin": os.path.basename(os.path.abspath(root)),
            "nodes": sorted(nodes), "edges": edges,
            "resumen": {"estados": len(nodes), "transiciones": len(edges)}}


def classify_transition(graph: Dict[str, Any], from_state: str,
                         to_state: str) -> Dict[str, Any]:
    matches = [e for e in graph["edges"]
              if e["from"] == from_state and e["to"] == to_state]
    return {"expected": bool(matches), "evidence": matches}


def observed_transition_record(from_state: str, action: str, to_state: str,
                                graph: Dict[str, Any]) -> Dict[str, Any]:
    """Formato exacto pedido: {from, action, to, expected, observed}."""
    cls = classify_transition(graph, from_state, to_state)
    rec = {"from": from_state, "action": action, "to": to_state,
          "expected": cls["expected"], "observed": True}
    if not cls["expected"]:
        rec["veredicto"] = "STATE-TRANSITION-CANDIDATE"
        rec["evidencia"] = ("no existe en el codigo un bloque "
                            "'if (status==%r) {...status=%r...}' que "
                            "declare esta transicion como legitima" % (
                                from_state, to_state))
    else:
        rec["veredicto"] = "ESPERADA"
        rec["evidencia"] = cls["evidence"]
    return rec


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: fin_state_transitions.py <dir_plugin> [--json]")
        sys.exit(1)
    res = build_graph(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1, ensure_ascii=False))
    else:
        print("FIN-STATE-TRANSITIONS %s | %s" % (res["plugin"], res["resumen"]))
        for e in res["edges"]:
            print("  %s -> %s  (%s:%d) %s" % (
                e["from"], e["to"], e["file"], e["line"], e["evidence"]))
