#!/usr/bin/env python3
"""FIN-INVARIANTS (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 2.

Toma el grafo de FIN-PARAM-GRAPH y el codigo fuente y PROPONE hipotesis
de invariante. No asume que una regla es correcta solo porque "deberia"
serlo: cada invariante exige evidencia concreta.

Dos fuentes de evidencia (las UNICAS que generan hipotesis):

  1. RELACIONAL (de fin_param_graph): un edge aritmetico HIGH-confidence
     (MULTIPLY/ADD/SUBTRACT/DIVIDE) prueba que el codigo CALCULA
     target = opA <op> opB. La hipotesis de invariante es que esa
     relacion debe mantenerse siempre: "subtotal == price * quantity".
     Evidencia = la linea de asignacion real.

  2. DE VALIDACION (del propio codigo del handler): si el handler
     compara el parametro contra un limite y RECHAZA cuando lo
     incumple (ej. "if ($price < 0) { wp_die(); }"), eso es evidencia
     de que la aplicacion MISMA declara el invariante "price >= 0".
     Sin ese patron, NO se infiere el limite (no se asume "todo precio
     deberia ser positivo" porque suene razonable).

  3. ENUM (de validacion de estado): "in_array($status, [...])" prueba
     que el handler declara una lista cerrada de estados validos.

Cada invariante: {invariant_id, expression, source_evidence,
confidence, affected_parameters, affected_state, file, line, handler}.

confidence:
  HIGH   relacion aritmetica con ambos operandos financieros, o
         enum con lista explicita de literales.
  MEDIA  bound inferido de una comparacion con rechazo cercano
         (heuristico: no se verifico ejecucion real, solo lectura).

Uso:
    python3 core/fin_invariants.py <dir_plugin> [--json]
"""
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import fin_param_graph as fpg  # noqa: E402
from core import gates_audit as ga  # noqa: E402

ARITH_RE = re.compile(
    r"\$(\w+)\s*=\s*\$(\w+)\s*([*+\-/])\s*\$(\w+)\s*;")
OP_SYMBOL = {"MULTIPLY": "*", "ADD": "+", "SUBTRACT": "-", "DIVIDE": "/"}

# patron de rechazo cerca de una comparacion: la app realmente CORTA la
# ejecucion si la condicion se cumple (si no hay rechazo cerca, la
# comparacion podria ser un simple log/no-op: no cuenta como invariante)
REJECT_RE = re.compile(
    r"\b(wp_die|die|return|throw|exit)\b")

# limites por categoria: (regex de comparacion sobre la variable,
# plantilla de expresion resultante si HAY rechazo cerca)
BOUND_PATTERNS = {
    "AMOUNT": [
        (re.compile(r"\$(\w+)\s*<\s*0\b"), "{v} >= 0"),
        (re.compile(r"\$(\w+)\s*<=\s*0\b"), "{v} > 0"),
    ],
    "QTY": [
        (re.compile(r"\$(\w+)\s*<\s*1\b"), "{v} >= 1"),
        (re.compile(r"\$(\w+)\s*<\s*0\b"), "{v} >= 0"),
    ],
    "DISCOUNT": [
        (re.compile(r"\$(\w+)\s*>\s*100\b"), "{v} <= 100"),
        (re.compile(r"\$(\w+)\s*<\s*0\b"), "{v} >= 0"),
    ],
}

ENUM_RE = re.compile(
    r"in_array\s*\(\s*\$(\w+)\s*,\s*(?:array\s*\(|\[)([^)\]]*)\)")
STR_LIT_RE = re.compile(r"['\"]([\w\-]+)['\"]")


def _inv_id(*parts: str) -> str:
    h = hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]
    return "INV-%s" % h


def _relational_invariants(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reconstruye la formula completa desde los edges HIGH (2 edges
    por formula: opA->target y opB->target, mismo file/line/evidence)."""
    groups: Dict[Any, Dict[str, Any]] = {}
    for e in graph["edges"]:
        if e["relation"] not in OP_SYMBOL or e["confidence"] != "HIGH":
            continue
        key = (e["file"], e["line"], e["target"], e["relation"],
              e["evidence"])
        g = groups.setdefault(key, {"ops": [], **e})
        g["ops"].append(e["source"])

    out = []
    for (file_, line, target, relation, evidence), g in groups.items():
        m = ARITH_RE.match(evidence)
        if not m:
            continue
        t, opa, op, opb = m.groups()
        expr = "%s == %s %s %s" % (target, opa, OP_SYMBOL[relation], opb)
        out.append({
            "invariant_id": _inv_id("REL", file_, str(line), target),
            "expression": expr,
            "source_evidence": evidence,
            "confidence": "HIGH",
            "affected_parameters": sorted(set([opa, opb])),
            "affected_state": target,
            "file": file_, "line": line, "handler": g["handler"],
            "kind": "RELATIONAL",
        })
    return out


def _bound_invariants(root: str,
                       handlers: List[Dict[str, Any]],
                       nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    by_handler: Dict[str, List[Dict[str, Any]]] = {}
    for n in nodes:
        by_handler.setdefault(n["handler"], []).append(n)

    for h in handlers:
        got = fpg._handler_body(root, h)
        if not got:
            continue
        body, callback_file, callback_line, handler_name = got
        lines = body.splitlines()
        relevant = by_handler.get(handler_name, [])
        tipos_por_nombre = {n["name"]: n["tipo"] for n in relevant}

        for i, line in enumerate(lines):
            for varname, tipo in tipos_por_nombre.items():
                patterns = BOUND_PATTERNS.get(tipo, [])
                for rx, tpl in patterns:
                    mm = rx.search(line)
                    if not mm or mm.group(1) != varname:
                        continue
                    ventana = "\n".join(lines[i:i + 4])
                    if not REJECT_RE.search(ventana):
                        continue  # comparacion sin rechazo: no cuenta
                    linea_real = callback_line + i
                    out.append({
                        "invariant_id": _inv_id("BOUND", callback_file,
                                                str(linea_real), varname,
                                                tpl),
                        "expression": tpl.format(v=varname),
                        "source_evidence": line.strip(),
                        "confidence": "MEDIA",
                        "affected_parameters": [varname],
                        "affected_state": varname,
                        "file": callback_file, "line": linea_real,
                        "handler": handler_name,
                        "kind": "BOUND",
                    })

            # enum de estado
            em = ENUM_RE.search(line)
            if em:
                varname = em.group(1)
                if tipos_por_nombre.get(varname) != "STATUS":
                    continue
                valores = STR_LIT_RE.findall(em.group(2))
                if not valores:
                    continue
                linea_real = callback_line + i
                out.append({
                    "invariant_id": _inv_id("ENUM", callback_file,
                                            str(linea_real), varname),
                    "expression": "%s in {%s}" % (
                        varname, ", ".join(sorted(valores))),
                    "source_evidence": line.strip(),
                    "confidence": "HIGH",
                    "affected_parameters": [varname],
                    "affected_state": varname,
                    "file": callback_file, "line": linea_real,
                    "handler": handler_name,
                    "kind": "ENUM",
                    "valid_values": sorted(valores),
                })
    return out


def infer_invariants(root: str,
                      handlers: Optional[List[Dict[str, Any]]] = None
                      ) -> Dict[str, Any]:
    if handlers is None:
        handlers = ga.audit(root).get("handlers", [])
    graph = fpg.build_graph(root, handlers=handlers)

    relational = _relational_invariants(graph)
    bounds = _bound_invariants(root, handlers, graph["nodes"])

    invariantes = relational + bounds
    # dedupe por invariant_id (determinista: mismo codigo -> mismo id)
    seen = set()
    dedup = []
    for inv in invariantes:
        if inv["invariant_id"] in seen:
            continue
        seen.add(inv["invariant_id"])
        dedup.append(inv)

    resumen = {"total": len(dedup),
              "por_kind": {k: sum(1 for i in dedup if i["kind"] == k)
                          for k in set(i["kind"] for i in dedup)},
              "high": sum(1 for i in dedup if i["confidence"] == "HIGH"),
              "media": sum(1 for i in dedup if i["confidence"] == "MEDIA")}

    return {"plugin": graph["plugin"], "graph": graph,
            "invariantes": dedup, "resumen": resumen}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: fin_invariants.py <dir_plugin> [--json]")
        sys.exit(1)
    res = infer_invariants(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1, ensure_ascii=False))
    else:
        print("FIN-INVARIANTS %s | %s" % (res["plugin"], res["resumen"]))
        for inv in res["invariantes"]:
            print("  [%s/%s] %s  (%s:%d) evidencia: %s" % (
                inv["kind"], inv["confidence"], inv["expression"],
                inv["file"], inv["line"], inv["source_evidence"]))
