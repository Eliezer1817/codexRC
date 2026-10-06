#!/usr/bin/env python3
"""FIN-PARAM-GRAPH (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 1.

Primer peldano de v2: en vez de tratar cada parametro financiero como
una variable aislada (asi funciona FIN-LOGIC v1), construye una
representacion RELACIONAL: QUE parametro deriva de CUALES otros, y con
QUE operacion.

No reemplaza fin_param_infer.py: lo REUSA. Este modulo solo agrega la
capa de relaciones encima de los parametros que ya detecto v1, mas los
nombres de variables LOCALES (no sourced de $_POST) que participan de
una formula financiera (ej. $subtotal, $total, $balance_after: se
calculan en el servidor, nunca llegan por request, pero el ataque real
casi siempre es ROMPER la relacion, no el valor aislado).

Regla ZERO BLIND COVERAGE (igual que v1): un edge SOLO existe si hay
una linea de codigo real que lo prueba (asignacion aritmetica). No se
infieren relaciones por similitud de nombres ("total" y "subtotal"
suenan relacionados, pero sin una linea que haga target = f(ops) no
hay edge).

Nodos:
  origen=source    nace de $_POST/$_GET/$_REQUEST (FIN-PARAM-DETECTED
                   de fin_param_infer).
  origen=computed  variable LOCAL con nombre financiero que participa
                   de al menos una formula pero el usuario no la
                   manda directo (ej. $subtotal, $total).

Relaciones (edges), cada una con su EVIDENCIA LITERAL (la linea exacta):
  MULTIPLY / ADD / SUBTRACT / DIVIDE   target = opA <op> opB ;
  ASSIGN                                target = opA ;  (copia directa,
                                        ambos lados financieros)
  COOCCURS                              dos nombres de la MISMA familia
                                        STATUS (ej. payment_status,
                                        order_status, paid_at) se
                                        escriben cerca uno del otro en
                                        el mismo handler: senal de
                                        acoplamiento temporal, NUNCA
                                        confidence HIGH (es coincidencia
                                        de posicion, no una formula).

confidence:
  HIGH   ambos operandos Y el target son financieros (arithmetic).
  MEDIA  solo el target + UN operando son financieros, o es
         ASSIGN/COOCCURS (acoplamiento mas debil, igual con evidencia).

Uso:
    python3 core/fin_param_graph.py <dir_plugin> [--json]
"""
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import gates_audit as ga  # noqa: E402
from core import fin_param_infer as fpi  # noqa: E402

# target = opA <op> opB ;  (operador binario simple, ambos operandos
# son variables). Chains de 3+ operandos no se matchean a proposito:
# si el codigo real los usa, casi siempre pasan por una variable
# intermedia (subtotal) que SI queda cubierta en dos pasos.
ARITH_RE = re.compile(
    r"\$(\w+)\s*=\s*\$(\w+)\s*([*+\-/])\s*\$(\w+)\s*;")
# target = opA ;  (copia directa, sin operador)
ASSIGN_RE = re.compile(r"\$(\w+)\s*=\s*\$(\w+)\s*;")
# escritura de un campo STATUS: asignacion local o persistencia directa
# (update_post_meta/update_option con la clave como 2do argumento)
META_WRITE_RE = re.compile(
    r"update_(?:post_meta|option)\s*\(\s*[^,]+,\s*['\"](\w+)['\"]")

REL_NAME = {"*": "MULTIPLY", "+": "ADD", "-": "SUBTRACT", "/": "DIVIDE"}
COOCCUR_WINDOW = 15  # lineas de distancia maxima para contar como cercano


def _fin_name(name: str) -> Optional[Dict[str, str]]:
    """Reusa el clasificador de fin_param_infer sobre un nombre de
    variable PHP arbitrario (no solo claves de $_POST/$_GET)."""
    return fpi._classify(name)


def _handler_body(root: str, h: Dict[str, Any]):
    """(body, callback_file, callback_line, handler_name) o None."""
    callback_file = h.get("archivo_callback") or h.get("archivo")
    callback_line = h.get("linea_callback") or h.get("linea_hook")
    if not callback_file or not callback_line:
        return None
    path = os.path.join(root, callback_file)
    if not os.path.isfile(path):
        return None
    try:
        lines = open(path, encoding="utf-8",
                     errors="ignore").read().splitlines()
    except Exception:
        return None
    body, _end = ga._body_of(lines, max(callback_line - 1, 0))
    handler_name = h.get("accion") or h.get("callback") or "rest"
    return body, callback_file, callback_line, handler_name


def _register_node(nodes: Dict[str, Dict[str, Any]], name: str,
                    cls: Dict[str, str], origen: str, file_: str,
                    line: int, handler: str) -> None:
    if name in nodes:
        return
    nodes[name] = {"name": name, "origen": origen, "tipo": cls["tipo"],
                   "confianza": cls["confianza"], "file": file_,
                   "line": line, "handler": handler}


def build_graph(root: str,
                 handlers: Optional[List[Dict[str, Any]]] = None
                 ) -> Dict[str, Any]:
    if handlers is None:
        handlers = ga.audit(root).get("handlers", [])

    params = fpi.infer_params(root, handlers=handlers)

    nodes: Dict[str, Dict[str, Any]] = {}
    for f in params["findings"]:
        _register_node(nodes, f["parametro"],
                       {"tipo": f["tipo"], "confianza": f["confianza"]},
                       "source", f["archivo"], f["linea"], f["endpoint"])

    edges: List[Dict[str, Any]] = []

    for h in handlers:
        got = _handler_body(root, h)
        if not got:
            continue
        body, callback_file, callback_line, handler_name = got

        # ---------------------------------------------------- aritmetica
        for m in ARITH_RE.finditer(body):
            target, opa, op, opb = m.groups()
            cls_t = _fin_name(target)
            cls_a = _fin_name(opa)
            cls_b = _fin_name(opb)
            # el target DEBE ser financiero y AL MENOS un operando
            # tambien: si no, es aritmetica ajena (paginacion, loops)
            if not cls_t or not (cls_a or cls_b):
                continue
            relation = REL_NAME[op]
            confidence = "HIGH" if (cls_a and cls_b) else "MEDIA"
            linea_real = callback_line + body[:m.start()].count("\n")
            evidence = m.group(0).strip()

            _register_node(nodes, target, cls_t, "computed",
                           callback_file, linea_real, handler_name)
            if cls_a:
                _register_node(nodes, opa, cls_a, "computed",
                               callback_file, linea_real, handler_name)
                edges.append({"source": opa, "target": target,
                             "relation": relation, "evidence": evidence,
                             "confidence": confidence, "file": callback_file,
                             "line": linea_real, "handler": handler_name})
            if cls_b:
                _register_node(nodes, opb, cls_b, "computed",
                               callback_file, linea_real, handler_name)
                edges.append({"source": opb, "target": target,
                             "relation": relation, "evidence": evidence,
                             "confidence": confidence, "file": callback_file,
                             "line": linea_real, "handler": handler_name})

        # ---------------------------------------------------- copia directa
        for m in ASSIGN_RE.finditer(body):
            target, opa = m.groups()
            if target == opa:
                continue
            cls_t = _fin_name(target)
            cls_a = _fin_name(opa)
            if not (cls_t and cls_a):
                continue
            linea_real = callback_line + body[:m.start()].count("\n")
            _register_node(nodes, target, cls_t, "computed", callback_file,
                           linea_real, handler_name)
            _register_node(nodes, opa, cls_a, "computed", callback_file,
                           linea_real, handler_name)
            edges.append({"source": opa, "target": target,
                         "relation": "ASSIGN", "evidence": m.group(0).strip(),
                         "confidence": "MEDIA", "file": callback_file,
                         "line": linea_real, "handler": handler_name})

        # ---------------------------------------------------- COOCCURS
        # campos STATUS que se escriben cerca uno del otro: acoplamiento
        # temporal real (ej. payment_status / order_status / paid_at
        # actualizados en el mismo bloque), NUNCA mas que MEDIA porque
        # es posicion, no una formula.
        lines = body.splitlines()
        status_hits: List[Any] = []
        for i, line in enumerate(lines):
            for m in META_WRITE_RE.finditer(line):
                cls = _fin_name(m.group(1))
                if cls and cls["tipo"] == "STATUS":
                    status_hits.append((i, m.group(1), cls))
            am = ASSIGN_RE.search(line)
            if am:
                cls = _fin_name(am.group(1))
                if cls and cls["tipo"] == "STATUS":
                    status_hits.append((i, am.group(1), cls))
        for i in range(len(status_hits)):
            for j in range(i + 1, len(status_hits)):
                li, namei, clsi = status_hits[i]
                lj, namej, clsj = status_hits[j]
                if namei == namej or abs(li - lj) > COOCCUR_WINDOW:
                    continue
                linea_real = callback_line + min(li, lj)
                _register_node(nodes, namei, clsi, "computed", callback_file,
                               callback_line + li, handler_name)
                _register_node(nodes, namej, clsj, "computed", callback_file,
                               callback_line + lj, handler_name)
                edges.append({
                    "source": namei, "target": namej,
                    "relation": "COOCCURS",
                    "evidence": "'%s' (linea %d) y '%s' (linea %d) se "
                                "escriben a %d lineas de distancia en "
                                "el mismo handler" % (
                                    namei, callback_line + li, namej,
                                    callback_line + lj, abs(li - lj)),
                    "confidence": "MEDIA", "file": callback_file,
                    "line": linea_real, "handler": handler_name})

    # dedupe: mismo (source,target,relation,file,line)
    seen = set()
    dedup_edges = []
    for e in edges:
        key = (e["source"], e["target"], e["relation"], e["file"], e["line"])
        if key in seen:
            continue
        seen.add(key)
        dedup_edges.append(e)

    return {
        "plugin": os.path.basename(os.path.abspath(root)),
        "nodes": list(nodes.values()),
        "edges": dedup_edges,
        "resumen": {
            "nodos": len(nodes),
            "nodos_source": sum(1 for n in nodes.values()
                                if n["origen"] == "source"),
            "nodos_computed": sum(1 for n in nodes.values()
                                  if n["origen"] == "computed"),
            "edges": len(dedup_edges),
            "edges_high": sum(1 for e in dedup_edges
                              if e["confidence"] == "HIGH"),
            "por_relacion": {
                rel: sum(1 for e in dedup_edges if e["relation"] == rel)
                for rel in set(e["relation"] for e in dedup_edges)
            },
        },
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: fin_param_graph.py <dir_plugin> [--json]")
        sys.exit(1)
    res = build_graph(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1, ensure_ascii=False))
    else:
        print("FIN-PARAM-GRAPH %s | %s" % (res["plugin"], res["resumen"]))
        for e in res["edges"]:
            print("  %s -[%s/%s]-> %s  (%s:%d)" % (
                e["source"], e["relation"], e["confidence"], e["target"],
                e["file"], e["line"]))
            print("     evidencia: %s" % e["evidence"])
