#!/usr/bin/env python3
"""FIN-MUTATION-PLANNER (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 3.

Selecciona EXPERIMENTOS, no ejecuta "todos x todos". Cada experimento
que este planner propone debe responder una pregunta concreta; si no
hay evidencia para justificarlo, se SKIPEA y se registra la razon
(ZERO BLIND COVERAGE, seccion 20 del pedido).

Niveles:

  L0  single-param. Reusa el catalogo de fin_payloads tal cual (ya
      existe en v1, no se reimplementa: solo se empaqueta como
      "experimento" con metadata uniforme).

  L1  pairwise. SOLO combina dos parametros SOURCE que el grafo de
      FIN-PARAM-GRAPH conecta porque ambos alimentan el MISMO target
      aritmetico (ej. price y quantity -> subtotal). Por cada par se
      generan 2 experimentos (ataque en A + control en B, y viceversa)
      para poder aislar cual mutacion es la que produce el efecto.
      Nunca "todos x todos": el numero de experimentos L1 es acotado
      por la cantidad de edges del grafo, no por combinatoria.

  L2  invariant mutation. Por cada invariante RELACIONAL
      (fin_invariants), si el "target" de la formula (ej. subtotal)
      TAMBIEN es un parametro que el cliente puede enviar directo
      (existe como nodo origen=source, osea fin_param_infer lo vio
      como $_POST['subtotal'] en algun handler), se genera UN
      experimento: operandos en valores de CONTROL validos + el
      target forzado a un valor que CONTRADICE la formula. Si el
      target NUNCA se lee de request (es puramente calculado), no hay
      forma de probarlo por mutacion: se SKIPEA con reason=NO_EVIDENCE.

Cada experimento: {level, experiment_id, params, hypothesis, priority,
endpoint, source (edge/invariante que lo justifica)}.

Orden de prioridad (information gain, seccion 21 del pedido): L2
primero (una violacion de invariante es la pregunta mas informativa),
despues L1 (relacion con evidencia de grafo), despues L0 (parametro
aislado, la señal mas debil).

Uso:
    python3 core/fin_mutation_planner.py <dir_plugin> [--json]
"""
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import fin_invariants as finv  # noqa: E402
from core import fin_payloads  # noqa: E402
from core import gates_audit as ga  # noqa: E402

OP_RELATIONS = ("MULTIPLY", "ADD", "SUBTRACT", "DIVIDE")


def _exp_id(*parts: str) -> str:
    return "EXP-%s" % hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _control_and_attacks(tipo: str, max_attacks: int = 4
                          ) -> Tuple[Optional[Dict[str, Any]],
                                    List[Dict[str, Any]]]:
    if tipo not in fin_payloads.CATALOG:
        return None, []
    ps = fin_payloads.payloads_for(tipo, max_ataques=max_attacks)
    attacks = [p for p in ps if p["riesgo"] != "CONTROL"]
    controls = [p for p in ps if p["riesgo"] == "CONTROL"]
    return (controls[0] if controls else None), attacks


def plan_l0(params_findings: List[Dict[str, Any]],
            max_attacks: int = 4) -> List[Dict[str, Any]]:
    out = []
    for f in params_findings:
        tipo = f["tipo"]
        if tipo not in fin_payloads.CATALOG:
            continue
        for p in fin_payloads.payloads_for(tipo, max_ataques=max_attacks):
            if p["riesgo"] == "CONTROL":
                continue
            out.append({
                "level": "L0",
                "experiment_id": _exp_id("L0", f["archivo"], str(f["linea"]),
                                        f["parametro"], p["nombre"]),
                "params": {f["parametro"]: p["valor"]},
                "payload_name": p["nombre"],
                "tipo": tipo,
                "endpoint": f["endpoint"],
                "hypothesis": p["hipotesis"],
                "priority": "HIGH" if p["riesgo"] == "BENEFICIO_ATACANTE"
                           else "MEDIA",
                "justificacion": "parametro FIN-PARAM-DETECTED aislado",
            })
    return out


def plan_l1(graph: Dict[str, Any],
            params_by_name: Dict[str, Dict[str, Any]],
            max_pairs: int = 6) -> List[Dict[str, Any]]:
    nodes_by_name = {n["name"]: n for n in graph["nodes"]}
    target_sources: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for e in graph["edges"]:
        if e["relation"] not in OP_RELATIONS:
            continue
        target_sources.setdefault(e["target"], []).append(
            (e["source"], e))

    pairs: List[Tuple[str, str, str, Dict[str, Any]]] = []
    for target, sources in target_sources.items():
        src_params = [(s, e) for s, e in sources
                     if nodes_by_name.get(s, {}).get("origen") == "source"]
        for i in range(len(src_params)):
            for j in range(i + 1, len(src_params)):
                a, ea = src_params[i]
                b, _eb = src_params[j]
                pairs.append((a, b, target, ea))

    out = []
    for a, b, target, edge in pairs[:max_pairs]:
        fa, fb = params_by_name.get(a), params_by_name.get(b)
        if not fa or not fb:
            continue
        ctrl_a, atk_a = _control_and_attacks(fa["tipo"])
        ctrl_b, atk_b = _control_and_attacks(fb["tipo"])
        if atk_a and ctrl_b:
            out.append({
                "level": "L1",
                "experiment_id": _exp_id("L1", edge["file"], str(edge["line"]),
                                        a, b, atk_a[0]["nombre"]),
                "params": {a: atk_a[0]["valor"], b: ctrl_b["valor"]},
                "endpoint": fa["endpoint"],
                "hypothesis": "%s (relacionado con %s via %s en %s): %s" % (
                    a, b, edge["relation"], target, atk_a[0]["hipotesis"]),
                "priority": "HIGH",
                "justificacion": "par conectado en FIN-PARAM-GRAPH "
                                "(evidencia: %s)" % edge["evidence"],
                "source_edge": edge,
            })
        if atk_b and ctrl_a:
            out.append({
                "level": "L1",
                "experiment_id": _exp_id("L1", edge["file"], str(edge["line"]),
                                        b, a, atk_b[0]["nombre"]),
                "params": {b: atk_b[0]["valor"], a: ctrl_a["valor"]},
                "endpoint": fb["endpoint"],
                "hypothesis": "%s (relacionado con %s via %s en %s): %s" % (
                    b, a, edge["relation"], target, atk_b[0]["hipotesis"]),
                "priority": "HIGH",
                "justificacion": "par conectado en FIN-PARAM-GRAPH "
                                "(evidencia: %s)" % edge["evidence"],
                "source_edge": edge,
            })
    return out


def plan_l2(invariantes: List[Dict[str, Any]],
            params_by_name: Dict[str, Dict[str, Any]]
            ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    out, skipped = [], []
    for inv in invariantes:
        if inv["kind"] != "RELATIONAL":
            continue
        target = inv["affected_state"]
        operands = inv["affected_parameters"]

        if target not in params_by_name:
            skipped.append({
                "level": "L2", "invariant_id": inv["invariant_id"],
                "expression": inv["expression"], "reason": "NO_EVIDENCE",
                "detail": "'%s' nunca se lee directo de request en ningun "
                         "handler detectado: no hay forma de mutarlo sin "
                         "inventar un parametro que el codigo no expone" %
                         target})
            continue

        params: Dict[str, Any] = {}
        ok = True
        for op in operands:
            f = params_by_name.get(op)
            if not f:
                ok = False
                break
            ctrl, _ = _control_and_attacks(f["tipo"])
            if not ctrl:
                ok = False
                break
            params[op] = ctrl["valor"]
        if not ok:
            skipped.append({
                "level": "L2", "invariant_id": inv["invariant_id"],
                "expression": inv["expression"], "reason": "NO_EVIDENCE",
                "detail": "uno de los operandos (%s) no tiene catalogo de "
                         "valores de control conocido" % operands})
            continue

        ft = params_by_name[target]
        ctrl_t, _atk_t = _control_and_attacks(ft["tipo"])
        # valor deliberadamente bajo para el target: viola la formula sin
        # importar los operandos (cualquier total/subtotal real con
        # operandos de control validos es > 1 en estos catalogos)
        params[target] = 1

        out.append({
            "level": "L2",
            "experiment_id": _exp_id("L2", inv["invariant_id"]),
            "params": params,
            "endpoint": ft["endpoint"],
            "invariant_id": inv["invariant_id"],
            "expression": inv["expression"],
            "hypothesis": "la app acepta '%s' enviado directo por el "
                          "cliente, violando la formula '%s' (los "
                          "operandos van en valores de control validos: "
                          "si el servidor IGNORA el '%s' recibido y "
                          "recalcula, no hay hallazgo; si lo ACEPTA tal "
                          "cual, la formula queda rota)" % (
                              target, inv["expression"], target),
            "priority": "HIGH",
            "justificacion": "invariante relacional con evidencia de "
                            "codigo + '%s' confirmado como parametro "
                            "controlable por el cliente" % target,
        })
    return out, skipped


def plan_all(root: str,
             handlers: Optional[List[Dict[str, Any]]] = None,
             max_l0: int = 4, max_l1_pairs: int = 6) -> Dict[str, Any]:
    if handlers is None:
        handlers = ga.audit(root).get("handlers", [])
    inv_result = finv.infer_invariants(root, handlers=handlers)
    graph = inv_result["graph"]
    invariantes = inv_result["invariantes"]

    params_findings = []
    for n in graph["nodes"]:
        if n["origen"] != "source":
            continue
        params_findings.append({
            "parametro": n["name"], "tipo": n["tipo"],
            "archivo": n["file"], "linea": n["line"],
            "endpoint": n["handler"]})
    params_by_name = {p["parametro"]: p for p in params_findings}

    l2, skipped = plan_l2(invariantes, params_by_name)
    l1 = plan_l1(graph, params_by_name, max_pairs=max_l1_pairs)
    l0 = plan_l0(params_findings, max_attacks=max_l0)

    experimentos = l2 + l1 + l0  # orden de informacion: invariante > par > aislado

    return {
        "plugin": graph["plugin"],
        "experimentos": experimentos,
        "skipped": skipped,
        "resumen": {
            "total": len(experimentos),
            "L0": len(l0), "L1": len(l1), "L2": len(l2),
            "skipped": len(skipped),
        },
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: fin_mutation_planner.py <dir_plugin> [--json]")
        sys.exit(1)
    res = plan_all(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1, ensure_ascii=False))
    else:
        print("FIN-MUTATION-PLANNER %s | %s" % (res["plugin"], res["resumen"]))
        for e in res["experimentos"]:
            print("  [%s/%s] %s -> %s" % (e["level"], e["priority"],
                                           e["params"], e["hypothesis"][:90]))
        for s in res["skipped"]:
            print("  [SKIP/%s] %s: %s" % (s["level"], s["expression"],
                                           s["detail"]))
