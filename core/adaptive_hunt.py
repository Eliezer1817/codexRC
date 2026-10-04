"""ADAPTIVE-HUNT (v0.81.0): la capa epistemica.

No pregunta "que vulnerabilidad puedo probar" sino "que
experimento me daria la mayor informacion para distinguir
entre las hipotesis que tengo".

Flujo:
  OBSERVACION (baseline) -> DISPARADOR -> HIPOTESIS ->
  EXPERIMENTO (contrato pre-registrado) -> EVIDENCIA ->
  ACTUALIZAR HIPOTESIS -> ... -> VEREDICTO + GAP LEDGER.

Tres salidas, todas validas:
  BASELINE-CARACTERIZADO: un unico mecanismo vivo explica la
    observacion (con soporte o por eliminacion honesta).
  BASELINE-STABLE: el blanco no presento varianza.
  UNKNOWN-DEMOSTRADO: la superficie no permite concluir HOY,
    con razon demostrable e hipotesis abiertas enumeradas.

Presupuesto heredado: 30 requests max por sesion.
"""

import datetime
import hashlib
import json
import sys

import hypothesis_graph as hg
import research_memory as rm
import experiment_selector as xs
from experiment_catalog import (
    EXPERIMENTS, contract, _open, _get, _parts)

BUDGET_TOTAL = 30
BASELINE_PROBES = 3


def _baseline(url, timeout):
    _, _, _, path = _parts(url)
    fps = []
    for _ in range(BASELINE_PROBES):
        conn = _open(url, timeout)
        try:
            fps.append(_get(conn, path))
        finally:
            conn.close()
    return fps


def audit(cfg):
    url = cfg["url"]
    if not url.startswith("http"):
        url = "https://" + url
    timeout = float(cfg.get("timeout", 8.0))
    spent = 0
    trace = []

    # ---- OBSERVACION
    fps = _baseline(url, timeout)
    spent += BASELINE_PROBES
    hashes = [f["body_hash"] for f in fps]
    ambiguous = len(set(hashes)) > 1
    trace.append({"paso": "baseline", "cost": BASELINE_PROBES,
                   "huellas": hashes,
                   "disparador": ("baseline_ambiguous"
                                  if ambiguous else "stable")})
    prev = (rm.load(url) if cfg.get("resume") else None)
    ttl = cfg.get("ttl_hours", rm.TTL_HOURS_DEFAULT)

    # ---- REUSO determinista: baseline identico dentro del TTL
    if prev and ambiguous and rm.reusable(prev, hashes, ttl):
        trace.append({"paso": "memoria",
                      "nota": (f"baseline identico a la ventana "
                               f"{prev['window']}: reuso")}
                     )
        graph = hg.seed("baseline_ambiguous")
        for node in graph["nodes"]:
            pn = next((h for h in prev.get("hipotesis", [])
                       if h["id"] == node["id"]), None)
            if pn:
                node["status"] = pn["status"]
                node["evidence"] = ["reusado: " + e
                                    for e in pn["evidence"]]
                node["contradictions"] = [
                    "reusado: " + c
                    for c in pn["contradictions"]]
        rec = _sesion(url, prev["verdicto"],
                      graph, prev.get("experimentos", []),
                      trace, spent, prev.get("gap_ledger"),
                      prev.get("atribucion", "UNKNOWN")
                      + " (REUSADO)",
                      fps=fps, ambiguous=ambiguous)
        rec["reuse"] = True
        rec["memoria"] = rm.meta(url)
        rm.save(rec)
        return rec

    if not ambiguous:
        rec = _sesion(url, "BASELINE-STABLE", None, [], trace,
                       spent, gap_note(
            "sin varianza: no hay hipotesis que formular"),
        fps=fps, ambiguous=ambiguous)
        rec["memoria"] = rm.meta(url)
        rm.save(rec)
        return rec

    # ---- HIPOTESIS (sembradas frescas; lo previo entra como
    # ANOTACION de ventana, nunca como veredicto heredado)
    graph = hg.seed("baseline_ambiguous")
    rm.annotate(graph, prev)

    # ---- LOOP DE EXPERIMENTOS (v0.82: seleccion por EDV)
    bundle = {}
    ejecutados = []
    selector_stop = None
    runners = {e["id"]: e for e in EXPERIMENTS}
    costs = {e["id"]: e["cost"] for e in EXPERIMENTS}
    hints = (set(prev.get("experimentos", []))
             if prev else None)
    while True:
        live = hg.live(graph)
        if not live:
            break
        if len(live) == 1 and ejecutados:
            break
        sel, tabla, porque = xs.select(
            graph, ejecutados, BUDGET_TOTAL - spent,
            costs, hints)
        if sel is None:
            selector_stop = porque
            trace.append({"paso": "selector",
                          "tabla": tabla,
                          "stop": porque})
            break
        exp = runners[sel[0]]
        res = exp["run"](url, timeout)
        spent += res["cost"]
        bundle[exp["id"]] = res
        ejecutados.append(exp["id"])
        acts = contract(exp["id"], bundle)
        hg.apply(graph, acts)
        trace.append({
            "paso": "experimento", "id": exp["id"],
            "cost": res["cost"],
            "eleccion": {"edv": round(sel[1], 3),
                         "tabla": tabla},
            "resultados": res["results"],
            "acciones": [f"{a}/{h}" for h, a, _ in acts],
            "vivas": [n["id"] for n in hg.live(graph)]})

    # ---- JUEZ
    live = hg.live(graph)
    if len(live) == 1:
        n = live[0]
        modo = ("SUPPORTED" if n["status"] == "SUPPORTED"
                else "BY-ELIMINATION")
        verdicto = "BASELINE-CARACTERIZADO"
        att = f"{n['id']}:{n['name']} ({modo})"
        gaps = []
    else:
        verdicto = "UNKNOWN-DEMOSTRADO"
        att = "UNKNOWN"
        gaps = gap_ledger(graph, ejecutados)
    rec = _sesion(url, verdicto, graph, ejecutados, trace,
                  spent, gaps, att, fps=fps, ambiguous=ambiguous)
    if selector_stop:
        rec["selector_stop"] = selector_stop
        if isinstance(gaps, dict) and verdicto == \
                "UNKNOWN-DEMOSTRADO":
            prev_razon = gaps.get("razon", "")
            gaps["razon"] = (f"{prev_razon} | {selector_stop}"
                             if prev_razon else selector_stop)
    rec["memoria"] = rm.meta(url)
    rm.save(rec)
    return rec


def _converge_por(graph, live):
    return len(live) == 1


def gap_note(nota):
    return nota


def gap_ledger(graph, ejecutados):
    """Lo que falta y por que no se consiguio. Determinista."""
    live = hg.live(graph)
    gaps = {
        "hipotesis_vivas": [
            {"id": n["id"], "name": n["name"],
             "status": n["status"],
             "evidencia_falta": (
                 "ningun experimento del catalogo la resolvio"
                 if n["status"] == "UNKNOWN" else
                 "soporte parcial: falta discriminante final")}
            for n in live],
        "experimentos_ejecutados": ejecutados,
        "experimentos_restantes": [
            e["id"] for e in EXPERIMENTS
            if e["id"] not in ejecutados],
        "razon": ("el catalogo de experimentos no discrimina "
                  "las hipotesis vivas en esta ventana: la "
                  "observacion ambigua no se reproducio en "
                  "ninguna dimension disponible"),
    }
    return gaps


def _sesion(url, verdicto, graph, ejecutados, trace, spent,
            gaps, att=None, fps=None, ambiguous=False):
    if att is None:
        att = ("NINGUNA (baseline sin varianza)"
               if verdicto == "BASELINE-STABLE" else "UNKNOWN")
    return {
        "target": url,
        "window": datetime.datetime.utcnow().isoformat(
            timespec="seconds"),
        "baseline": {"huellas": ([f["body_hash"] for f in fps]
                                if fps else []),
                     "trigger": ("baseline_ambiguous"
                                 if ambiguous else "stable")},
        "verdicto": verdicto,
        "atribucion": att,
        "hipotesis": (hg.summary(graph) if graph else []),
        "experimentos": ejecutados,
        "trace": trace,
        "gap_ledger": gaps,
        "budget": {"caps": {"total": BUDGET_TOTAL},
                   "spent": {"total": spent}},
    }


def render(rec):
    out = [f"ADAPTIVE-HUNT: {rec['target']}",
           "-" * 52,
           f"veredicto: {rec['verdicto']}",
           f"atribucion: {rec['atribucion']}"]
    for n in rec["hipotesis"]:
        out.append(f"  {n['id']} {n['name']}: {n['status']}")
        for e in n["evidence"]:
            out.append(f"    [+] {e}")
        for c in n["contradictions"]:
            out.append(f"    [-] {c}")
    m = rec.get("memoria") or {}
    if m.get("ventanas"):
        extra = f" (reuso)" if rec.get("reuse") else ""
        out.append(f"memoria: {m['ventanas']} ventana(s)"
                   f"{extra}, ultima: "
                   f"{m.get('ultimo_veredicto')}")
    for n in rec["hipotesis"]:
        pr = n.get("prior")
        if pr:
            out.append(f"  {n['id']} ventana previa "
                       f"({pr.get('window')}): "
                       f"{pr.get('status')}")
    if rec.get("selector_stop"):
        out.append(f"selector: {rec['selector_stop']}")
    out.append(f"experimentos: "
               f"{', '.join(rec['experimentos']) or 'ninguno'}")
    g = rec["gap_ledger"]
    if isinstance(g, str):
        out.append(f"gaps: {g}")
    elif g:
        out.append(f"hipotesis vivas: "
                   f"{', '.join(x['id'] for x in g['hipotesis_vivas'])}")
        out.append(f"razon: {g['razon']}")
        rest = g["experimentos_restantes"]
        if rest:
            out.append(f"experimentos sin correr: {', '.join(rest)}")
    b = rec["budget"]
    out.append(f"presupuesto: {b['spent']['total']}/"
                f"{b['caps']['total']} requests")
    return "\n".join(out)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="consultar memoria del target")
    ap.add_argument("--ttl", type=float, default=None,
                    help="TTL horas para reuso (default 6)")
    ap.add_argument("--history", action="store_true",
                    help="mostrar dossier y salir")
    a = ap.parse_args()
    if a.history:
        for w in rm.dossier(a.url if a.url.startswith("http")
                            else "https://" + a.url):
            print(f"{w.get('window')} {w.get('verdicto')}"
                  f" | {w.get('atribucion')}"
                  f" | {w['budget']['spent']['total']} req")
        return
    rec = audit({"url": a.url, "timeout": a.timeout,
                 "resume": a.resume,
                 "ttl_hours": a.ttl})
    if a.json:
        print(json.dumps(rec, indent=1, default=str))
    else:
        print(render(rec))


if __name__ == "__main__":
    main()
