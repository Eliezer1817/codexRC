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

import hashlib
import json
import sys

import hypothesis_graph as hg
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
    if not ambiguous:
        return _sesion(url, "BASELINE-STABLE", None, [], trace,
                       spent, gap_note(
            "sin varianza: no hay hipotesis que formular"))

    # ---- HIPOTESIS
    graph = hg.seed("baseline_ambiguous")

    # ---- LOOP DE EXPERIMENTOS
    bundle = {}
    ejecutados = []
    for exp in EXPERIMENTS:
        live = hg.live(graph)
        if not live:
            break
        if len(live) == 1 and ejecutados and len(live) == 1 \
                and _converge_por(graph, live):
            break
        if spent + exp["cost"] > BUDGET_TOTAL:
            trace.append({"paso": "presupuesto", "nota":
                f"{exp['id']} omitido: presupuesto agotado"})
            break
        res = exp["run"](url, timeout)
        spent += res["cost"]
        bundle[exp["id"]] = res
        ejecutados.append(exp["id"])
        acts = contract(exp["id"], bundle)
        hg.apply(graph, acts)
        trace.append({
            "paso": "experimento", "id": exp["id"],
            "cost": res["cost"],
            "resultados": res["results"],
            "acciones": [f"{a}/{h}" for h, a, _ in acts],
            "vivas": [n["id"] for n in hg.live(graph)]})
        if len(hg.live(graph)) == 1:
            break

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
    return _sesion(url, verdicto, graph, ejecutados, trace,
                   spent, gaps, att)


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
            gaps, att=None):
    if att is None:
        att = ("NINGUNA (baseline sin varianza)"
               if verdicto == "BASELINE-STABLE" else "UNKNOWN")
    return {
        "target": url,
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
    a = ap.parse_args()
    rec = audit({"url": a.url, "timeout": a.timeout})
    if a.json:
        print(json.dumps(rec, indent=1, default=str))
    else:
        print(render(rec))


if __name__ == "__main__":
    main()
