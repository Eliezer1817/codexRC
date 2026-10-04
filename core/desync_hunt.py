"""DESYNC-HUNT (v0.83.0): investigacion DESYNC sobre el
EXPERIMENT-GRAPH.

Consume EDGESYNC (v0.74: sondas de framing con 3
dimensiones) SIN reemplazarlo. Cada sonda es un EXPERIMENTO
con contrato pre-registrado; cada disparo produce una
OBSERVACION cruda con huellas de reproducibilidad; el
contrato convierte senales en EVIDENCIA; el candidato
DESYNC avanza solo con evidencia.

Escalera de impacto (nunca se salta):
    DESYNC OBSERVED -> REPRODUCIBLE -> STATE EFFECT ->
    CROSS-CONNECTION -> SECURITY IMPACT

La corona (CONFIRMED) exige E-DESYNC-IMPACT reproducible:
efecto de seguridad fuera del propio experimento. La mera
discrepancia de parsing no basta.
"""

import datetime
import http.client
import json
import os
import ssl
import sys
import time
import uuid

import experiment_graph as eg
import edgesync as es

BUDGET_PROBES = 10          # tope anti-DoS de la sesion
BASELINE_PROBES = 3

HYPOTHESES = [
    ("HD1", "parsing-differential edge/origin"),
    ("HD2", "edge-safe: valida o normaliza framing"),
    ("HD3", "connection-state observable en sonda"),
    ("HD4", "baseline-artifact explica anomalias"),
]

# senal -> accion (el contrato es la autoridad)
BRANCHES = {
    "eco-state": {"supports": ["HD1", "HD3"],
                  "clase": eg.E_SIGNAL,
                  "nota": "la sonda recibio el eco: efecto "
                          "de estado observable"},
    "eco-cand": {"supports": ["HD1"],
                 "clase": eg.E_SIGNAL,
                 "nota": "eco en pre: diferencia "
                         "observable que merece "
                         "investigacion; atribucion de "
                         "capa UNKNOWN (pipeline del "
                         "edge vs split del backend: "
                         "una sola conexion no "
                         "distingue)",
                 "inconclusive": ["HD3"]},
    "anomalia": {"supports": ["HD3"],
                 "clase": eg.E_SIGNAL,
                 "nota": "sonda con estado alterado tras "
                         "framing"},
    "conteo": {"supports": ["HD1"],
               "clase": eg.E_SIGNAL,
               "nota": "conteo de respuestas anormal: las "
                       "capas cuentan distinto"},
    "rechazo": {"supports": ["HD2"],
                "clase": None,
                "nota": "el edge detecto ambiguedad y "
                        "rechazo: frontera estricta"},
    "cierre": {"inconclusive": ["HD1", "HD2"],
               "nota": "el edge cerro sin explicacion"},
    "consistent": {"inconclusive": ["HD1", "HD3"],
                   "nota": "framing sin senal en esta "
                           "familia (no descarta otras)"},
}

VARIANTES = ["V1", "V2", "V3", "V4", "V5",
             "V6", "V7", "V8", "V9", "P1", "P2"]

_CTX = ssl.create_default_context()


def _disparar_seg(url, vid, timeout, smug_path):
    """Disparo segmentado: devuelve pre y post por
    separado para LOCALIZAR el eco. El eco en PRE puede
    ser pipelining del edge (una sola capa) o split del
    backend: desde una conexion son indistinguibles y la
    atribucion honesta es UNKNOWN. El eco en POST (la
    sonda recibe una respuesta que no pidio) si es un
    efecto de estado observable."""
    s, host = es._connect(url, timeout)
    try:
        probe, sonda, familia = es.build_probe(
            vid, host, smug_path)
        s.sendall(probe)
        pre = es._read_all(s, quiet=0.7)
        s.sendall(sonda)
        post = es._read_all(s, quiet=1.2)
    finally:
        s.close()
    raw = pre + post
    txt = raw.decode("latin-1", "replace")
    pre_txt = pre.decode("latin-1", "replace")
    post_txt = post.decode("latin-1", "replace")
    eco_pre = (smug_path in pre_txt
               or es.SMUG_MARKER in pre_txt)
    eco_post = (smug_path in post_txt
                or es.SMUG_MARKER in post_txt)
    return {
        "variante": vid, "familia": familia,
        "pre": es._n_responses(pre),
        "post": es._n_responses(post),
        "status_pre": es._statuses(pre),
        "status_post": es._statuses(post),
        "eco_pre": eco_pre, "eco_post": eco_post,
        "bytes": len(raw), "txt_eco_pre": eco_pre,
        "txt_eco_post": eco_post,
        "eco": eco_pre or eco_post, "raw": txt,
    }


def _signal(r):
    """Clasifica el disparo en una senal del contrato."""
    if r["eco_post"]:
        return "eco-state"
    if r["eco_pre"]:
        return "eco-cand"
    if r["post"] == 0:
        st = r["status_pre"]
        if r["pre"] == 1 and st and st[0] in \
                es.STATUS_RECHAZO:
            return "rechazo"
        return "cierre"
    if r["post"] >= 1 and r["status_post"] and not any(
            s.startswith("2") for s in r["status_post"]):
        return "anomalia"
    if r["pre"] + r["post"] != 2:
        return "conteo"
    return "consistent"


def _baseline(url, timeout):
    scheme = url.split(":")[0]
    host = url.split("//")[-1].split("/")[0].split(":")[0]
    port = (url.split(":")[2].split("/")[0]
            if url.count(":") == 2 else
            (443 if scheme == "https" else 80))
    fps = []
    for _ in range(BASELINE_PROBES):
        c = (http.client.HTTPSConnection(host, port,
                                         timeout=timeout,
                                         context=_CTX)
             if scheme == "https"
             else http.client.HTTPConnection(
                 host, port, timeout=timeout))
        try:
            c.request("GET", "/")
            r = c.getresponse()
            fps.append((r.status,
                        hash(r.read()) & 0xffff))
        finally:
            c.close()
    return fps


def investigate(cfg):
    url = cfg["url"]
    if not url.startswith("http"):
        url = "https://" + url
    timeout = float(cfg.get("timeout", 10.0))
    host = url.split("//")[-1].split("/")[0].split(":")[0]

    # ---- baseline: caracterizado antes de interpretar
    bf = _baseline(url, timeout)
    stable = len(set(bf)) == 1
    baseline_state = ("STABLE" if stable
                      else "AMBIGUO-NO-CARACTERIZADO")

    g = eg.ExpGraph(host,
                    hypotheses=HYPOTHESES,
                    baseline_state=baseline_state)
    g.journal.append({
        "event": "baseline", "fps": [list(f) for f in bf],
        "state": baseline_state, "ts": g.created,
        "probes": BASELINE_PROBES})

    # ---- contratos pre-registrados (antes de disparar)
    spectrum = [
        [("HD1", "SUPPORT"), ("HD3", "SUPPORT")],
        [("HD2", "SUPPORT")],
        [("HD1", "INCONCLUSIVE"),
         ("HD3", "INCONCLUSIVE")],
    ]
    for vid in VARIANTES:
        g.register_contract(
            "EXP-" + vid, ["HD1", "HD2", "HD3"],
            f"edgesync framing {vid}: 1 conexion, probe "
            f"+ sonda, 3 dimensiones",
            BRANCHES, ["baseline", "topology-pre"],
            {"max_requests": 2, "max_connections": 1},
            spectrum)

    # ---- loop EDV
    probes = 0
    signals = []
    repro_pending = {}
    while probes < BUDGET_PROBES:
        vivas = [h["id"] for h in g.live()]
        if not vivas:
            break
        sel, edv_sel, tabla, razon = g.next_experiment(
            budget_left=BUDGET_PROBES - probes,
            cost_fn=lambda e: 1)
        if sel is None:
            g.journal.append({
                "event": "selector_stop", "razon": razon,
                "ts": eg._now()})
            break
        vid = sel.replace("EXP-", "")
        g.record_selection(
            sel, edv=edv_sel, tabla=tabla,
            targets=g.contracts[sel]["hypothesis_ids"],
            reason=razon)
        smug = es.SMUG_PATH.format(uuid.uuid4().hex[:12])
        t0 = time.time()
        r = _disparar_seg(url, vid, timeout, smug)
        dt_ms = int((time.time() - t0) * 1000)
        probes += 1
        sig = _signal(r)
        if sig in ("eco-state", "eco-cand", "anomalia",
                   "conteo"):
            signals.append((vid, sig))
        r_dump = {k: v for k, v in r.items()
                  if k != "raw"}
        obs_id = g.add_observation(
            sel, facts=r_dump, signal=sig, parent=repro_pending.get(vid),
            repro={"request_fp": f"{vid}:{smug}",
                   "conn_identity": "nueva por probe",
                   "conn_reuse": "no reusada",
                   "timing_ms": dt_ms,
                   "response_fp": r["bytes"],
                   "state_fp": [r["pre"], r["post"],
                                r["status_pre"],
                                r["status_post"]],
                   "cache_fp": "no-cache-sonda",
                   "baseline_ref": baseline_state,
                   "controls": "baseline+toplevel",
                   "genealogy": [g.run_id, vid, smug]})
        evs = g.apply(sel, obs_id, sig)

        # E_STATE solo si la SONDA recibio el eco:
        # el efecto de estado debe ser observable, no
        # un eco inmediato atribuible a pipelining
        if sig == "eco-state":
            g.add_evidence(
                "EV-S-" + obs_id.split("-")[-1],
                obs_id, "HD3", "SUPPORT", "OBSERVED",
                eg.E_STATE,
                "la sonda recibio el eco: estado de "
                "conexion alterado")

        # senal -> candidato + contrato de reproduccion
        if sig in ("eco-state", "eco-cand",
                   "anomalia", "conteo"):
            g.declare_transition(
                "CANDIDATE",
                f"senal {sig} en {vid}")
            if baseline_state == "STABLE":
                g.declare_transition(
                    "SUPPORTED", "baseline estable")
            if vid not in repro_pending:
                repro_pending[vid] = sel
                g.register_contract(
                    "EXP-REPRO-" + vid,
                    ["HD1", "HD3"],
                    f"reproduccion de {vid} con genealogia "
                    f"independiente (smug_path nuevo)",
                    BRANCHES, ["baseline"],
                    {"max_requests": 2,
                     "max_connections": 1}, spectrum)
            if len(g._distinct_genealogies(
                    eg.E_SIGNAL)) >= 2:
                g.declare_transition(
                    "REPRODUCIBLE",
                    "2 genealogias independientes")
            if (g._evidences_of_class(eg.E_STATE)
                    and g.candidate == "REPRODUCIBLE"):
                g.declare_transition(
                    "IMPACT-CANDIDATE",
                    "efecto de estado reproducible")

    # ---- escalera de impacto honesta
    g.journal.append({
        "event": "impact_ladder",
        "observed": bool(signals),
        "reproducible": (g.candidate in
                         ("REPRODUCIBLE",
                          "IMPACT-CANDIDATE",
                          "CONFIRMED")),
        "state_effect": bool(
            g._evidences_of_class(eg.E_STATE)),
        "cross_connection": bool(
            g._evidences_of_class(eg.E_CROSSCONN)),
        "security_impact": bool(
            g._evidences_of_class(eg.E_IMPACT)),
        "probes": probes, "ts": eg._now()})

    rec = g.dump()
    rec["url"] = url
    rec["probes_gastados"] = probes
    rec["senales"] = [(v, s) for v, s in signals]
    p = g.save()
    rec["path"] = p
    return rec


# ---------------- CLI ----------------

def render(rec):
    out = [f"TARGET: {rec['target']}",
           "INVESTIGATION",
           "=" * 40, ""]
    for hid, st in rec["hypotheses"].items():
        out.append(f"{hid}  {st}")
    out.append("")
    out.append(f"probes: {rec['probes_gastados']}"
               f"/{BUDGET_PROBES}"
               f"  baseline: {rec['baseline_state']}")
    if rec["senales"]:
        out.append("senales: " + ", ".join(
            f"{v}:{s}" for v, s in rec["senales"]))
    else:
        out.append("senales: ninguna")
    out.append("")
    out.append(f"CURRENT STATUS: "
               f"{rec['candidate']}")
    impact = ("DEMONSTRATED"
              if rec["candidate"] == "CONFIRMED"
              else "NOT DEMONSTRATED")
    out.append(f"SECURITY IMPACT: {impact}")
    if rec["confirm_blockers"]:
        out.append("bloqueos: "
                   + ", ".join(rec["confirm_blockers"]))
    out.append("")
    out.append("VERDICT: INVESTIGATION "
               + ("CONTINUES" if rec["senales"]
                  else "CLOSED SIN SENAL"))
    return "\n".join(out)


def _render_cmd(rec, cmd, exp=None):
    if cmd == "active":
        out = ["ACTIVE HYPOTHESES", "-" * 20]
        for hid, st in rec["hypotheses"].items():
            out.append(f"{hid}  {st}")
        return "\n".join(out)
    if cmd == "next":
        sels = [j for j in rec["journal"]
                if j["event"] == "selection"]
        if not sels:
            return "sin selecciones registradas"
        s = sels[-1]
        return (f"LAST: {s['id']} EDV {s['edv']}\n"
                f"tabla: {s['tabla']}\n"
                f"reason: {s['reason']}")
    if cmd == "explain":
        sels = [j for j in rec["journal"]
                if j["event"] == "selection"
                and j["id"] == exp]
        if not sels:
            return f"sin registro de {exp}"
        s = sels[-1]
        out = [f"{s['id']} EDV {s['edv']}",
               f"targets: {', '.join(s['targets'])}",
               f"reason: {s['reason']}",
               "vivas al elegir: "
               + ", ".join(s["live"])]
        for j in rec["journal"]:
            if (j["event"] == "observation"
                    and j["experiment"] == exp):
                out.append(f"observo senal {j['signal']}")
        return "\n".join(out)
    if cmd == "graph":
        n = {t: sum(1 for x in rec["observations"]
                    if True) for t in ["obs"]}
        return (f"run {rec['run_id']}\n"
                f"hypotheses {len(rec['hypotheses'])}\n"
                f"observations {len(rec['observations'])}\n"
                f"evidence {len(rec['evidence'])}\n"
                f"candidate {rec['candidate']}")
    return "comando desconocido"


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--cmd",
                    choices=["active", "graph", "next",
                             "explain"])
    ap.add_argument("--exp")
    a = ap.parse_args()
    host = (a.url.split("//")[-1].split("/")[0]
            .split(":")[0])
    if a.cmd:
        rec = eg.latest_run(host)
        if not rec:
            print("sin investigaciones para " + host)
            return
        if a.cmd == "explain" and not a.exp:
            print("usa --exp EXP-xxxx")
            return
        print(_render_cmd(rec, a.cmd, a.exp))
        return
    rec = investigate({"url": a.url,
                       "timeout": a.timeout})
    if a.json:
        print(json.dumps(rec, default=str, indent=1))
    else:
        print(render(rec))


if __name__ == "__main__":
    main()
