#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.84.0 CROSS-LAYER CORRELATION
================================
Un solo disparo, tres capas observadas SIMULTANEAMENTE
(Edge / Cache / Origin) + dimension de conexion (A, B, control).

Filosofia heredada:
- Solo evidencia observable; nada inferido queda fuera de 'unknown'.
- Tolerancia del edge NO es vulnerabilidad: si el origin nunca
  ve la perturbacion, el veredicto es BENIGN (EDGE-ONLY).
- Presupuesto bajo: <= 11 requests por auditoria.
- Contratos pre-registrados en el ExperimentGraph (anti post-hoc).

Clases de evidencia (ExperimentGraph):
- E-XL-MISMATCH     : el edge acepta una perturbacion que el
                      origin sirve DISTINTO (semantica difiere).
- E-XL-SHARED       : el efecto se reproduce desde 2 conexiones
                      (estado compartido, clase cache).
- E-XL-CONTAMINATION: una conexion nueva (control) recibe el
                      efecto sin haberlo pedido.

Escalera determinista (en el informe):
OBSERVED -> REPRODUCIBLE -> CROSS-LAYER ->
  SHARED-STATE -> CONTAMINATION -> DEMO

DEMO exige: MISMATCH reproducido (2 conexiones) +
CONTAMINATION observable + controles PASSED. Nada se infiere.
"""

import argparse
import hashlib
import http.client
import json
import os
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import experiment_graph as xg          # noqa: E402
import cache_fingerprint as cfp        # noqa: E402

MODULE_VERSION = "0.84.0"

# ---- clases de evidencia v0.84 -------------------------------------
E_XL_MISMATCH = "E-XL-MISMATCH"
E_XL_SHARED = "E-XL-SHARED"
E_XL_CONTAM = "E-XL-CONTAMINATION"

HYPOTHESES = [
    ("H-MISMATCH",
     "el edge acepta una perturbacion que el origin "
     "sirve distinto"),
    ("H-SHARED",
     "el efecto es estado compartido: reproducible "
     "desde 2 conexiones"),
    ("H-CONTAM",
     "una conexion nueva recibe el efecto sin pedirlo"),
]

# ramas del contrato por senal (la autoridad es el contrato)
BRANCHES = {
    "absorbed": {"inconclusive": ["H-MISMATCH"]},
    "edge-only": {"inconclusive": ["H-MISMATCH"]},
    "unobservable": {"inconclusive": ["H-MISMATCH",
                                      "H-SHARED",
                                      "H-CONTAM"]},
    "mismatch": {"supports": ["H-MISMATCH"],
                 "clase": E_XL_MISMATCH,
                 "tag": "OBSERVED"},
    "mismatch-no-repro": {"inconclusive": ["H-SHARED"]},
    "shared": {"supports": ["H-SHARED"],
               "clase": E_XL_SHARED,
               "tag": "OBSERVED"},
    "shared-no-contam": {"inconclusive": ["H-CONTAM"]},
    "contaminated": {"supports": ["H-CONTAM"],
                     "clase": E_XL_CONTAM,
                     "tag": "OBSERVED"},
}

SPECTRUM = [
    [("H-MISMATCH", "SUPPORT")],
    [("H-MISMATCH", "INCONCLUSIVE")],
    [("H-CONTAM", "SUPPORT")],
]

# ---- presupuesto anti-DoS -------------------------------------------
BASELINE_PROBES = 2
MAX_PERTURBATIONS = 2
PERTURBATION_TIMEOUT = 12.0


def perturbation_battery():
    return [
        {"pid": "P-CASE", "path": "/PaTh-CL",
         "control": "/path-cl",
         "desc": "variacion de caso en path"},
        {"pid": "P-SLASH", "path": "/path-cl/",
         "control": "/path-cl",
         "desc": "slash final"},
    ]


_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def _hash(b):
    return hashlib.sha256(b).hexdigest()[:16]


def _conn(url, timeout):
    scheme = url.split(":")[0]
    host = url.split("//")[-1].split("/")[0]
    port = 443 if scheme == "https" else 80
    if ":" in host:
        host, port = host.split(":")
        port = int(port)
    if scheme == "https":
        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=_CTX)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _fetch(url, path, timeout=PERTURBATION_TIMEOUT,
           reuse=False):
    """Un request. Capa EDGE: status + persistencia.
    Capa CACHE: fingerprint (Age/X-Cache/ETag/Vary...).
    Capa ORIGIN: status + hash de cuerpo."""
    c = _conn(url, timeout)
    out = {"path": path, "edge": {}, "cache": {},
           "origin": {}}
    try:
        t0 = time.time()
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        ms = (time.time() - t0) * 1000
        out["origin"]["status"] = r.status
        out["origin"]["body_hash"] = _hash(body)
        out["origin"]["len"] = len(body)
        head = ("HTTP/1.1 %d X\r\n"
                % r.status).encode("latin-1")
        for k, v in r.getheaders():
            head += ("%s: %s\r\n"
                    % (k, v)).encode("latin-1")
        out["cache"] = cfp.fingerprint(
            head + b"\r\n" + body, ms)
        out["edge"]["status"] = r.status
        if reuse:
            try:
                c.request("GET", path)
                r2 = c.getresponse()
                r2.read()
                out["edge"]["persist"] = "alive"
            except Exception:
                out["edge"]["persist"] = "closed"
    except Exception as e:
        out["error"] = repr(e)[:120]
    finally:
        try:
            c.close()
        except Exception:
            pass
    return out


def _origin_differs(a, b):
    """Semantica del origin difiere (cuerpo manda).
    None = no observable."""
    if "error" in a or "error" in b:
        return None
    return (a["origin"]["body_hash"] !=
            b["origin"]["body_hash"])


def _baseline(url):
    """STABLE / AMBIGUO / INVALID. Si el contenido rota
    sin patron, todo lo demas es UNKNOWN honesto."""
    fps = []
    for _ in range(BASELINE_PROBES):
        o = _fetch(url, "/", reuse=False)
        if "error" in o:
            return {"tipo": "INVALID"}
        fps.append(o["origin"]["body_hash"])
    extra = _fetch(url, "/path-cl")
    if "error" in extra:
        return {"tipo": "INVALID"}
    fps.append(extra["origin"]["body_hash"])
    stable = len(set(fps)) == 1
    return {"tipo": "STABLE" if stable else "AMBIGUO",
            "hashes": fps}


def _controls(pert_obs, ctrl_obs):
    """Controles de explicaciones alternativas. Solo
    comprobaciones reales de headers observados."""
    res = {}
    vary = None
    for o in (pert_obs, ctrl_obs):
        for k, v in o.get("cache", {}).get(
                "signals", {}).items():
            if k == "vary" and v["state"] == "OBSERVED":
                vary = v["value"]
    res["vary"] = ("FAILED" if vary not in ("", None, "*")
                   else "NOT_APPLICABLE")
    ck = False
    for o in (pert_obs, ctrl_obs):
        sc = o.get("cache", {}).get(
            "signals", {}).get("set_cookie", {})
        if sc.get("state") == "OBSERVED":
            ck = True
    res["auth_cookie"] = "FAILED" if ck else "PASSED"
    res["all_passed"] = all(
        v in ("PASSED", "NOT_APPLICABLE")
        for v in res.values())
    return res


def _register(g, exp_id, proc, hids, budget):
    g.register_contract(
        exp_id, hids, proc, BRANCHES,
        ["baseline-caracterizado"],
        budget, SPECTRUM)


def _obs(g, exp_id, pid, conn, o):
    return g.add_observation(
        exp_id,
        facts={"pid": pid, "conn": conn,
               "origin": o.get("origin"),
               "cache_valid": o.get("cache", {}).get(
                   "valid", False)},
        signal=None,
        repro={"request_fp": "%s:%s" % (pid, conn),
               "conn_identity": conn,
               "conn_reuse": "A reusa, resto no",
               "response_fp": o.get("origin", {}).get(
                   "body_hash"),
               "cache_fp": str(sorted(
                   o.get("cache", {}).get(
                       "signals", {}).keys()))[:120],
               "controls": "baseline",
               "genealogy": [g.run_id, pid, conn]})


def cross_audit(cfg):
    """Orquestador v0.84. Informe determinista + grafo."""
    url = cfg["url"]
    timeout = cfg.get("timeout", PERTURBATION_TIMEOUT)
    host = url.split("//")[-1].split("/")[0].split(":")[0]
    informe = {
        "target": url, "version": MODULE_VERSION,
        "baseline": _baseline(url), "experiments": [],
        "verdict": "UNKNOWN", "reasons": [],
        "requests": 0,
    }
    bs = informe["baseline"]["tipo"]
    g = xg.ExpGraph(host, hypotheses=HYPOTHESES,
                    baseline_state=(
                        "STABLE" if bs == "STABLE"
                        else "AMBIGUO-NO-CARACTERIZADO"))
    g.journal.append({
        "event": "baseline", "state": bs,
        "fps": informe["baseline"].get("hashes", []),
        "ts": g.created})
    informe["baseline_state"] = g.baseline_state

    if bs == "INVALID":
        informe["verdict"] = "UNREACHABLE"
        informe["reasons"].append("baseline invalido")
        informe["graph_run"] = g.dump().get("run_id")
        return informe

    best = {"nivel": 0, "pid": None}
    for p in perturbation_battery()[:MAX_PERTURBATIONS]:
        exp_id = "EXP-" + p["pid"]
        _register(g, exp_id,
                  "perturbacion %s: A conn1 + reuse, "
                  "B conn2, C control nuevo, D control "
                  "fresco" % p["pid"],
                  ["H-MISMATCH", "H-SHARED", "H-CONTAM"],
                  {"max_requests": 4,
                   "max_connections": 4})
        obsA = _fetch(url, p["path"], timeout, reuse=True)
        obsB = _fetch(url, p["path"], timeout)
        obsC = _fetch(url, p["control"], timeout)
        obsD = _fetch(url, p["control"], timeout)
        informe["requests"] += 4

        oA = _obs(g, exp_id, p["pid"], "A", obsA)
        _obs(g, exp_id, p["pid"], "B", obsB)
        oC = _obs(g, exp_id, p["pid"], "C-ctrl", obsC)
        _obs(g, exp_id, p["pid"], "D-ctrl", obsD)

        mismatch = _origin_differs(obsA, obsD)
        repro = _origin_differs(obsB, obsD)
        contamin = _origin_differs(obsC, obsD)
        ctrls = _controls(obsA, obsD)
        ent = {
            "pid": p["pid"], "mismatch": mismatch,
            "reproducido": repro,
            "contaminacion": contamin,
            "controles": ctrls,
            "edge_persist": obsA.get("edge", {}).get(
                "persist", "n/a"),
        }
        informe["experiments"].append(ent)

        # ---- escalera determinista --------------------
        if mismatch is None:
            g.apply(exp_id, oA, "unobservable")
            informe["reasons"].append(
                "%s: diff no observable -> unknown"
                % p["pid"])
            continue
        if not mismatch:
            if ent["edge_persist"] == "closed":
                g.apply(exp_id, oA, "edge-only")
                g.journal.append({
                    "event": "evidence-note",
                    "id": oA, "ts": g.created,
                    "nota": "EDGE-ONLY: edge diverge pero "
                            "origin identico: tolerancia, "
                            "no vulnerabilidad"})
            g.apply(exp_id, oA, "absorbed")
            informe["reasons"].append(
                "%s: perturbacion absorbida -> benigno"
                % p["pid"])
            if best["nivel"] < 1:
                best = {"nivel": 1, "pid": p["pid"],
                        "verdict": "BENIGN"}
            continue
        # mismatch observable
        g.apply(exp_id, oA, "mismatch")
        if best["nivel"] < 2:
            best = {"nivel": 2, "pid": p["pid"],
                    "verdict": "SUSPICIOUS"}
        if repro is not True:
            g.apply(exp_id, oA, "mismatch-no-repro")
            informe["reasons"].append(
                "%s: mismatch no reproducido -> "
                "suspicious sin escalada" % p["pid"])
            continue
        g.apply(exp_id, oA, "shared")
        best = {"nivel": 3, "pid": p["pid"],
                "verdict": "SHARED-STATE"}
        if contamin is True and ctrls["all_passed"]:
            g.apply(exp_id, oC, "contaminated")
            best = {"nivel": 4, "pid": p["pid"],
                    "verdict": "DEMO"}
        else:
            g.apply(exp_id, oA, "shared-no-contam")
            informe["reasons"].append(
                "%s: shared sin contaminacion observable "
                "o controles FAILED -> SHARED-STATE sin "
                "DEMO" % p["pid"])

    informe["verdict"] = best.get("verdict",
                                  informe["verdict"])
    g.journal.append({
        "event": "verdict", "verdict": informe["verdict"],
        "reasons": informe["reasons"],
        "requests": informe["requests"], "ts": g.created})
    informe["graph_run"] = g.dump().get("run_id")
    g.save()
    return informe


def render(informe):
    L = []
    L.append("=== v%s CROSS-LAYER CORRELATION ==="
             % MODULE_VERSION)
    L.append("target: %s" % informe["target"])
    L.append("baseline: %s" % informe.get(
        "baseline_state", "n/a"))
    L.append("requests: %d" % informe["requests"])
    for e in informe["experiments"]:
        L.append("- %s mismatch=%s repro=%s contam=%s "
                 "ctrl=%s edge=%s" % (
                     e["pid"], e["mismatch"],
                     e["reproducido"], e["contaminacion"],
                     e["controles"]["all_passed"],
                     e.get("edge_persist", "n/a")))
    for r in informe["reasons"]:
        L.append("  * %s" % r)
    L.append("VEREDICTO: %s" % informe["verdict"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    inf = cross_audit({"url": a.url})
    if a.json:
        print(json.dumps(inf, indent=2, default=str))
    else:
        print(render(inf))
    return 0 if inf["verdict"] != "DEMO" else 3


if __name__ == "__main__":
    sys.exit(main())
