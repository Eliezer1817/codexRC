#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.86.0 WCD-CACHE-KEY (Web Cache Deception)
============================================
Familia WCD con la disciplina de la linea DESYNC: contratos
pre-registrados, juez determinista, presupuesto bajo y cero-FP
por diseno.

Filosofia heredada (v0.72-v0.85):
- Solo evidencia observable; nada inferido queda fuera de 'unknown'.
- Un endpoint abierto (anonimo ya ve los datos SIN disfraz) NO es
  WCD: es un candidato BAC, familia distinta, veredicto honesto.
- Sin almacenamiento positivo observable en el edge (HIT/Age)
  NO es WCD reportable: es LEAK-NO-CACHE (probable, no reportable).
- DEMO exige contaminacion: una conexion NUEVA y SIN sesion recibe
  el cuerpo autenticado desde el cache, con controles PASSED.
  (Vary sobre Cookie o Set-Cookie en la respuesta descalifican.)

Contratos (pre-registrados en el ExperimentGraph):
  baseline: A0 sesion@base debe contener el marcador autenticado
            (si no, NO-AUTH-DATA: no hay linea base de que es
            'dato autenticado'); D0 anon@base NO debe verlo
            (si lo ve: OPEN-ENDPOINT, no es WCD).
  por variante:
    A  sesion + disfraz        -> leak? cache-positive?
    B  sesion + disfraz (re)  -> HIT reproducido?
    C  anon  + disfraz        -> contaminacion observable?

Veredictos (escalera determinista):
  BENIGN -> LEAK-NO-CACHE -> WCD-CACHE -> WCD-DEMO
  (+ OPEN-ENDPOINT / NO-AUTH-DATA / UNREACHABLE / UNKNOWN)

Presupuesto: 2 baseline + 2 variantes x 3 = max 8 requests.
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

MODULE_VERSION = "0.86.0"

# ---- clases de evidencia v0.86 -------------------------------------
E_WCD_LEAK = "E-WCD-LEAK"
E_WCD_CACHE = "E-WCD-CACHE"
E_WCD_CONTAM = "E-WCD-CONTAM"

HYPOTHESES = [
    ("H-LEAK",
     "el origin sirve datos autenticados ante un path "
     "disfrazado (confusion de router/delimitadores)"),
    ("H-CACHE",
     "el edge almacena la respuesta autenticada bajo la "
     "clave del path disfrazado (HIT/Age observable)"),
    ("H-CONTAM",
     "una conexion nueva sin sesion recibe el cuerpo "
     "autenticado desde el cache"),
]

BRANCHES = {
    # disfraz sin leak: la confucion no existe
    "no-leak": {"inconclusive": ["H-LEAK"]},
    # leak observable pero el edge no lo almacena
    "leak-nocache": {"supports": ["H-LEAK"],
                     "clase": E_WCD_LEAK,
                     "tag": "OBSERVED"},
    # almacenado (HIT) pero contaminacion no observable
    # o controles FAILED (Vary cookie / Set-Cookie)
    "cache-no-contam": {"supports": ["H-CACHE"],
                        "clase": E_WCD_CACHE,
                        "tag": "OBSERVED",
                        "inconclusive": ["H-CONTAM"]},
    # contaminacion observable + controles PASSED
    "contaminated": {"supports": ["H-CONTAM"],
                     "clase": E_WCD_CONTAM,
                     "tag": "OBSERVED"},
}

SPECTRUM = [
    [("H-LEAK", "SUPPORT")],
    [("H-LEAK", "INCONCLUSIVE")],
    [("H-CONTAM", "SUPPORT")],
]

# ---- presupuesto anti-DoS -------------------------------------------
BASELINE_PROBES = 2
MAX_PERTURBATIONS = 2
PROBE_TIMEOUT = 12.0


def perturbation_battery():
    """Variantes de disfraz WCD (matriz de delimitadores
    ambiguos + sufijo estatico). La autoridad del presupuesto
    es MAX_PERTURBATIONS: solo las primeras N se disparan."""
    return [
        {"pid": "D-SEMI",
         "suffix": ";x.css",
         "desc": "delimitador ';' + sufijo estatico"},
        {"pid": "D-DDOT",
         "suffix": "/..;/x.css",
         "desc": "'/..;/' + sufijo estatico"},
        {"pid": "D-QM",
         "suffix": "%3Fx.css",
         "desc": "'%3F' codificado + sufijo"},
        {"pid": "D-HASH",
         "suffix": "%23x.css",
         "desc": "'%23' codificado + sufijo"},
    ]


_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

# cabeceras que indican almacenamiento positivo en el edge
CACHE_POSITIVE_HEADERS = ("x-cache", "cf-cache-status",
                          "x-varnish", "age")


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
    return http.client.HTTPConnection(host, port,
                                      timeout=timeout)


def _fetch(url, path, timeout=PROBE_TIMEOUT,
           headers=None):
    """Un request con headers propios (sesion). Devuelve
    status, body, headers parseados y senales WCD."""
    c = _conn(url, timeout)
    out = {"path": path, "status": None, "body": b"",
           "headers": {}, "cache": {}, "error": None}
    try:
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        out["body"] = r.read()
        out["status"] = r.status
        for k, v in r.getheaders():
            out["headers"].setdefault(
                k.lower(), []).append(v)
    except Exception as e:
        out["error"] = repr(e)[:120]
    finally:
        try:
            c.close()
        except Exception:
            pass
    out["cache"] = _cache_signals(out)
    return out


def _cache_signals(obs):
    """Senales de cache OBSERVADAS (nada inferido)."""
    sig = {"positive": None, "vary_cookie": None,
           "set_cookie": None}
    if obs["error"]:
        return sig
    h = obs["headers"]
    for k in CACHE_POSITIVE_HEADERS:
        if k in h:
            v = h[k][0]
            if k == "age":
                try:
                    positive = float(v) > 0
                except ValueError:
                    positive = None
                sig["positive"] = positive
                break
            if v.strip().lower() in ("hit", "hit()",
                                     "cached"):
                sig["positive"] = True
                break
            if v.strip().lower() in ("miss", "dynamic",
                                     "bypass"):
                sig["positive"] = False
                break
    for k, vals in h.items():
        if k == "vary":
            tokens = [t.strip().lower()
                      for v in vals
                      for t in v.split(",")]
            if "cookie" in tokens:
                sig["vary_cookie"] = True
        if k == "set-cookie":
            sig["set_cookie"] = True
    return sig


def _leak(obs, marker):
    """El cuerpo contiene el marcador autenticado.
    None = no observable (error)."""
    if obs["error"]:
        return None
    return marker.encode() in obs["body"]


def _controls(obs_a, obs_c):
    """Controles de explicaciones alternativas (v0.84-style).
    Vary: Cookie o Set-Cookie descalifican el DEMO."""
    res = {}
    vary = any(o["cache"]["vary_cookie"]
               for o in (obs_a, obs_c)
               if o["cache"]["vary_cookie"] is not None)
    res["vary"] = "FAILED" if vary else "PASSED"
    ck = any(o["cache"]["set_cookie"]
             for o in (obs_a, obs_c)
             if o["cache"]["set_cookie"] is not None)
    res["auth_cookie"] = "FAILED" if ck else "PASSED"
    res["all_passed"] = all(
        v == "PASSED" for v in res.values())
    return res


def _register(g, exp_id, proc, hids, budget):
    g.register_contract(
        exp_id, hids, proc, BRANCHES,
        ["baseline-caracterizado"],
        budget, SPECTRUM)


def _obs(g, exp_id, pid, conn, o, auth):
    return g.add_observation(
        exp_id,
        facts={"pid": pid, "conn": conn, "auth": auth,
               "status": o["status"],
               "cache_positive": o["cache"]["positive"],
               "vary_cookie": o["cache"]["vary_cookie"],
               "set_cookie": o["cache"]["set_cookie"],
               "body_hash": _hash(o["body"])},
        signal=None,
        repro={"request_fp": "%s:%s" % (pid, conn),
               "conn_identity": conn,
               "conn_reuse": "conexiones frescas por sonda",
               "response_fp": _hash(o["body"]),
               "cache_fp": str(sorted(o["headers"]
                                      .keys()))[:120],
               "controls": "baseline",
               "genealogy": [g.run_id, pid, conn]})


def wcd_audit(cfg):
    """Orquestador v0.86. Informe determinista + grafo."""
    url = cfg["url"]
    endpoint = cfg.get("endpoint", "/")
    marker = cfg.get("auth_marker")
    timeout = cfg.get("timeout", PROBE_TIMEOUT)
    auth_headers = cfg.get("auth_headers") or {}
    host = url.split("//")[-1].split("/")[0].split(":")[0]

    informe = {
        "target": url, "endpoint": endpoint,
        "version": MODULE_VERSION,
        "baseline": {}, "experiments": [],
        "verdict": "UNKNOWN", "reasons": [],
        "requests": 0,
    }
    if not marker:
        informe["verdict"] = "NO-MARKER"
        informe["reasons"].append(
            "auth_marker requerido: sin marcador no hay "
            "line base de 'dato autenticado' (anti-FP)")
        return informe

    g = xg.ExpGraph(host, hypotheses=HYPOTHESES,
                    baseline_state="NO-CARACTERIZADO")

    # ---- baseline: contrato antes de disparar ---------------
    _register(g, "EXP-BASELINE",
              "A0 sesion@base (debe contener marcador), "
              "D0 anon@base (NO debe contenerlo)",
              ["H-LEAK"], {"max_requests": 2,
                           "max_connections": 2})
    oA0 = _fetch(url, endpoint, timeout,
                 headers=auth_headers)
    informe["requests"] += 1
    oD0 = _fetch(url, endpoint, timeout)
    informe["requests"] += 1
    if oA0["error"] or oD0["error"]:
        informe["baseline"] = {"tipo": "INVALID"}
        informe["verdict"] = "UNREACHABLE"
        informe["reasons"].append("baseline invalido")
        g.journal.append({"event": "baseline",
                          "state": "INVALID",
                          "ts": g.created})
        informe["graph_run"] = g.dump().get("run_id")
        g.save()
        return informe

    leakA0 = _leak(oA0, marker)
    leakD0 = _leak(oD0, marker)
    g.journal.append({
        "event": "baseline", "ts": g.created,
        "a0_leak": leakA0, "d0_leak": leakD0})
    if leakA0 is not True:
        informe["baseline"] = {"tipo": "NO-AUTH-DATA"}
        informe["verdict"] = "NO-AUTH-DATA"
        informe["reasons"].append(
            "A0 sin marcador: la sesion no expone el dato "
            "-> no hay linea base observable")
        informe["graph_run"] = g.dump().get("run_id")
        g.save()
        return informe
    if leakD0 is True:
        informe["baseline"] = {"tipo": "OPEN-ENDPOINT"}
        informe["verdict"] = "OPEN-ENDPOINT"
        informe["reasons"].append(
            "D0 anonimo ya ve el dato SIN disfraz: "
            "endpoint abierto (candidato BAC, familia "
            "distinta; NO es WCD y no se gasta presupuesto)")
        informe["graph_run"] = g.dump().get("run_id")
        g.save()
        return informe
    informe["baseline"] = {"tipo": "STABLE"}
    g.baseline_state = "STABLE"

    best = {"nivel": 0, "pid": None}
    for p in perturbation_battery()[:MAX_PERTURBATIONS]:
        path = endpoint + p["suffix"]
        exp_id = "EXP-" + p["pid"]
        _register(g, exp_id,
                  "disfraz %s: A sesion+disfraz, "
                  "B sesion+disfraz (repro), C anon+disfraz"
                  " (contaminacion)" % p["pid"],
                  ["H-LEAK", "H-CACHE", "H-CONTAM"],
                  {"max_requests": 3,
                   "max_connections": 3})

        # A: sesion + disfraz (conexion fresca)
        obsA = _fetch(url, path, timeout,
                      headers=auth_headers)
        informe["requests"] += 1
        oA = _obs(g, exp_id, p["pid"], "A", obsA,
                   True)
        leakA = _leak(obsA, marker)
        if leakA is None:
            g.apply(exp_id, oA, "no-leak")
            informe["reasons"].append(
                "%s: error de red -> unknown" % p["pid"])
            continue
        if leakA is not True:
            g.apply(exp_id, oA, "no-leak")
            informe["reasons"].append(
                "%s: disfraz sin leak -> benigno"
                % p["pid"])
            if best["nivel"] < 1:
                best = {"nivel": 1, "pid": p["pid"],
                        "verdict": "BENIGN"}
            continue

        # leak observable
        g.apply(exp_id, oA, "leak-nocache")
        informe["reasons"].append(
            "%s: leak observable (origin sirve el dato "
            "ante el disfraz)" % p["pid"])
        if best["nivel"] < 2:
            best = {"nivel": 2, "pid": p["pid"],
                    "verdict": "LEAK-NO-CACHE"}

        # B: sesion + disfraz, repro del HIT
        obsB = _fetch(url, path, timeout,
                      headers=auth_headers)
        informe["requests"] += 1
        oB = _obs(g, exp_id, p["pid"], "B", obsB, True)
        cache_pos = (obsA["cache"]["positive"] is True
                     or obsB["cache"]["positive"] is True)
        if not cache_pos:
            g.apply(exp_id, oB, "leak-nocache")
            informe["reasons"].append(
                "%s: sin almacenamiento positivo "
                "(HIT/Age) -> LEAK-NO-CACHE, probable "
                "pero NO reportable" % p["pid"])
            continue

        # almacenado en cache: WCD-CACHE
        g.apply(exp_id, oB, "cache-no-contam")
        if best["nivel"] < 3:
            best = {"nivel": 3, "pid": p["pid"],
                    "verdict": "WCD-CACHE"}
        informe["reasons"].append(
            "%s: almacenamiento positivo observado -> "
            "WCD-CACHE" % p["pid"])

        # C: anon + disfraz, contaminacion
        obsC = _fetch(url, path, timeout)
        informe["requests"] += 1
        oC = _obs(g, exp_id, p["pid"], "C-anon", obsC,
                   False)
        leakC = _leak(obsC, marker)
        ctrls = _controls(obsB, obsC)
        if leakC is True and ctrls["all_passed"]:
            g.apply(exp_id, oC, "contaminated")
            best = {"nivel": 4, "pid": p["pid"],
                    "verdict": "WCD-DEMO"}
        else:
            g.apply(exp_id, oB, "cache-no-contam")
            informe["reasons"].append(
                "%s: sin contaminacion anonima o controles"
                " FAILED -> WCD-CACHE sin DEMO" % p["pid"])

        ent = {
            "pid": p["pid"], "path": path,
            "leak": leakA,
            "cache_positive": cache_pos,
            "cache_first": obsA["cache"]["positive"],
            "cache_repro": obsB["cache"]["positive"],
            "contaminacion_anon": leakC,
            "controles": ctrls,
        }
        informe["experiments"].append(ent)

    informe["verdict"] = best.get("verdict",
                                  informe["verdict"])
    g.journal.append({
        "event": "verdict",
        "verdict": informe["verdict"],
        "reasons": informe["reasons"],
        "requests": informe["requests"], "ts": g.created})
    informe["graph_run"] = g.dump().get("run_id")
    g.save()
    return informe


def render(informe):
    L = []
    L.append("=== v%s WCD-CACHE-KEY ==="
             % MODULE_VERSION)
    L.append("target: %s%s" % (informe.get("target"),
                               informe.get("endpoint", "")))
    L.append("baseline: %s" % informe.get(
        "baseline", {}).get("tipo", "n/a"))
    L.append("requests: %d" % informe["requests"])
    for e in informe["experiments"]:
        L.append("- %s leak=%s cache=%s/%s contam=%s "
                 "ctrl=%s" % (
                     e["pid"], e["leak"], e["cache_first"],
                     e["cache_repro"],
                     e["contaminacion_anon"],
                     e["controles"]["all_passed"]))
    for r in informe["reasons"]:
        L.append("  * %s" % r)
    L.append("VEREDICTO: %s" % informe["verdict"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--endpoint", default="/")
    ap.add_argument("--marker", required=True,
                    help="marcador de dato autenticado "
                         "(ej. el usuario de la sesion)")
    ap.add_argument("--header", action="append", default=[],
                    help="header de sesion, "
                         "'Name: value' (repetible)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    headers = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    inf = wcd_audit({
        "url": a.url, "endpoint": a.endpoint,
        "auth_marker": a.marker,
        "auth_headers": headers})
    if a.json:
        print(json.dumps(inf, indent=2, default=str))
    else:
        print(render(inf))
    return 0 if inf["verdict"] != "WCD-DEMO" else 3


if __name__ == "__main__":
    sys.exit(main())
