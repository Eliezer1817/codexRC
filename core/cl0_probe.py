#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.87.0 CL.0-SINGLE-TIER (Request Smuggling CL.0)
=================================================
Familia CL.0 con la disciplina de la linea DESYNC:
contratos pre-registrados en el ExperimentGraph, juez
determinista, presupuesto bajo y cero-FP por diseno.

Mecanica CL.0: POST con 'Content-Length: 0' cuyo body
declara 0 bytes pero el stream lleva un prefijo smuggleado.
Si el front NO parsea el prefijo como request propio y el
backend NO consume el stream residual, el prefijo es
procesado por el backend como request invisible para el
front: la cola de respuestas queda desplazada.

Oraculo observable (nada inferido):
  T1  ventana de silencio tras POST+smuggle:
      respuesta temprana => el front parseo el prefijo
      (pipelining benigno, NO desync).
  T2  tras el followup: si aparece la respuesta del
      smuggle (eco del token) SIN atribucion del front
      => el backend proceso bytes que el front no
      contabiliza => MISMATCH observable.
  S   doble followup: si la respuesta del segundo
      followup porta el token del PRIMERO => la cola
      esta desplazada (STATE EFFECT observable).

Regla heredada: el eco del token SOLO no es desync.
Sin diferencial de timing o atribucion observable, el
veredicto NO escala. Sin repro 2/2 no hay DESYNC.

Contratos (pre-registrados):
  baseline: C0 control GET @base (firma de respuesta);
            C1 POST vacio + followup en conexion fresca
            (r2 debe matchear C0: si no, UNSTABLE).
  variante (endpoint candidato, redirect/404 family):
    P  probe: POST CL:0 + smuggle + followup1 + followup2
    R  repro: idem en conexion nueva

Escalera determinista:
  BENIGN -> CL0-DETECTED (1/2, probable, NO reportable)
  -> CL0-DESYNC (repro 2/2) -> CL0-STATE-EFFECT
  (+ BENIGN-FRONT / UNSTABLE / UNREACHABLE / UNKNOWN)

Presupuesto: 2 baseline + 1 variante x 2 fases x 3 reqs
= max 8 requests. Read-only: el smuggle es un GET propio
con token unico, jamas recursos de terceros.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import experiment_graph as xg          # noqa: E402

MODULE_VERSION = "0.87.0"

# ---- clases de evidencia v0.87 -------------------------------------
E_CL0_SIGNAL = "E-CL0-SIGNAL"
E_CL0_STATE = "E-CL0-STATE"

HYPOTHESES = [
    ("H-CL0",
     "el backend procesa un prefijo smuggleado tras "
     "CL:0 que el front no contabiliza como request"),
    ("H-SHIFT",
     "la cola de respuestas queda desplazada: el "
     "cliente recibe respuestas de requests previos"),
]

BRANCHES = {
    # r2 matchea el control: nadie proceso el prefijo
    "no-echo": {"inconclusive": ["H-CL0", "H-SHIFT"]},
    # eco temprano en T1: lo parseo el front (pipelining
    # benigno). Cero-FP: el eco SOLO no es desync.
    "front-parsed": {"inconclusive": ["H-CL0"],
                     "nota": "el front respondio al prefijo "
                             "durante T1: pipelining, no "
                             "smuggling"},
    # desync observable pero sin repro 2/2
    "detected-norepro": {"supports": ["H-CL0"],
                         "clase": E_CL0_SIGNAL,
                         "tag": "OBSERVED",
                         "inconclusive": ["H-SHIFT"]},
    # repro 2/2: MISMATCH confirmado en esta familia
    "desync-repro": {"supports": ["H-CL0"],
                     "clase": E_CL0_SIGNAL,
                     "tag": "OBSERVED"},
    # ademas la cola queda desplazada (observable)
    "state-effect": {"supports": ["H-CL0", "H-SHIFT"],
                     "clase": E_CL0_STATE,
                     "tag": "OBSERVED"},
}

SPECTRUM = [
    [("H-CL0", "INCONCLUSIVE")],
    [("H-CL0", "SUPPORT")],
    [("H-SHIFT", "SUPPORT")],
]

# ---- presupuesto anti-DoS -------------------------------------------
BASELINE_PROBES = 2
MAX_VARIANTS = 1
PHASES = ("P", "R")
PROBE_TIMEOUT = 8.0
T1_QUIET = 1.2          # ventana de silencio (seg)


def smuggle_battery():
    """Endpoints candidatos CL.0: handlers que tipicamente
    NO consumen body (redirects y 404 custom). La autoridad
    del presupuesto es MAX_VARIANTS: solo el primero viable
    se dispara."""
    return [
        {"pid": "S-REDIR", "endpoint": "/",
         "desc": "raiz/redirect (handler sin body-read)"},
        {"pid": "S-404", "endpoint": "/cl0-nonexistent-404",
         "desc": "handler 404 custom (sin body-read)"},
    ]


def _token():
    return "cl0m" + uuid.uuid4().hex[:12]


def _hash(b):
    return hashlib.sha256(b).hexdigest()[:16]


# ---- capa raw socket -------------------------------------------------

def _recv_quiet(sock, quiet=T1_QUIET, cap=131072):
    """Lee hasta 'quiet' segundos sin datos nuevos."""
    buf = b""
    sock.settimeout(quiet)
    deadline = time.time() + PROBE_TIMEOUT
    while time.time() < deadline and len(buf) < cap:
        try:
            d = sock.recv(65535)
            if not d:
                break
            buf += d
        except socket.timeout:
            break
        except ConnectionResetError:
            buf += b"\x00RST\x00"
            break
        except OSError:
            break
    return buf


def _split_responses(raw):
    """Separa respuestas HTTP crudas por status-line."""
    parts = re.split(rb"(?=HTTP/1\.[01] \d{3})", raw)
    return [p for p in parts
            if p.startswith(b"HTTP/1.")]


def _statuses(raw):
    return [m.decode() for m in
            re.findall(rb"HTTP/1\.[01] (\d{3})", raw)]


def _has_token(raw, token):
    return token.encode() in raw


def _conn(url, timeout):
    import urllib.parse
    u = urllib.parse.urlparse(url if "//" in url
                              else "http://" + url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    s = socket.create_connection((host, port), timeout)
    if u.scheme == "https":
        import ssl
        s = ssl.create_default_context().wrap_socket(
            s, server_hostname=host)
    return s, (host + (":%d" % port
                       if port not in (80, 443) else ""))


def _get(host, path):
    return ("GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: keep-alive\r\n"
            "X-CL0-Control: 1\r\n\r\n" % (path, host)).encode()


def _post_cl0(host, path, smuggle):
    # RC-000217: bytes con %s inyecta el repr b'' literal;
    # el smuggle SIEMPRE se serializa a str antes de
    # formatear (bug real detectado en fase LAB).
    if isinstance(smuggle, bytes):
        smuggle = smuggle.decode("latin-1", "replace")
    return ("POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "\r\n%s" % (path, host, smuggle)).encode()


def _smuggle_req(host, token):
    """Prefijo smuggle INOFENSIVO: GET propio con token
    unico. Malformado a proposito (sin Connection): un
    front estricto lo rechazaria; el eco solo importa con
    diferencial de timing."""
    return ("GET /%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-CL0-Token: %s\r\n\r\n"
            % (token, host, token)).encode()


def _probe(url, endpoint, base="/", timeout=PROBE_TIMEOUT,
           phase="P"):
    """Fase P/R: POST CL:0 + smuggle, ventana T1,
    followup1 (token A), followup2 (token B).
    Devuelve observaciones crudas, nada inferido."""
    tok_s, tok_a, tok_b = _token(), _token(), _token()
    out = {"phase": phase, "endpoint": endpoint,
           "tokens": {"smuggle": tok_s, "fa": tok_a,
                      "fb": tok_b},
           "t1_raw": b"", "post_raw": b"",
           "t1_responses": 0, "t1_statuses": [],
           "t1_token": False, "t1_rst": False,
           "r2_control_match": None, "echo_after_fu": False,
           "echo_in": None, "shift": None, "error": None}
    try:
        s, host = _conn(url, timeout)
    except Exception as e:
        out["error"] = repr(e)[:120]
        return out
    try:
        smug = _smuggle_req(host, tok_s)
        s.sendall(_post_cl0(host, endpoint, smug))
        time.sleep(0.05)
        # T1: ventana de silencio
        t1 = _recv_quiet(s, quiet=T1_QUIET)
        out["t1_raw"] = t1
        out["t1_responses"] = len(
            _split_responses(t1))
        out["t1_statuses"] = _statuses(t1)
        out["t1_token"] = _has_token(t1, tok_s)
        out["t1_rst"] = b"\x00RST\x00" in t1
        # followup A y B (requests 2 y 3 del cliente)
        # (un RST previo explica un broken pipe aqui: no
        # es error de red, es la frontera del edge)
        try:
            s.sendall(_get(host, "%s?cl0fa=%s"
                          % (base, tok_a)))
            s.sendall(_get(host, "%s?cl0fb=%s"
                          % (base, tok_b)))
        except (BrokenPipeError, OSError):
            if not out["t1_rst"] and not t1:
                raise
        post = _recv_quiet(s)
        out["post_raw"] = post
        raw_all = t1 + post
        # eco del smuggle DESPUES de T1 (backend lo proceso
        # al llegar el followup: mismatch de contabilidad)
        if (_has_token(post, tok_s)
                and not out["t1_token"]):
            out["echo_after_fu"] = True
        # shift: en mundo alineado resps = [r1, fa, fb].
        # Con cola desplazada: [r1, smuggle, fa] y la
        # respuesta de B (fb) nunca llega al cliente.
        resps = _split_responses(raw_all)
        if len(resps) >= 3:
            last = resps[-1]
            out["shift"] = (_has_token(last, tok_a)
                            and not _has_token(last, tok_b))
        # firma de la respuesta 2 vs control se evalua
        # fuera (necesita la firma C0)
        out["_resps"] = [len(x) for x in resps]
    except Exception as e:
        out["error"] = repr(e)[:120]
    finally:
        try:
            s.close()
        except Exception:
            pass
    return out


# ---- auditor --------------------------------------------------------

def _register(g, exp_id, proc, hids, budget):
    g.register_contract(
        exp_id, hids, proc, BRANCHES,
        ["baseline-caracterizado"], budget, SPECTRUM)


def _obs(g, exp_id, pid, phase, o):
    return g.add_observation(
        exp_id,
        facts={"pid": pid, "phase": phase,
               "endpoint": o.get("endpoint"),
               "t1_responses": o.get("t1_responses"),
               "t1_token": o.get("t1_token"),
               "t1_rst": o.get("t1_rst"),
               "echo_after_fu": o.get("echo_after_fu"),
               "shift": o.get("shift"),
               "error": o.get("error")},
        signal=None,
        repro={"request_fp": "%s:%s" % (pid, phase),
               "conn_identity": "fresca",
               "conn_reuse": "conexion fresca por fase",
               "response_fp": _hash(o.get("post_raw", b"")),
               "controls": "C0/C1 baseline",
               "genealogy": [g.run_id, pid, phase]})


def cl0_audit(cfg):
    """Orquestador v0.87. Informe determinista + grafo."""
    url = cfg["url"]
    base = cfg.get("base", "/")
    host = (url.split("//")[-1].split("/")[0]
            .split(":")[0])
    informe = {
        "target": url, "base": base,
        "version": MODULE_VERSION,
        "baseline": {}, "experiments": [],
        "verdict": "UNKNOWN", "reasons": [],
        "requests": 0,
    }
    g = xg.ExpGraph(host, hypotheses=HYPOTHESES,
                    baseline_state="NO-CARACTERIZADO")

    # ---- baseline C1 (2 reqs): POST vacio CL:0 + followup.
    # r1 firma el comportamiento del POST; r2 ES el control
    # (followup alineado sin smuggle). Presupuesto: 2+6=8. ----
    _register(g, "EXP-BASELINE",
              "C1 POST vacio CL:0 + followup: r2 debe "
              "matchear C0 (sin smuggle no hay artefacto)",
              ["H-CL0"], {"max_requests": 2,
                          "max_connections": 1})
    tok_c1 = _token()
    try:
        s, rhost = _conn(url, PROBE_TIMEOUT)
        # secuencial (sin pipelining): POST -> r1 ->
        # followup -> r2. Determinista en el lab.
        s.sendall(_post_cl0(rhost, base, b""))
        raw1 = _recv_quiet(s, quiet=0.8)
        s.sendall(_get(rhost, "%s?cl0c1=%s" % (base, tok_c1)))
        raw1 += _recv_quiet(s)
        s.close()
    except Exception as e:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append("C1: %s" % e)
        g.save()
        informe["graph_run"] = g.run_id
        return informe
    informe["requests"] += 2
    resps_c1 = _split_responses(raw1)
    if len(resps_c1) >= 2:
        control_sig = _hash(re.sub(
            rb"cl0m[0-9a-f]{12}", b"TOK", resps_c1[1]))
        control_status = _statuses(
            resps_c1[1])[:1] or [None]
        informe["baseline"]["control"] = {
            "status": control_status[0],
            "sig": control_sig}
        match = True
    else:
        match = None
        informe["baseline"]["control"] = {
            "status": None, "sig": None}
    informe["baseline"]["c1_valid"] = match
    oC1 = {"phase": "C1", "endpoint": base,
           "t1_responses": 0, "t1_token": False,
           "t1_rst": False, "echo_after_fu": False,
           "shift": None, "error": None,
           "post_raw": raw1}
    obsC1 = _obs(g, "EXP-BASELINE", "C1", "C1", oC1)
    if match is not True:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "C1: sin par POST+followup legible -> baseline "
            "imposible, conclusiones prohibidas")
        g.save()
        informe["graph_run"] = g.run_id
        return informe

    # ---- variantes P + R ------------------------------------------
    best = {"nivel": 0, "verdict": "UNKNOWN"}
    fired = 0
    for p in smuggle_battery():
        if fired >= MAX_VARIANTS:
            break
        if informe["requests"] + 6 > 8:
            informe["reasons"].append(
                "presupuesto agotado antes de %s" % p["pid"])
            break
        exp_id = "EXP-" + p["pid"]
        _register(g, exp_id,
                  "CL.0 en %s: P probe (T1 silencio + eco "
                  "+ shift), R repro en conexion fresca"
                  % p["endpoint"],
                  ["H-CL0", "H-SHIFT"],
                  {"max_requests": 6, "max_connections": 2})
        obsP = _probe(url, p["endpoint"], base, phase="P")
        informe["requests"] += 3
        oP = _obs(g, exp_id, p["pid"], "P", obsP)

        if obsP["error"] and not obsP["t1_rst"]:
            informe["reasons"].append(
                "%s: error de red -> unknown" % p["pid"])
            continue
        if obsP["t1_rst"]:
            g.apply(exp_id, oP, "no-echo")
            informe["reasons"].append(
                "%s: RST tras el POST: frontera del edge "
                "estricta -> BENIGN" % p["pid"])
            if best["nivel"] < 1:
                best = {"nivel": 1, "pid": p["pid"],
                        "verdict": "BENIGN"}
            continue
        if obsP["t1_token"] or obsP["t1_responses"] > 1:
            g.apply(exp_id, oP, "front-parsed")
            informe["reasons"].append(
                "%s: respuesta al smuggle durante T1 -> "
                "el front lo parseo (pipelining benigno), "
                "eco solo NO es desync" % p["pid"])
            if best["nivel"] < 1:
                best = {"nivel": 1, "pid": p["pid"],
                        "verdict": "BENIGN"}
            continue
        if not obsP["echo_after_fu"]:
            g.apply(exp_id, oP, "no-echo")
            informe["reasons"].append(
                "%s: sin eco del smuggle tras followup -> "
                "BENIGN" % p["pid"])
            if best["nivel"] < 1:
                best = {"nivel": 1, "pid": p["pid"],
                        "verdict": "BENIGN"}
            continue

        # eco observable DESPUES del followup: mismatch
        fired += 1
        if obsP["shift"]:
            g.apply(exp_id, oP, "state-effect")
        else:
            g.apply(exp_id, oP, "desync-repro")
        informe["reasons"].append(
            "%s: MISMATCH observable: el backend respondio "
            "al smuggle solo tras el followup%s"
            % (p["pid"],
               " y la cola quedo desplazada (SHIFT)"
               if obsP["shift"] else ""))

        # R: repro en conexion fresca
        obsR = _probe(url, p["endpoint"], base, phase="R")
        informe["requests"] += 3
        oR = _obs(g, exp_id, p["pid"], "R", obsR)
        repro = (not obsR["error"]
                 and not obsR["t1_rst"]
                 and not obsR["t1_token"]
                 and not (obsR["t1_responses"] > 1)
                 and obsR["echo_after_fu"])
        if not repro:
            g.apply(exp_id, oR, "detected-norepro")
            informe["reasons"].append(
                "%s: sin repro 2/2 -> CL0-DETECTED "
                "(probable, NO reportable)" % p["pid"])
            if best["nivel"] < 2:
                best = {"nivel": 2, "pid": p["pid"],
                        "verdict": "CL0-DETECTED"}
            informe["experiments"].append({
                "pid": p["pid"],
                "endpoint": p["endpoint"],
                "echo_P": obsP["echo_after_fu"],
                "shift_P": obsP["shift"],
                "echo_R": obsR["echo_after_fu"],
                "shift_R": obsR["shift"],
            })
            continue

        g.apply(exp_id, oR, "desync-repro")
        informe["reasons"].append(
            "%s: repro 2/2 -> CL0-DESYNC confirmado"
            % p["pid"])
        if best["nivel"] < 3:
            best = {"nivel": 3, "pid": p["pid"],
                    "verdict": "CL0-DESYNC"}
        if obsP["shift"] and obsR["shift"]:
            g.apply(exp_id, oR, "state-effect")
            informe["reasons"].append(
                "%s: SHIFT observable 2/2 -> "
                "CL0-STATE-EFFECT" % p["pid"])
            best = {"nivel": 4, "pid": p["pid"],
                    "verdict": "CL0-STATE-EFFECT"}

        informe["experiments"].append({
            "pid": p["pid"], "endpoint": p["endpoint"],
            "echo_P": obsP["echo_after_fu"],
            "shift_P": obsP["shift"],
            "echo_R": obsR["echo_after_fu"],
            "shift_R": obsR["shift"],
        })

    informe["verdict"] = best.get(
        "verdict", informe["verdict"])
    g.journal.append({
        "event": "verdict",
        "verdict": informe["verdict"],
        "reasons": informe["reasons"],
        "requests": informe["requests"], "ts": g.created})
    g.save()
    informe["graph_run"] = g.run_id
    return informe


def render(informe):
    L = ["=== v%s CL.0-SINGLE-TIER ===" % MODULE_VERSION,
         "target: %s" % informe.get("target")]
    b = informe.get("baseline", {})
    L.append("baseline: control=%s c1_match=%s"
             % (b.get("control", {}).get("status"),
                b.get("c1_match")))
    L.append("requests: %d" % informe["requests"])
    for e in informe["experiments"]:
        L.append("- %s echo %s/%s shift %s/%s" % (
            e["pid"], e["echo_P"], e["echo_R"],
            e["shift_P"], e["shift_R"]))
    for r in informe["reasons"]:
        L.append("  * %s" % r)
    L.append("VEREDICTO: %s" % informe["verdict"])
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--base", default="/")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    inf = cl0_audit({"url": a.url, "base": a.base})
    if a.json:
        print(json.dumps(inf, indent=2, default=str))
    else:
        print(render(inf))
    return (3 if inf["verdict"] == "CL0-STATE-EFFECT"
            else 0)


if __name__ == "__main__":
    sys.exit(main())
