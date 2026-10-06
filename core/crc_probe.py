#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.90.0 CROSS-REQUEST CORRELATION
=================================
Reconstruccion de la cola del origin por CORRELACION
entre requests, con la disciplina de la linea DESYNC:
contratos pre-registrados en el ExperimentGraph, juez
determinista, presupuesto bajo y cero-FP por diseno.

Mecanica CROSS-REQUEST CORRELATION: un POST CL.0 lleva
DOS requests smuggleadas (T1, T2: GETs propios con
tokens unicos). Si el origin procesa el residual como
cola, las respuestas de los followups quedan
DESPALAZADAS por k consistente y MEDIBLE:

  k=0  [ECHO-fb,     ECHO-fc,     ECHO-fd]   alineado
  k=1  [SMUGGLE-T1,  ECHO-fb,     ECHO-fc]   shift 1
  k=2  [SMUGGLE-T1,  SMUGGLE-T2,  ECHO-fb]   shift 2

Oraculo observable (nada inferido): la PERMUTACION de la
coleccion. La firma del desync es la correlacion
CONSISTENTE: el eco propio aparece desplazado
EXACTAMENTE por el numero de ecos del smuggle
observados (fi == si_count). Un patron disperso (ecos
sin permutacion consistente) NO escala a STATE-EFFECT.

Regla heredada (v0.87-89): el eco del token SOLO no es
desync; sin permutacion observable, el veredicto NO
escala. Sin repro 2/2 no hay DESYNC.

Auto-control por atribucion (sin baseline separado): el
eco propio del followup en la posicion 0 es el control
de cada fase; sin eco propio ni eco del smuggle:
UNKNOWN (no BENIGN, cero-FP).

Contratos (pre-registrados):
  fase P  POST doble-smuggleado (T1, T2) + 3 GETs
          (fb, fc, fd) en conexion fresca
  fase R  repro idem con tokens nuevos

Escalera determinista:
  BENIGN -> CRC-DETECTED (1/2, probable, NO reportable)
  -> CRC-DESYNC (repro 2/2)
  -> CRC-STATE-EFFECT (ademas permutacion consistente,
     k medible y reproducible)
  (+ BENIGN-EDGE / UNSTABLE / UNREACHABLE / UNKNOWN)

Presupuesto: 1 variante x 2 fases x 4 reqs (A: 1 POST
doble-smuggleado; B: 3 GETs) = max 8 requests. Read-only:
los smuggles son GETs propios con tokens unicos, jamas
recursos de terceros.

Aprendizajes v0.87-89: bytes crudos jamas repr(b'..');
buffers PERSISTENTES por conexion; grace de ciclo de
vida antes de heredar.
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import experiment_graph as xg          # noqa: E402

MODULE_VERSION = "0.90.0"

# ---- clases de evidencia v0.90 -------------------------------------
E_CRC_SIGNAL = "E-CRC-SIGNAL"
E_CRC_STATE = "E-CRC-STATE"

HYPOTHESES = [
    ("H-CRCQUEUE",
     "el origin procesa el residual del POST como cola "
     "de requests invisibles y las respuestas de los "
     "followups quedan desplazadas"),
    ("H-CRCK",
     "el desplazamiento k es consistente: el eco propio "
     "del followup cae desplazado EXACTAMENTE por el "
     "numero de ecos del smuggle observados"),
    ("H-CRCREPRO",
     "la permutacion es reproducible con tokens nuevos "
     "(firma determinista, no ruido de red)"),
]

BRANCHES = {
    "aligned": {"inconclusive": ["H-CRCQUEUE", "H-CRCK",
                                 "H-CRCREPRO"]},
    "edge-strict": {"inconclusive": ["H-CRCQUEUE",
                                      "H-CRCK"],
                    "nota": "el edge rechazo el smuggle "
                            "antes del origin"},
    "detected-norepro": {"supports": ["H-CRCQUEUE"],
                         "clase": E_CRC_SIGNAL,
                         "tag": "OBSERVED",
                         "inconclusive": ["H-CRCK",
                                          "H-CRCREPRO"]},
    "desync-repro": {"supports": ["H-CRCQUEUE",
                                   "H-CRCREPRO"],
                     "clase": E_CRC_SIGNAL,
                     "tag": "OBSERVED",
                     "inconclusive": ["H-CRCK"]},
    "state-effect": {"supports": ["H-CRCQUEUE", "H-CRCK",
                                   "H-CRCREPRO"],
                     "clase": E_CRC_STATE,
                     "tag": "OBSERVED"},
}

SPECTRUM = [
    [("H-CRCQUEUE", "INCONCLUSIVE")],
    [("H-CRCQUEUE", "SUPPORT")],
    [("H-CRCK", "SUPPORT")],
]

# ---- presupuesto anti-DoS ------------------------------------------
BASELINE_PROBES = 0        # auto-control por atribucion
MAX_VARIANTS = 1
PHASES = ("P", "R")
PHASE_REQS = 4              # A: 1 POST, B: 3 GETs
PROBE_TIMEOUT = 8.0

BATTERY = ("double",)

RESP_KEYS = ("crca", "crcb", "crcc", "crcd")


def _token():
    return uuid.uuid4().hex[:12]


def _hash(b):
    return hashlib.sha256(b).hexdigest()[:16]


# ---- mini-cliente H1 ----------------------------------------------

class H1Reader(object):
    """Lector de respuestas H1 con buffer PERSISTENTE por
    conexion (leccion v0.88)."""

    def __init__(self, s):
        self.s = s
        self.buf = b""

    def _recv(self):
        try:
            d = self.s.recv(65535)
        except (socket.timeout, OSError):
            return False
        if not d:
            return False
        self.buf += d
        return True

    def read_resp(self):
        """Una respuesta H1 (status, body) o (None, None)."""
        while b"\r\n\r\n" not in self.buf:
            if not self._recv():
                if b"\r\n\r\n" in self.buf:
                    break
                return None, None
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status = (lines[0].split(b" ")[1].decode(
            "latin-1", "replace") if lines and b" "
            in lines[0] else "")
        cl = 0
        for ln in lines[1:]:
            if ln.lower().startswith(b"content-length:"):
                try:
                    cl = int(ln.split(b":", 1)[1] or b"0")
                except ValueError:
                    cl = 0
        while len(rest) < cl:
            if not self._recv():
                break
        body = rest[:cl]
        self.buf = rest[cl:]
        return status, body.decode("latin-1", "replace")


def _smuggle_req(token):
    return ("GET /%s HTTP/1.1\r\nHost: crc\r\n\r\n"
            % token).encode()


def _connect(host, port, timeout, use_tls=False):
    """Socket al blanco; TLS si el esquema es https
    (validacion en vivo). El lab usa plain sockets."""
    s = socket.create_connection((host, port), timeout)
    if use_tls:
        import ssl
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(timeout)
    return s


def _phase_conn(host, port, t1, t2, toks,
                 timeout=PROBE_TIMEOUT, use_tls=False):
    """UNA conexion por fase (correlacion entre requests
    de la MISMA conexion): POST CL.0 con DOS requests
    smuggleadas + 3 GETs followup. Devuelve
    (a_kind, bodies, err). BYTES crudos (v0.87)."""
    post = ("POST / HTTP/1.1\r\nHost: crc\r\n"
            "Content-Length: 0\r\n\r\n").encode()
    a_kind = "post-ok"
    bodies = []
    err = None
    s = None
    try:
        s = _connect(host, port, timeout, use_tls)
    except (socket.timeout, OSError) as e:
        # blanco muerto a mitad de fase: error honesto,
        # nunca crash (lecciones live v0.90.1)
        return "conn-dead", bodies, repr(e)
    rd = H1Reader(s)
    try:
        s.sendall(post + _smuggle_req(t1)
                  + _smuggle_req(t2))
        st, _ = rd.read_resp()
        if not st:
            a_kind = "edge-strict"
            return a_kind, bodies, err
        for key, tok in zip(("crcb", "crcc", "crcd"),
                            toks):
            req = ("GET /?%s=%s HTTP/1.1\r\nHost: crc\r\n"
                   "\r\n" % (key, tok)).encode()
            s.sendall(req)
            st2, body = rd.read_resp()
            bodies.append(body if st2 else None)
    except (ConnectionResetError, BrokenPipeError):
        if not bodies:
            a_kind = "edge-strict"
        else:
            err = "reset-en-followup"
    except (socket.timeout, OSError) as e:
        err = repr(e)
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
    return a_kind, bodies, err

def _probe(host, port, battery, phase,
           timeout=PROBE_TIMEOUT, use_tls=False):
    """Una fase completa (A siembra doble, B recolecta)."""
    t1, t2 = _token(), _token()
    fb, fc, fd = _token(), _token(), _token()
    obs = {"phase": phase, "t1": t1, "t2": t2,
           "fb": fb, "fc": fc, "fd": fd}
    obs["a_kind"], bodies, err = _phase_conn(
        host, port, t1, t2, (fb, fc, fd), timeout,
        use_tls)
    obs["bodies"] = bodies
    if err:
        obs["error"] = err
    return obs


def _register(g, exp_id, proc, hids, budget):
    g.register_experiment({
        "id": exp_id, "process": proc,
        "hypotheses": hids,
        "budget": {"max_requests": budget,
                   "policy": "anti-DoS"},
        "preregistration": True})


def _obs(g, exp_id, pid, phase, o):
    g.add_observation(exp_id, pid, {
        "phase": phase, "observable": o,
        "ts": time.time()})


def crc_audit(cfg):
    """Auditoria CROSS-REQUEST CORRELATION de un blanco.
    cfg: url (host O url http), battery ('double')."""
    host = cfg.get("host")
    port = cfg.get("port")
    url = cfg.get("url", "")
    use_tls = url.startswith("https://")
    if not host and url:
        u = url.split("://", 1)[-1]
        host = u.split("/")[0].split(":")[0]
        if ":" in u.split("/")[0]:
            try:
                port = int(u.split("/")[0].split(":")[1])
            except ValueError:
                pass
    port = port or (443 if use_tls else 80)
    battery = cfg.get("battery", "double")
    if battery not in BATTERY:
        battery = "double"

    informe = {
        "module": "cross_request_correlation",
        "version": MODULE_VERSION,
        "battery": battery,
        "url": url or "http://%s:%s" % (host, port),
        "verdict": "UNKNOWN", "reasons": [],
        "requests": 0,
        "evidence": {},
    }

    try:
        g = xg.seed(
            "cross_request_correlation_%s" % battery)
    except Exception:
        g = None

    exp_id = "CRC-%s" % battery.upper()
    proc = ("medir permutacion consistente de la cola del "
            "origin por doble marcador smuggleado (%s)"
            % battery)
    hids = [h[0] for h in HYPOTHESES]
    budget = (BASELINE_PROBES
              + MAX_VARIANTS * len(PHASES) * PHASE_REQS)
    if g:
        _register(g, exp_id, proc, hids, budget)

    # reachability
    try:
        s = _connect(host, port, PROBE_TIMEOUT, use_tls)
        s.close()
    except (socket.timeout, OSError) as e:
        informe["verdict"] = "UNREACHABLE"
        informe["reasons"].append(repr(e))
        return informe

    resultados = []
    for phase in PHASES:
        o = _probe(host, port, battery, phase,
                  use_tls=use_tls)
        informe["requests"] += PHASE_REQS
        if g:
            _obs(g, exp_id, phase, phase, o)
        resultados.append(o)

    def _interp(o):
        """Clasifica UNA fase por observables puros: la
        PERMUTACION de la coleccion de B."""
        if "error" in o:
            return "unknown", [o["error"]], None
        if o["a_kind"] == "edge-strict":
            return ("edge-strict",
                    ["RST del edge al smuggle"], None)
        if o["a_kind"].startswith("timeout"):
            return "unknown", [o["a_kind"]], None
        bodies = o["bodies"]
        fb_e = "ECHO %s" % o["fb"]
        sm_pos = [i for i, bd in enumerate(bodies)
                  if isinstance(bd, str)
                  and bd.startswith("SMUGGLE-ECHO ")]
        fi = (bodies.index(fb_e) if fb_e in bodies
              else None)
        rs = []
        if sm_pos and fi is not None and fi > 0:
            k = fi - 0
            if fi == len(sm_pos):
                rs.append("permutacion consistente: "
                          "%d eco(s) del smuggle en %s, "
                          "eco propio en pos %d (k=%d)"
                          % (len(sm_pos), sm_pos, fi, k))
                return "state-effect", rs, k
            rs.append("ecos del smuggle en %s PERO eco "
                      "propio en pos %d: permutacion "
                      "INCONSISTENTE" % (sm_pos, fi))
            return "desync", rs, None
        if sm_pos:
            rs.append("ecos del smuggle en %s sin eco "
                      "propio observable" % (sm_pos,))
            return "desync", rs, None
        if fi == 0:
            return "aligned", ["B alineado: eco "
                              "propio en pos 0"], 0
        return ("unknown",
                ["respuestas sin eco propio ni eco del "
                 "smuggle: %r" % (bodies[:3],)], None)

    inter = [_interp(o) for o in resultados]
    for ph, (kind, rs, k) in zip(PHASES, inter):
        informe["reasons"] += ["%s: %s" % (ph, r)
                               for r in rs]
        informe["evidence"][ph] = kind
        if k is not None:
            informe["evidence"]["k_%s" % ph] = k

    ka, kb = inter[0][0], inter[1][0]
    ka_k, kb_k = inter[0][2], inter[1][2]
    contam = ("desync", "state-effect")
    if ka == "aligned" and kb == "aligned":
        informe["verdict"] = "BENIGN"
        informe["reasons"].append("ambas fases alineadas")
    elif "edge-strict" in (ka, kb):
        informe["verdict"] = "BENIGN-EDGE"
        informe["reasons"].append(
            "el edge rechazo el smuggle: sin desync")
    elif (ka == "state-effect" and kb == "state-effect"
            and ka_k == kb_k):
        informe["verdict"] = "CRC-STATE-EFFECT"
        informe["evidence"]["class"] = E_CRC_STATE
        informe["evidence"]["k"] = ka_k
    elif ka in contam and kb in contam:
        informe["verdict"] = "CRC-DESYNC"
        informe["evidence"]["class"] = E_CRC_SIGNAL
    elif ka in contam or kb in contam:
        informe["verdict"] = "CRC-DETECTED"
        informe["reasons"].append(
            "sin repro 2/2: NO reportable")
        informe["evidence"]["class"] = E_CRC_SIGNAL
    else:
        informe["verdict"] = "UNKNOWN"

    if g:
        tag = {"CRC-DESYNC": "desync-repro",
               "CRC-STATE-EFFECT": "state-effect",
               "CRC-DETECTED": "detected-norepro",
               "BENIGN": "aligned",
               "BENIGN-EDGE": "edge-strict",
               }.get(informe["verdict"])
        if tag and tag in BRANCHES:
            xg.apply(g, [
                (h, "SUPPORT" if BRANCHES[tag].get(
                    "supports", []).count(h)
                 else ("INCONCLUSIVE"
                       if h in BRANCHES[tag].get(
                    "inconclusive", []) else "NONE"))
                for h in hids])
    return informe


def main():
    ap = argparse.ArgumentParser(
        description="v0.90 CROSS-REQUEST CORRELATION "
                    "audit")
    ap.add_argument("--url", required=True,
                    help="http://host:port del blanco")
    ap.add_argument("--battery",
                    choices=BATTERY, default="double")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    inf = crc_audit({"url": a.url, "battery": a.battery})
    if a.json:
        print(json.dumps(inf, indent=2,
                         ensure_ascii=False))
    else:
        print("[%s] veredicto: %s" % (
            inf["battery"], inf["verdict"]))
        for r in inf["reasons"]:
            print("  - %s" % r)
        print("  requests: %d" % inf["requests"])
    return 0 if inf["verdict"] not in (
        "UNKNOWN", "UNREACHABLE", "UNSTABLE") else 1


if __name__ == "__main__":
    sys.exit(main())
