#!/usr/bin/env python3
"""EDGE-PROFILE (v0.75.0): caracteriza el CONTRATO del edge.

No busca desync, no lanza smuggles. Responde una sola pregunta:

  ¿Que transformaciones aplica cada frontera antes de entregar el
  mensaje a la siguiente capa?

Metodo: sondeos beningos (framing contradictorio con cuerpo
VACIO, sin contenido smuggleado) y observacion de lo que regresa.
Nada se infiere: lo no observable queda "unknown".

Ficha:
  version          HTTP observado
  reuse            la conexion reutilizada responde secuencial
  cierre_rechazo   el rechazo viene con cierre de conexion
  cl_te / te_doble / te_espacio / te_case
                   rejected | accepted | unknown
  normalizacion    normalized | conserved | unknown
                   (observable solo si el downstream hace ECO;
                   en blancos reales sin eco queda unknown)
  downstream       reached (eco visto) | unknown
  cache            firma Age/X-Cache entre requests repetidos
  origin           unknown (siempre: no observable)

Presupuesto: 1 conexion de reutilizacion (3 GET) + 4 probes
benignos (1 conexion, probe+sonda cada uno) = ~11 requests,
secuencial, lectura A->B, cuerpos <= 4KB.
"""
import argparse
import json
import re
import socket
import ssl
import time
from urllib.parse import urlparse

MAX_REQS = 16
COOLDOWN = 0.4
MAX_BODY = 4096
STATUS_RECHAZO = {"400", "405", "411", "413", "501", "505"}


def _connect(url, timeout=10.0):
    u = urlparse(url if "//" in url else "http://" + url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    s = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)
    return s, host


def _read_all(sock, quiet=0.8, cap=65535):
    sock.settimeout(quiet)
    out = b""
    try:
        while len(out) < cap:
            d = sock.recv(65535)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    return out


def _n_responses(raw):
    return max(0, sum(1 for p in raw.split(b"HTTP/1.1 ")
                      if b" " in p[:32]))


def _statuses(raw):
    return [x.decode() for x in re.findall(rb"HTTP/1\.1 (\d{3})", raw)]


def _headers_of(raw):
    """Headers de la PRIMERA respuesta del bloque raw."""
    m = re.match(rb"HTTP/1\.1 \d{3}[^\r]*\r\n((?:[\w-]+:[^\r]*\r\n)*)",
                 raw)
    h = {}
    if m:
        for line in m.group(1).split(b"\r\n"):
            if b":" in line:
                k, v = line.split(b":", 1)
                h[k.decode().lower()] = v.strip().decode(
                    "latin-1", errors="replace")
    return h


def _probe_benigno(tipo, host):
    """POST con framing contradictorio y cuerpo VACIO (sin
    smuggle): pregunta pura de contrato. Devuelve (probe, sonda)."""
    body = b"0\r\n\r\n"
    if tipo == "cl_te":
        te = b"Transfer-Encoding: chunked\r\n"
    elif tipo == "te_doble":
        te = b"Transfer-Encoding: chunked\r\n" \
             b"Transfer-Encoding: chunked\r\n"
    elif tipo == "te_espacio":
        te = b"Transfer-Encoding : chunked\r\n"
    elif tipo == "te_case":
        te = b"tRansfer-EnCoDiNg: ChUnKeD\r\n"
    else:
        raise ValueError(tipo)
    cl = len(body)
    probe = (b"POST / HTTP/1.1\r\n"
             b"Host: " + host.encode() + b"\r\n"
             b"Content-Length: " + str(cl).encode() + b"\r\n"
             + te +
             b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
             + body)
    sonda = (f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").encode()
    return probe, sonda


def _clasifica_framing(pre, post, st_pre):
    """rejected | accepted | unknown para un probe benigno."""
    post_vacio = post == 0
    if post_vacio:
        if pre >= 1 and st_pre and st_pre[0] in STATUS_RECHAZO:
            return "rejected"
        if pre == 0:
            return "unknown"
        return "rejected"     # respondio y cerro sin atender sonda
    if pre >= 1 and st_pre and st_pre[0] in STATUS_RECHAZO:
        return "rejected"
    # respondio al probe y a la sonda: acepto el framing
    return "accepted"


def profile(cfg):
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    ficha = {"target": url}
    reqs = 0

    # ---- fase 1: baseline + reutilizacion (1 conexion, 3 GETs)
    s, host = _connect(url, timeout)
    try:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        reqs += 1
        r1 = _read_all(s, quiet=1.0)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        reqs += 1
        r2 = _read_all(s, quiet=0.8)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        reqs += 1
        r3 = _read_all(s, quiet=0.8)
    finally:
        s.close()
    time.sleep(COOLDOWN)
    if not r1.strip():
        ficha["error"] = "NO-RESPONDE"
        ficha["requests"] = reqs
        return ficha

    m = re.match(rb"(HTTP/1\.[01])", r1)
    ficha["version"] = m.group(1).decode() if m else "unknown"
    n_reuse = _n_responses(r1) + _n_responses(r2) + _n_responses(r3)
    ficha["reuse"] = "yes" if n_reuse >= 3 else "no"
    if n_reuse < 3:
        ficha["reuse_nota"] = f"{n_reuse}/3 respuestas en la misma conexion"

    # cache: firma Age/X-Cache entre repeticiones
    h1, h2, h3 = (_headers_of(x) for x in (r1, r2, r3))
    cache_h = [h3.get("age"), h3.get("x-cache"),
                h3.get("cf-cache-status")]
    cache_hit = any(
        x and x.lower() in ("hit", "cached") for x in cache_h)
    if all(x is None for x in cache_h):
        ficha["cache"] = "unknown"
    elif cache_hit:
        ficha["cache"] = "present(hits)"
    else:
        ficha["cache"] = f"present({cache_h[1] or cache_h[2] or 'age'})"

    # ---- fase 2: probes benignos de contrato (1 conexion c/u)
    normalizacion = "unknown"
    downstream = "unknown"
    cierre_rechazo = "unknown"
    for tipo in ["cl_te", "te_doble", "te_espacio", "te_case"]:
        if reqs >= MAX_REQS:
            ficha["presupuesto"] = "agotado"
            break
        s2, _ = _connect(url, timeout)
        try:
            probe, sonda = _probe_benigno(tipo, host)
            s2.sendall(probe)
            pre = _read_all(s2, quiet=0.7)
            s2.sendall(sonda)
            reqs += 2
            post = _read_all(s2, quiet=1.0)
        finally:
            s2.close()
        st_pre = _statuses(pre)
        res = _clasifica_framing(_n_responses(pre),
                                 _n_responses(post), st_pre)
        ficha[tipo] = res
        if res == "rejected":
            conn_hdr = _headers_of(pre).get("connection", "").lower()
            cierre = ("yes" if "close" in conn_hdr
                      or _n_responses(post) == 0 else "no")
            cierre_rechazo = cierre
            # el rechazo puede trae ECO del downstream igualmente
        # ECO del downstream (lab eco / blancos verbosos)
        # ECO del downstream: gana la PRIMERA ocurrencia (la
        # respuesta al probe, no la de la sonda)
        eco_hdrs = {}
        for blk in (pre, post):
            for mm in re.finditer(
                    rb"X-Received-(Te|Cl|Path): *([^\r\n]*)", blk):
                kk = mm.group(1).decode().lower()
                if kk not in eco_hdrs:
                    eco_hdrs[kk] = mm.group(2).decode(
                        "latin-1", "replace").strip()
            if "path" in eco_hdrs:
                break
        if eco_hdrs.get("path"):
            downstream = "reached"
            if "te" in eco_hdrs:
                normalizacion = ("conserved"
                                 if eco_hdrs["te"].lower() != "none"
                                 else "normalized")
        time.sleep(COOLDOWN)

    ficha["cierre_rechazo"] = cierre_rechazo
    ficha["normalizacion"] = normalizacion
    ficha["downstream"] = downstream
    ficha["origin"] = "unknown"
    ficha["requests"] = reqs
    ficha["max_requests"] = MAX_REQS
    return ficha


def _render(ficha):
    out = [f"EDGE-PROFILE: {ficha.get('target', '?')}",
           "-" * 38]
    orden = ["version", "reuse", "cierre_rechazo", "cl_te",
             "te_doble", "te_espacio", "te_case", "normalizacion",
             "downstream", "cache", "origin"]
    for k in orden:
        if k in ficha:
            out.append(f"{k + ':':20} {ficha[k]}")
    if "reuse_nota" in ficha:
        out.append(f"{'nota_reuse:':20} {ficha['reuse_nota']}")
    out.append(f"{'requests:':20} {ficha.get('requests', '?')}"
                f"/{ficha.get('max_requests', '?')}")
    if "error" in ficha:
        out.append(f"ERROR: {ficha['error']}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="EDGE-PROFILE: contrato observable del edge")
    ap.add_argument("url")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    ficha = profile({"url": a.url, "timeout": a.timeout})
    if a.json:
        print(json.dumps(ficha, indent=2, default=str))
    else:
        print(_render(ficha))


if __name__ == "__main__":
    main()
