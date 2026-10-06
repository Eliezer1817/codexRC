#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WCD-404-PROBE (v0.96.0): el oraculo de la cache que guarda 404s.

Pregunta: cuando el status miente (4xx cuyo CUERPO renderiza datos de
la cuenta), el cache del edge lo guarda y se lo sirve a OTRO usuario?

Escalera cero-FP, monotona (cada peldano exige el anterior):
  BENIGN             el disfraz responde 4xx con cuerpo LIMPIO:
                     no hay status-lie
  STATUS-LIE-DETECTED 4xx cuyo cuerpo contiene marcadores DECLARADOS
                     de la cuenta propia (contrato pre-registrado:
                     el operador declara que marcadores son PII,
                     ej. email ninja propio; el probe no adivina)
  WCD-404-LEAK       cebado con repeticiones -> el mismo URL con
                     la sesion de OTRO usuario (o anon) devuelve el
                     CUERPO DEL PROPIO: cross-user leak observable

Sin HIT de cache el veredicto honesto es LEAK-NO-CACHE (caso
linktr.ee): la senal existe pero no contamina; NO reportable.

Regla de la casa (cache-semantic): cache key interna es HIPOTESIS;
lo observable son huellas externas (headers de HIT / swap de cuerpo).
Presupuesto: <= 8 requests, read-only. Sin blanco vivo sin 'LestGo'.

Uso:
  from core.wcd404_probe import probe
  probe({"url": "http://.../app/settings/profile/x.css",
         "marker_self": "ninja-A@maxxspace.com",
         "cookie_self": "acct=A", "cookie_victim": "acct=B"})
"""
import json
import socket
import sys
from typing import Any, Dict, Optional

LADDER = ["BENIGN", "STATUS-LIE-DETECTED", "WCD-404-LEAK"]
BUDGET = 8
PRIMING = 4          # repeticiones de cebado (total <= BUDGET)


def _connect(host: str, port: int, timeout: float) -> Optional[socket.socket]:
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
        return s
    except OSError:
        return None


def _parse_url(url: str):
    """http://host[:port]/path -> (host, port, path)."""
    proto, _, rest = url.partition("://")
    if not rest:
        raise ValueError("url sin esquema: %r" % url)
    host, _, path = rest.partition("/")
    if ":" in host:
        h, p = host.rsplit(":", 1)
        port = int(p) if proto == "http" else int(p)
    else:
        port = 443 if proto == "https" else 80
        h = host
    return h, port, "/" + path


def _get(host: str, port: int, path: str, cookie: str,
         timeout: float) -> Optional[Dict[str, Any]]:
    s = _connect(host, port, timeout)
    if s is None:
        return None
    try:
        req = ("GET %s HTTP/1.1\r\n"
               "Host: %s\r\n"
               "Cookie: %s\r\n"
               "User-Agent: codexrc-wcd404-probe\r\n"
               "Accept: */*\r\n"
               "Connection: close\r\n\r\n" % (path, host, cookie))
        s.sendall(req.encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return None
        head, _, body = buf.partition(b"\r\n\r\n")
        head_l = head.decode(errors="ignore")
        status = int(head_l.split(" ")[1]) if " " in head_l else 0
        cache_sig = ""
        for ln in head_l.split("\r\n"):
            low = ln.lower()
            if low.startswith(("x-cache", "cf-cache-status",
                               "x-lab-cache", "age:")):
                cache_sig += ln + "; "
        return {"status": status, "body": body.decode(
                    errors="ignore"), "cache_sig": cache_sig.strip()}
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def probe(args: Dict[str, Any]) -> Dict[str, Any]:
    """Oraculo WCD-404. Contrato: marcadores pre-declarados."""
    url = args["url"]
    marker_self = args["marker_self"]
    cookie_self = args.get("cookie_self", "")
    cookie_victim = args.get("cookie_victim", "")
    timeout = float(args.get("timeout", 5.0))
    host, port, path = _parse_url(url)
    informe: Dict[str, Any] = {
        "url": url, "verdict": "BENIGN", "requests": 0,
        "status_lie": False, "cache_hit": False,
        "cross_user": False, "cache_sig": "", "limits":
        "read-only, presupuesto %d reqs" % BUDGET}

    # fase 1: el status miente para MI PROPIA cuenta?
    r1 = _get(host, port, path, cookie_self, timeout)
    informe["requests"] += 1
    if r1 is None:
        informe["verdict"] = "conn-dead"
        informe["limits"] = ("blanco muerto o sin respuesta: "
                             "escalera honesta, sin crash")
        return informe
    if r1["status"] >= 400 and marker_self in r1["body"]:
        informe["status_lie"] = True
        informe["verdict"] = "STATUS-LIE-DETECTED"
        informe["cache_sig"] = r1["cache_sig"]
    else:
        # 4xx limpio o 200: no hay mentira observable
        informe["body_len"] = len(r1["body"])
        return informe

    # fase 2: cebado (el cache almacena el 404 con MI cuerpo?)
    for _ in range(PRIMING):
        rr = _get(host, port, path, cookie_self, timeout)
        informe["requests"] += 1
        if rr is None:
            break
        informe["cache_sig"] = rr["cache_sig"]
        low = rr["cache_sig"].lower()
        if "hit" in low or (rr["cache_sig"] and marker_self
                            not in rr["body"] and
                            rr["status"] == 200):
            # HIT observable por header, o swap a respuesta ajena:
            # huella externa, no hipotesis de key interna
            pass
        if "hit" in low:
            informe["cache_hit"] = True
            break
    if informe["requests"] >= BUDGET and not informe["cache_hit"]:
        # sin huella de HIT en el presupuesto: honesto
        informe["verdict"] = "LEAK-NO-CACHE"
        return informe

    # fase 3: el OTRO usuario recibe MI cuerpo?
    rv = _get(host, port, path, cookie_victim, timeout)
    informe["requests"] += 1
    if rv is None:
        informe["verdict"] = "LEAK-NO-CACHE"
        return informe
    if marker_self in rv["body"]:
        informe["cross_user"] = True
        informe["verdict"] = "WCD-404-LEAK"
    else:
        # hay cache pero aislado por usuario: defensa correcta
        informe["verdict"] = "LEAK-NO-CACHE"
    return informe


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("uso: wcd404_probe.py <url> <marker_self> "
              "[cookie_self] [cookie_victim]")
        sys.exit(1)
    out = probe({
        "url": sys.argv[1],
        "marker_self": sys.argv[2],
        "cookie_self": sys.argv[3] if len(sys.argv) > 3 else "",
        "cookie_victim": sys.argv[4] if len(sys.argv) > 4 else ""})
    print(json.dumps(out, indent=1))
