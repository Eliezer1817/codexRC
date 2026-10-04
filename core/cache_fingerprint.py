#!/usr/bin/env python3
"""CACHE-FINGERPRINT (v0.79.0): huella SOLO de senales
observables.

Cada senal es tri-estado:
  OBSERVED  presente en la respuesta
  ABSENT    ausente en la respuesta
  UNKNOWN   no determinable (respuesta ilegible)

REGLA DEL OPERADOR: header ausente NO significa cache miss.
Age: ABSENT no puede convertirse en CACHE-MISS. Age/Date/
timing y orden de headers son senales SECUNDARIAS: nunca
producen diferencial por si solas ("Age diferente" no es
diferencial). El diferencial real compara el nucleo:
status, body_hash, etag, last_modified, content_type,
cache_control, vary.
"""
import hashlib
import re
import socket
import ssl
import time
from urllib.parse import urlparse

MAX_REQS = 24
COOLDOWN = 0.4

# solo senales de cache EXPLICITAS; jamas inferidas
CACHE_STATUS_HEADERS = [
    "x-cache", "x-cache-status", "x-cache-hits",
    "cf-cache-status", "x-varnish", "x-drupal-cache",
    "x-fastly-request-id", "x-proxy-cache"]

CORE = ["status_code", "body_hash", "etag", "last_modified",
        "content_type", "cache_control", "vary"]
SEC = ["age", "date", "cache_status", "server", "served_by",
       "timing_bucket", "set_cookie", "header_order"]


def _parse(url):
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    return host, port, p.scheme == "https"


def fetch(url, path="/", headers=None, timeout=10.0):
    """GET secuencial con Connection: close (el cache no debe
    keyear por conexion). Devuelve (fp, raw, err)."""
    host, port, tls = _parse(url)
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        base = {"Host": host,
                "User-Agent": "cache-correlation/0.79",
                "Accept": "*/*",
                "Connection": "close"}
        merged = dict(base)
        merged.update(headers or {})
        lines = ["GET %s HTTP/1.1" % path]
        for k, v in merged.items():
            lines.append("%s: %s" % (k, v))
        req = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        s.sendall(req)
        s.settimeout(timeout)
        raw = b""
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            raw += b
            if len(raw) > 262144:
                break
        s.close()
    except Exception as e:  # noqa
        return None, b"", str(e)
    return fingerprint(raw, (time.time() - t0) * 1000), raw, None


def fingerprint(raw, elapsed_ms=0.0):
    if not raw:
        return {"valid": False, "signals": {}, "body_len": 0}
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    m = re.match(r"HTTP/[\d.]+\s+(\d{3})", lines[0]) if lines \
        else None
    status = int(m.group(1)) if m else None
    hmap = {}
    horder = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hmap.setdefault(k.strip().lower(), []).append(
                v.strip())
            horder.append(k.strip())

    def sig(name):
        vals = hmap.get(name)
        if vals:
            return {"state": "OBSERVED",
                    "value": ", ".join(vals)}
        return {"state": "ABSENT", "value": None}

    cache_status = None
    for h in CACHE_STATUS_HEADERS:
        if h in hmap:
            cache_status = ", ".join(hmap[h])
            break
    body_hash = hashlib.sha256(body).hexdigest()[:16] if body \
        else ""
    tb = ("t<50" if elapsed_ms < 50 else "t<150"
          if elapsed_ms < 150 else "t<400" if elapsed_ms < 400
          else "t<1000" if elapsed_ms < 1000
          else "t<2500" if elapsed_ms < 2500 else "t>=2500")
    signals = {
        "status_code": {"state": "OBSERVED", "value": status},
        "body_hash": {"state": "OBSERVED" if body else "ABSENT",
                      "value": body_hash},
        "etag": sig("etag"),
        "last_modified": sig("last-modified"),
        "content_type": sig("content-type"),
        "cache_control": sig("cache-control"),
        "vary": sig("vary"),
        # --- secundarias: NUNCA producen diferencial solas
        "age": sig("age"),
        "date": sig("date"),
        "cache_status": {"state": "OBSERVED" if cache_status
                         else "ABSENT", "value": cache_status},
        "server": sig("server"),
        "served_by": sig("x-served-by"),
        "timing_bucket": {"state": "OBSERVED", "value": tb},
        "set_cookie": sig("set-cookie"),
        "header_order": {"state": "OBSERVED",
                         "value": "|".join(horder[:8])},
    }
    return {"valid": True, "signals": signals,
            "body_len": len(body),
            "body_preview": body[:96].decode("latin-1",
                                             "replace")}


def core_differs(fp1, fp2):
    """Diferencial REAL entre dos huellas: nucleo distinto.
    Age/Date/timing/orden NUNCA cuentan. None = sin diferencial.
    Si alguna huella es invalida: None (no se concluye)."""
    if not (fp1 and fp2 and fp1.get("valid")
            and fp2.get("valid")):
        return None
    dif = [k for k in CORE
           if fp1["signals"][k] != fp2["signals"][k]]
    return dif or None


def converged(fp_a, fp_b):
    """B recibio (aparentemente) la respuesta de A: nucleos
    identicos incluyendo body_hash. Devuelve dict con estado."""
    if not (fp_a and fp_b and fp_a.get("valid")
            and fp_b.get("valid")):
        return {"match": False, "state": "UNKNOWN"}
    same = core_differs(fp_a, fp_b) is None
    status = fp_a["signals"]["status_code"]["value"]
    if same:
        if status is not None and status >= 400:
            return {"match": True, "state": "APARENTE",
                    "nota": ("paginas de error identicas: "
                             "convergencia sin atribucion")}
        return {"match": True, "state": "ATRIBUIDA"}
    return {"match": False, "state": "OBSERVED"}


def _selftest():
    raw = (b"HTTP/1.1 200 OK\r\nETag: \"a1\"\r\n"
           b"Content-Type: text/html\r\n\r\nHOLA")
    fp = fingerprint(raw, 30)
    assert fp["signals"]["etag"]["value"] == '"a1"'
    assert fp["signals"]["age"]["state"] == "ABSENT"
    fp2 = fingerprint(raw.replace(b"HOLA", b"CHAU"), 30)
    assert core_differs(fp, fp2) == ["body_hash"]
    assert core_differs(fp, fp) is None
    print("cache_fingerprint selftest OK")


if __name__ == "__main__":
    _selftest()
