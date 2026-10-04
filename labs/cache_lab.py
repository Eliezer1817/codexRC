#!/usr/bin/env python3
"""CACHE-LAB (v0.79.0): 6 escenarios deterministas.

Los labs demuestran que el sistema sabe diferenciar:
  consistent             estabilidad
  divergent_equivalent   diferencial real en par EQUIVALENT
  convergent_distinct    estado compartido indebido
                        (request inocente recibe respuesta ajena)
  personalized           personalizacion legitima (Vary: Cookie)
  bot_ambiguous          baseline ambiguo (rotacion sin explicar)
  ttl_variant            variacion temporal caracterizable

Uso: python3 labs/cache_lab.py PORT MODO
POST /__reset limpia el almacen (solo soporte de tests).
"""
import socket
import sys
import threading
import time

BODY_CAP = 65536
STORE = {}
STATE = {"count": 0}


def _respond(conn, status, headers, body):
    reason = {200: "OK", 404: "Not Found"}.get(status, "OK")
    hs = ["HTTP/1.1 %d %s" % (status, reason),
          "Content-Type: text/plain",
          "Content-Length: %d" % len(body),
          "Connection: close"]
    hs.extend(headers)
    raw = ("\r\n".join(hs) + "\r\n\r\n").encode("latin-1") \
        + body
    conn.sendall(raw)


def _handle(conn, modo):
    conn.settimeout(6.0)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < BODY_CAP:
        try:
            b = conn.recv(4096)
        except socket.timeout:
            break
        if not b:
            break
        data += b
    if not data:
        conn.close()
        return
    try:
        head = data.split(b"\r\n\r\n")[0].decode("latin-1")
        lines = head.split("\r\n")
        parts = lines[0].split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        hdrs = []
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs.append((k.strip(), v.strip()))
    except Exception:
        conn.close()
        return
    STATE["count"] += 1
    n = STATE["count"]

    if path == "/__reset":
        STORE.clear()
        STATE["count"] = 0
        _respond(conn, 200, [], b"reset-ok")
        conn.close()
        return

    hmap = {k.lower(): v for k, v in hdrs}

    if modo == "consistent":
        _respond(conn, 200,
                 ["ETag: \"fixed-1\"",
                  "Cache-Control: public, max-age=300",
                  "Age: 0"],
                 ("resource=%s stable" % path).encode())

    elif modo == "ttl_variant":
        # nucleo estable; Age avanza por request (temporal)
        _respond(conn, 200,
                 ["ETag: \"ttl-fixed\"",
                  "Cache-Control: public, max-age=60",
                  "Last-Modified: Sun, 04 Oct 2026 00:00:00 GMT",
                  "Age: %d" % n],
                 ("resource=%s ttl" % path).encode())

    elif modo == "personalized":
        if "cookie" in hmap:
            _respond(conn, 200, ["Vary: Cookie",
                                "Set-Cookie: sid=lab",
                                "Cache-Control: private"],
                     ("personalized %s" % n).encode())
        else:
            _respond(conn, 200, ["Vary: Cookie",
                                "Cache-Control: private"],
                     ("anon %s" % path).encode())

    elif modo == "bot_ambiguous":
        body = ("variant-alpha n=%d" % n).encode() if n % 2 \
            else ("variant-beta n=%d" % n).encode()
        _respond(conn, 200, [], body)

    elif modo == "divergent_equivalent":
        # origin/cache defectuoso: distingue por CASE del nombre
        # de header (viola RFC 7230 3.2)
        case_upper = any(k == "X-Cache-Probe" for k, _ in hdrs)
        if case_upper:
            _respond(conn, 200, ["ETag: W/\"up\"",
                                "Cache-Control: public",
                                "X-Cache: hit-up"],
                     b"representation=upper")
        else:
            _respond(conn, 200, ["ETag: W/\"lo\"",
                                "Cache-Control: public",
                                "X-Cache: hit-lo"],
                     b"representation=lower")

    elif modo == "convergent_distinct":
        # cache defectuosa: keyea solo por el primer segmento ->
        # /x-shared/a y /x-shared/b COMPARTEN entrada
        key = "/" + (path.strip("/").split("/") + [""])[0]
        if key in STORE:
            stored = STORE[key]
            _respond(conn, 200,
                     ["ETag: \"%s\"" % stored[1],
                      "Cache-Control: public, max-age=300",
                      "Age: 1", "X-Cache: hit"],
                     ("resource=%s marker=TOKEN123"
                      % stored[0]).encode())
        else:
            STORE[key] = (path, "conv-%d" % n)
            _respond(conn, 200,
                     ["ETag: \"conv-%d\"" % n,
                      "Cache-Control: public, max-age=300",
                      "Age: 0", "X-Cache: miss"],
                     ("resource=%s marker=TOKEN123"
                      % path).encode())
    else:
        _respond(conn, 404, [], b"modo desconocido")
    conn.close()


def serve(port, modo):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print("cache lab: port=%d modo=%s" % (port, modo),
          flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle,
                         args=(conn, modo),
                         daemon=True).start()


if __name__ == "__main__":
    serve(int(sys.argv[1]), sys.argv[2])
