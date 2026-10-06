#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab WCD-404-LEAK v0.96: la cache que guarda cadaveres con datos.

Fuente: reporte real 2025 (System Weakness, duplicado = la clase se
paga): endpoint autenticado + disfraz de extension -> el origin
responde 404 PERO el cuerpo sigue renderizando datos de la cuenta; el
cache guarda el 404 como clave por URL; otro usuario recibe el cuerpo
del primero. "El status code miente": lo observable es el CUERPO.

Mecanica del lab (Python puro, sockets crudos, determinista):
  Edge+cache en un solo ThreadingTCPServer por escenario, origin
  simulado inline. Cache key = URL (ignora cookies: EL DEFECTO).
  El origin:
    /app/settings/profile            -> 200 + datos de la cuenta
                                        (por Cookie: acct=A|B)
    /app/settings/profile/<disfraz>  -> 404 + IGUAL los datos de la
                                        cuenta (status-lie) con los
                                        cache-headers del escenario

Escenarios:
  19501 lie_cached   -> 404-lie con Cache-Control: public: el edge
                        cachea y el usuario B recibe el cuerpo de A
                        -> WCD-404-LEAK
  19502 lie_nocache  -> 404-lie con no-store/private: el edge NO
                        cachea -> LEAK-NO-CACHE honesto (caso
                        linktr.ee)
  19503 honest_404   -> disfraz responde 404 LIMPIO sin datos: sin
                        status-lie -> BENIGN
  19504 lie_expired  -> 404-lie public PERO el edge expira el entry
                        al instante (ttl=0): nunca hay HIT -> el
                        cebado no contamina -> LEAK-NO-CACHE honesto

Uso:
  python3 labs/wcd404_lab.py <escenario> [puerto]
"""

import socket
import socketserver
import sys
import threading

SCENARIOS = {
    "lie_cached": 19501,
    "lie_nocache": 19502,
    "honest_404": 19503,
    "lie_expired": 19504,
}

PROFILE_BODY = ("HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Cache-Control: private, no-store\r\n"
                "Content-Length: %d\r\n\r\n%s")

DATA = {
    "A": ("<!DOCTYPE html><body>email=ninja-A@maxxspace.com "
          "name=Ninja-A token=TOKEN-A</body>"),
    "B": ("<!DOCTYPE html><body>email=ninja-B@maxxspace.com "
          "name=Ninja-B token=TOKEN-B</body>"),
}

BODY_404 = {
    "A": ("<!DOCTYPE html><html><head><title>Not Found</title></head>"
          "<body class=\"error404\">email=ninja-A@maxxspace.com "
          "name=Ninja-A token=TOKEN-A</body></html>"),
    "B": ("<!DOCTYPE html><html><head><title>Not Found</title></head>"
          "<body class=\"error404\">email=ninja-B@maxxspace.com "
          "name=Ninja-B token=TOKEN-B</body></html>"),
    "clean": ("<!DOCTYPE html><html><head><title>Not Found</title>"
              "</head><body>Nothing found here.</body></html>"),
}


def _acct(headers: bytes) -> str:
    for ln in headers.split(b"\r\n"):
        if ln.lower().startswith(b"cookie:"):
            if b"acct=A" in ln:
                return "A"
            if b"acct=B" in ln:
                return "B"
    return "anon"


def _resp(status: str, body: str, cache_hdr: str,
          lab_cache: str) -> bytes:
    head = ("HTTP/1.1 %s\r\n"
            "Content-Type: text/html\r\n"
            "%s\r\n"
            "X-Lab-Cache: %s\r\n"
            "Content-Length: %d\r\n\r\n" % (
                status, cache_hdr, lab_cache, len(body)))
    return (head + body).encode()


def _origin(path: str, acct: str, scen: str):
    """Origin del lab: status-lie en el disfraz."""
    if path == "/app/settings/profile":
        body = DATA.get(acct, "login-please")
        return _resp("200 OK", body,
                     "private, no-store", "ORIGIN")
    # disfraz: termina en extension falsa
    if path.startswith("/app/settings/profile/"):
        acct = acct if acct in ("A", "B") else "A"
        if scen == "honest_404":
            body, cache = BODY_404["clean"], "no-store"
        elif scen == "lie_nocache":
            body, cache = BODY_404[acct], "private, no-store"
        else:                     # lie_cached / lie_expired
            body, cache = BODY_404[acct], "public, max-age=300"
        return _resp("404 Not Found", body, cache, "ORIGIN")
    return _resp("404 Not Found", BODY_404["clean"],
                 "no-store", "ORIGIN")


class EdgeCacheHandler(socketserver.BaseRequestHandler):
    def handle(self):
        scen = self.server.scenario
        cache = self.server.cache     # {url: (body_bytes, status)}
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _rest = data.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            try:
                method, path, _proto = lines[0].decode().split(" ")
            except ValueError:
                return
            acct = _acct(head)
            if path in cache:
                body, status = cache[path]
                if scen == "lie_expired":
                    cache.pop(path, None)   # ttl=0: muere al leer
                    resp = _origin(path, acct, scen)
                else:
                    resp = _resp(status, body.decode(),
                                 "public, max-age=300", "HIT")
            else:
                resp = _origin(path, acct, scen)
                # el edge cachea 4xx publicos por URL (ignora cookie:
                # EL DEFECTO). no-store/private nunca entra.
                if (scen in ("lie_cached", "lie_expired")
                        and b"404" in resp.split(b"\r\n")[0]
                        and b"public" in resp):
                    body = resp.split(b"\r\n\r\n", 1)[1]
                    cache[path] = (body, "404 Not Found")
            self.request.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                self.request.close()
            except Exception:
                pass


class _TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    scen = sys.argv[1] if len(sys.argv) > 1 else "lie_cached"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else SCENARIOS[scen]
    srv = _TS(("127.0.0.1", port), EdgeCacheHandler)
    srv.scenario = scen
    srv.cache = {}
    threading.Thread(target=srv.serve_forever,
                     daemon=True).start()
    print("UP", flush=True)
    import time
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
