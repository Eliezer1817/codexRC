#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab WCD-CACHE-KEY v0.86: 5 escenarios deterministicos.

Puertos:
  19184 benign        -> BENIGN (disfraz sin leak: 403)
  19185 leak_nocache  -> LEAK-NO-CACHE (router confusion
                         sin almacenamiento)
  19186 cache_vary    -> WCD-CACHE (HIT con Vary: Cookie:
                         controles FAILED, sin DEMO)
  19187 contamination -> WCD-DEMO (anon recibe el cuerpo
                         autenticado desde cache)
  19188 open_endpoint -> OPEN-ENDPOINT (anon ya ve el dato
                         sin disfraz: NO es WCD)

Python puro, ThreadingHTTPServer, determinista. Uso:
  python3 labs/wcd_lab.py <escenario> [puerto]

Simula edge+origin en un proceso: el 'cache' es el edge
(clave = path normalizado), el 'router' es el origin que
confunde delimitadores/sufijos con el endpoint base.
"""

import sys
from http.server import (BaseHTTPRequestHandler,
                          ThreadingHTTPServer)

SCENARIOS = {
    "benign": 19184,
    "leak_nocache": 19185,
    "cache_vary": 19186,
    "contamination": 19187,
    "open_endpoint": 19188,
}
BASE_PATH = "/account"
MARKER = b"WCD-ACCOUNT-DATA"
FORBIDDEN = b"WCD-FORBIDDEN"


def _normalize(path):
    """Router confuso del origin: recorta en delimitadores
    ambiguos y sufijos estaticos (simula Next.js/Spring/
    Rails sobre /account;.css, /account/..;/x.css, etc)."""
    p = path.split("?")[0]
    for tok in ("/..;", ";", "%3F", "%23"):
        idx = p.find(tok)
        if idx != -1:
            p = p[:idx]
    while p.endswith(".css") or p.endswith(".js"):
        p = p[:-4]
    while p.endswith("/"):
        p = p[:-1]
    return p


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    scenario = "benign"
    cache = {}

    def log_message(self, *a):
        pass

    def _session(self):
        return "session=1" in (
            self.headers.get("Cookie") or "")

    def _serve(self, body, cache_state=None,
               vary_cookie=False):
        self.send_response(200 if body != FORBIDDEN
                           else 403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length",
                        str(len(body)))
        if cache_state is not None:
            self.send_header("X-Cache", cache_state)
            if cache_state == "HIT":
                self.send_header("Age", "10")
        if vary_cookie:
            self.send_header("Vary", "Cookie")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        s = self.scenario
        sess = self._session()
        norm = _normalize(p)
        disguised = (p != BASE_PATH)

        # baseline: path base
        if p == BASE_PATH:
            if s == "open_endpoint":
                self._serve(MARKER)
            elif sess:
                self._serve(MARKER)
            else:
                self._serve(FORBIDDEN)
            return

        # ---- escenario open_endpoint: path base anonimo
        # ya expone el dato; el modulo debe frenar antes.

        if s == "benign":
            # origin estricto: el disfraz NO resuelve a la
            # sesion (403 siempre que no sea el path base)
            self._serve(FORBIDDEN)
            return

        if s == "leak_nocache":
            # router confusion: sirve el dato autenticado
            # para el path disfrazado, pero el edge NO
            # almacena (sin cabeceras de cache)
            if norm == BASE_PATH and sess:
                self._serve(MARKER)
            else:
                self._serve(FORBIDDEN)
            return

        if s == "cache_vary":
            # edge que almacena pero respeta Cookie en Vary
            key = norm
            if norm == BASE_PATH and sess:
                entry = Handler.cache.get(key)
                if entry is not None:
                    self._serve(MARKER, "HIT",
                                vary_cookie=True)
                else:
                    Handler.cache[key] = MARKER
                    self._serve(MARKER, "MISS",
                                vary_cookie=True)
            else:
                # anonimo: MISS, el origin exige sesion
                self._serve(FORBIDDEN, "MISS")
            return

        if s == "contamination":
            # edge que almacena IGNORANDO la cookie: la
            # clave es el path normalizado; anon recibe HIT
            key = norm
            if norm == BASE_PATH:
                entry = Handler.cache.get(key)
                if entry is not None:
                    self._serve(MARKER, "HIT")
                elif sess:
                    Handler.cache[key] = MARKER
                    self._serve(MARKER, "MISS")
                else:
                    self._serve(FORBIDDEN, "MISS")
            else:
                self._serve(FORBIDDEN, "MISS")
            return

        self._serve(FORBIDDEN)


def main():
    scen = sys.argv[1] if len(sys.argv) > 1 else "benign"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else \
        SCENARIOS[scen]
    Handler.scenario = scen
    Handler.cache = {}
    srv = ThreadingHTTPServer(("127.0.0.1", port),
                              Handler)
    print("lab wcd %s en %d" % (scen, port),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
