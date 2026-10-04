#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab CROSS-LAYER v0.84: 4 escenarios deterministicos.

Puertos:
  19180 absorbed        -> BENIGN (perturbacion normalizada)
  19181 edge_local      -> BENIGN + EDGE-ONLY (tolerancia)
  19182 shared_state    -> SHARED-STATE (sin contaminacion)
  19183 contamination   -> DEMO (control recibe el efecto)

Python puro, un hilo, determinista. Uso:
  python3 labs/cross_layer_lab.py <escenario> [puerto]
"""

import sys
from http.server import (BaseHTTPRequestHandler,
                           HTTPServer, ThreadingHTTPServer)

SCENARIOS = {
    "absorbed": 19180, "edge_local": 19181,
    "shared_state": 19182, "contamination": 19183,
}
BASE = b"CL-BASE-CONTROL-BODY"
SECRET_CASE = b"CL-SECRET-CASE-VARIANT"
SECRET_SLASH = b"CL-SECRET-SLASH-VARIANT"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    scenario = "absorbed"
    state = {"last": "base"}

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path.split("?")[0]
        s = self.scenario
        st = Handler.state

        if s == "absorbed":
            body = BASE
        elif s == "edge_local":
            body = BASE
        elif s == "shared_state":
            if p == "/PaTh-CL":
                body = SECRET_CASE
            elif p == "/path-cl/":
                body = SECRET_SLASH
            else:
                body = BASE
        elif s == "contamination":
            # estado global compartido entre conexiones:
            # la perturbacion envenena al control siguiente
            if p == "/PaTh-CL":
                st["last"] = "case"
                body = SECRET_CASE
            elif p == "/path-cl/":
                st["last"] = "slash"
                body = SECRET_SLASH
            else:
                if st["last"] == "case":
                    body = SECRET_CASE   # contaminacion
                elif st["last"] == "slash":
                    body = SECRET_SLASH   # contaminacion
                else:
                    body = BASE
                st["last"] = "base"       # reset tras servir
        else:
            body = BASE

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length",
                         str(len(body)))
        if s == "edge_local" and p != "/path-cl":
            # tolerancia del edge: cierra la conexion en
            # perturbaciones pero el origin sirve igual
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def main():
    scen = sys.argv[1] if len(sys.argv) > 1 else "absorbed"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else \
        SCENARIOS[scen]
    Handler.scenario = scen
    Handler.state = {"last": "base"}
    # ThreadingHTTPServer: un edge real acepta conexiones concurrentes
    # (con keep-alive de clientes previos, el single-thread se bloqueaba)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("lab %s en %d" % (scen, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
