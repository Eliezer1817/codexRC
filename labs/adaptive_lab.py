"""LAB ADAPTATIVE (v0.81.0): tres mecanismos deterministas que
el loop de ADAPTIVE-HUNT debe caracterizar o declarar no
discriminables.

Modos:
  lb_variance      cuerpo estable por conexion, distinto
                   entre conexiones (backend A/B sticky)
  origin_dynamics  cuerpo distinto en CADA request (contador)
  transient        los primeros 4 requests rotan; luego el
                   cuerpo es constante para siempre

Uso: python3 labs/adaptive_lab.py <puerto> <modo>
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODO = sys.argv[2] if len(sys.argv) > 2 else "lb_variance"
_conns = 0
_reqs = 0


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        global _conns, _reqs
        if not hasattr(self, "_nueva_conn"):
            _conns += 1
            self._nueva_conn = True
        _reqs += 1
        if MODO == "lb_variance":
            if not hasattr(self, "_body"):
                # sticky por conexion: backend A/B
                self._body = ("LB-BACKEND-A" if _conns % 2
                              else "LB-BACKEND-B")
            body = self._body
        elif MODO == "origin_dynamics":
            body = f"ORIGIN-REQ-{_reqs}"
        elif MODO == "transient":
            body = (f"TRANSIENT-{_reqs}" if _reqs <= 3
                    else "TRANSIENT-FINAL")
        else:
            body = "ok"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
