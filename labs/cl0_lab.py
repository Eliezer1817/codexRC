#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab CL.0-SINGLE-TIER v0.87: 5 escenarios deterministicos.

Simula el stack front+origin EN UN PROCESO sobre sockets
crudos, con una COLA de respuestas entre el 'front' y el
'origin'. La cola es la unica diferencia estructural entre
escenarios: en el desync real, el front entrega al cliente
la respuesta QUEUED del smuggle como si fuera la respuesta
de su proximo request legitimo.

Puertos:
  19194 benign_strict  -> BENIGN (el front parsea el
                          prefijo durante T1: pipelining;
                          eco temprano NO es desync)
  19195 edge_safe_rst  -> BENIGN (RST tras el POST:
                          frontera del edge estricta)
  19196 cl0_desync     -> CL0-STATE-EFFECT (backend
                          procesa el smuggle invisible
                          para el front; cola desplazada
                          observable: [r1, smuggle, fa])
  19197 flaky_desync   -> CL0-DETECTED (desync en la
                          primera conexion solo: sin repro)
  19198 quiet_benign   -> BENIGN (el front drena el
                          residual: sin eco, sin RST)

Python puro, sockets crudos, determinista. Uso:
  python3 labs/cl0_lab.py <escenario> [puerto]
"""

import socket
import socketserver
import struct
import sys
import time

SCENARIOS = {
    "benign_strict": 19194,
    "edge_safe_rst": 19195,
    "cl0_desync": 19196,
    "flaky_desync": 19197,
    "quiet_benign": 19198,
}


def _resp(status, body, keep=True):
    return ("HTTP/1.1 %s\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n"
            "Connection: %s\r\n\r\n%s"
            % (status, len(body),
               "keep-alive" if keep else "close",
               body)).encode()


def _token_from_query(query):
    for part in query.split("&"):
        if part.startswith(("cl0fa=", "cl0fb=",
                            "cl0c=", "cl0c1=")):
            return part.split("=", 1)[1]
    return None


def _get_body(path):
    """Respuesta del origin a un GET legitimo: eco del
    token de control/followup (o cuerpo base)."""
    if "?" in path:
        q = path.split("?", 1)[1]
        tok = _token_from_query(q)
        if tok:
            return "ECHO %s" % tok
    return "CL0-BASE OK"


class Handler(socketserver.BaseRequestHandler):
    scenario = "benign_strict"
    conn_count = 0
    smuggle_conns = 0

    def setup(self):
        self.request.settimeout(0.6)
        self.queue = []          # cola backend -> front
        self.buf = b""
        self.glued = False       # residual en el mismo
                                 # paquete que el POST

    # ---------- utilidades de parseo crudo ----------

    def _read_headers(self):
        """Lee del buffer (y socket) hasta \\r\\n\\r\\n."""
        while b"\r\n\r\n" not in self.buf:
            try:
                d = self.request.recv(65535)
            except socket.timeout:
                return None
            if not d:
                return None
            self.buf += d
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest
        self.glued = bool(rest)
        return head.decode("latin-1", "replace")

    def _read_line_reqs(self):
        """Lee un request HTTP/1.1 crudo del stream.
        Devuelve (method, path, headers) o None."""
        head = self._read_headers()
        if head is None:
            return None
        lines = head.split("\r\n")
        try:
            method, path, _proto = lines[0].split(" ", 2)
        except ValueError:
            return None
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return method, path, headers

    def _drain(self):
        """Drena bytes residuales del socket."""
        try:
            while True:
                d = self.request.recv(65535)
                if not d:
                    break
        except (socket.timeout, OSError):
            pass

    def _probe_more(self):
        """Hay bytes residuales esperando en el socket?"""
        try:
            d = self.request.recv(65535)
            if d:
                self.buf += d
                return True
        except (socket.timeout, OSError):
            pass
        return False

    def _parse_smuggle(self):
        """Extrae un request smuggleado del residual."""
        while b"\r\n\r\n" not in self.buf:
            try:
                d = self.request.recv(65535)
            except socket.timeout:
                return None
            if not d:
                return None
            self.buf += d
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        self.buf = rest
        lines = head.decode("latin-1", "replace").split(
            "\r\n")
        if not lines or "HTTP" not in lines[0]:
            return None
        return lines[0]

    def _origin_get(self, path):
        """El origin genera la respuesta a un GET."""
        return _resp("200 OK", _get_body(path))

    def _origin_smuggle(self, reqline):
        """El origin responde al smuggle (200 + eco del
        token del path). Se encola, NO va directo."""
        parts = reqline.split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        tok = path.lstrip("/")
        return _resp("200 OK", "SMUGGLE-ECHO %s" % tok)

    def _flush_one(self):
        if self.queue:
            self.request.sendall(self.queue.pop(0))
            return True
        return False

    def _aligned_pair(self):
        """POST ya respondido: lee hasta 2 followups y
        responde alineado (mundo benigno)."""
        for _ in range(2):
            nxt = self._read_line_reqs()
            if nxt and nxt[0] == "GET":
                self.request.sendall(
                    self._origin_get(nxt[1]))

    # ---------- escenarios ----------

    def handle(self):
        type(self).conn_count += 1
        scen = self.scenario

        req = self._read_line_reqs()
        if req is None:
            return
        method, path, headers = req

        if method == "GET":
            # request de control/followup alineado
            self.request.sendall(self._origin_get(path))
            nxt = self._read_line_reqs()
            if nxt and nxt[0] == "GET":
                self.request.sendall(
                    self._origin_get(nxt[1]))
            return

        # POST: el front responde al POST y decide que
        # hacer con el residual post-CL:0
        self.request.sendall(_resp("200 OK", "OK-POST"))

        # ---- rutas de escenario --------------------------

        if scen == "benign_strict":
            # front estricto: el residual ES el proximo
            # request del cliente -> lo parsea y lo
            # responde DURANTE T1 (pipelining benigno)
            self.request.settimeout(1.5)
            smug = self._parse_smuggle()
            if smug:
                parts = smug.split(" ")
                pth = parts[1] if len(parts) > 1 else "/"
                self.request.sendall(
                    self._origin_get(pth))
            self._aligned_pair()
            return

        if scen == "edge_safe_rst":
            # frontera del edge: RST solo si el residual
            # viene GLUED al POST (smuggle); el pipelined
            # legitimo (paquete separado) sigue su curso
            if self.glued:
                self.request.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0))
                self.request.close()
                return
            self._aligned_pair()
            return

        smug_first = False
        if scen == "flaky_desync":
            # la PRIMERA conexion con smuggle glued se
            # comporta como desync; las siguientes drenan
            if self.glued:
                if Handler.smuggle_conns == 0:
                    Handler.smuggle_conns += 1
                    smug_first = True
                else:
                    self._drain()
                    self.request.settimeout(2.5)
                    self._aligned_pair()
                    return
            else:
                self._aligned_pair()
                return

        if scen == "cl0_desync" or smug_first:
            # front raw-forwarder: cuenta UN request del
            # cliente; el origin procesa el smuggle y su
            # respuesta queda ENCOLADA. Cada request
            # legitimo del cliente entrega una respuesta
            # encolada (cola desplazada off-by-one).
            self.request.settimeout(2.5)
            smug = (self._parse_smuggle()
                    if self.glued else None)
            if smug:
                self.queue.append(
                    self._origin_smuggle(smug))
            for _ in range(2):
                nxt = self._read_line_reqs()
                if nxt is None:
                    break
                if nxt[0] == "GET":
                    # el origin tambien responde al
                    # followup legitimo (se encola)
                    self.queue.append(
                        self._origin_get(nxt[1]))
                # el front entrega UNA respuesta encolada
                # por cada request del cliente
                if not self._flush_one():
                    break
            time.sleep(0.1)
            return

        # quiet_benign: el front drena el residual y la
        # vida sigue alineada
        self._drain()
        self.request.settimeout(2.5)
        self._aligned_pair()
        return

    def finish(self):
        try:
            self.request.close()
        except OSError:
            pass


class Lab(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    scen = sys.argv[1] if len(sys.argv) > 1 else \
        "benign_strict"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else \
        SCENARIOS[scen]
    Handler.scenario = scen
    Handler.conn_count = 0
    srv = Lab(("127.0.0.1", port), Handler)
    print("lab cl0 %s en %d" % (scen, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
