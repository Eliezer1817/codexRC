#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab MULTI-CONNECTION v0.89: 5 escenarios deterministas.

Simula un edge HTTP/1.1 con POOL de conexiones keep-alive a
un origin interno (mismo proceso, sockets crudos, sin
librerias). Mecanica v0.89 (efecto de segundo orden):
  1. la conexion cliente A hace POST CL.0 con prefijo
     smuggleado y CIERRA: la origin conn envenenada vuelve
     al POOL con respuestas pendientes;
  2. la conexion cliente B (TCP DISTINTO) hereda del pool
     la conn envenenada: su primer followup recibe el eco
     del smuggle de A (contaminacion CRUZADA observable) y
     su coleccion queda desplazada.

El edge lee EXACTAMENTE una respuesta del origin por cada
request reenviado (apareamiento por request): las
respuestas pendientes del smuggle quedan en la origin conn,
no se drenan al cliente que cerro.

Aprendizajes v0.87/88: bytes crudos jamas repr(b'..');
buffer de lectura PERSISTENTE por conexion (el smuggle
viaja en el MISMO segmento TCP que el head del POST).

Puertos:
  19301 benign_pin  -> BENIGN (origin conn pinneada 1:1
                       al cliente: la poison muere con A)
  19302 quiet_drain -> BENIGN (el edge drena el residual:
                       la poison nunca llega al origin)
  19303 pool_desync -> MC-STATE-EFFECT (pool FIFO sin
                       drenaje: B hereda la conn de A)
  19304 edge_strict -> BENIGN-EDGE (RST al ver bytes mas
                       alla del content-length)
  19305 flaky_pool  -> MC-DETECTED (el pool reusa UNA
                       sola vez una conn marcada sucia:
                       sin repro 2/2)

Python puro, sockets crudos, determinista. Uso:
  python3 labs/mc_lab.py <escenario> [puerto]
"""

import select
import socket
import socketserver
import struct
import sys
import threading

SCENARIOS = {
    "benign_pin": 19301,
    "quiet_drain": 19302,
    "pool_desync": 19303,
    "edge_strict": 19304,
    "flaky_pool": 19305,
}

RESP = ("HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n\r\n%s")


def _parse_head(buf):
    """(method, path, content_length, head_len) o None si
    el head no esta completo. Headers lowercase."""
    i = buf.find(b"\r\n\r\n")
    if i < 0:
        return None
    head = buf[:i]
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 3:
        return None
    method = parts[0].decode("latin-1", "replace")
    path = parts[1].decode("latin-1", "replace")
    cl = 0
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            if k.strip().lower() == b"content-length":
                try:
                    cl = int(v.strip() or b"0")
                except ValueError:
                    cl = 0
    return method, path, cl, i + 4


def _token_from_query(path):
    """Tokens de control/followup: mca/mcb/mcc/mcd."""
    if "?" not in path:
        return None
    q = path.split("?", 1)[1]
    for part in q.split("&"):
        for k in ("mca=", "mcb=", "mcc=", "mcd="):
            if part.startswith(k):
                return part.split("=", 1)[1]
    return None


# ---------- origin H1 interno --------------------------------------

class OriginHandler(socketserver.BaseRequestHandler):

    def setup(self):
        self.request.settimeout(30.0)
        self.buf = b""

    def _recv(self):
        try:
            d = self.request.recv(65535)
        except (socket.timeout, OSError):
            return False
        if not d:
            return False
        self.buf += d
        return True

    def handle(self):
        while True:
            while _parse_head(self.buf) is None:
                if not self._recv():
                    return
            method, path, cl, hl = _parse_head(self.buf)
            while len(self.buf) < hl + cl:
                if not self._recv():
                    return
            self.buf = self.buf[hl + cl:]
            body = self._route(method, path)
            try:
                self.request.sendall(
                    (RESP % (len(body), body)).encode())
            except OSError:
                return
            # el residual (smuggle) queda en self.buf: la
            # siguiente iteracion lo parsea como request

    def _route(self, method, path):
        if method == "POST":
            return "OK"
        tok = _token_from_query(path)
        if tok:
            return "ECHO %s" % tok
        if path.startswith("/") and len(path) > 1:
            smug = path[1:].split("?")[0].split("/")[0]
            if smug:
                return "SMUGGLE-ECHO %s" % smug
        return "MC-BASE OK"


# ---------- edge con pool ------------------------------------------

class EdgeHandler(socketserver.BaseRequestHandler):
    scenario = "pool_desync"
    origin_port = 0
    pool = []                  # [(sock, dirty, obuf), ...]
    flaky = {"dirty_reused": False}
    lock = threading.Lock()

    def setup(self):
        self.request.settimeout(2.5)
        self.buf = b""
        self.obuf = b""
        self.o = None
        self.dirty = False
        self.unhealthy = False

    # ---- gestion del pool ----

    def _origin_new(self):
        s = socket.create_connection(
            ("127.0.0.1", type(self).origin_port), 2.5)
        s.settimeout(2.5)
        return s, b""          # el obuf vive con la CONN

    def _borrow(self):
        """Devuelve (sock, obuf). El buffer de recepcion
        del origin viaja CON la conexion del pool: bytes
        mas alla de una respuesta NO se pierden al morir
        el handler (leccion v0.88 aplicada al pool)."""
        scen = type(self).scenario
        if scen == "benign_pin":
            return self._origin_new()
        with EdgeHandler.lock:
            pool = type(self).pool
            if scen in ("quiet_drain", "pool_desync"):
                # LIFO realista (nginx keepalive): la conn
                # recien liberada se reusa primero
                if pool:
                    e = pool.pop()
                    return e[0], e[2]
                return self._origin_new()
            if scen == "flaky_pool":
                fl = type(self).flaky
                # 1) dirty-once: la sucia mas reciente,
                #    reusada UNA sola vez en la vida del lab
                for i in range(len(pool) - 1, -1, -1):
                    if pool[i][1]:
                        if not fl["dirty_reused"]:
                            fl["dirty_reused"] = True
                            e = pool.pop(i)
                            return e[0], e[2]
                        break
                # 2) la limpia mas reciente
                for i in range(len(pool) - 1, -1, -1):
                    if not pool[i][1]:
                        e = pool.pop(i)
                        return e[0], e[2]
                return self._origin_new()
        return self._origin_new()

    def _release(self):
        if self.o is None:
            return
        scen = type(self).scenario
        o, obuf, self.o, self.obuf = (
            self.o, self.obuf, None, b"")
        try:
            if (scen in ("benign_pin", "edge_strict")
                    or self.unhealthy):
                o.close()
            else:
                with EdgeHandler.lock:
                    type(self).pool.append(
                        (o, self.dirty, obuf))
        except OSError:
            try:
                o.close()
            except OSError:
                pass

    # ---- lectura del cliente (buffer PERSISTENTE) ----

    def _recv_client(self):
        try:
            d = self.request.recv(65535)
        except (socket.timeout, OSError):
            return False
        if not d:
            return False
        self.buf += d
        return True

    def _read_request(self):
        """Head + body CL del cliente. Devuelve (raw, rest)
        o None. Los bytes mas alla del body viajan en rest
        (el smuggle llega EN EL MISMO segmento TCP)."""
        while _parse_head(self.buf) is None:
            if not self._recv_client():
                return None
        method, path, cl, hl = _parse_head(self.buf)
        while len(self.buf) < hl + cl:
            if not self._recv_client():
                return None
        raw = self.buf[:hl + cl]
        rest = self.buf[hl + cl:]
        self.buf = b""
        return raw, rest

    def _poll_client(self, wait=0.06):
        """Bytes disponibles ya en el socket (residual)."""
        out = b""
        while True:
            r, _, _ = select.select(
                [self.request], [], [], wait)
            if not r:
                return out
            try:
                d = self.request.recv(65535)
            except OSError:
                return out
            if not d:
                return out
            out += d
            wait = 0.02

    # ---- una respuesta del origin (apareamiento) ----

    def _read_one_origin(self):
        """Lee EXACTAMENTE una respuesta H1 del origin."""
        while _parse_head(self.obuf) is None:
            try:
                d = self.o.recv(65535)
            except (socket.timeout, OSError):
                return None
            if not d:
                return None
            self.obuf += d
        _, _, cl, hl = _parse_head(self.obuf)
        while len(self.obuf) < hl + cl:
            try:
                d = self.o.recv(65535)
            except (socket.timeout, OSError):
                return None
            if not d:
                return None
            self.obuf += d
        raw = self.obuf[:hl + cl]
        self.obuf = self.obuf[hl + cl:]
        return raw

    def _rst(self):
        try:
            self.request.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER,
                struct.pack("ii", 1, 0))
        except OSError:
            pass
        try:
            self.request.close()
        except OSError:
            pass

    # ---- loop principal ----

    def handle(self):
        self.o, self.obuf = self._borrow()
        try:
            while True:
                req = self._read_request()
                if req is None:
                    return
                raw, rest = req
                resid = rest + self._poll_client()
                scen = type(self).scenario
                if resid and scen == "edge_strict":
                    self._rst()
                    self.unhealthy = True
                    return
                if resid and scen == "quiet_drain":
                    resid = b""          # drenado y sano
                elif resid:
                    raw += resid        # poison al origin
                    self.dirty = True
                try:
                    self.o.sendall(raw)
                except OSError:
                    self.unhealthy = True
                    return
                resp = self._read_one_origin()
                if resp is None:
                    self.unhealthy = True
                    return
                try:
                    self.request.sendall(resp)
                except OSError:
                    self.unhealthy = True
                    return
        finally:
            self._release()


# ---------- main ---------------------------------------------------

class _TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    scen = (sys.argv[1] if len(sys.argv) > 1
            else "pool_desync")
    port = (int(sys.argv[2]) if len(sys.argv) > 2
            else SCENARIOS.get(scen, 19303))
    EdgeHandler.scenario = scen
    origin = _TS(("127.0.0.1", 0), OriginHandler)
    EdgeHandler.origin_port = origin.server_address[1]
    t = threading.Thread(
        target=origin.serve_forever, daemon=True)
    t.start()
    print("lab mc: escenario=%s origin=%d edge=%d"
          % (scen, EdgeHandler.origin_port, port),
          flush=True)
    edge = _TS(("127.0.0.1", port), EdgeHandler)
    edge.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
