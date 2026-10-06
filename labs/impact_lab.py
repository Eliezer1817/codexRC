#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab IMPACT CORRELATION v0.92: 5 escenarios deterministas.

Responde la pregunta de IMPACT del roadmap: el desync
reproducido hace dano a un usuario DISTINTO del atacante
(contaminacion de respuesta cross-user)?

Mecanica v0.92 (herencia del pool v0.89 + recurso
protegido simulado):
  1. la conexion A (atacante) hace POST CL.0 con un
     request smuggleado y CIERRA tras leer su propia
     respuesta: el smuggle ya viajo al origin y su
     respuesta queda PENDIENTE en la conn del pool;
  2. la conexion V (victima, TCP DISTINTO) hereda del
     pool LIFO la conn envenenada: su primer request
     recibe la respuesta del smuggle del atacante
     (contaminacion CRUZADA de respuesta).

Recurso protegido simulado (solo lab):
  /admin/secret -> SECRET-IMPACT-<hex>   (dato que la
  victima jamas podria obtener con su propio request).

Puertos:
  19601 quiet_drain -> BENIGN (el edge drena el
                       residual: el smuggle nunca llega
                       al origin; la victima recibe su
                       propio eco)
  19602 benign_pin  -> BENIGN (conn origin pinneada 1:1
                       al cliente: el veneno muere con A)
  19603 pool_swap   -> SECURITY-IMPACT-DEMO (la victima
                       recibe SECRET-IMPACT del smuggle
                       del atacante, 2/2 rondas)
  19604 pool_shift  -> IMPACT-CANDIDATE (la victima
                       recibe el eco del TOKEN DEL
                       ATACANTE: mispairing cruzado pero
                       contenido benigno: NO reportable)
  19605 flaky_swap  -> IMPACT-CANDIDATE (swap UNA sola
                       vez en la vida del lab: 1/2, el
                       impacto no se reproduce)

Python puro, sockets crudos, determinista. Uso:
  python3 labs/impact_lab.py <escenario> [puerto]
"""

import select
import secrets
import socket
import socketserver
import struct
import sys
import threading

SCENARIOS = {
    "quiet_drain": 19601,
    "benign_pin": 19602,
    "pool_swap": 19603,
    "pool_shift": 19604,
    "flaky_swap": 19605,
}

RESP = ("HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n\r\n%s")


def _parse_head(buf):
    """(method, path, content_length, head_len) o None."""
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
    """Tokens de control/victima: itok/ictl."""
    if "?" not in path:
        return None
    q = path.split("?", 1)[1]
    for part in q.split("&"):
        for k in ("ictl=", "itok="):
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
            # siguiente iteracion lo procesa como request

    def _route(self, method, path):
        # recurso PROTEGIDO simulado (solo lab): dato
        # que la victima no puede obtener por si misma
        if path.split("?")[0] == "/admin/secret":
            return "SECRET-IMPACT-%s" % secrets.token_hex(6)
        if method == "POST":
            return "OK"
        tok = _token_from_query(path)
        if tok:
            return "ECHO %s" % tok
        if path.startswith("/") and len(path) > 1:
            smug = path[1:].split("?")[0].split("/")[0]
            if smug:
                return "SMUGGLE-ECHO %s" % smug
        return "IMPACT-BASE OK"


# ---------- edge con pool LIFO --------------------------------------

class EdgeHandler(socketserver.BaseRequestHandler):
    scenario = "pool_swap"
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
        self.borrowed_dirty = False
        self.unhealthy = False

    # ---- gestion del pool ----

    def _origin_new(self):
        s = socket.create_connection(
            ("127.0.0.1", type(self).origin_port), 2.5)
        s.settimeout(2.5)
        return s, b""

    def _borrow(self):
        """(sock, obuf): el buffer de recepcion del
        origin viaja CON la conexion del pool (leccion
        v0.88/v0.89: bytes mas alla de una respuesta NO
        se pierden al morir el handler)."""
        scen = type(self).scenario
        self.borrowed_dirty = False
        if scen == "benign_pin":
            return self._origin_new()
        with EdgeHandler.lock:
            pool = type(self).pool
            if scen in ("quiet_drain", "pool_swap",
                        "pool_shift"):
                # LIFO realista (nginx keepalive)
                if pool:
                    e = pool.pop()
                    self.borrowed_dirty = e[1]
                    return e[0], e[2]
                return self._origin_new()
            if scen == "flaky_swap":
                fl = type(self).flaky
                # la sucia mas reciente, reusada UNA sola
                # vez en la vida del lab
                for i in range(len(pool) - 1, -1, -1):
                    if pool[i][1]:
                        if not fl["dirty_reused"]:
                            fl["dirty_reused"] = True
                            e = pool.pop(i)
                            self.borrowed_dirty = True
                            return e[0], e[2]
                        break
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
                    or self.unhealthy
                    or (scen in ("pool_swap",
                                 "pool_shift")
                        and self.borrowed_dirty)):
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
        """(raw, rest) o None. Los bytes mas alla del
        body viajan en rest: el smuggle llega EN EL
        MISMO segmento TCP que el head del POST."""
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
        scen = type(self).scenario
        try:
            self.o, self.obuf = self._borrow()
        except OSError:
            return
        try:
            while True:
                req = self._read_request()
                if req is None:
                    return
                raw, rest = req
                resid = rest + self._poll_client()
                if resid:
                    if scen == "quiet_drain":
                        resid = b""      # drena: sin smuggle
                    else:
                        self.dirty = True
                raw += resid
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
                    return
        finally:
            self._release()


# ---------- main ---------------------------------------------------

class _TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    scen = (sys.argv[1] if len(sys.argv) > 1
            else "pool_swap")
    port = (int(sys.argv[2]) if len(sys.argv) > 2
            else SCENARIOS.get(scen, 19603))
    EdgeHandler.scenario = scen
    origin = _TS(("127.0.0.1", 0), OriginHandler)
    EdgeHandler.origin_port = origin.server_address[1]
    t = threading.Thread(
        target=origin.serve_forever, daemon=True)
    t.start()
    print("lab impact: escenario=%s origin=%d edge=%d"
          % (scen, EdgeHandler.origin_port, port),
          flush=True)
    edge = _TS(("127.0.0.1", port), EdgeHandler)
    edge.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
