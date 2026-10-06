#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab CROSS-REQUEST CORRELATION v0.90: 5 escenarios.

Simula un edge HTTP/1.1 (apareamiento UNA respuesta por
request reenviado) sobre un origin H1 interno (mismo
proceso, sockets crudos, sin librerias). Mecanica v0.90
(correlacion entre requests): un POST CL.0 lleva DOS
requests smuggleadas (T1, T2). El origin procesa el
residual como cola: [POST, T1, T2] y las respuestas de
los followups del cliente quedan DESPLAZADAS por k
medible y CONSISTENTE (correlacion):

  slots observados por el followup (fb, fc, fd):
    k=2  [SMUGGLE-T1, SMUGGLE-T2, ECHO-fb]
    k=1  [SMUGGLE-T1, ECHO-fb,      ECHO-fc]
    k=0  [ECHO-fb,      ECHO-fc,    ECHO-fd]  (alineado)

La firma del desync es la PERMUTACION consistente: el
eco propio aparece desplazado EXACTAMENTE por el numero
de ecos del smuggle observados (correlacion cruzada
entre requests). Un patron disperso NO escala.

Puertos:
  19401 quiet_drain   -> BENIGN (el edge drena TODO el
                         residual: sin smuggle)
  19402 edge_strict   -> BENIGN-EDGE (RST al ver bytes
                         mas alla del content-length)
  19403 seq_desync    -> CRC-STATE-EFFECT k=2 (reenvia
                         el residual completo: ambas
                         smuggles procesan)
  19404 partial_drain -> CRC-STATE-EFFECT k=1 (drena
                         desde el segundo limite de
                         request: T2 muere, T1 vive)
  19405 flaky_forward -> CRC-DETECTED (reenvia el
                         residual SOLO LA PRIMERA vez;
                         despues se cura: sin repro 2/2)

Python puro, sockets crudos, determinista. Uso:
  python3 labs/crc_lab.py <escenario> [puerto]
"""

import select
import socket
import socketserver
import struct
import sys
import threading

SCENARIOS = {
    "quiet_drain": 19401,
    "edge_strict": 19402,
    "seq_desync": 19403,
    "partial_drain": 19404,
    "flaky_forward": 19405,
}

RESP = ("HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n\r\n%s")

_edge_state = {"resid_forwarded": False}


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
    """Tokens de control/followup: crca/crcb/crcc/crcd."""
    if "?" not in path:
        return None
    q = path.split("?", 1)[1]
    for part in q.split("&"):
        for k in ("crca=", "crcb=", "crcc=", "crcd="):
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
            # el residual (smuggles) queda en self.buf: las
            # siguientes iteraciones lo parsean como cola

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
        return "CRC-BASE OK"


# ---------- edge con apareamiento por request -----------------------

class EdgeHandler(socketserver.BaseRequestHandler):
    scenario = "seq_desync"
    origin_port = 0

    def setup(self):
        self.request.settimeout(2.5)
        self.buf = b""
        self.obuf = b""

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
        """Head + body CL del cliente. Devuelve (raw, rest)."""
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

    def handle(self):
        scen = type(self).scenario
        self.o = socket.create_connection(
            ("127.0.0.1", type(self).origin_port), 2.5)
        self.o.settimeout(2.5)
        try:
            while True:
                req = self._read_request()
                if req is None:
                    return
                raw, rest = req
                resid = rest + self._poll_client()
                if resid:
                    if scen == "edge_strict":
                        self._rst()
                        return
                    if scen == "quiet_drain":
                        resid = b""
                    elif scen == "partial_drain":
                        # drena desde el SEGUNDO limite de
                        # request: T1 vive, T2 muere
                        i = resid.find(b"\r\n\r\n")
                        if i >= 0:
                            resid = resid[:i + 4]
                    elif scen == "flaky_forward":
                        st = _edge_state
                        if st["resid_forwarded"]:
                            resid = b""    # ya se curo
                        else:
                            st["resid_forwarded"] = True
                    # seq_desync: reenvia TODO el residual
                raw += resid
                try:
                    self.o.sendall(raw)
                except OSError:
                    return
                resp = self._read_one_origin()
                if resp is None:
                    return
                try:
                    self.request.sendall(resp)
                except OSError:
                    return
        finally:
            try:
                self.o.close()
            except OSError:
                pass


# ---------- main ---------------------------------------------------

class _TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    scen = (sys.argv[1] if len(sys.argv) > 1
            else "seq_desync")
    port = (int(sys.argv[2]) if len(sys.argv) > 2
            else SCENARIOS.get(scen, 19403))
    EdgeHandler.scenario = scen
    origin = _TS(("127.0.0.1", 0), OriginHandler)
    EdgeHandler.origin_port = origin.server_address[1]
    t = threading.Thread(
        target=origin.serve_forever, daemon=True)
    t.start()
    print("lab crc: escenario=%s origin=%d edge=%d"
          % (scen, EdgeHandler.origin_port, port),
          flush=True)
    edge = _TS(("127.0.0.1", port), EdgeHandler)
    edge.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    main()
