#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lab H2-TRANSLATION v0.88: 5 escenarios deterministas.

Simula un edge HTTP/2 (habla preface + HPACK literal + frames
SOBRE sockets crudos, sin librerias) que traduce a un origin
HTTP/1.1 interno en el mismo proceso. La COLECCION de
respuestas del origin se mapea FIFO a los streams H2 del
cliente: en la traduccion correcta cada stream recibe SU
respuesta; con bug de traduccion, el origin emite una
respuesta extra (al request smuggleado) y la coleccion queda
DESPAZADA: el stream del followup recibe el eco del smuggle.

Aprentizaje v0.87 (RC-000217): los payloads de DATA son bytes
crudos, jamas repr(b'..').

Puertos:
  19201 benign_strict    -> BENIGN (CL respetado; DATA
                            sobrante o CRLF en headers:
                            RST_STREAM + GOAWAY)
  19202 quiet_benign     -> BENIGN (el edge drena el DATA
                            residual y sanitiza CRLF)
  19203 h2cl_desync      -> H2-CL-STATE-EFFECT (h2.CL:
                            el edge ignora el content-length
                            y reenvia TODO el DATA: el
                            origin consume CL bytes y
                            procesa el prefijo smuggleado)
  19204 hdr_injection    -> H2-INJECTION-DETECTED (HPACK
                            leniente: valor con CRLF se
                            copia verbatim a la request H1:
                            el origin parsea 2 requests)
  19205 flaky_translation-> H2-DETECTED (desync solo en la
                            primera conexion smuggleada)

Python puro, sockets crudos, determinista. Uso:
  python3 labs/h2_lab.py <escenario> [puerto]
"""

import socket
import socketserver
import struct
import sys
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

SCENARIOS = {
    "benign_strict": 19201,
    "quiet_benign": 19202,
    "h2cl_desync": 19203,
    "hdr_injection": 19204,
    "flaky_translation": 19205,
}

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST = 0x3
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7

F_END_STREAM = 0x1
F_END_HEADERS = 0x4
S_ACK = 0x1

ERR_PROTOCOL = 0x1


# ---------- frames H2 (solo lo que el lab necesita) ---------

def _frame(ftype, flags, sid, payload):
    return (struct.pack(">I", len(payload))[1:]
            + struct.pack(">BB", ftype, flags)
            + struct.pack(">I", sid & 0x7FFFFFFF)
            + payload)


def _hpack_literal(headers):
    """HPACK literal sin indexar, sin huffman: 0x00 + 7-bit
    len + name + 7-bit len + value. Subconjunto valido."""
    out = b""
    for name, value in headers:
        n = name.encode() if isinstance(name, str) else name
        v = (value.encode() if isinstance(value, str)
             else value)
        out += b"\x00" + bytes([len(n) & 0x7F]) + n
        out += bytes([len(v) & 0x7F]) + v
    return out


def _hpack_decode(buf):
    """Decodifica el subconjunto literal del lab. En el
    escenario hdr_injection NO sanitiza CRLF: el bug que
    cazamos es exactamente el traductor leniente."""
    out = []
    i = 0
    while i < len(buf):
        if buf[i] != 0x00:
            return None          # huffman/indexado: no lab
        i += 1
        nlen = buf[i]; i += 1
        name = buf[i:i + nlen]; i += nlen
        vlen = buf[i]; i += 1
        val = buf[i:i + vlen]; i += vlen
        out.append((name, val))
    return out


def _h2_headers(sid, headers, end_stream=False):
    flags = F_END_HEADERS
    if end_stream:
        flags |= F_END_STREAM
    return _frame(FRAME_HEADERS, flags, sid,
                  _hpack_literal(headers))


def _h2_data(sid, body, end_stream=True):
    return _frame(FRAME_DATA,
                  F_END_STREAM if end_stream else 0,
                  sid, body)


def _h2_rst(sid, err):
    return _frame(FRAME_RST, 0, sid, struct.pack(">I", err))


def _h2_goaway(err):
    return _frame(FRAME_GOAWAY, 0, 0,
                  struct.pack(">II", 0, err))


# ---------- origin H1 interno (logica, no sockets) ----------

def _token_from_query(path):
    """Tokens de control/followup: h2fa/h2fb/h2fc."""
    if "?" not in path:
        return None
    q = path.split("?", 1)[1]
    for part in q.split("&"):
        for k in ("h2fa=", "h2fb=", "h2fc="):
            if part.startswith(k):
                return part.split("=", 1)[1]
    return None


def _origin_h1_get(path):
    """El origin responde a un GET legitimo: eco del token."""
    tok = _token_from_query(path)
    body = ("ECHO %s" % tok) if tok else "H2-BASE OK"
    return body


def _parse_h1_smuggle(raw):
    """El origin H1 consume content-length bytes y parsea
    el residual como siguiente request. Devuelve el
    request-line del smuggle o None."""
    head, sep, rest = raw.partition(b"\r\n\r\n")
    if not sep:
        return None
    headers = {}
    for ln in head.split(b"\r\n")[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    cl = int(headers.get(b"content-length", b"0") or 0)
    residual = rest[cl:]
    line = residual.split(b"\r\n")[0]
    if b" HTTP/1.1" in line or b" HTTP/1.0" in line:
        return line.decode("latin-1", "replace")
    return None


def _smuggle_token(reqline):
    parts = reqline.split(" ")
    path = parts[1] if len(parts) > 1 else "/"
    return path.lstrip("/").split("?")[0]


# ---------- handler: edge H2 -> origin H1 --------------------

class Handler(socketserver.BaseRequestHandler):
    scenario = "benign_strict"
    smuggle_conns = 0

    def setup(self):
        self.request.settimeout(2.5)
        self.buf = b""
        self.streams = {}       # sid -> dict
        self.order = []         # sids completados, FIFO
        self.oq = []            # coleccion de respuestas
                                 # del origin (cuerpos)
        self.closed = False

    # ---- lectura de frames ----

    def _recv_exact(self, n):
        while len(self.buf) < n:
            try:
                d = self.request.recv(65535)
            except (socket.timeout, OSError):
                return False
            if not d:
                return False
            self.buf += d
        return True

    def _read_frame(self):
        """(type, flags, sid, payload) o None."""
        if not self._recv_exact(9):
            return None
        ln = struct.unpack(">I", b"\x00" + self.buf[:3])[0]
        ftype = self.buf[3]
        flags = self.buf[4]
        sid = struct.unpack(
            ">I", self.buf[5:9])[0]
        if not self._recv_exact(9 + ln):
            return None
        payload = self.buf[9:9 + ln]
        self.buf = self.buf[9 + ln:]
        return ftype, flags, sid, payload

    # ---- envio ----

    def _send_resp(self, sid, body):
        """HEADERS(:status 200) + DATA(body) END_STREAM."""
        headers = [(":status", "200"),
                   ("content-type", "text/plain"),
                   ("content-length", str(len(body)))]
        self.request.sendall(
            _h2_headers(sid, headers)
            + _h2_data(sid, body.encode()))

    def _deliver(self, sid):
        """Mapea la coleccion del origin al stream: pop FIFO;
        si esta vacia, respuesta propia alineada (el origin
        no desincronizo)."""
        if self.oq:
            body = self.oq.pop(0)
            self._send_resp(sid, body)
            return
        # alineado: el stream recibe SU respuesta
        st = self.streams.get(sid) or {}
        self._send_resp(sid, st.get("own", "H2-BASE OK"))

    # ---- traduccion H2 -> H1 (según escenario) ----

    def _translate(self, st):
        """Construye la request H1 'tal como la vera el
        origin' y produce las respuestas del origin."""
        scen = type(self).scenario
        method = st["method"]
        path = st["path"]

        if method == "GET":
            self.oq.append(_origin_h1_get(path))
            st["own"] = self.oq[-1]
            return

        # POST: armar la vista H1 del origin
        raw = ("POST %s HTTP/1.1\r\nHost: h\r\n"
               "Content-Length: %d\r\n\r\n"
               % (path, st["cl"])).encode()
        raw += st["data"]

        injected = None
        for _n, v in st["headers"]:
            if (scen == "hdr_injection"
                    and b"\r\n" in v and method == "POST"):
                # traductor leniente: copia verbatim
                injected = v

        if scen == "benign_strict":
            if len(st["data"]) > st["cl"]:
                # DATA sobrante tras CL: frontera estricta
                self.request.sendall(
                    _h2_rst(st["sid"], ERR_PROTOCOL))
                self.request.sendall(
                    _h2_goaway(ERR_PROTOCOL))
                self.closed = True
                return
            if injected is not None:
                # CRLF en valor de header: protocolo violado
                self.request.sendall(
                    _h2_rst(st["sid"], ERR_PROTOCOL))
                self.request.sendall(
                    _h2_goaway(ERR_PROTOCOL))
                self.closed = True
                return
            self.oq.append("OK-POST")
            st["own"] = "OK-POST"
            return

        if scen == "quiet_benign":
            # drena el residual y sanitiza: sin desync
            if injected is not None:
                st["headers"] = [
                    (n, v.replace(b"\r\n", b" "))
                    for n, v in st["headers"]]
            self.oq.append("OK-POST")
            st["own"] = "OK-POST"
            return

        if scen == "hdr_injection":
            if injected is not None:
                # el origin recibe valor verbatim: parsea
                # 2 requests (inyeccion H1 por HPACK leniente)
                raw = ("POST %s HTTP/1.1\r\nHost: h\r\n"
                       "Content-Length: 0\r\n"
                       "x-q: " % path).encode() + injected
                smug = _parse_h1_smuggle(raw)
                self.oq.append("OK-POST")
                st["own"] = "OK-POST"
                if smug:
                    self.oq.append(
                        "SMUGGLE-ECHO %s"
                        % _smuggle_token(smug))
                return
            self.oq.append("OK-POST")
            st["own"] = "OK-POST"
            return

        # h2cl_desync / flaky_translation: h2.CL
        smug = _parse_h1_smuggle(raw)
        self.oq.append("OK-POST")
        st["own"] = "OK-POST"
        if scen == "flaky_translation" and smug:
            # solo la PRIMERA conexion smuggleada desincroniza;
            # las siguientes drenan (sin repro)
            if Handler.smuggle_conns == 0:
                Handler.smuggle_conns += 1
                self.oq.append("SMUGGLE-ECHO %s"
                               % _smuggle_token(smug))
            return
        if smug:
            self.oq.append("SMUGGLE-ECHO %s"
                           % _smuggle_token(smug))

    # ---- ciclo principal ----

    def handle(self):
        scen = type(self).scenario

        # preface
        while len(self.buf) < len(PREFACE):
            try:
                d = self.request.recv(65535)
            except (socket.timeout, OSError):
                return
            if not d:
                return
            self.buf += d
        if not self.buf.startswith(PREFACE):
            return
        self.buf = self.buf[len(PREFACE):]

        while not self.closed:
            fr = self._read_frame()
            if fr is None:
                break
            ftype, flags, sid, payload = fr

            if ftype == FRAME_SETTINGS:
                if not (flags & S_ACK):
                    self.request.sendall(
                        _frame(FRAME_SETTINGS, S_ACK, 0, b""))
                continue
            if ftype in (FRAME_RST, FRAME_GOAWAY):
                return

            if ftype == FRAME_HEADERS:
                hs = _hpack_decode(payload)
                if hs is None:
                    self.request.sendall(
                        _h2_goaway(ERR_PROTOCOL))
                    return
                st = self.streams.setdefault(
                    sid, {"sid": sid, "data": b"",
                          "headers": [], "method": "GET",
                          "path": "/", "cl": 0})
                for n, v in hs:
                    k = n.decode("latin-1", "replace")
                    if k == ":method":
                        st["method"] = (
                            v.decode("latin-1", "replace"))
                    elif k == ":path":
                        st["path"] = (
                            v.decode("latin-1", "replace"))
                    elif k == "content-length":
                        try:
                            st["cl"] = int(
                                v.decode("latin-1"))
                        except ValueError:
                            pass
                    st["headers"].append((n, v))
                if flags & F_END_STREAM:
                    self._complete(sid)
                continue

            if ftype == FRAME_DATA:
                st = self.streams.setdefault(
                    sid, {"sid": sid, "data": b"",
                          "headers": [], "method": "GET",
                          "path": "/", "cl": 0})
                st["data"] += payload
                if flags & F_END_STREAM:
                    self._complete(sid)
                continue

    def _complete(self, sid):
        if sid in self.order:
            return
        st = self.streams[sid]
        self.order.append(sid)
        self._translate(st)
        if self.closed:
            return
        # entrega FIFO: el stream recibe lo que el origin
        # produjo para el (o lo DESPLAZADO del smuggle)
        self._deliver(sid)

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
    Handler.smuggle_conns = 0
    srv = Lab(("127.0.0.1", port), Handler)
    print("lab h2 %s en %d" % (scen, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
