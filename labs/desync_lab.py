#!/usr/bin/env python3
"""Lab desync para EDGESYNC-HUNT (solo localhost).

Puertos: argv = puerto_edge puerto_backend modo

Modos (par edge->back):
  desync          edge CL        back TE-strict   (CL.TE clasico)
  consistente     edge CL        back CL           (control negativo)
  tecl            edge TE        back CL           (TE.CL invertido)
  consistente-te  edge TE        back TE-strict    (control negativo TE)
  lenient         edge CL        back TE-lenient   (parsers tolerantes)
  rechaza         edge 400+close  back TE-strict    (rechaza framing
                                                  ambiguo; back vuln)
  eco-normaliza   edge RECONSTRUYE el request (suelta TE,
                  pone CL real); back responde ECO con lo recibido
  eco-conserva    edge reenvia crudo; back responde ECO

TE-strict: honra chunked SOLO con un unico header Transfer-Encoding,
sin espacio antes de los dos puntos, valor == chunked (tras strip).
TE-lenient: tolera duplicados, espacio antes de los dos puntos y
"identity,chunked" (gana el ultimo TE con chunked).
"""
import socket
import sys
import threading

PORT_EDGE = int(sys.argv[1])
PORT_BACK = int(sys.argv[2])
MODO = sys.argv[3] if len(sys.argv) > 3 else "desync"

EDGE_FRAMING = {"desync": "cl", "consistente": "cl", "tecl": "te",
                "consistente-te": "te", "lenient": "cl",
                "rechaza": "cl-rechaza",
                "eco-normaliza": "cl-rebuild",
                "eco-conserva": "cl"}[MODO]
BACK_FRAMING = {"desync": "te-strict", "consistente": "cl",
                "tecl": "cl", "consistente-te": "te-strict",
                "lenient": "te-lenient", "rechaza": "te-strict",
                "eco-normaliza": "cl",
                "eco-conserva": "te-lenient"}[MODO]
ECO = MODO in ("eco-normaliza", "eco-conserva")


def recv_until(sock, buf, marker, timeout=5.0):
    sock.settimeout(timeout)
    while marker not in buf:
        chunk = sock.recv(65535)
        if not chunk:
            return buf, False
        buf += chunk
    return buf, True


def recv_n(sock, buf, n, timeout=5.0):
    sock.settimeout(timeout)
    while len(buf) < n:
        chunk = sock.recv(65535)
        if not chunk:
            return buf, False
        buf += chunk
    return buf, True


def header_lines(raw_head_text):
    """Lista de (key_raw, value_raw) sin normalizar."""
    out = []
    for line in raw_head_text.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out.append((k, v))
    return out


def te_honored(raw_head_text, rule):
    """Decide si el parser honra Transfer-Encoding: chunked."""
    lines = header_lines(raw_head_text)
    if rule == "te-strict":
        tes = [(k, v) for k, v in lines
               if k.lower() == "transfer-encoding"]   # sin strip
        if len(tes) != 1:
            return False
        return tes[0][1].strip().lower() == "chunked"
    if rule == "te-lenient":
        tes = [(k, v) for k, v in lines
               if k.strip().lower() == "transfer-encoding"]
        if not tes:
            return False
        return "chunked" in tes[-1][1].strip().lower()
    return False


def parse_first(raw_head_text):
    return raw_head_text.split("\r\n")[0]


def cl_value(raw_head_text):
    for k, v in header_lines(raw_head_text):
        if k.strip().lower() == "content-length":
            try:
                return int(v.strip())
            except ValueError:
                return 0
    return 0


def chunked_extent(sock, buf):
    """Consume un cuerpo chunked desde buf (y del socket si falta).
    Devuelve (cuerpo_completo, leftover). len(izq) bytes van al wire."""
    wire = b""
    while True:
        while b"\r\n" not in buf:
            buf, ok = recv_until(sock, buf, b"\r\n")
            if not ok:
                return wire + buf, b""
        linea, _, resto = buf.partition(b"\r\n")
        try:
            tam = int(linea.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return wire + buf, b""
        if tam == 0:
            if resto.startswith(b"\r\n"):
                resto = resto[2:]
            return wire + linea + b"\r\n\r\n", resto
        while len(resto) < tam + 2:
            resto, ok = recv_n(sock, resto, tam + 2)
            if not ok:
                return wire + buf, b""
        wire += linea + b"\r\n" + resto[:tam + 2]
        buf = resto[tam + 2:]


def responder(sock, path, head_txt=""):
    if path.startswith("/secreto"):
        body = b"SECRETO-SMUGGLED-CONTENT\n"
    elif path == "/":
        body = b"ok-base\n"
    elif path == "/post":
        body = b"post-accepted\n"
    else:
        body = b"not-found\n"
    extra = b""
    if ECO:
        te_v = "none"
        cl_v = "none"
        for k, v in header_lines(head_txt):
            kk = k.strip().lower()
            if kk == "transfer-encoding":
                te_v = v.strip()
            elif kk == "content-length":
                cl_v = v.strip()
        extra = (b"X-Received-Te: " + te_v.encode() + b"\r\n"
                 b"X-Received-Cl: " + cl_v.encode() + b"\r\n"
                 b"X-Received-Path: " + path.encode() + b"\r\n")
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"X-Path: " + path.encode() + b"\r\n" + extra +
            b"\r\n" + body)
    print(f"[back] responde a {path}", file=sys.stderr, flush=True)
    sock.sendall(resp)


def backend_conn(conn):
    buf = b""
    try:
        while True:
            buf, ok = recv_until(conn, buf, b"\r\n\r\n")
            if not ok:
                return
            raw_head, rest = buf.split(b"\r\n\r\n", 1)
            head_txt = raw_head.decode("latin-1")
            if BACK_FRAMING.startswith("te") and te_honored(head_txt,
                                                             BACK_FRAMING):
                cuerpo, buf = chunked_extent(conn, rest)
            else:
                n = cl_value(head_txt)
                while len(rest) < n:
                    rest, ok2 = recv_n(conn, rest, n)
                    if not ok2:
                        return
                buf = rest[n:]
            first = parse_first(head_txt)
            path = first.split(" ")[1] if " " in first else "/"
            responder(conn, path, head_txt)
    except Exception as e:
        print(f"[back-conn] EXCEP: {e!r}", file=sys.stderr, flush=True)
    finally:
        conn.close()


def tiene_cl_y_te(head_txt):
    keys = [k.strip().lower() for k, _ in header_lines(head_txt)]
    return ("content-length" in keys
            and "transfer-encoding" in keys)


def edge_conn(conn, back_sock):
    buf = b""
    try:
        while True:
            buf, ok = recv_until(conn, buf, b"\r\n\r\n")
            if not ok:
                return
            raw_head, rest = buf.split(b"\r\n\r\n", 1)
            head_txt = raw_head.decode("latin-1")
            if EDGE_FRAMING == "cl-rechaza" and tiene_cl_y_te(head_txt):
                # postura activa: rechaza el framing ambiguo aunque
                # el back sea vulnerable (modo "rechaza")
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n"
                             b"Content-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
                return
            if EDGE_FRAMING == "cl-rebuild":
                # normaliza: consume el cuerpo bajo SU lectura y
                # reenvia un request limpio (sin TE, CL real)
                if te_honored(head_txt, "te-lenient"):
                    cuerpo, buf = chunked_extent(conn, rest)
                else:
                    n = cl_value(head_txt)
                    while len(rest) < n:
                        rest, ok2 = recv_n(conn, rest, n)
                        if not ok2:
                            return
                    cuerpo = rest[:n]
                    buf = rest[n:]
                first = parse_first(head_txt)
                rebuilt = (first.encode() + b"\r\n"
                           b"Content-Length: "
                           + str(len(cuerpo)).encode()
                           + b"\r\n\r\n" + cuerpo)
                print(f"[edge] rebuild: {rebuilt[:60]!r}",
                      file=sys.stderr, flush=True)
                back_sock.sendall(rebuilt)
            elif (EDGE_FRAMING == "te"
                    and te_honored(head_txt, "te-strict")):
                cuerpo, buf = chunked_extent(conn, rest)
                back_sock.sendall(raw_head + b"\r\n\r\n" + cuerpo)
            else:
                n = cl_value(head_txt)
                while len(rest) < n:
                    rest, ok2 = recv_n(conn, rest, n)
                    if not ok2:
                        return
                back_sock.sendall(raw_head + b"\r\n\r\n" + rest[:n])
                buf = rest[n:]
    except Exception as e:
        print(f"[edge-conn] EXCEP: {e!r}", file=sys.stderr, flush=True)


def backend_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT_BACK))
    srv.listen(50)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=backend_conn, args=(c,),
                         daemon=True).start()


def relay(src, dst):
    try:
        while True:
            d = src.recv(65535)
            if not d:
                break
            dst.sendall(d)
    except Exception:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass


def edge_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT_EDGE))
    srv.listen(50)
    while True:
        c, _ = srv.accept()
        b = socket.socket()
        b.connect(("127.0.0.1", PORT_BACK))
        threading.Thread(target=relay, args=(b, c), daemon=True).start()
        threading.Thread(target=edge_conn, args=(c, b), daemon=True).start()


if __name__ == "__main__":
    print(f"lab desync: edge={PORT_EDGE} back={PORT_BACK} modo={MODO}",
          flush=True)
    threading.Thread(target=backend_server, daemon=True).start()
    edge_server()
