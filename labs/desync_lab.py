#!/usr/bin/env python3
"""Lab desync para EDGESYNC-HUNT (solo localhost).
Edge (CL) -> Backend (TE si desync / CL si consistente).
Puerto: args = puerto_edge puerto_backend modo(desync|consistente)
"""
import re
import socket
import sys
import threading

PORT_EDGE = int(sys.argv[1])
PORT_BACK = int(sys.argv[2])
MODO = sys.argv[3] if len(sys.argv) > 3 else "desync"


def recv_until(sock, buf, marker, timeout=5.0):
    """Recibe hasta encontrar marker en buf acumulado."""
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


def parse_headers(text):
    head = text.split("\r\n\r\n", 1)[0]
    hdrs = {}
    first = head.split("\r\n")[0]
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return first, hdrs


def responder(sock, path):
    if path.startswith("/secreto"):
        body = b"SECRETO-SMUGGLED-CONTENT\n"
    elif path == "/":
        body = b"ok-base\n"
    elif path == "/post":
        body = b"post-accepted\n"
    else:
        body = b"not-found\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"X-Path: " + path.encode() + b"\r\n\r\n" + body)
    import sys as _s
    print(f"[back] responde a {path}", file=_s.stderr, flush=True)
    sock.sendall(resp)


def body_len_backend(hdrs, raw_head):
    """Backend: TE si modo desync, CL si consistente."""
    if MODO == "desync" and "transfer-encoding" in hdrs:
        return "chunked", None
    return "cl", int(hdrs.get("content-length", 0) or 0)


def backend_conn(conn):
    import sys as _s
    print("[back-conn] nace", file=_s.stderr, flush=True)
    buf = b""
    try:
        while True:
            buf, ok = recv_until(conn, buf, b"\r\n\r\n")
            if not ok:
                return
            print(f"[back-conn] headers: {buf[:40]!r}", file=_s.stderr,
                  flush=True)
            raw_head, rest = buf.split(b"\r\n\r\n", 1)
            first, hdrs = parse_headers(raw_head.decode("latin-1"))
            modo_body, n = body_len_backend(hdrs, raw_head)
            if modo_body == "chunked":
                # parsear chunked manual hasta chunk 0
                rest2 = rest
                while True:
                    if b"\r\n" not in rest2:
                        rest2 += conn.recv(65535)
                        continue
                    linea, _, resto = rest2.partition(b"\r\n")
                    tam = int(linea.split(b";")[0] or b"0", 16)
                    resto2 = resto
                    if tam == 0:
                        # fin chunked: consumir CRLF final si viene
                        if resto2.startswith(b"\r\n"):
                            resto2 = resto2[2:]
                        break
                    while len(resto2) < tam + 2:
                        resto2 += conn.recv(65535)
                    resto2 = resto2[tam + 2:]
                buf = resto2
            else:
                while len(rest) < n:
                    rest, ok2 = recv_n(conn, rest, n)
                    if not ok2:
                        return
                buf = rest[n:]
            path = first.split(" ")[1] if " " in first else "/"
            responder(conn, path)
    except Exception as e:
        import traceback
        print(f"[back-conn] EXCEP: {e!r}", file=_s.stderr, flush=True)
        traceback.print_exc()
    finally:
        conn.close()


def edge_conn(conn, back_sock):
    """Edge: SIEMPRE parsea con CL (aunque haya TE). Reenvia crudo."""
    buf = b""
    try:
        while True:
            buf, ok = recv_until(conn, buf, b"\r\n\r\n")
            if not ok:
                return
            raw_head, rest = buf.split(b"\r\n\r\n", 1)
            first, hdrs = parse_headers(raw_head.decode("latin-1"))
            n = int(hdrs.get("content-length", 0) or 0)
            while len(rest) < n:
                rest, ok2 = recv_n(conn, rest, n)
                if not ok2:
                    return
            # reenviar el request crudo completo al backend
            import sys as _s
            print(f"[edge] fwd: {raw_head[:40]!r} cl={n}", file=_s.stderr,
                  flush=True)
            try:
                back_sock.sendall(raw_head + b"\r\n\r\n" + rest[:n])
                print("[edge] sendall OK", file=_s.stderr, flush=True)
            except Exception as e:
                print(f"[edge] sendall FALLO: {e!r}", file=_s.stderr,
                      flush=True)
            buf = rest[n:]
    except Exception as e:
        import traceback
        print(f"[edge-conn] EXCEP: {e!r}", file=_s.stderr, flush=True)
        traceback.print_exc()


def backend_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT_BACK))
    srv.listen(50)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=backend_conn, args=(c,),
                         daemon=True).start()


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


def relay(src, dst):
    import sys as _s
    print("[relay] vivo", file=_s.stderr, flush=True)
    try:
        while True:
            d = src.recv(65535)
            if not d:
                break
            print(f"[relay] -> {len(d)} bytes", file=_s.stderr, flush=True)
            dst.sendall(d)
    except Exception:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass


if __name__ == "__main__":
    print(f"lab desync: edge={PORT_EDGE} back={PORT_BACK} modo={MODO}",
          flush=True)
    threading.Thread(target=backend_server, daemon=True).start()
    edge_server()
