#!/usr/bin/env python3
"""NORMALIZATION-AUDIT (v0.76.0): que representacion recibe el
origin cuando el edge ACEPTA un framing contradictorio.

Pregunta: cuando el edge acepta una variante, ¿que representacion
termina recibiendo el origin?

REGLA DE ORO: una tolerancia del edge NO es una vulnerabilidad
por si misma. Este modulo describe TRANSFORMACIONES OBSERVABLES;
no convierte una transformacion en hallazgo automaticamente.
Lo no observable queda unknown (nunca "probablemente").

Sonda central: BODY-DIFFERENTIAL (benigna). Cuerpo
  5\\r\\nhello\\r\\n0\\r\\n\\r\\n
  - leido como TE/chunked  -> cuerpo "hello" (5 bytes)
  - leido como CL          -> 15 bytes crudos
Las DOS lecturas consumen el mensaje completo: no hay smuggle,
no hay leftover, no hay request secondario. Solo dos
interpretaciones posibles del mismo mensaje, contrastables contra
dos canonicos limpios enviados aparte:
  canonical A: POST CL con cuerpo "hello"  (normalizador TE->CL)
  canonical B: POST CL con cuerpo crudo    (conservador)

Veredictos por variante (todos exigidos por evidencia):
  NORMALIZED  input != downstream PERO ECO muestra TE eliminado
  CONSERVED   input ~= downstream, ECO muestra TE intacto y la
              respuesta coincide con el canonico crudo
  MISMATCH    ECO muestra que el origin ACTUO sobre la lectura TE
              (te=chunked) mientras la respuesta coincide con el
              canonico A: dos capas, dos interpretaciones
  REJECTED    el probe diferencial recibio 400/cierre
  UNKNOWN     sin eco y sin diferencia observable de respuesta

Escalera MISMATCH (nada escala sin evidencia):
  ¿reproducible? -> ¿afecta estado/conexion? -> ¿evidencia
  downstream (ECO)? -> SOSPECHA. DEMO queda para las capas de
  estado/cache del roadmap (v0.77+).

Presupuesto: perfil v0.75 (11 req) + 3 req por variante aceptada
(probe + 2 canonicos), secuencial, lectura A->B. Tope 24.
"""
import argparse
import hashlib
import json
import time

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
from core.edge_profile import (_connect, _read_all, _statuses,
                               _headers_of, profile,
                               STATUS_RECHAZO)

MAX_REQS = 24
COOLDOWN = 0.4
BODY_DIFF = b"5\r\nhello\r\n0\r\n\r\n"   # 17 bytes
BODY_CANON_A = b"hello"
BODY_CANON_B = BODY_DIFF


def _firma(raw):
    """Firma observable de la primera respuesta: status,
    content-length, hash del cuerpo, cabeceras de cache."""
    if not raw.strip():
        return None
    st = _statuses(raw)
    h = _headers_of(raw)
    m = re_search_body(raw)
    return {"status": st[0] if st else "?",
            "content_length": h.get("content-length", "?"),
            "body_sha": hashlib.sha1(m).hexdigest()[:12] if m
            is not None else "empty",
            "cache": (h.get("age") or h.get("x-cache")
                      or h.get("cf-cache-status") or "-"),
            "etag": h.get("etag", "-")}


def re_search_body(raw):
    """Cuerpo de la primera respuesta (split por doble CRLF)."""
    parts = raw.split(b"\r\n\r\n", 1)
    return parts[1] if len(parts) == 2 else b""


def _post(host, body, extra_headers=b""):
    cl = len(body)
    return (b"POST / HTTP/1.1\r\n"
            b"Host: " + host.encode() + b"\r\n"
            b"Content-Length: " + str(cl).encode() + b"\r\n"
            b"Content-Type: text/plain\r\n"
            + extra_headers +
            b"\r\n" + body)


def _te_headers(variant):
    if variant == "cl_te":
        return b"Transfer-Encoding: chunked\r\n"
    if variant == "te_doble":
        return (b"Transfer-Encoding: chunked\r\n"
                b"Transfer-Encoding: chunked\r\n")
    if variant == "te_case":
        return b"tRansfer-EnCoDiNg: ChUnKeD\r\n"
    if variant == "te_espacio":
        return b"Transfer-Encoding : chunked\r\n"
    raise ValueError(variant)


def _eco(raw):
    """ECO del downstream: primera ocurrencia de X-Received-*."""
    out = {}
    for m in re_iter_xreceived(raw):
        k, v = m
        if k not in out:
            out[k] = v
    return out


def re_iter_xreceived(raw):
    import re as _re
    for mm in _re.finditer(rb"X-Received-(Te|Cl|Path): *([^\r\n]*)",
                          raw):
        yield (mm.group(1).decode().lower(),
               mm.group(2).decode("latin-1", "replace").strip())


def _normalizacion_de(probe_raw, sig_probe, sig_a, sig_b, eco):
    """Veredicto de representacion para UNA variante aceptada."""
    te_v = eco.get("te", "").lower()
    if te_v and te_v != "none":
        # el downstream actuo sobre representacion TE
        if sig_probe and sig_a and _similar(sig_probe, sig_a):
            return "MISMATCH"
        if sig_probe and sig_b and _similar(sig_probe, sig_b):
            return "CONSERVED"
        return "CONSERVED"
    if te_v == "none":
        return "NORMALIZED"
    # sin ECO: solo diferencial de respuesta puede hablar.
    # REGLA: si los dos canonicos son indistinguibles, el target
    # no tiene poder discriminatorio y NINGUN match del probe
    # significa algo: queda UNKNOWN, no "aparente".
    st = _statuses(probe_raw)
    if st and st[0] in STATUS_RECHAZO:
        return "REJECTED"
    if (sig_a and sig_b and _similar(sig_a, sig_b)
            and sig_probe and _similar(sig_probe, sig_a)):
        return "UNKNOWN"
    if sig_probe and sig_a and _similar(sig_probe, sig_a):
        return "NORMALIZED-APARENTE"
    if sig_probe and sig_b and _similar(sig_probe, sig_b):
        return "CONSERVED-APARENTE"
    return "UNKNOWN"


def _similar(s1, s2):
    """Coincidencia de firma: status + content-length + hash."""
    return (s1["status"] == s2["status"]
            and s1["content_length"] == s2["content_length"]
            and s1["body_sha"] == s2["body_sha"])


def audit(cfg):
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    informe = {"target": url, "regla_de_oro":
               "tolerancia no es vulnerabilidad; solo MISMATCH "
               "con evidencia escala"}
    reqs = 0

    # fase 1: contrato del edge (v0.75)
    ficha = profile({"url": url, "timeout": timeout})
    reqs += ficha.get("requests", 11)
    informe["edge_profile"] = ficha

    variantes = ["cl_te", "te_doble", "te_espacio", "te_case"]
    aceptadas = [v for v in variantes if ficha.get(v) == "accepted"]
    rechazadas = [v for v in variantes if ficha.get(v) == "rejected"]
    informe["aceptadas"] = aceptadas
    informe["rechazadas_por_perfil"] = rechazadas

    matriz = {}
    mismatch_pendiente = []
    host = None
    for v in aceptadas:
        if reqs >= MAX_REQS:
            informe["presupuesto"] = "agotado"
            break
        if host is None:
            s_tmp, host = _connect(url, timeout)
            s_tmp.close()
        # probe diferencial (contradictorio, cuerpo DIFF)
        s1, _ = _connect(url, timeout)
        try:
            probe = _post(host, BODY_DIFF, _te_headers(v))
            s1.sendall(probe)
            reqs += 1
            probe_raw = _read_all(s1, quiet=1.2)
        finally:
            s1.close()
        time.sleep(COOLDOWN)
        # canonico A: cuerpo "hello" (representacion TE->CL)
        s2, _ = _connect(url, timeout)
        try:
            s2.sendall(_post(host, BODY_CANON_A))
            reqs += 1
            raw_a = _read_all(s2, quiet=1.2)
        finally:
            s2.close()
        time.sleep(COOLDOWN)
        # canonico B: cuerpo crudo (representacion conservada)
        s3, _ = _connect(url, timeout)
        try:
            s3.sendall(_post(host, BODY_CANON_B))
            reqs += 1
            raw_b = _read_all(s3, quiet=1.2)
        finally:
            s3.close()
        time.sleep(COOLDOWN)

        eco = _eco(probe_raw)
        veredicto = _normalizacion_de(
            probe_raw, _firma(probe_raw), _firma(raw_a),
            _firma(raw_b), eco)
        matriz[v] = {"veredicto": veredicto,
                     "eco": eco or None,
                     "firma_probe": _firma(probe_raw),
                     "firma_canon_a": _firma(raw_a),
                     "firma_canon_b": _firma(raw_b)}
        if veredicto == "MISMATCH":
            mismatch_pendiente.append(v)

    informe["matriz"] = matriz
    informe["requests"] = reqs
    informe["max_requests"] = MAX_REQS

    # escalera MISMATCH: reproducible -> estado/conexion ->
    # evidencia downstream -> SOSPECHA
    escalera = {}
    if mismatch_pendiente:
        v = mismatch_pendiente[0]
        s4, _ = _connect(url, timeout)
        try:
            s4.sendall(_post(host, BODY_DIFF, _te_headers(v)))
            reqs += 1
            probe2_raw = _read_all(s4, quiet=1.2)
        finally:
            s4.close()
        eco2 = _eco(probe2_raw)
        repro = eco2.get("te", "").lower() not in ("", "none")
        escalera["variante"] = v
        escalera["reproducible"] = "yes" if repro else "no"
        st2 = _statuses(probe2_raw)
        escalera["origin_acto_te_repro"] = ("yes" if repro
                                            else "no")
        escalera["estado_conexion"] = "cierre-tras-respuesta" \
            if probe2_raw and not probe2_raw.strip() else \
            ("respuesta-sin-cierre" if st2 else "sin-respuesta")
        escalera["evidencia_downstream"] = "eco" if repro else \
            "ninguna"
        if repro:
            informe["veredicto"] = "SOSPECHA"
        else:
            informe["veredicto"] = "SOSPECHA-ESPORADICA"
        informe["escalera_mismatch"] = escalera
    else:
        informe["veredicto"] = "MATRIX"
        if not aceptadas:
            informe["veredicto"] = "RECHAZADO-TOTAL"

    return informe


def _render(informe):
    out = [f"NORMALIZATION-AUDIT: {informe.get('target', '?')}",
           "-" * 46]
    out.append(f"veredicto: {informe.get('veredicto', '?')}")
    out.append("")
    for v, m in informe.get("matriz", {}).items():
        out.append(f"{v:12} -> {m['veredicto']}"
                   + (f"  (ECO te={m['eco']['te']})"
                      if m.get("eco") and "te" in m["eco"] else ""))
    if informe.get("rechazadas_por_perfil"):
        out.append("")
        out.append("rechazadas por el perfil: "
                   + ", ".join(informe["rechazadas_por_perfil"]))
    esc = informe.get("escalera_mismatch")
    if esc:
        out.append("")
        out.append("escalera MISMATCH:")
        out.append(f"  variante:          {esc['variante']}")
        out.append(f"  reproducible:      {esc['reproducible']}")
        out.append(f"  estado/conexion:   {esc['estado_conexion']}")
        out.append(f"  evidencia downst.: {esc['evidencia_downstream']}")
    out.append("")
    out.append(f"requests: {informe.get('requests', '?')}/"
               f"{informe.get('max_requests', '?')}")
    out.append("regla de oro: tolerancia no es vulnerabilidad;")
    out.append("solo MISMATCH con evidencia escala.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="NORMALIZATION-AUDIT: representacion que "
                    "recibe el origin por framing aceptado")
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
