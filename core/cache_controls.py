#!/usr/bin/env python3
"""CACHE-CONTROLS (v0.79.0): explicaciones alternativas ANTES
de elevar un diferencial.

Cada control emite PASSED / FAILED / NOT_APPLICABLE con
EVIDENCIA real que lo respalda. Nada decorativo: un PASSED
siempre corresponde a una comprobacion efectiva.

Controles CRITICOS (pueden explicar un diferencial y
degradarlo a BENIGN): cookies_session, authorization, vary,
ttl_wait, bot_management.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap


import time

from core import cache_fingerprint as F


def run(url, fp_a, fp_b, req_a, req_b, baseline, timeout=10.0):
    """Re-sondea el target para los controles que necesitan
    evidencia fresca. Devuelve {controles, explican, budget}."""
    controls = {}

    def add(name, status, evidence):
        controls[name] = {"status": status, "evidence": evidence}

    hdrs = lambda r: {k.lower() for k in (r.get("headers")
                                          or {})}
    ha, hb = hdrs(req_a), hdrs(req_b)

    # --- cookies / session
    cookie_in = "cookie" in ha or "cookie" in hb
    setck = [fp["signals"]["set_cookie"]["state"]
             for fp in (fp_a, fp_b) if fp]
    if cookie_in or "OBSERVED" in setck:
        add("cookies_session", "FAILED",
            "Cookie en peticion o Set-Cookie en respuesta: "
            "sesion/personalizacion presente")
    else:
        add("cookies_session", "PASSED",
            "sin Cookie en el par y sin Set-Cookie en las "
            "respuestas (comprobado en las huellas)")

    # --- authorization
    if "authorization" in ha or "authorization" in hb:
        add("authorization", "FAILED",
            "Authorization presente en el par")
    else:
        add("authorization", "PASSED",
            "sin Authorization en ninguna peticion del par")

    # --- vary
    varies = [fp["signals"]["vary"] for fp in (fp_a, fp_b)
              if fp]
    vvals = {v["value"] for v in varies if v["state"]
             == "OBSERVED"}
    if vvals:
        refs = {str(v).lower() for v in vvals}
        dif_hdrs = ha ^ hb
        if any(r in refs for r in dif_hdrs) or \
                "cookie" in refs:
            add("vary", "FAILED",
                "Vary=%s referencia lo que difiere entre A y B: "
                "diferencia legitimamente explicada"
                % sorted(refs))
        else:
            add("vary", "PASSED",
                "Vary=%s presente pero no referencia nada que "
                "difiera entre A y B" % sorted(refs))
    else:
        add("vary", "PASSED",
            "Vary ausente en las respuestas del par")

    # --- user-agent / accept-language / accept
    for h in ("user-agent", "accept-language", "accept"):
        same = req_a.get("headers", {}).get(h, "") == \
            req_b.get("headers", {}).get(h, "")
        add(h.replace("-", "_"), "PASSED" if same else "FAILED",
            "identicos por construccion en el par" if same
            else "difieren: %s" % h)

    # --- ttl_wait: re-sonda A; si la representacion cambia
    # sola, la dinamica temporal/backend explica el diferencial
    fp_a2, _, err = F.fetch(url, req_a.get("path", "/"),
                           headers=req_a.get("headers"),
                           timeout=timeout)
    time.sleep(F.COOLDOWN)
    reqs = 1
    if err or not fp_a2 or not fp_a2.get("valid"):
        add("ttl_wait", "NOT_APPLICABLE",
            "re-sonda imposible (sin respuesta utilizable)")
    else:
        d = F.core_differs(fp_a, fp_a2)
        if d:
            add("ttl_wait", "FAILED",
                "la MISMA representacion cambia sola (%s): "
                "dinamica temporal/backend explica"
                % ",".join(d))
        else:
            add("ttl_wait", "PASSED",
                "misma representacion re-sondeada: nucleo "
                "estable (%s)" % fp_a2["signals"]["body_hash"]
                ["value"])

    # --- backend dynamics / bot management: via baseline
    bc = baseline.get("classification")
    if bc == "AMBIGUO":
        add("backend_dynamics", "FAILED",
            "baseline AMBIGUO: variacion sin caracterizar "
            "(evidencia: %s)" % baseline.get("evidence"))
        add("bot_management", "FAILED",
            "baseline AMBIGUO: posible bot management; sin "
            "poder discriminatorio")
    else:
        add("backend_dynamics", "PASSED",
            "baseline %s: nucleo caracterizado" % bc)
        add("bot_management", "PASSED",
            "baseline %s: sin rotacion no explicada" % bc)

    # --- geolocation: honesto desde una sola vista
    add("geolocation", "NOT_APPLICABLE",
        "vision unica: no medible desde un solo punto de "
        "observacion")

    criticos = [c for c in ("cookies_session", "authorization",
                            "vary", "ttl_wait",
                            "bot_management")
                if controls[c]["status"] == "FAILED"]
    return {"controls": controls, "explican": criticos,
            "requests": reqs}


def _selftest():
    from core.cache_fingerprint import fingerprint
    raw = (b"HTTP/1.1 200 OK\r\nVary: Cookie\r\n\r\nX")
    fp = fingerprint(raw)
    assert fp["signals"]["vary"]["value"] == "Cookie"
    print("cache_controls selftest OK")


if __name__ == "__main__":
    _selftest()
