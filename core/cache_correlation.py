#!/usr/bin/env python3
"""CACHE-CORRELATION (v0.79.0): el orquestador.

Pregunta central: ¿dos representaciones que deberian ser
equivalentes generan estados de cache distintos, o dos
representaciones distintas terminan compartiendo un estado que
no deberian compartir?

REGLA FUNDAMENTAL: no asumimos ni afirmamos conocer la cache
key interna. CacheBindingEvidence expresa FUERZA DE EVIDENCIA
EXTERNA compatible con binding/correlacion; no es un
descubrimiento de la key.

Flujo: SemanticRelation -> CacheFingerprint -> Baseline ->
Controls -> Correlation -> Target Judge.

EVIDENCIA E0-E6 (no son puntos, no hay confidence=0.85):
  E0 CACHE OBSERVATION
  E1 REPRODUCIBILITY
  E2 SEMANTIC DIFFERENTIAL
  E3 CACHE BINDING
  E4 DOWNSTREAM DIFFERENTIAL
  E5 CROSS-CONSUMER IMPACT
  E6 SECURITY IMPACT

Juez determinista. DEMO es dificil de alcanzar por diseno:
exige binding STRONG + (E5 o E6) + controles criticos PASSED +
atribucion razonable + baseline no ambiguo. NUNCA se produce
DEMO por: Age diferente, HIT/MISS, ausencia de headers, body
diferente solo, dos requests diferentes, convergencia
aparente, inferencia de cache key, o E0+E1.
"""
import argparse
import json
import os as _os
import sys as _sys
import time

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))

from core import cache_fingerprint as F
from core import cache_baseline as B
from core import cache_controls as C
from core import cache_semantic as S

MAX_REQS = F.MAX_REQS
CRITICOS = ["cookies_session", "authorization", "vary",
            "ttl_wait", "bot_management"]


def _binding(eq_div, eq_repro, conv, conv_repro, conv_attrib,
            fp_a, fp_b, fps):
    """CacheBindingEvidence: fuerza de evidencia externa
    compatible con binding. NO es la cache key interna."""
    explicit = any(fp["signals"]["cache_status"]["state"]
                   == "OBSERVED" for fp in fps if fp)
    etag_diff = (fp_a and fp_b and fp_a["signals"]["etag"]
                 ["state"] == "OBSERVED"
                 and fp_b["signals"]["etag"]["state"]
                 == "OBSERVED"
                 and fp_a["signals"]["etag"]["value"]
                 != fp_b["signals"]["etag"]["value"])
    if conv and conv_repro and conv_attrib:
        return "STRONG", ("convergencia ATRIBUIDA reproducible: "
                          "una peticion recibio la respuesta de "
                          "la otra, con especificidad de path "
                          "demostrada")
    if eq_div and eq_repro and (explicit or etag_diff):
        return "MODERATE", ("diferencial reproducible con "
                            "senales de cache explicitas que "
                            "distinguen estados")
    if conv and conv_repro:
        return "WEAK", ("convergencia reproducible SIN "
                        "atribucion (aparente: nucleos iguales "
                        "sin especificidad de path; no es "
                        "binding")
    if eq_div:
        return "WEAK", ("diferencial observado sin senales de "
                       "cache explicitas suficientes")
    return "UNKNOWN", "sin diferencial ni convergencia"


def audit(cfg):
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    informe = {"target": url}
    reqs = 0

    def get(path, headers=None):
        nonlocal reqs
        fp, raw, err = F.fetch(url, path, headers=headers,
                               timeout=timeout)
        reqs += 1
        time.sleep(F.COOLDOWN)
        return fp, err

    # ---------- 1. baseline
    base = B.classify(url, k=3, timeout=timeout)
    reqs += 3
    informe["baseline"] = base
    informe["baseline_usable"] = base["classification"] in (
        "STABLE", "VARIANT")

    # ---------- 2. bateria de pares
    pares = {
        "P1-EQ": ({"path": "/cache-probe",
                   "headers": {"X-Cache-Probe": "v1"}},
                  {"path": "/cache-probe",
                   "headers": {"x-cache-probe": "v1"}}),
        "P2-SESS": ({"path": "/cache-probe", "headers": {}},
                    {"path": "/cache-probe",
                     "headers": {"Cookie": "cache-probe=1"}}),
        "P3-DI": ({"path": "/x-shared/a", "headers": {}},
                  {"path": "/x-shared/b", "headers": {}}),
    }
    # especificidad: ¿el target SIRVE contenido distinto para
    # paths distintos? Sin esto, una convergencia es aparente
    # (target generico) y NO atribuible
    fspec, _ = get("/x-specificity/probe")
    rels = {}
    fps = {}
    divs = {}
    for pid, (ra, rb) in pares.items():
        rels[pid] = S.relate(ra, rb)
        fa, _ = get(ra["path"], ra["headers"])
        fb, _ = get(rb["path"], rb["headers"])
        fps[pid] = (fa, fb)
        divs[pid] = F.core_differs(fa, fb)
    # repro de cada par (E1)
    repro = {}
    for pid, (ra, rb) in pares.items():
        fa2, _ = get(ra["path"], ra["headers"])
        fb2, _ = get(rb["path"], rb["headers"])
        repro[pid] = (fa2, fb2)
    informe["pares"] = {
        pid: {"relation": rels[pid]["relation"],
              "diferencial": divs[pid]}
        for pid in pares}
    reqs_ctl = 0

    # ---------- 3. convergencia P3-DI (cross-request)
    fa3, fb3 = fps["P3-DI"]
    conv = F.converged(fa3, fb3)
    fa3r, fb3r = repro["P3-DI"]
    conv_r = F.converged(fa3r, fb3r)
    conv_repro = bool(conv["match"] and conv_r["match"])
    path_specific = bool(
        fspec and fspec.get("valid")
        and F.core_differs(fspec, fa3)
        and F.core_differs(fspec, fb3))
    conv_attrib = (conv["match"] and conv["state"] == "ATRIBUIDA"
                   and conv_r["match"]
                   and conv_r["state"] == "ATRIBUIDA"
                   and path_specific)
    if conv["match"] and not path_specific:
        conv["state"] = "APARENTE-GENERICA"
        conv["nota"] = ("el target sirve contenido identico "
                        "para paths distintos: convergencia "
                        "sin atribucion posible")

    # ---------- 4. controles (sobre el par que diverge)
    div_pid = None
    for pid in ("P1-EQ", "P2-SESS"):
        if divs[pid]:
            div_pid = pid
            break
    if div_pid:
        ra, rb = pares[div_pid]
        ctl = C.run(url, fps[div_pid][0], fps[div_pid][1],
                    ra, rb, base, timeout=timeout)
        reqs_ctl = ctl["requests"]
    else:
        ctl = {"controls": {}, "explican": [], "requests": 0}
        if conv["match"]:
            ra, rb = pares["P3-DI"]
            ctl = C.run(url, fa3, fb3, ra, rb, base,
                        timeout=timeout)
            reqs_ctl = ctl["requests"]
    informe["controls"] = ctl
    informe["requests"] = reqs + reqs_ctl
    informe["max_requests"] = MAX_REQS

    # ---------- 5. correlacion
    eq_div = bool(divs["P1-EQ"])
    eq_repro = bool(divs["P1-EQ"]) and \
        F.core_differs(*repro["P1-EQ"]) is not None and \
        F.core_differs(*fps["P1-EQ"]) == \
        F.core_differs(*repro["P1-EQ"])
    sess_div = bool(divs["P2-SESS"])
    binding, binding_just = _binding(
        eq_div, eq_repro, conv["match"], conv_repro, conv_attrib,
        fps["P1-EQ"][0], fps["P1-EQ"][1],
        [fp for par in fps.values() for fp in par])
    informe["correlation"] = {
        "eq_divergente": eq_div,
        "eq_reproducible": eq_repro,
        "sess_divergente": sess_div,
        "convergencia": conv,
        "convergencia_repro": conv_repro,
        "convergencia_atribuida": conv_attrib,
        "especificidad_path": path_specific,
        "binding_evidence": binding,
        "binding_nota": binding_just}

    # ---------- 6. vector E0-E6 (condiciones, no puntos)
    ev = {"E0": bool(eq_div or sess_div or conv["match"]),
          "E1": bool(eq_repro or conv_repro),
          "E2": eq_div, "E3": binding in ("MODERATE", "STRONG"),
          "E4": (eq_div and eq_repro
                 and (fps["P1-EQ"][0]["signals"]
                      ["cache_status"]["state"] == "OBSERVED"
                      or fps["P1-EQ"][1]["signals"]
                      ["cache_status"]["state"] == "OBSERVED")),
          "E5": bool(conv_attrib and conv_repro),
          "E6": bool(conv_attrib and conv_repro
                     and fa3 and fa3.get("valid")
                     and fa3["signals"]["status_code"]["value"]
                     and fa3["signals"]["status_code"]["value"]
                     < 400)}
    informe["evidence"] = ev

    # ---------- 7. JUEZ determinista
    juez = {"regla": ("DEMO exige binding STRONG + E5/E6 + "
                      "controles criticos PASSED + atribucion + "
                      "baseline no ambiguo; explicacion legitima "
                      "-> BENIGN; sin poder discriminatorio -> "
                      "UNKNOWN")}
    bc = base["classification"]
    ctrl_ok = all(ctl["controls"].get(c, {}).get("status")
                  != "FAILED" for c in CRITICOS)
    if bc in ("AMBIGUO", "INVALID"):
        verdicto = "UNKNOWN"
        juez["nota"] = ("baseline %s: sin poder "
                        "discriminatorio no se concluye" % bc)
    elif (ctl["explican"] and (eq_div or sess_div)):
        verdicto = "BENIGN"
        juez["nota"] = ("diferencial explicado por control: %s"
                        % ",".join(ctl["explican"]))
    elif (conv_attrib and conv_repro and binding == "STRONG"
            and ctrl_ok and bc in ("STABLE", "VARIANT")
            and (ev["E5"] or ev["E6"])):
        verdicto = "DEMO"
        juez["nota"] = ("representaciones semanticamente "
                        "DISTINTAS comparten estado: peticion "
                        "inocente recibio respuesta ajena, "
                        "reproducible, con especificidad de "
                        "path demostrada")
    elif eq_div and eq_repro and ctrl_ok \
            and binding in ("MODERATE", "STRONG"):
        verdicto = "SUSPICIOUS"
        juez["nota"] = ("par EQUIVALENT divergente reproducible "
                        "con controles superados y binding %s; "
                        "sin impacto de seguridad demostrado"
                        % binding)
    elif conv["match"] and not conv_attrib:
        verdicto = "BENIGN"
        juez["nota"] = ("convergencia aparente sin atribucion "
                        "(%s)" % conv.get("nota",
                                          "nucleos iguales sin "
                                          "atribucion clara"))
    elif eq_div and eq_repro:
        verdicto = "DIFFERENTIAL"
        juez["nota"] = ("diferencia reproducible + relacion "
                        "semantica clara + baseline usable; "
                        "evidencia de impacto insuficiente")
    elif eq_div or sess_div:
        verdicto = "UNKNOWN"
        juez["nota"] = ("divergencia sin reproducibilidad o "
                        "controles incompletos: evidencia "
                        "insuficiente")
    else:
        verdicto = "STABLE"
        juez["nota"] = ("baseline %s y comportamiento "
                        "consistente" % bc)
    juez["verdicto"] = verdicto
    informe["juez"] = juez
    informe["verdicto"] = verdicto
    return informe


def _render(informe):
    out = ["CACHE-CORRELATION: %s" % informe.get("target", "?"),
           "-" * 52,
           "verdicto: %s" % informe.get("verdicto", "?"),
           "juez: %s" % informe.get("juez", {}).get("verdicto"),
           ""]
    b = informe.get("baseline") or {}
    out.append("baseline: %s %s" % (b.get("classification"),
                                    b.get("characterization",
                                          "")))
    out.append("evidence: %s" % json.dumps(
        informe.get("evidence", {})))
    c = informe.get("correlation") or {}
    out.append("binding: %s (%s)" % (
        c.get("binding_evidence"), c.get("binding_nota")))
    out.append("")
    out.append("pares:")
    for pid, p in (informe.get("pares") or {}).items():
        out.append("  %-8s rel=%-9s dif=%s" % (
            pid, p["relation"], p["diferencial"]))
    out.append("")
    out.append("controles:")
    for name, ctl in (informe.get("controls", {})
                      .get("controls") or {}).items():
        out.append("  %-16s %-14s %s" % (
            name, ctl["status"], ctl["evidence"][:60]))
    out.append("")
    out.append("requests: %s/%s" % (informe.get("requests"),
                                    informe.get("max_requests")))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="CACHE-CORRELATION v0.79")
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
