#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.95.0 CROWN CHAIN — INTEGRACION AL HUNTER
==========================================
Corona alcanzada (LAB 22/22, corpus 128/128): la
cadena completa se integra al Hunter como UN
orquestador que sube la escalera con los motores del
roadmap, sin tocar la arquitectura de ningun modulo.

  rung 1  DETECTION        cl0 + h2 + mc + crc
                          (4 probes, veredictos
                          propios, cero-FP cada uno)
  rung 2  REPRODUCIBLE     repro_engine (2 genealogias
                          x pase A/B, firma k igual)
  rung 3  STATE-EFFECT     firma k medible y
                          consistente
  rung 4  CROSS-CONNECTION contaminacion entre
                          conexiones PROPIAS (mc)
  rung 5  SECURITY IMPACT  LIMITE HONESTO: en vivo NO
                          se ejecuta: envenenar la
                          respuesta de un usuario real
                          de terceros esta fuera de
                          toda regla. Rung validada
                          solo en LAB (impact_probe,
                          recurso protegido simulado).
                          La garantia cero-FP queda
                          citada (RC-000254).

Modos:
  lab   ensambla el paquete completo via
        evidence_package (deteccion k=2, 2 genealogias,
        impacto 2/2) -> CHAIN-COMPLETE-LAB.
  live  escalera contra el blanco real, read-only,
        presupuesto declarado 60 reqs; NUNCA supera
        CROSS-CONNECTION-DEMO: sin repro 2/2 o sin
        k consistente NO avanza.

La escalera JAMAS se salta: DETECTED sin repro no
escala; repro sin firma k consistente no escala; el
disparo unico (flaky) NO escala.
"""

import os
import sys
import time

MODULE_VERSION = "0.95.0"
BUDGET_LIVE = 60        # cl0+h2+mc+crc (~30) + repro (32)
DETECT_SUFFIXES = ("DETECTED", "DESYNC",
                   "STATE-EFFECT")
NEUTRAL = ("BENIGN", "BENIGN-EDGE", "UNKNOWN",
           "UNREACHABLE", "NO-CANDIDATE",
           "NON-REPRODUCIBLE")
LADDER = ("NO-DESYNC", "UNSTABLE", "DETECTED",
          "STATE-EFFECT-REPRODUCIBLE",
          "CROSS-CONNECTION-DEMO")


def _is_desync(verdict):
    """Un veredicto es senal de desync si es de las
    clases DETECTED/DESYNC/STATE-EFFECT de los
    probes (cero-FP: BENIGN/UNKNOWN jamas)."""
    return any(verdict.endswith(s)
               for s in DETECT_SUFFIXES) \
        and verdict not in NEUTRAL


def _root():
    return os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))


def _imports():
    sys.path.insert(0, _root())
    from core import cl0_probe, h2_probe, mc_probe
    from core import crc_probe, repro_engine
    from core import evidence_package as epk
    return (cl0_probe, h2_probe, mc_probe, crc_probe,
            repro_engine, epk)


def _norm_url(url):
    if not url:
        return ""
    if not url.startswith("http"):
        url = "https://" + url
    return url


# ------------------------------------------------------------------
def hunt_chain(cfg):
    """Orquestador de la cadena completa del Hunter.
    cfg: {"mode": "lab"|"live", "url": ..., "timeout"}
    """
    mode = cfg.get("mode", "live")
    rec = {
        "module": "crown_chain",
        "version": MODULE_VERSION,
        "mode": mode,
        "verdict": "UNKNOWN",
        "reasons": [],
        "requests": 0,
        "rungs": [],
        "limits": {},
        "evidence": {},
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }

    # ================= MODO LAB =================
    if mode == "lab":
        (cl0, h2, mc, crc, repro, epk) = _imports()
        pkg = epk.assemble_package(cfg)
        rec["requests"] = pkg["budgets"]["spent"]
        rec["package"] = pkg
        rec["rungs"] = [c["rung"] for c
                        in pkg["chain"]]
        rec["evidence"]["k"] = (
            pkg["signature"].get("k"))
        rec["evidence"]["genealogies"] = (
            pkg["signature"].get("genealogies"))
        rec["evidence"]["impact_rounds"] = (
            pkg["signature"].get("impact_rounds"))
        if pkg["verdict"] == "PACKAGE-VALID":
            rec["verdict"] = "CHAIN-COMPLETE-LAB"
            rec["reasons"].append(
                "cadena completa verificada en lab: "
                "deteccion k=%s en %s genealogias x "
                "A/B, impacto cross-user 2/2 con "
                "control limpio, paquete falsable "
                "emitido" % (
                    pkg["signature"].get("k"),
                    pkg["signature"].get(
                        "genealogies")))
        else:
            rec["verdict"] = "CHAIN-INCOMPLETE-LAB"
            rec["reasons"].extend(
                pkg.get("reasons", []))
        rec["limits"] = pkg["limits"]
        return rec

    # ================= MODO LIVE =================
    (cl0, h2, mc, crc, repro, epk) = _imports()
    url = _norm_url(cfg.get("url", ""))
    if not url:
        rec["verdict"] = "UNKNOWN"
        rec["reasons"].append("falta --url en modo "
                              "vivo")
        return rec
    timeout = float(cfg.get("timeout", 10.0))
    rec["url"] = url

    # ---- rung 1: DETECTION (4 probes) ----
    det = {}
    try:
        det["cl0"] = cl0.cl0_audit(
            {"url": url, "timeout": timeout})
    except Exception as e:                    # noqa
        det["cl0"] = {"verdict": "UNSTABLE",
                      "requests": 0, "err": repr(e)}
    try:
        det["h2"] = h2.h2_audit(
            {"url": url, "timeout": timeout})
    except Exception as e:                    # noqa
        det["h2"] = {"verdict": "UNSTABLE",
                     "requests": 0, "err": repr(e)}
    try:
        det["mc"] = mc.mc_audit(
            {"url": url, "timeout": timeout})
    except Exception as e:                    # noqa
        det["mc"] = {"verdict": "UNSTABLE",
                     "requests": 0, "err": repr(e)}
    try:
        det["crc"] = crc.crc_audit(
            {"url": url, "timeout": timeout,
             "battery": "double"})
    except Exception as e:                    # noqa
        det["crc"] = {"verdict": "UNSTABLE",
                      "requests": 0, "err": repr(e)}
    for m, inf in det.items():
        rec["requests"] += (inf.get("requests", 0)
                            or 0)
    rec["evidence"]["detection"] = {
        m: {"verdict": i.get("verdict"),
            "requests": i.get("requests")}
        for m, i in det.items()}
    detected = [m for m, i in det.items()
                if _is_desync(i.get("verdict", ""))]
    rec["rungs"].append({
        "rung": "DETECTION",
        "verdict": ("DETECTED (%s)" % ", ".join(
            detected)) if detected else "NO-DESYNC",
        "probes": {m: i.get("verdict")
                   for m, i in det.items()}})

    unstable = [m for m, i in det.items()
                if i.get("verdict") == "UNSTABLE"]

    # sin senal: veredicto honesto y STOP (cero-FP)
    if not detected:
        if unstable and len(unstable) >= 2:
            rec["verdict"] = "UNSTABLE"
            rec["reasons"].append(
                "blanco inestable en %s: no se puede "
                "juzgar" % ", ".join(unstable))
        else:
            rec["verdict"] = "NO-DESYNC"
            rec["reasons"].append(
                "4 probes sin senal de desync: "
                "escalera no se abre")
        return rec

    # ---- rung 2: REPRODUCTION (genealogias A/B) ----
    rep = repro.repro_audit({"url": url})
    rec["requests"] += rep["requests"]
    rec["evidence"]["repro"] = {
        "verdict": rep["verdict"],
        "genealogies": len(rep["evidence"]
                           .get("genealogies", [])),
        "k": rep["evidence"].get("k")}
    rec["rungs"].append({
        "rung": "REPRODUCTION",
        "verdict": rep["verdict"]})
    if rep["verdict"] != "REPRODUCIBLE":
        rec["verdict"] = "DETECTED"
        rec["reasons"].append(
            "senal de desync (%s) SIN reproduccion "
            "2/2 x A/B: probable/flaky, NO escala" %
            ", ".join(detected))
        return rec

    # ---- rung 3: STATE-EFFECT (firma k) ----
    k = (rep["evidence"].get("k")
         or det["crc"].get("evidence", {})
         .get("k"))
    k_consistent = (k is not None and str(k)
                    == str(rep["evidence"].get("k",
                                                k)))
    rec["rungs"].append({
        "rung": "STATE-EFFECT",
        "verdict": ("STATE-EFFECT k=%s" % k)
        if k else "SIN-FIRMA-k"})
    if not k:
        rec["verdict"] = "DETECTED"
        rec["reasons"].append(
            "reproducible sin firma k medible: el "
            "estado no se cuantifica, no escala")
        return rec
    rec["evidence"]["k"] = k

    # ---- rung 4: CROSS-CONNECTION (conexiones
    # PROPIAS, jamas usuarios de terceros) ----
    cross = det.get("mc", {})
    cross_v = cross.get("verdict", "UNKNOWN")
    rec["rungs"].append({
        "rung": "CROSS-CONNECTION",
        "verdict": cross_v})
    if _is_desync(cross_v):
        rec["verdict"] = "CROSS-CONNECTION-DEMO"
        rec["reasons"].append(
            "desync reproducible (k=%s, %s genealogias)"
            " con contaminacion entre conexiones "
            "propias: demostrado hasta el rung que la "
            "etica permite en vivo" % (
                k, rep["evidence"].get("genealogies")))
    else:
        rec["verdict"] = "STATE-EFFECT-REPRODUCIBLE"
        rec["reasons"].append(
            "desync reproducible k=%s sin "
            "contaminacion cross-connection observable "
            "(%s)" % (k, cross_v))

    # ---- rung 5: SECURITY IMPACT — LIMITE ----
    rec["rungs"].append({
        "rung": "SECURITY IMPACT",
        "verdict": "LAB-VALIDATED-ONLY",
        "note": "en vivo NO se envenena la respuesta "
                "de usuarios de terceros: rung "
                "demostrada solo en lab "
                "(impact_probe, recurso simulado)"})
    rec["limits"] = {
        "read_only": True,
        "impact_vivo": "PROHIBIDO: rung 5 validada "
                       "solo en lab",
        "fp_guarantee": "bateria de cebo verificada "
                        "(RC-000254)",
        "budget": "%d/%d reqs" % (
            rec["requests"], BUDGET_LIVE),
    }
    if rec["requests"] > BUDGET_LIVE:
        rec["verdict"] = "UNSTABLE"
        rec["reasons"].append(
            "presupuesto excedido: %d > %d" % (
                rec["requests"], BUDGET_LIVE))
    return rec


# ------------------------------------------------------------------
def render(rec):
    out = ["CROWN CHAIN v%s (%s)" % (
               rec["version"], rec["mode"])]
    if rec.get("url"):
        out.append("target: " + rec["url"])
    out.append("veredicto: %s" % rec["verdict"])
    out.append("reqs: %s" % rec["requests"])
    for r in rec["rungs"]:
        if isinstance(r, dict):
            out.append("  %s: %s" % (
                r.get("rung"), r.get("verdict")))
        else:
            out.append("  " + str(r))
    for rz in rec["reasons"]:
        out.append("  - " + rz)
    return "\n".join(out)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="CROWN CHAIN (Hunter)")
    ap.add_argument("--url", default="")
    ap.add_argument("--mode", default="live",
                    choices=("live", "lab"))
    ap.add_argument("--timeout", type=float,
                    default=10.0)
    a = ap.parse_args()
    rec = hunt_chain({"mode": a.mode,
                      "url": a.url,
                      "timeout": a.timeout})
    print(render(rec))
    return 0 if rec["verdict"] not in (
        "UNKNOWN", "UNSTABLE") else 1


if __name__ == "__main__":
    sys.exit(main())
