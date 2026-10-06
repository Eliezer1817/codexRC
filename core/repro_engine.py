#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REPRODUCTION ENGINE v0.91 — etapa 21 del roadmap
(ultima etapa de MODULO antes de IMPACT / FP-ELIMINATION
/ EVIDENCE PACKAGE).

Escalera de impacto (nunca se salta):
  DESYNC OBSERVED -> REPRODUCIBLE (2 genealogias
  independientes) -> STATE EFFECT -> CROSS-CONNECTION
  -> SECURITY IMPACT.

Este modulo toma un candidato STATE-EFFECT y responde
UNA pregunta: la firma se reproduce a demanda?

Genealogia = estado del servidor INDEPENDIENTE:
  * modo lab: instancia FRESCA de labs/crc_lab.py
    (proceso y pool propios, puerto distinto).
  * modo vivo: secuencia completa de conexiones nuevas
    contra el blanco (sin estado compartido del lado
    del cliente).

Cada genealogia ejecuta DOS pases del probe subyacente
(por defecto crc_probe, bateria double):
  * pase A (deteccion): la corrida original.
  * pase B (replay): MISMA genealogia, corrida nueva
    que debe volver a mostrar la firma. Un disparo
    unico (flaky) NO escala: NON-REPRODUCIBLE.

Veredictos (conservadores, cero-FP):
  REPRODUCIBLE     todas las genealogias muestran
                   STATE-EFFECT con la MISMA firma
                   (k) en pase A y pase B.
  NON-REPRODUCIBLE hubo senal (DETECTED/STATE-EFFECT)
                   en algun pase pero no se sostiene
                   en A+B de todas las genealogias.
                   El candidato NO avanza.
  NO-CANDIDATE     todos los pases BENIGN/BENIGN-EDGE:
                   reproducible pero no es nada.
  UNSTABLE         instancia muerta o control caido:
                   no se puede juzgar. Sin claim.

Presupuesto: genealogias (2) x pases (2) x 8 reqs
= 32 requests max. Read-only. Python puro.
"""

import os
import subprocess
import sys
import time

MODULE_VERSION = "0.91.0"
ENGINE = "crc"          # probe subyacente (registro)
GENEALOGIES = 2         # 2 genealogias independientes
PASSES = ("A", "B")     # deteccion + replay por genealogia
BUDGET = 32             # 2 genealogias x 2 pases x 8 reqs
LAB_PORTS = (19511, 19512)
LAB_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "labs", "crc_lab.py")


# ------------------------------------------------------------------
# registro de probes subyacentes: cada uno expone
# <nombre>_audit(cfg) -> informe {verdict, requests,
# evidence{k}}. Agregar una bateria nueva = una linea aca.
# ------------------------------------------------------------------
def _audit(cfg):
    try:
        from core import crc_probe as crcp
    except ImportError:
        # ejecutado como script: agregar la raiz del
        # repo al path (patron de los probes)
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        from core import crc_probe as crcp
    return crcp.crc_audit(cfg)


def _port_up(host, port, timeout=8.0):
    """True si el puerto escucha antes de timeout."""
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection((host, port), 0.4)
            s.close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


def repro_audit(cfg):
    """Auditoria de reproducibilidad de un candidato.
    cfg:
      lab_scenario  escenario de labs/crc_lab.py
                    (modo lab; si esta, se spawnea
                    instancia fresca por genealogia)
      url           blanco (modo vivo, sin lab_scenario)
      genealogies   default 2 (max 2: presupuesto)
      battery       default 'double'
    """
    scen = cfg.get("lab_scenario")
    url = cfg.get("url", "")
    gens = int(cfg.get("genealogies", GENEALOGIES))
    if gens < 1:
        gens = 1
    if gens > 2:
        # presupuesto: >2 genealogias rompe el techo de
        # 32 reqs; rechazar antes de gastar nada.
        return {
            "module": "reproduction_engine",
            "version": MODULE_VERSION,
            "verdict": "UNSTABLE",
            "reasons": [
                "genealogies > 2 rompe el presupuesto "
                "de %d reqs; rechazado" % BUDGET],
            "requests": 0,
            "evidence": {},
        }
    battery = cfg.get("battery", "double")

    informe = {
        "module": "reproduction_engine",
        "version": MODULE_VERSION,
        "engine": ENGINE,
        "battery": battery,
        "genealogies": gens,
        "mode": "lab" if scen else "live",
        "url": url,
        "verdict": "UNKNOWN",
        "reasons": [],
        "requests": 0,
        "evidence": {"genealogies": []},
    }

    host = "127.0.0.1"
    proc = None
    try:
        for gi in range(gens):
            gal = {"genealogy": gi + 1,
                   "scenario": scen, "passes": {}}
            if scen:
                # genealogia = instancia FRESCA: proceso
                # y estado propios, puerto propio.
                port = LAB_PORTS[gi]
                if _port_up(host, port, 0.5):
                    informe["verdict"] = "UNSTABLE"
                    informe["reasons"].append(
                        "genealogia %d: puerto %d "
                        "ocupado por instancia ajena "
                        "(nunca se audita lo que uno "
                        "no spawnó)" % (gi + 1, port))
                    return informe
                if not os.path.exists(LAB_SCRIPT):
                    informe["verdict"] = "UNSTABLE"
                    informe["reasons"].append(
                        "labs/crc_lab.py ausente")
                    return informe
                proc = subprocess.Popen(
                    [sys.executable, LAB_SCRIPT,
                     scen, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                if not _port_up(host, port):
                    informe["verdict"] = "UNSTABLE"
                    informe["reasons"].append(
                        "genealogia %d: instancia no "
                        "escucha en %d (muerta al "
                        "levantar)" % (gi + 1, port))
                    return informe
                target = "http://%s:%s" % (host, port)
            else:
                target = url

            for p in PASSES:
                inf = _audit({"url": target,
                              "battery": battery})
                informe["requests"] += inf["requests"]
                gal["passes"][p] = {
                    "verdict": inf["verdict"],
                    "k": inf["evidence"].get("k"),
                    "reqs": inf["requests"]}
            informe["evidence"]["genealogies"].append(gal)

            if proc is not None:
                proc.kill()
                proc.wait()
                proc = None
    finally:
        if proc is not None:
            proc.kill()
            proc.wait()

    # presupuesto duro
    if informe["requests"] > BUDGET:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "presupuesto excedido: %d > %d" % (
                informe["requests"], BUDGET))
        return informe

    # clasificacion: recorrer pases por genealogia
    senal = False      # DETECTED/STATE-EFFECT en algun pase
    unstable = False   # instancia muerta o control caido
    sigs = []          # firmas (verdict, k) de cada pase
    for gal in informe["evidence"]["genealogies"]:
        for p in PASSES:
            v = gal["passes"][p]["verdict"]
            k = gal["passes"][p]["k"]
            if v in ("UNREACHABLE", "UNSTABLE",
                     "UNKNOWN"):
                unstable = True
            elif v not in ("BENIGN", "BENIGN-EDGE"):
                senal = True
                sigs.append((v, k))

    if unstable:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "pase con instancia muerta o control "
            "caido: no se puede juzgar la "
            "reproducibilidad (sin claim)")
    elif not senal:
        informe["verdict"] = "NO-CANDIDATE"
        informe["reasons"].append(
            "todas las genealogias y pases BENIGN/"
            "BENIGN-EDGE: reproducible pero no es nada")
    else:
        # exigir firma identica en A y B de TODAS las
        # genealogias: el disparo unico no escala
        repro = True
        for gal in informe["evidence"]["genealogies"]:
            a = (gal["passes"]["A"]["verdict"],
                 gal["passes"]["A"]["k"])
            b = (gal["passes"]["B"]["verdict"],
                 gal["passes"]["B"]["k"])
            if (a != b
                    or a[0] != "CRC-STATE-EFFECT"):
                repro = False
        if repro:
            informe["verdict"] = "REPRODUCIBLE"
            informe["reasons"].append(
                "firma CRC-STATE-EFFECT k=%s en pase A "
                "y B de las %d genealogias: el "
                "candidato ES reproducible a demanda" % (
                    sigs[0][1], len(
                        informe["evidence"][
                            "genealogies"])))
        else:
            informe["verdict"] = "NON-REPRODUCIBLE"
            informe["reasons"].append(
                "senal presente pero NO se sostiene en "
                "deteccion+replay de todas las "
                "genealogias: el candidato NO avanza "
                "(cero-FP)")
    return informe


if __name__ == "__main__":
    import json
    import argparse
    ap = argparse.ArgumentParser(
        description="REPRODUCTION ENGINE v0.91")
    ap.add_argument("--url", default="")
    ap.add_argument("--lab-scenario", default="")
    ap.add_argument("--genealogies", type=int,
                    default=GENEALOGIES)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not a.url and not a.lab_scenario:
        print("falta --url o --lab-scenario")
        sys.exit(2)
    inf = repro_audit({
        "url": a.url,
        "lab_scenario": a.lab_scenario or None,
        "genealogies": a.genealogies})
    if a.json:
        print(json.dumps(inf, indent=2, default=str))
    else:
        print("veredicto:", inf["verdict"])
        print("reqs:", inf["requests"])
        for r in inf["reasons"]:
            print("  -", r)
        for g in inf["evidence"].get(
                "genealogies", []):
            print("  genealogia %s:" % g["genealogy"],
                  {p: (g["passes"][p]["verdict"],
                       "k=%s" % g["passes"][p]["k"])
                   for p in PASSES})
