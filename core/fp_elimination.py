#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.93.0 FP-ELIMINATION
=====================
Etapa 21-bis del roadmap: caza SISTEMATICA de falsos
positivos. La red conservadora de veredictos (flaky no
escala, benigno se descarta, muerto no se promedia) ya
elimina la mayoria de los FP por diseno; este modulo los
convierte en GARANTIA verificable:

1. TABLA DE CLASES DE SENAL: cada clase observable del
   oraculo tiene su regla de clasificacion y su estatus
   reportable. Una senal sin regla = FP potencial: el
   modulo NO aprueba.

2. BATERIA DE CEBO (FP-bait): escenarios que DEBEN
   producir veredictos NO reportables. Si algun cebo
   produce un veredicto reportable (SECURITY-IMPACT-
   DEMO), es un falso positivo: FP-LEAK.

   Cebos: quiet_drain (drenaje), benign_pin (conn
   pinneada), pool_shift (mispairing benigno cruzado),
   flaky_swap (swap 1/2, un solo disparo en la vida).

3. CONTROL POSITIVO: pool_swap DEBE producir
   SECURITY-IMPACT-DEMO. Sin control positivo la
   bateria es vacua (no puede detectar nada): UNSTABLE,
   sin claim.

Veredictos:
  FP-ELIMINATED  todos los cebos no reportables Y el
                 control positivo reporta: la garantia
                 cero-FP queda VERIFICADA en bateria.
  FP-LEAK        un cebo produjo veredicto reportable:
                 falso positivo REAL: hay que arreglar.
  UNSTABLE       lab muerto o control positivo mudo:
                 no se puede juzgar.

Presupuesto: 5 auditorias x 5 reqs = 25 (techo 26).
Read-only. Labs propios, nada en paralelo.
"""

import os
import subprocess
import sys
import time

MODULE_VERSION = "0.93.0"
BUDGET = 26
LAB_PORTS = {"quiet_drain": 19611,
             "benign_pin": 19612,
             "pool_swap": 19613,
             "pool_shift": 19614,
             "flaky_swap": 19615}
BAITS = ("quiet_drain", "benign_pin",
         "pool_shift", "flaky_swap")
POSITIVE = "pool_swap"
NON_REPORTABLE = ("BENIGN", "BENIGN-EDGE",
                  "IMPACT-CANDIDATE", "UNKNOWN",
                  "UNSTABLE", "UNREACHABLE",
                  "NO-CANDIDATE",
                  "CRC-DETECTED", "CRC-DESYNC",
                  "NON-REPRODUCIBLE")
REPORTABLE = ("SECURITY-IMPACT-DEMO",
              "CRC-STATE-EFFECT")

# Tabla de clases de senal: clase observable -> regla
# (veredicto, reportable). Una senal sin regla es un FP
# potencial: el modulo no aprueba.
FP_TABLE = {
    "ALIGNED":
        ("la victima recibe su propio eco: BENIGN", 0),
    "MISPAIRED-BENIGN":
        ("atribucion alterada sin contenido protegido: "
         "IMPACT-CANDIDATE, NO reportable", 0),
    "SMUGGLED-PROTECTED-1/2":
        ("swap probable sin reproduccion: "
         "IMPACT-CANDIDATE, NO reportable", 0),
    "SMUGGLED-PROTECTED-2/2":
        ("swap reproducido con control limpio: "
         "SECURITY-IMPACT-DEMO, reportable", 1),
    "NO-RESPONSE":
        ("blanco muerto o mute: UNSTABLE honesto, "
         "sin claim", 0),
    "RST":
        ("el edge rechaza el smuggle: BENIGN-EDGE", 0),
    "UNEXPECTED":
        ("cuerpo sin clasificar: UNKNOWN, cero-FP", 0),
    "DISPERSO":
        ("senal sin permutacion consistente: NO "
         "escala a STATE-EFFECT", 0),
}


def _lab_path():
    root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "labs", "impact_lab.py")


def _port_up(port, timeout=8.0):
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            s = socket.create_connection(
                ("127.0.0.1", port), 0.4)
            s.close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


def _run_scenario(scen, smug, _audit):
    """Spawnea instancia FRESCA del lab, corre la
    auditoria de impacto, mata el lab. Devuelve
    (verdict, informe) o (None, informe-UNSTABLE)."""
    port = LAB_PORTS[scen]
    if _port_up(port, 0.5):
        return None, {"verdict": "UNSTABLE",
                      "reasons": ["puerto %d ocupado "
                                  "por instancia "
                                  "ajena" % port],
                      "requests": 0}
    proc = subprocess.Popen(
        [sys.executable, _lab_path(), scen, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    informe = None
    try:
        if not _port_up(port):
            return None, {"verdict": "UNSTABLE",
                          "reasons": ["lab %s muerto al "
                                      "levantar" % scen],
                          "requests": 0}
        informe = _audit({"host": "127.0.0.1",
                          "port": port,
                          "smuggle_path": smug})
        return informe["verdict"], informe
    finally:
        proc.kill()
        proc.wait()


def fp_audit(cfg):
    try:
        from core import impact_probe as ipr
    except ImportError:
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        from core import impact_probe as ipr

    informe = {
        "module": "fp_elimination",
        "version": MODULE_VERSION,
        "verdict": "UNKNOWN",
        "reasons": [],
        "requests": 0,
        "evidence": {
            "baits": [], "positive_control": None,
            "fp_table": FP_TABLE},
    }

    # ---- 1) tabla de clases completa ----
    clases = {"ALIGNED", "MISPAIRED-BENIGN",
              "SMUGGLED-PROTECTED-1/2",
              "SMUGGLED-PROTECTED-2/2", "NO-RESPONSE",
              "RST", "UNEXPECTED", "DISPERSO"}
    if set(FP_TABLE) != clases:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "tabla de clases incompleta: senal sin "
            "regla = FP potencial")
        return informe

    # ---- 2) bateria de cebo: NINGUN reportable ----
    leaks = []
    for scen in BAITS:
        smug = ("/?itok=attacker-echo"
                if scen == "pool_shift"
                else "/admin/secret")
        v, inf = _run_scenario(scen, smug,
                               ipr.impact_audit)
        informe["requests"] += (inf.get("requests", 0)
                                if inf else 0)
        rec = {"scenario": scen, "verdict": v,
               "requests": (inf or {}).get("requests")}
        informe["evidence"]["baits"].append(rec)
        if v is None:
            informe["verdict"] = "UNSTABLE"
            informe["reasons"].append(
                "cebo %s: lab muerto a mitad de "
                "bateria: sin claim" % scen)
            return informe
        if v in REPORTABLE:
            leaks.append(scen)

    # ---- 3) control positivo: DEBE reportar ----
    v, inf = _run_scenario(POSITIVE, "/admin/secret",
                           ipr.impact_audit)
    informe["requests"] += (inf.get("requests", 0)
                            if inf else 0)
    informe["evidence"]["positive_control"] = {
        "scenario": POSITIVE, "verdict": v}
    if v is None or v not in REPORTABLE:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "control positivo mudo (%s): bateria "
            "vacua, no se puede juzgar cero-FP" % v)
        return informe

    # ---- presupuesto duro ----
    if informe["requests"] > BUDGET:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "presupuesto excedido: %d > %d" % (
                informe["requests"], BUDGET))
        return informe

    # ---- veredicto ----
    if leaks:
        informe["verdict"] = "FP-LEAK"
        informe["reasons"].append(
            "cebo(s) con veredicto reportable: %s: "
            "FALSO POSITIVO real: hay que arreglar"
            % ", ".join(leaks))
    else:
        informe["verdict"] = "FP-ELIMINATED"
        informe["reasons"].append(
            "bateria de cebo limpia (0/%d reportables) "
            "y control positivo reporta (%s): la "
            "garantia cero-FP queda VERIFICADA" % (
                len(BAITS), v))
    return informe


def fp_source_invariants():
    """Reglas conservadoras cruzadas: los tres modulos
    de la escalera deben contener la regla de
    no-escala del disparo unico. Devuelve (ok, lista)."""
    root = os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    ok = True
    det = []
    reglas = [
        ("core/crc_probe.py",
         "NO reportable"),          # crc: 1/2 DETECTED
        ("core/repro_engine.py",
         "NO avanza"),              # repro: flaky
        ("core/impact_probe.py",
         "NO reproducido"),         # impact: 1/2
    ]
    for rel, marca in reglas:
        try:
            src = open(os.path.join(root, rel)).read()
            if marca not in src:
                ok = False
                det.append("%s sin regla de no-escala"
                           " (%r)" % (rel, marca))
        except OSError:
            ok = False
            det.append("%s ilegible" % rel)
    return ok, det


# ------------------------------------------------------------------
def main():
    import json
    inf = fp_audit({})
    print("veredicto:", inf["verdict"])
    print("reqs:", inf["requests"])
    for r in inf["reasons"]:
        print("  -", r)
    ok, det = fp_source_invariants()
    print("invariantes fuente:", "OK" if ok
          else "; ".join(det))
    if inf["verdict"] != "FP-ELIMINATED" or not ok:
        print(json.dumps(inf, indent=2, default=str))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
