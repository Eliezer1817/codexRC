#!/usr/bin/env python3
"""STATE-CORRELATION (v0.78.0): un veredicto por target, no por
sonda.

No agrega payloads. Toma lo que v0.75 (contrato del edge),
v0.76 (representacion) y v0.77 (estado de conexion) observan
sobre el MISMO target y lo une en una ficha de estado unica.

Cuatro resultados:
  STABLE                      sin nada observable fuera de
                              varianza
  PIPE-BENIGN                 desplazamiento observado PERO la
                              conexion inocente quedo limpia:
                              pipelining legitimo del front
                              (edge honra TE, RFC 7230).
                              SELLADO: re-observarlo mil veces
                              jamas escala
  STATE-CHANGED               cambio de estado reproducible sin
                              evidencia cross-connection
  CROSS-CONNECTION-MISMATCH   la conexion inocente recibio
                              respuesta ajena: desacuerdo real
                              de cadena. UNICO que alimenta la
                              escalera

EVIDENCE QUALITY (E0-E5), anotacion transversal:
  E0  observacion nula
  E1  reproducible
  E2  diferencial
  E3  downstream observado (ECO)
  E4  cross-connection
  E5  impacto de seguridad (respuesta ajena entregada a una
      conexion inocente, reproducible)

El vector va a un JUEZ determinista, no a una suma:
DEMO exige E4 + E5 SIEMPRE (E3 sube confianza, no es
requerido). La confianza sube porque llego evidencia
independiente que reduce incertidumbre, no porque una
anomalia se repitio.

REGLA v0.77 (leccion del falso DEMO): un desplazamiento en
conexion unica NO demuestra desync; hay que demostrar
contaminacion o desacuerdo entre conexiones independientes.
"""
import argparse
import json
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))

from core.edge_profile import profile
from core import normalization_audit
from core import connection_state


def _e_representacion(f76):
    """Mejor evidencia de la capa REPRESENTACION (v0.76)."""
    mejor = {"nivel": "E0", "detalle": "sin observacion"}
    for v, r in (f76.get("matriz") or {}).items():
        verd = r.get("veredicto")
        eco = r.get("eco") or {}
        # E3 = downstream OBSERVADO: el ECO existe y reporta la
        # representacion que llego (te=none es observacion de
        # normalizacion; te intacto, de conservacion)
        eco_presente = bool(eco)
        if eco_presente and verd in ("MISMATCH", "NORMALIZED",
                                     "CONSERVED"):
            if mejor["nivel"] in ("E0", "E2"):
                mejor = {"nivel": "E3", "detalle": (
                    f"{v}: {verd} con ECO downstream "
                    f"(te={eco.get('te', '?')})")}
        elif verd in ("NORMALIZED-APARENTE",
                      "CONSERVED-APARENTE") \
                and mejor["nivel"] == "E0":
            mejor = {"nivel": "E2", "detalle":
                     f"{v}: {verd} (diferencial)"}
    return mejor


def _e_conexion(f77):
    """Evidencia de la capa CONNECTION-STATE (v0.77)."""
    t2 = (f77.get("resultados") or {}).get("T2:veneno", {})
    v = t2.get("veredicto")
    if v == "DEMO":
        return {"nivel": "E4", "detalle": (
            "respuesta ajena entregada a una conexion inocente, "
            "reproducible (cross-connection)")}
    if v == "SOSPECHA":
        return {"nivel": "E2", "detalle": (
            "cambio de estado reproducible sin evidencia "
            "cross-connection")}
    if v == "STATE-STABLE+PIPE":
        return {"nivel": "E2", "detalle": (
            "desplazamiento de B observado pero conexion "
            "inocente limpia: PIPE (benigno)")}
    if v == "STATE-CHANGED":
        return {"nivel": "E2", "detalle": "cambio de estado"}
    if v == "REJECTED":
        return {"nivel": "E0", "detalle": "veneno rechazado"}
    return {"nivel": "E0",
            "detalle": "sin desplazamiento observable"}


def _e_impacto(f77):
    """Evidencia de la capa SECURITY-IMPACT."""
    t2 = (f77.get("resultados") or {}).get("T2:veneno", {})
    if t2.get("veredicto") == "DEMO" and t2.get("conn2_marker"):
        return {"nivel": "E5", "detalle": (
            "impacto observado: request inocuo de otro cliente "
            "recibio la respuesta del POST del veneno")}
    return {"nivel": "E0",
            "detalle": "ningun impacto de seguridad observado"}


def _sello_pipe(f77):
    """PIPE-BENIGN queda sellado: nada de lo re-observado puede
    elevarlo. El desplazamiento ya fue observado y NO escalo."""
    t2 = (f77.get("resultados") or {}).get("T2:veneno", {})
    return {"sellado": t2.get("veredicto") == "STATE-STABLE+PIPE",
            "nota": ("desplazamiento observado con conexion "
                     "inocente limpia: pipelining legitimo del "
                     "front; re-observarlo no lo eleva")}


def audit(cfg):
    url = cfg["url"]
    timeout = float(cfg.get("timeout", 10.0))
    informe = {"target": url}

    # ---- capas observadas sobre el mismo target
    f75 = profile({"url": url, "timeout": timeout})
    f76 = normalization_audit.audit({"url": url,
                                     "timeout": timeout})
    f77 = connection_state.audit({"url": url,
                                  "timeout": timeout})
    informe["requests"] = (f75.get("requests", 11)
                           + f76.get("requests", 0)
                           + f77.get("requests", 0))

    # ---- identificadores de estado (ficha unica)
    base = f77.get("baseline") or {}
    t2 = (f77.get("resultados") or {}).get("T2:veneno", {})
    informe["state_id"] = {
        "reuse": f75.get("reuse"),
        "aceptadas": f76.get("aceptadas", []),
        "baseline_varianza": (f"{base.get('huellas_B', '?')}"
                              f" huella(s) en "
                              f"{base.get('corridas', '?')} corridas"),
        "n_resp_baseline": base.get("n_resp"),
        "b1_tragado": t2.get("b1_tragado"),
        "cross_connection_effect": (
            "respuesta-ajena" if t2.get("conn2_marker")
            else ("silencio" if t2.get("conn2_silencio")
                  else "limpia")),
        "reproducibilidad": t2.get("escalera",
                                   "sin escalera necesaria"),
        "cerrada_tras_A": (t2.get("evidencia") or {})
        .get("a_status") in STATUS_SILEN,
    }
    informe["sello_pipe"] = _sello_pipe(f77)

    # ---- vector de calidad de evidencia
    vector = {
        "REPRESENTATION": _e_representacion(f76),
        "CONNECTION-STATE": _e_conexion(f77),
        "SECURITY-IMPACT": _e_impacto(f77)}
    informe["evidence_quality"] = vector

    # ---- cuatro resultados
    ambiguo = ((f77.get("baseline") or {})
               .get("huellas_B", 0) or 0) > 1
    v77 = t2.get("veredicto")
    if ambiguo:
        resultado = "UNKNOWN-BASELINE"
    elif v77 == "DEMO":
        resultado = "CROSS-CONNECTION-MISMATCH"
    elif v77 == "SOSPECHA" or v77 == "STATE-CHANGED":
        resultado = "STATE-CHANGED"
    elif v77 == "STATE-STABLE+PIPE":
        resultado = "PIPE-BENIGN"
    else:
        resultado = "STABLE"
    informe["resultado"] = resultado

    # ---- JUEZ determinista (no suma: vector)
    niveles = {k: int(v["nivel"][1]) for k, v in
              vector.items()}
    e4 = niveles.get("CONNECTION-STATE", 0) >= 4 \
        or niveles.get("SECURITY-IMPACT", 0) >= 4
    e5 = niveles.get("SECURITY-IMPACT", 0) >= 5
    juez = {
        "regla": ("DEMO exige E4 (cross-connection) + E5 "
                  "(impacto observado); E3 sube confianza, no "
                  "es requerido; PIPE-BENIGN esta sellado y no "
                  "escala por re-observacion"),
        "vector": {k: v["nivel"] for k, v in vector.items()}}
    if resultado == "PIPE-BENIGN":
        juez["veredicto"] = "PIPE-BENIGN (sellado)"
        juez["nota"] = informe["sello_pipe"]["nota"]
    elif ambiguo:
        juez["veredicto"] = "UNKNOWN"
        juez["nota"] = ("baseline inestable: sin poder "
                        "discriminatorio ninguna capa concluye")
    elif e4 and e5:
        juez["veredicto"] = "DEMO"
    elif e4:
        juez["veredicto"] = "SOSPECHA"
    elif niveles.get("CONNECTION-STATE", 0) >= 2 and \
            v77 in ("SOSPECHA", "STATE-CHANGED"):
        juez["veredicto"] = "SOSPECHA"
    else:
        juez["veredicto"] = "STABLE"
    informe["juez"] = juez

    # ---- atribucion por capa
    eco_presente = any(
        (r.get("eco") or {})
        for r in (f76.get("matriz") or {}).values())
    atribucion = {
        "layers_con_evidencia": [],
        "unknown_layers": [],
        "responsible_layer": "unknown"}
    if f75.get("aceptadas") or f75.get("rejected"):
        atribucion["layers_con_evidencia"].append("edge")
    if eco_presente:
        atribucion["layers_con_evidencia"].append("downstream")
    if e4:
        atribucion["layers_con_evidencia"].append(
            "cadena-front/back (desacuerdo de framing)")
        atribucion["responsible_layer"] = (
            "desacuerdo de framing entre capas; atribucion "
            "finapor capa queda para ATTRIBUTION-CHAIN (v0.79)")
    for capa in ["cache", "origin", "balanceador",
                 "aplicacion"]:
        if capa not in atribucion["layers_con_evidencia"]:
            atribucion["unknown_layers"].append(capa)
    informe["attribution"] = atribucion
    return informe


STATUS_SILEN = (None,)


def _render(informe):
    out = [f"STATE-CORRELATION: {informe.get('target', '?')}",
           "-" * 52,
           f"resultado: {informe.get('resultado', '?')}",
           f"juez: {informe.get('juez', {}).get('veredicto')}",
           ""]
    out.append("evidence quality:")
    for k, v in (informe.get("evidence_quality")
                 or {}).items():
        out.append(f"  {k:18} {v['nivel']:3} {v['detalle']}")
    out.append("")
    sid = informe.get("state_id") or {}
    out.append("ficha de estado:")
    out.append(f"  reuse={sid.get('reuse')} "
               f"varianza={sid.get('baseline_varianza')} "
               f"n_resp={sid.get('n_resp_baseline')}")
    out.append(f"  b1_tragado={sid.get('b1_tragado')} "
               f"cross_conn={sid.get('cross_connection_effect')}")
    out.append(f"  repro: {sid.get('reproducibilidad')}")
    out.append("")
    at = informe.get("attribution") or {}
    out.append(f"atribucion: {at.get('responsible_layer')}")
    out.append(f"  con evidencia: "
               f"{', '.join(at.get('layers_con_evidencia', []))}")
    out.append(f"  unknown: "
               f"{', '.join(at.get('unknown_layers', []))}")
    out.append("")
    out.append(f"requests: {informe.get('requests', '?')}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="STATE-CORRELATION: un veredicto por target "
                    "con calidad de evidencia expuesta")
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
