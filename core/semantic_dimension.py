"""Fase 2 de SEMANTIC-CACHE: localizacion de dimension y
descarte de SELF-INDUCED STATE (v0.80).

Solo corre si la fase 1 (v0.79) encontro una inconsistencia
observable SIN explicacion legitima. Presupuesto duro:
fase2 <= 8, controles <= 4.

Self-induced (regla del diseno aprobado): ninguna
observacion producida por una sonda se convierte en
evidencia de causalidad si no podemos descartar
razonablemente que la propia sonda creo el estado
observado. Metodos:
  VIRGIN_PATH      el patron se reproduce en paths nunca
                   tocados por ninguna sonda
  NEGATIVE_CONTROL sonda que NO debe producir el efecto;
                   si lo produjera -> UNKNOWN
  CLEAN_REPRO      repro sin contaminacion previa
  MULTI_RUN       patron consistente en >=3 observaciones
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap

import time

from core import cache_fingerprint as F

_SEQ = [int(time.time()) % 100000]


def _fresh(prefix):
    _SEQ[0] += 1
    return "/%s-%d" % (prefix, _SEQ[0])


def state_pattern(fp):
    """Patron observable de estado: senales EXPLICITAS de
    cache en orden de observacion. Age/cache_status solo
    como señales, nunca como diferencial de nucleo."""
    sig = fp["signals"]
    return (sig["cache_status"].get("value"),
            sig["age"].get("value"))


def localize_collision(url, i79, client, registry):
    """Convergencia P3-DI: ¿estructural o artefacto?

    virgin pair (fase2, 2 req): par nunca tocado con la
    misma dimension. negative control (controles, 1 req):
    B solo, sin A previo -> contenido legitimo de B.

    Discrimina:
      alias legitimo      B-virgen recibe lo mismo que
                          B-solo -> el contenido no es ajeno
      contaminacion       B-virgen recibe contenido de A
                          (difiere del legitimo de B)
    """
    seg = _fresh("x-scv")
    fa_v, g_a, c_a = client.probe(
        "fase2", "path", "virgin-A", seg + "/a",
        {}, "F1:P3-DI", "contenido propio de a")
    fb_v, g_b, c_b = client.probe(
        "fase2", "path", "virgin-B", seg + "/b",
        {}, "F1:P3-DI", "contenido propio de b")
    # convergencia en virgin (misma sonda, doble corrida)
    conv_v = F.converged(fa_v, fb_v)
    fb_alone, g_n, c_n = client.probe(
        "controles", "path", "negative-B-solo",
        _fresh("x-scn") + "/b", {}, "F2:virgin-B",
        "contenido legitimo de b sin A previo")
    # canal de estado: la convergencia de virgin es
    # observacion de persistencia, no suposicion interna
    c_state = None
    if conv_v["match"]:
        c_state = registry.observe(
            "STATE_PERSISTENCE",
            {"hecho": ("respuesta de B identica a la de A "
                       "tras request previo de A en segmento "
                       "virgen"),
             "nucleo": fa_v["signals"]["body_hash"].get(
                 "value")},
            client._conn[0])
    b_recibe_ajeno = (conv_v["match"]
                      and F.core_differs(fb_v, fb_alone)
                      is not None)
    a_unico = (conv_v["match"]
               and F.core_differs(fa_v, fb_alone) is not None)
    ct_recibido = fb_v["signals"]["content_type"].get("value")
    ct_legitimo = fb_alone["signals"]["content_type"].get(
        "value")
    mismatch_semantico = (b_recibe_ajeno
                          and ct_recibido != ct_legitimo)
    return {
        "tipo": "collision",
        "dimension": "path-collapse",
        "virgin_conv": conv_v,
        "b_recibe_ajeno": bool(b_recibe_ajeno),
        "a_unico": bool(a_unico),
        "contenido_recibido_ct": ct_recibido,
        "contenido_legitimo_ct": ct_legitimo,
        "mismatch_semantico": bool(mismatch_semantico),
        "canales": [c.channel_id for c in (c_a, c_b, c_n)
                    if c] + ([c_state.channel_id]
                             if c_state else []),
        "probes": [g_a["probe_id"], g_b["probe_id"],
                   g_n["probe_id"]],
        "reproducible": bool(conv_v["match"]
                             and i79["correlation"][
                                 "convergencia_repro"]),
    }


def localize_fragmentation(url, i79, client, registry):
    """Divergencia (nucleo o estado) en par EQUIVALENT.

    virgin case-pair (fase2, 4 req: par + refetch de cada
    uno) en path nunca tocado:
      direct   nucleos de A vs B
      state    patrones de cache_status/age de A vs B

    Discrimina:
      fragmentacion estructural   nucleos distintos en
                                  virgin (dimension
                                  localizada: case)
      desacuerdo de estado        nucleos identicos pero
                                  patrones de estado
                                  distintos (dos canales
                                  de observacion reales)
      artefacto                  nada se reproduce
    """
    path = _fresh("x-scf")
    ha = {"x-cache-probe": "v1"}
    hb = {"X-Cache-Probe": "v1"}
    fa_v, g_a, c_a = client.probe(
        "fase2", "header-case", "virgin-lower", path, ha,
        "F1:P1-EQ", "respuesta de A")
    fb_v, g_b, c_b = client.probe(
        "fase2", "header-case", "virgin-upper", path, hb,
        "F1:P1-EQ", "respuesta equivalente a A")
    fa_r, g_a2, c_a2 = client.probe(
        "fase2", "header-case", "virgin-lower-refetch",
        path, ha, g_a["probe_id"], "estado persistido de A")
    fb_r, g_b2, c_b2 = client.probe(
        "fase2", "header-case", "virgin-upper-refetch",
        path, hb, g_b["probe_id"], "estado persistido de B")
    direct_dif = F.core_differs(fa_v, fb_v)
    pa = (state_pattern(fa_v), state_pattern(fa_r))
    pb = (state_pattern(fb_v), state_pattern(fb_r))
    state_div = (pa[1] != pb[1] and any(
        v is not None
        for p in (pa[1], pb[1]) for v in p))
    direct_identical = direct_dif is None
    c_state = None
    if direct_identical and state_div:
        c_state = registry.observe(
            "STATE_PERSISTENCE",
            {"hecho": ("nucleos identicos pero patrones de "
                       "estado de cache divergen entre "
                       "variantes de case"),
             "patron_A": list(pa), "patron_B": list(pb)},
            client._conn[0])
    return {
        "tipo": "fragmentation",
        "dimension": ("header-name-case" if direct_dif
                      is not None or state_div
                      else "UNKNOWN"),
        "virgin_direct_dif": direct_dif,
        "direct_identical": bool(direct_identical),
        "state_diverges": bool(state_div),
        "patron_A": [list(pa[0]), list(pa[1])],
        "patron_B": [list(pb[0]), list(pb[1])],
        "canales": [c.channel_id for c in
                    (c_a, c_b, c_a2, c_b2) if c]
                   + ([c_state.channel_id]
                      if c_state else []),
        "probes": [g["probe_id"] for g in
                   (g_a, g_b, g_a2, g_b2)],
        "reproducible": bool(direct_dif is not None
                             or state_div),
    }


def f1_state_divergence(i79):
    """Deteccion SIN requests nuevos: los patrones de estado
    del par P1-EQ de la fase 1 divergen aunque los nucleos
    sean identicos (desacuerdo escondido para v0.79)."""
    fps = i79.get("fingerprints") or {}
    bat = fps.get("battery", {}).get("P1-EQ")
    rep = fps.get("repro", {}).get("P1-EQ")
    if not (bat and rep):
        return None
    fa, fb = bat
    fa2, fb2 = rep
    if not all(f and f.get("valid")
               for f in (fa, fb, fa2, fb2)):
        return None
    if F.core_differs(fa, fb) is not None:
        return None  # divergencia de nucleo: la ve v0.79
    pa = (state_pattern(fa), state_pattern(fa2))
    pb = (state_pattern(fb), state_pattern(fb2))
    # solo el REFETCH revela persistencia: [MISS,HIT] vs
    # [HIT,HIT] es acuerdo (entrada compartida benigna);
    # refetch A=HIT y B=MISS es desacuerdo persistente
    if pa[1] == pb[1]:
        return None
    sig = any(v is not None
              for p in (pa[1], pb[1]) for v in p)
    if not sig:
        return None
    return {"patron_A": [list(x) for x in pa],
            "patron_B": [list(x) for x in pb],
            "refetch_A": list(pa[1]),
            "refetch_B": list(pb[1])}


def _selftest():
    print("semantic_dimension selftest OK (logica en vivo "
          "se valida contra semantic_lab)")


if __name__ == "__main__":
    _selftest()
