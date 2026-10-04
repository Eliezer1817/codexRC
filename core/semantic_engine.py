"""SEMANTIC-CACHE (v0.80): motor de desacuerdos semanticos.

Flujo:
  FASE 1  bateria v0.79 INTACTA (17 req) via
          cache_correlation.audit
  FASE 2  solo si hay inconsistencia observable SIN
          explicacion legitima (<= 8 req + <= 4 controles)
  JUEZ    determinista sobre atributos separados

HARD CAP: total <= 30 requests. Si se alcanza el limite
sin discriminar: UNKNOWN. No se persigue la hipotesis.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap

from core import cache_correlation as CC
from core import semantic_dimension as LOC
from core import semantic_channels as SC
from core import semantic_judge as SJ
from core.semantic_models import Budget


def _reg_f1_channels(registry, i79):
    """Registrar como canales las observaciones YA hechas
    por la fase 1 (sin requests nuevos). connection_id -1:
    conexiones de la bateria v0.79, no rastreadas por el
    motor v0.80 (honesto: se cita lo que se midio)."""
    fps = (i79.get("fingerprints") or {})
    spec = fps.get("spec")
    if spec and spec.get("valid"):
        registry.observe("RESPONSE_DIRECT", {
            "origen": "fase1 sonda de especificidad",
            "path": "/x-specificity/probe",
            "content_type": spec["signals"]["content_type"]
            .get("value")},
            -1)
    bat = fps.get("battery", {})
    rep = fps.get("repro", {})
    for pid in ("P1-EQ", "P2-SESS", "P3-DI"):
        par = bat.get(pid)
        if par:
            for f in par:
                if f and f.get("valid"):
                    registry.observe("RESPONSE_DIRECT", {
                        "origen": "fase1 %s" % pid,
                        "status": f["signals"]["status_code"].get(
                            "value"),
                        "body_hash": f["signals"]["body_hash"]
                        .get("value")}, -1)
        rpar = rep.get(pid)
        if rpar:
            for f in rpar:
                if f and f.get("valid"):
                    registry.observe("STATE_PERSISTENCE", {
                        "origen": ("fase1 repro %s "
                                   "(refetch)" % pid),
                        "cache_status": f["signals"][
                            "cache_status"].get("value"),
                        "age": f["signals"]["age"].get(
                            "value")}, -1)


def audit(cfg):
    url = cfg["url"]
    timeout = cfg.get("timeout", 10.0)
    budget = Budget()
    # ---------- FASE 1: bateria v0.79 intacta
    i79 = CC.audit({"url": url, "timeout": timeout})
    n1 = i79.get("requests", 17)
    if n1 <= 17:
        budget.spend("fase1", n1)
    else:
        # los requests de control de v0.79 (p.ej. ttl
        # refetch) cuentan como controles, no como bateria
        budget.spend("fase1", 17)
        extra = min(n1 - 17, 4)
        if extra:
            budget.spend("controles", extra)
    registry = SC.ChannelRegistry()
    client = SC.TrackedClient(url, timeout, budget, registry)
    _reg_f1_channels(registry, i79)

    corr79 = i79["correlation"]
    expl = (i79["controls"] or {}).get("explican") or []
    conv = corr79.get("convergencia") or {}
    eq_div = corr79.get("eq_divergente")
    eq_repro = corr79.get("eq_reproducible")
    st_div = LOC.f1_state_divergence(i79)

    # ---------- FASE 2: solo inconsistencias no explicadas
    ph2 = None
    coll_route = (conv.get("match")
                  and conv.get("state") == "ATRIBUIDA")
    frag_route = ((eq_div and eq_repro and not expl)
                  or (bool(st_div) and not expl
                      and not (eq_div and eq_repro)))
    try:
        if coll_route:
            ph2 = LOC.localize_collision(url, i79, client,
                                        registry)
        elif frag_route:
            ph2 = LOC.localize_fragmentation(url, i79, client,
                                            registry)
    except RuntimeError as e:
        # presupuesto agotado: UNKNOWN, no se persigue
        ph2 = None

    rec = SJ.judge(url, i79, ph2, budget, registry)
    rec.genealogy = client.genealogy
    return rec.to_dict()


def _render(rec):
    print("SEMANTIC-CACHE: %s" % rec.get("target", "?"))
    print("-" * 52)
    print("verdicto: %s" % rec.get("verdict", "?"))
    a = rec.get("attributes", {})
    print("semantic_state=%s correlation=%s impact=%s "
          "attribution=%s" % (a.get("semantic_state"),
                              a.get("correlation"),
                              a.get("impact"),
                              a.get("attribution")))
    print("binding=%s self_induced=%s (%s)"
          % (a.get("binding"), a.get("self_induced"),
             a.get("self_induced_method")))
    print("v0.79: %s" % rec.get("informe79_verdict", "?"))
    if rec.get("conditions"):
        print("condiciones: %s" % rec["conditions"])
    if rec.get("unknown_causes"):
        print("causas UNKNOWN: %s"
              % "; ".join(rec["unknown_causes"]))
    if rec.get("falto_para_escalar"):
        print("falto para escalar: %s"
              % "; ".join(rec["falto_para_escalar"]))
    if rec.get("nota"):
        print("nota: %s" % rec["nota"])
    b = rec.get("budget", {}).get("spent", {})
    print("presupuesto: fase1=%s fase2=%s controles=%s "
          "total=%s/30" % (b.get("fase1"), b.get("fase2"),
                           b.get("controles"),
                           b.get("total")))


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()
    rec = audit({"url": args.url, "timeout": args.timeout})
    _render(rec)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
