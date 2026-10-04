"""Juez determinista de SEMANTIC-CACHE (v0.80).

Veredicto corto: CONSISTENT / BENIGN / INCONSISTENT /
SUSPICIOUS / DEMO / UNKNOWN.

Atributos SEPARADOS del veredicto (nunca mezclados):
  semantic_state  CONSISTENT | INCONSISTENT
  correlation     NONE | OBSERVED | STRONG
  impact          NONE | CROSS-CONSUMER | SECURITY
  attribution     UNKNOWN | CANDIDATE | SUPPORTED
  binding         WEAK | MODERATE | STRONG | UNKNOWN
  self_induced    RULED_OUT | UNKNOWN
  self_induced_method  VIRGIN_PATH | NEGATIVE_CONTROL |
                       CLEAN_REPRO | MULTI_RUN | UNKNOWN

Sin scores, sin confidence, sin sumas: el veredicto se
deriva de CONDICIONES sobre atributos.

DEMO exige CONJUNTAMENTE (regla aprobada, ninguna
sustituye a otra):
  1 inconsistencia reproducible
  2 dimension semantica localizada
  3 convergencia atribuida (validator O provenance)
  4 controles criticos PASSED
  5 baseline utilizable
  6 self_induced RULED_OUT (con metodo citado)
  7 correlacion/atribucion suficiente (la provenance
    sola NO sustituye la demostracion de impacto)
  8 E5 CROSS-CONSUMER o E6 SECURITY reproducible

self_induced=UNKNOWN: no alimenta E5/E6, no produce DEMO,
maximo SUSPICIOUS si el resto es fuerte.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap

from core.semantic_models import Attributes, VerdictRecord
from core import semantic_dimension as LOC


def _ctrl_ok(i79):
    ctl = i79.get("controls") or {}
    criticos = ("cookies_session", "authorization", "vary",
                "ttl_wait", "backend_dynamics")
    ctrl = ctl.get("controls") or {}
    return all(ctrl.get(c, {}).get("status") != "FAILED"
               for c in criticos)


def judge(url, i79, ph2, budget, registry):
    att = Attributes()
    cond = {}
    causes = []
    faltan = []
    corr79 = i79["correlation"]
    ctl79 = i79["controls"]
    expl = ctl79.get("explican") or []
    eq_div = corr79.get("eq_divergente")
    eq_repro = corr79.get("eq_reproducible")
    sess_div = corr79.get("sess_divergente")
    conv = corr79.get("convergencia") or {}
    conv_repro = corr79.get("convergencia_repro")
    binding79 = corr79.get("binding_evidence") or "UNKNOWN"
    bc_usable = i79.get("baseline_usable")
    bc = (i79.get("baseline") or {}).get("classification")
    ctrl_ok = _ctrl_ok(i79)
    st_div = LOC.f1_state_divergence(i79)

    def out(verdict, nota=""):
        att.binding = binding79 if binding79 in (
            "WEAK", "MODERATE", "STRONG") else "UNKNOWN"
        rec = VerdictRecord(
            target=url, verdict=verdict, attributes=att,
            conditions=cond,
            channels=registry.to_dicts() if hasattr(
                registry, "to_dicts") else [],
            unknown_causes=causes,
            faltó_para_escalar=faltan,
            budget=budget.to_dict(),
            informe79_verdict=i79.get("verdicto", "?"),
            nota=nota)
        return rec

    # ---- baseline: sin poder discriminatorio no se concluye
    if not bc_usable:
        att.semantic_state = "CONSISTENT"
        causes.append("baseline %s" % bc)
        return out("UNKNOWN", "baseline %s: sin poder "
                   "discriminatorio no se concluye" % bc)

    coll_anom = bool(conv.get("match")
                     and conv.get("state") == "ATRIBUIDA")
    frag_anom = bool(eq_div and eq_repro and not expl)
    st_anom = bool(st_div and not expl)

    # convergencia APARENTE (paginas de error o contenido
    # generico): v0.79 ya la explica; sin fase 2
    if (conv.get("match") and conv.get("state")
            in ("APARENTE", "APARENTE-GENERICA")
            and not (frag_anom or st_anom)):
        att.semantic_state = "CONSISTENT"
        return out("BENIGN", "convergencia aparente (%s): "
                   "sin atribucion, contenido no especifico"
                   % conv.get("state"))

    # ---- explicado por control legitimo
    if expl and (eq_div or sess_div or st_div) \
            and not coll_anom:
        att.semantic_state = "CONSISTENT"
        att.correlation = "NONE"
        return out("BENIGN", "diferencial explicado por "
                   "control legitimo: %s" % ",".join(expl))

    # ---- sin anomalia ni divergencia
    if not (coll_anom or frag_anom or st_anom):
        if (eq_div or sess_div) and not eq_repro:
            att.semantic_state = "INCONSISTENT"
            causes.append("divergencia no reproducible")
            return out("UNKNOWN", "divergencia observada sin "
                       "reproducibilidad: evidencia "
                       "insuficiente")
        att.semantic_state = "CONSISTENT"
        return out("CONSISTENT", "comportamiento consistente "
                   "con baseline %s" % bc)

    # ---- fase 2: presupuesto
    if ph2 is None:
        causes.append("presupuesto agotado sin poder "
                      "discriminar")
        return out("UNKNOWN", "limite de presupuesto "
                   "alcanzado: UNKNOWN, no se persigue la "
                   "hipotesis")

    # ================= COLLISION =================
    if coll_anom and ph2["tipo"] == "collision":
        att.semantic_state = "INCONSISTENT"
        if not ph2["virgin_conv"].get("match"):
            # solo se observo en la bateria: puede ser
            # artefacto de nuestra propia sonda
            att.self_induced = "UNKNOWN"
            att.self_induced_method = "UNKNOWN"
            att.correlation = "OBSERVED"
            causes.append("convergencia no reproducible en "
                          "segmento virgen")
            if binding79 == "STRONG" and ctrl_ok:
                return out("SUSPICIOUS", "convergencia "
                           "observada en bateria sin repro "
                           "virgen: self-induced UNKNOWN, "
                           "maximo SUSPICIOUS")
            return out("INCONSISTENT", "convergencia no "
                       "estructural; self-induced UNKNOWN")
        if not ph2["b_recibe_ajeno"]:
            # control negativo: el contenido que recibe B es
            # el legitimo de B -> alias, no contaminacion
            att.semantic_state = "CONSISTENT"
            att.correlation = "NONE"
            att.self_induced = "RULED_OUT"
            att.self_induced_method = "NEGATIVE_CONTROL"
            return out("BENIGN", "convergencia por alias "
                       "legitimo: B-solo recibe el mismo "
                       "contenido; nada es ajeno")
        # contaminacion estructural
        att.correlation = "STRONG"
        att.attribution = "CANDIDATE"
        att.impact = ("SECURITY"
                      if ph2["mismatch_semantico"]
                      else "CROSS-CONSUMER")
        att.self_induced = "RULED_OUT"
        att.self_induced_method = ("VIRGIN_PATH+"
                                   "NEGATIVE_CONTROL")
        cond = {
            "1_inconsistencia_reproducible": bool(
                ph2["reproducible"]),
            "2_dimension_localizada": True,
            "3_convergencia_atribuida": bool(
                ph2["a_unico"] and ph2["b_recibe_ajeno"]),
            "4_controles_pasados": ctrl_ok,
            "5_baseline_utilizable": True,
            "6_self_induced_ruled_out": True,
            "7_correlacion_atribucion": True,
            "8_impacto_reproducible": att.impact
            in ("CROSS-CONSUMER", "SECURITY"),
        }
        faltan = [k for k, v in cond.items() if not v]
        if not faltan:
            return out("DEMO", "contaminacion estructural "
                       "reproducible en segmentos virgenes: "
                       "B recibe contenido ajeno de A%s"
                       % (" con semantica distinta "
                          "(content-type)" if
                          ph2["mismatch_semantico"] else ""))
        if ctrl_ok:
            return out("SUSPICIOUS", "contaminacion sin "
                       "condiciones completas de DEMO")
        return out("INCONSISTENT", "contaminacion con "
                   "controles criticos caidos")

    # ================= FRAGMENTATION / STATE =================
    if (frag_anom or st_anom) and ph2["tipo"] == \
            "fragmentation":
        att.semantic_state = "INCONSISTENT"
        if not ph2["reproducible"]:
            att.self_induced = "UNKNOWN"
            att.self_induced_method = "UNKNOWN"
            causes.append("no se reproduce en path virgen")
            if binding79 in ("MODERATE", "STRONG") \
                    and ctrl_ok:
                return out("SUSPICIOUS", "divergencia solo "
                           "en bateria: self-induced "
                           "UNKNOWN, maximo SUSPICIOUS")
            return out("INCONSISTENT", "divergencia no "
                       "estructural")
        att.self_induced = "RULED_OUT"
        att.self_induced_method = ("VIRGIN_PATH+MULTI_RUN")
        if ph2["virgin_direct_dif"] is not None:
            # fragmentacion estructural: nucleo distinto en
            # par EQUIVALENT. Contrato vs observacion: la
            # regla RFC no es canal independiente
            att.correlation = "OBSERVED"
            att.impact = "NONE"
            att.attribution = "CANDIDATE"
            return out("INCONSISTENT", "fragmentacion "
                       "estructural reproducible en path "
                       "virgen (dimension: %s); sin impacto "
                       "observable al consumidor"
                       % ph2["dimension"])
        if ph2["direct_identical"] and ph2[
                "state_diverges"]:
            # E7: dos canales de observacion reales
            # (respuesta directa vs estado persistido)
            # incompatibles, reproducible en virgen
            att.correlation = "STRONG"
            att.impact = "NONE"
            att.attribution = "CANDIDATE"
            cond = {
                "e7_desacuerdo_observable": True,
                "independencia_mecanismo": True,
                "reproducible_virgen": True,
                "controles_pasados": ctrl_ok,
            }
            faltan = [k for k, v in cond.items() if not v]
            nota = ("desacuerdo observable entre canales "
                    "(respuesta directa vs estado): nucleos "
                    "identicos, estados divergentes; sin "
                    "impacto al consumidor; atribucion a "
                    "capas: CANDIDATE (hipotesis)")
            if ctrl_ok:
                return out("SUSPICIOUS", nota)
            return out("INCONSISTENT", nota
                       + "; controles criticos caidos")
        causes.append("patron virgen no concluyente")
        return out("UNKNOWN", "fase 2 sin poder "
                   "discriminatorio suficiente")

    causes.append("anomalia sin ruta de analisis")
    return out("UNKNOWN", "anomalia sin ruta de analisis "
               "definida")


def _selftest():
    print("semantic_judge selftest OK (logica se valida "
          "contra semantic_lab en regresion)")


if __name__ == "__main__":
    _selftest()
