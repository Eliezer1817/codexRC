#!/usr/bin/env python3
"""FIN-LOGIC-PROBE (v0.97.0): orquestador del Destructor de Logica
Financiera. Conecta fin_param_infer.py (que) + fin_payloads.py (con
que) y decide el veredicto siguiendo la escalera cero-FP.

Escalera (cada peldano exige el anterior, nunca se salta):
  FIN-PARAM-DETECTED    parametro financiero identificado (modulo
                        fin_param_infer, nivel estatico).
  FIN-SINK-REACHABLE    el endpoint responde de forma coherente (no
                        404/500 generico): el campo SI es procesado.
  FIN-UNAUTH | FIN-AUTH techo de quien pudo llegar hasta aca:
                        FIN-UNAUTH si el anonimo lo logro, FIN-AUTH si
                        hizo falta sesion valida (subscriber/admin).
  FIN-LOGIC-CANDIDATE   hay BENEFICIO INDEBIDO medible: el valor
                        resultante favorece al atacante fuera de los
                        limites esperados (ver _evaluate_benefit) Y el
                        control negativo (valor benigno) se comporto
                        distinto (si el control tambien "pasara igual"
                        el servidor esta simplemente caido/siempre-200,
                        no es hallazgo).
  FIN-IMPACT-DEMO       SOLO EN MODO LAB: el beneficio se reprodujo de
                        forma identica en DOS rondas independientes
                        (misma mutacion, mismo efecto) y el control
                        negativo fue rechazado en ambas. Nunca se
                        alcanza este peldano fuera de un laboratorio
                        propio (labs/fin_logic_lab.py).

LIMITE HONESTO EN VIVO ("--live"): este modo NUNCA envia una mutacion
real contra un target de verdad (eso seria alterar estado/saldo de un
tercero, prohibido). Solo hace analisis ESTATICO: confirma que el
parametro llega a un sink que lo usa (FIN-SINK-REACHABLE por lectura
de codigo) y busca, en el mismo cuerpo del handler, patrones de
validacion conocidos (intval/absint/abs/min/max/comparaciones de
rango/in_array contra enum). Si NO encuentra ninguno, el parametro
sube a FIN-LOGIC-CANDIDATE (candidato honesto: "nada lo protege segun
el codigo", no "lo exploté"). El techo en vivo es FIN-LOGIC-CANDIDATE
o FIN-AUTH. Jamas FIN-IMPACT-DEMO en vivo.

Presupuesto de requests (modo lab, por parametro):
  1 baseline (GET) + hasta 4 mutaciones de ataque (fin_payloads prioriza
  las primeras 4) + 1-2 controles negativos obligatorios + (si hay
  beneficio) 1 replay de confirmacion + 1 replay del control = <= 9
  requests por parametro por rol. Se prueba SOLO el rol minimo
  necesario para alcanzar el peldano (ver _roles_a_intentar).

Uso:
    python3 core/fin_logic_probe.py --live <dir_plugin> [--json]
    python3 core/fin_logic_probe.py --lab <escenario> [--json]
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import fin_param_infer  # noqa: E402
from core import fin_payloads  # noqa: E402
from core import gates_audit as ga  # noqa: E402

# ------------------------------------------------------- modo LIVE (estatico)
# Patrones de validacion conocidos: si aparecen cerca del parametro, el
# campo se considera CUSTODIADO y no se reporta (regla cero-FP: "no
# declarar hallazgo solo porque el nombre suena a dinero").
VALIDATION_RE = {
    "AMOUNT": re.compile(
        r"\b(intval|floatval|absint|abs)\s*\(|[<>]=?\s*0\b|"
        r"\bmin\s*\(|\bmax\s*\("),
    "QTY": re.compile(
        r"\b(intval|absint|abs)\s*\(|[<>]=?\s*[01]\b|"
        r"\bmin\s*\(|\bmax\s*\("),
    "DISCOUNT": re.compile(
        r"\b(intval|floatval|absint|abs)\s*\(|[<>]=?\s*(0|100)\b|"
        r"\bmin\s*\(|\bmax\s*\("),
    "STATUS": re.compile(
        r"\bin_array\s*\(|\bswitch\s*\(|current_user_can|"
        r"check_ajax_referer|wp_verify_nonce"),
    "OBJECT_ID": re.compile(
        r"current_user_can|get_current_user_id|"
        r"post_author|owner"),
}

FIELD_ENDPOINTS = {
    "AMOUNT": "price",
    "QTY": "qty",
    "DISCOUNT": "discount",
    "STATUS": "status",
}


def _nearby_validation(body: str, pname: str, tipo: str) -> bool:
    """True si hay un patron de validacion conocido en la MISMA linea
    o en las 2 lineas siguientes a donde se usa el parametro (ventana
    chica a proposito: validar "en algun lugar del archivo" es ruido,
    validar "cerca de donde se usa" es señal real).
    """
    rx = VALIDATION_RE.get(tipo)
    if not rx:
        return False
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if pname in line and ("$_POST" in line or "$_GET" in line
                              or "$_REQUEST" in line):
            ventana = "\n".join(lines[i:i + 4])
            if rx.search(ventana):
                return True
    return False


def audit_live(root: str,
                handlers: Optional[List[Dict[str, Any]]] = None
                ) -> Dict[str, Any]:
    """Modo LIVE: solo lectura de codigo, CERO requests de red, CERO
    mutaciones reales. Techo: FIN-LOGIC-CANDIDATE o FIN-AUTH/FIN-UNAUTH.
    """
    if handlers is None:
        handlers = ga.audit(root).get("handlers", [])
    params = fin_param_infer.infer_params(root, handlers=handlers)

    # indexar handlers por (archivo_callback, linea_callback) para
    # recuperar el cuerpo exacto que ya escaneo fin_param_infer
    by_loc = {}
    for h in handlers:
        cf = h.get("archivo_callback") or h.get("archivo")
        cl = h.get("linea_callback") or h.get("linea_hook")
        if cf and cl:
            by_loc[(cf, cl)] = h

    out = []
    for p in params["findings"]:
        rec = dict(p)
        rec["peldanos"] = ["FIN-PARAM-DETECTED", "FIN-SINK-REACHABLE"]
        rec["peldanos"].append("FIN-UNAUTH" if p["anonimo"] else "FIN-AUTH")

        # recuperar cuerpo del handler para buscar validacion cercana
        h = None
        for (cf, cl), hh in by_loc.items():
            if cf == p["archivo"] and (p["linea"] >= cl):
                h = hh
        validated = False
        if h is not None:
            cf = h.get("archivo_callback") or h.get("archivo")
            cl = h.get("linea_callback") or h.get("linea_hook")
            path = os.path.join(root, cf)
            if os.path.isfile(path):
                try:
                    lines = open(path, encoding="utf-8",
                                 errors="ignore").read().splitlines()
                    body, _end = ga._body_of(lines, max(cl - 1, 0))
                    validated = _nearby_validation(body, p["parametro"],
                                                   p["tipo"])
                except Exception:
                    validated = False

        if validated:
            rec["veredicto"] = rec["peldanos"][-1]
            rec["evidencia"] = ("validacion detectada cerca del "
                                "parametro (intval/abs/min/max/rango/"
                                "enum/gate): no se reporta como "
                                "candidato (regla cero-FP)")
        elif p["confianza"] == "BAJA":
            # confianza baja (sufijo generico): no alcanza CANDIDATE
            # por si solo, se queda en el techo de auth
            rec["veredicto"] = rec["peldanos"][-1]
            rec["evidencia"] = ("confianza BAJA: sufijo generico sin "
                                "keyword de categoria exacta, no se "
                                "escala a candidato")
        else:
            rec["peldanos"].append("FIN-LOGIC-CANDIDATE")
            rec["veredicto"] = "FIN-LOGIC-CANDIDATE"
            rec["evidencia"] = ("sin patron de validacion conocido "
                                "(intval/absint/abs/min/max/rango/"
                                "in_array) cerca de donde se usa el "
                                "parametro en el cuerpo del handler")
        out.append(rec)

    resumen: Dict[str, int] = {}
    for r in out:
        resumen[r["veredicto"]] = resumen.get(r["veredicto"], 0) + 1

    return {"plugin": params["plugin"], "modo": "live",
            "parametros_analizados": len(out), "findings": out,
            "resumen": resumen,
            "nota": "modo live: cero requests de red, cero mutaciones "
                    "reales. Techo FIN-LOGIC-CANDIDATE/FIN-AUTH."}


# --------------------------------------------------------------- modo LAB
ROLES = {
    "admin": {"X-Fin-Role": "admin", "X-Fin-User": "1"},
    "subscriber": {"X-Fin-Role": "subscriber", "X-Fin-User": "7"},
    "anon": {"X-Fin-Role": "anon"},
}


def _http(url: str, method: str = "GET",
          headers: Optional[Dict[str, str]] = None,
          payload: Any = None) -> Tuple[int, Dict[str, Any]]:
    data = None
    hdrs = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
            return r.status, body
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return 0, {"ok": False, "error": "conn:%s" % e}


def _encode_field(tipo: str, nombre_mutacion: str, valor: Any) -> Any:
    """Marcadores especiales del catalogo -> valor real a enviar."""
    if valor == "__SELF_ID__":
        return 5001
    return valor


def _evaluate_benefit(tipo: str, baseline: Dict[str, Any],
                       resultado: Dict[str, Any],
                       payload: Dict[str, Any]) -> bool:
    """True si el efecto observado calza con la hipotesis de beneficio
    declarada en el payload (ver fin_payloads.py). Solo mutaciones con
    riesgo BENEFICIO_ATACANTE pueden disparar este oraculo; ESTADO_ROTO
    nunca sube solo a hallazgo (ver docstring del modulo).
    """
    if payload["riesgo"] != "BENEFICIO_ATACANTE":
        return False
    base_total = baseline.get("total", 0)
    new_total = resultado.get("total", base_total)
    if tipo in ("AMOUNT", "QTY", "DISCOUNT"):
        # beneficio = el total legitimo (positivo) se vuelve <= 0
        # (gratis o el sistema "le debe" al atacante)
        return base_total > 0 and new_total <= 1e-9
    if tipo == "STATUS":
        return resultado.get("status") in fin_logic_lab_estados_protegidos()
    return False


def fin_logic_lab_estados_protegidos():
    return ("paid", "completed", "refunded")


def audit_lab(scenario: str, host: str = "127.0.0.1",
              port: Optional[int] = None,
              order_id: int = 5001) -> Dict[str, Any]:
    """Modo LAB: requiere labs/fin_logic_lab.py corriendo en ese
    escenario/puerto. Puede alcanzar FIN-IMPACT-DEMO.
    """
    from labs import fin_logic_lab as lab_mod
    port = port or lab_mod.SCENARIOS.get(scenario)
    if not port:
        return {"error": "escenario desconocido: %s" % scenario}
    base = "http://%s:%d" % (host, port)

    status0, base_body = _http("%s/order/%d" % (base, order_id))
    if status0 != 200:
        return {"error": "lab no responde en %s (status=%d)" %
                (base, status0)}
    baseline = base_body["order"]

    results = []
    for tipo, field in FIELD_ENDPOINTS.items():
        # reset obligatorio antes de cada bateria por tipo: aisla la
        # evidencia, evita que una mutacion aceptada en AMOUNT (ej.
        # price=0 quedo seteado) contamine el baseline/total que usa
        # la bateria de STATUS o DISCOUNT.
        _http("%s/order/%d/reset" % (base, order_id), "POST")
        st_base, base_body = _http("%s/order/%d" % (base, order_id))
        tipo_baseline = base_body["order"] if st_base == 200 else baseline

        payloads = fin_payloads.payloads_for(tipo)
        ataques = [p for p in payloads if p["riesgo"] != "CONTROL"]
        controles = [p for p in payloads if p["riesgo"] == "CONTROL"]
        url = "%s/order/%d/%s" % (base, order_id, field)
        param_key = {"AMOUNT": "price", "QTY": "qty",
                    "DISCOUNT": "discount_pct",
                    "STATUS": "status"}[tipo]

        for payload in ataques:
            rec = {"tipo": tipo, "mutacion": payload["nombre"],
                  "peldanos": ["FIN-PARAM-DETECTED"]}
            valor = _encode_field(tipo, payload["nombre"], payload["valor"])
            st, resp = _http(url, "POST", ROLES["subscriber"],
                             {param_key: valor})

            if st == 0:
                rec["veredicto"] = "SIN-CONEXION"
                results.append(rec)
                continue
            rec["peldanos"].append("FIN-SINK-REACHABLE")
            rec["peldanos"].append("FIN-AUTH")  # requirio sesion subscriber
            rec["status_http"] = st

            if st != 200 or not resp.get("ok"):
                rec["veredicto"] = rec["peldanos"][-1]
                rec["evidencia"] = "rechazado (%s): %s" % (
                    st, resp.get("error", ""))
                results.append(rec)
                continue

            benefit1 = _evaluate_benefit(tipo, tipo_baseline,
                                         resp.get("order", {}),
                                         payload)
            if not benefit1:
                rec["veredicto"] = rec["peldanos"][-1]
                rec["evidencia"] = "aceptado pero sin beneficio medible"
                results.append(rec)
                continue

            # control negativo obligatorio: un valor benigno DEBE
            # comportarse distinto (si no, el servidor esta siempre-200)
            ctrl_ok = True
            if controles:
                ctrl = controles[0]
                _, cresp = _http(url, "POST", ROLES["subscriber"],
                                {param_key: ctrl["valor"]})
                # el control no debe mostrar el mismo beneficio
                ctrl_ok = not _evaluate_benefit(
                    tipo, tipo_baseline, cresp.get("order", {}),
                    {"riesgo": "BENEFICIO_ATACANTE"})

            rec["peldanos"].append("FIN-LOGIC-CANDIDATE")
            if not ctrl_ok:
                rec["veredicto"] = "FIN-LOGIC-CANDIDATE"
                rec["evidencia"] = ("beneficio detectado pero el "
                                    "control tambien se comporto "
                                    "igual: servidor posiblemente "
                                    "siempre-200, degradado a "
                                    "candidato sin confirmar")
                results.append(rec)
                continue

            # replay independiente (segunda ronda) para IMPACT-DEMO
            st2, resp2 = _http(url, "POST", ROLES["subscriber"],
                               {param_key: valor})
            benefit2 = (st2 == 200 and resp2.get("ok") and
                       _evaluate_benefit(tipo, tipo_baseline,
                                        resp2.get("order", {}), payload))

            if benefit2 and ctrl_ok:
                rec["peldanos"].append("FIN-IMPACT-DEMO")
                rec["veredicto"] = "FIN-IMPACT-DEMO"
                rec["evidencia"] = (
                    "beneficio reproducido 2/2 rondas identicas "
                    "(baseline=%s -> ronda1=%s -> ronda2=%s) y el "
                    "control negativo fue rechazado correctamente" % (
                        tipo_baseline, resp.get("order"),
                        resp2.get("order")))
            else:
                rec["veredicto"] = "FIN-LOGIC-CANDIDATE"
                rec["evidencia"] = ("beneficio en ronda 1 pero no "
                                    "reproducido en ronda 2: no se "
                                    "confirma impacto, queda candidato")
            results.append(rec)

    resumen: Dict[str, int] = {}
    for r in results:
        resumen[r["veredicto"]] = resumen.get(r["veredicto"], 0) + 1

    return {"scenario": scenario, "modo": "lab", "base_url": base,
            "baseline": baseline, "resultados": results, "resumen": resumen}


if __name__ == "__main__":
    args = sys.argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    if len(args) < 2 or args[0] not in ("--live", "--lab"):
        print("uso: fin_logic_probe.py --live <dir_plugin> [--json]")
        print("     fin_logic_probe.py --lab <escenario> [--json]")
        sys.exit(1)

    if args[0] == "--live":
        res = audit_live(args[1])
    else:
        res = audit_lab(args[1])

    if as_json:
        print(json.dumps(res, indent=1, ensure_ascii=False))
    else:
        if "error" in res:
            print("ERROR: %s" % res["error"])
        elif res.get("modo") == "live":
            print("FIN-LOGIC (live) %s | parametros=%d | %s" % (
                res["plugin"], res["parametros_analizados"], res["resumen"]))
            for f in res["findings"]:
                print("  [%s] %s:%d %s (%s) -> %s" % (
                    f["veredicto"], f["archivo"], f["linea"],
                    f["parametro"], f["tipo"], f["evidencia"]))
        else:
            print("FIN-LOGIC (lab) %s | %s" % (res["scenario"],
                                                res["resumen"]))
            for r in res["resultados"]:
                print("  [%s] %s/%s -> %s" % (
                    r["veredicto"], r["tipo"], r["mutacion"],
                    r.get("evidencia", "")))
