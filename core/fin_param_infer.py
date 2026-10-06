#!/usr/bin/env python3
"""FIN-PARAM-INFER (v0.97.0): inferencia semantica de parametros financieros.

Primer peldano del "Destructor de Logica Financiera". NO es un fuzzer
generico de parametros: solo marca un campo como financiero cuando se
cumplen las TRES condiciones a la vez:

  1. Nace de input de usuario ($_GET/$_POST/$_REQUEST, igual que las
     fuentes de TAINT-TRACE).
  2. Su NOMBRE matchea una categoria semantica de una lista CERRADA
     (no hay heuristica abierta tipo "cualquier palabra que suene a
     dinero"): si el nombre no calza, se descarta, no se reporta como
     UNKNOWN-por-las-dudas.
  3. Vive DENTRO del cuerpo de un handler ya mapeado por GATES-AUDIT
     (no escanea el plugin entero a ciegas: reutiliza el mapa de
     endpoints que el motor ya construyo).

Categorias semanticas (orden = prioridad de match):
  AMOUNT     price, amount, total, subtotal, cost, fee, valor, monto,
             importe, precio, unit_price, line_total, grand_total,
             balance, balance_before, balance_after, saldo
  QTY        qty, quantity, cant, cantidad, units, stock, unidades
  DISCOUNT   discount, coupon, cupon, promo, rebate, descuento
  STATUS     status, state, paid, payment_status, order_status, estado
  OBJECT_ID  order_id, ticket_id, invoice_id, cart_id, item_id,
             booking_id, product_id

Niveles de confianza (campo "confianza" en cada hallazgo):
  ALTA   el nombre del parametro es IGUAL a una keyword de la categoria.
  MEDIA  el nombre CONTIENE una keyword fuerte (ej. "new_total",
         "unit_price") pero no es identico.
  BAJA   solo matchea un sufijo generico ("_id") sin keyword de
         categoria exacta: el motor lo anota pero el peso de la
         decision queda del lado del operador.

Lo que esta etapa NO hace: no dispara nada, no manda requests, no
decide si hay vulnerabilidad. Solo produce la materia prima tipada
que consume fin_logic_probe.py. Veredicto de salida: FIN-PARAM-DETECTED.

Uso:
    python3 core/fin_param_infer.py <dir_plugin> [--json]
"""
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import gates_audit as ga  # noqa: E402

# ---------------------------------------------------- fuentes (igual a TAINT-TRACE)
SRC_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([\w\-]+)['\"]\s*\]")

# ----------------------------------------------------------- categorias (lista cerrada)
# Cada tupla: (tipo, regex de match EXACTO del nombre, lista de keywords
# "fuertes" para el nivel MEDIA de contains-match).
CATEGORIES: List[Tuple[str, "re.Pattern[str]", List[str]]] = [
    ("AMOUNT", re.compile(
        r"^(price|amount|total|subtotal|cost|fee|valor|importe|monto|"
        r"precio|unit_price|line_total|grand_total|balance|"
        r"balance_before|balance_after|saldo)$", re.I),
     ["price", "amount", "total", "cost", "fee", "valor", "importe",
      "monto", "precio", "balance", "saldo"]),
    ("QTY", re.compile(
        r"^(qty|quantity|cant|cantidad|units|stock|unidades)$", re.I),
     ["qty", "quantity", "cantidad", "units", "stock"]),
    ("DISCOUNT", re.compile(
        r"^(discount|coupon|cupon|promo|rebate|descuento|discount_pct|"
        r"discount_percent)$", re.I),
     ["discount", "coupon", "cupon", "promo", "rebate", "descuento"]),
    ("STATUS", re.compile(
        r"^(status|state|paid|payment_status|order_status|estado)$",
        re.I),
     ["status", "state", "paid", "estado"]),
    ("OBJECT_ID", re.compile(
        r"^(order_id|ticket_id|invoice_id|cart_id|item_id|booking_id|"
        r"product_id)$", re.I),
     ["order_id", "ticket_id", "invoice_id", "cart_id", "item_id"]),
]
GENERIC_ID_RE = re.compile(r"_id$", re.I)


def _classify(name: str) -> Optional[Dict[str, str]]:
    """{'tipo','confianza','justificacion'} o None si no es financiero.

    Precision > cobertura: si el nombre no calza con nada de la lista
    cerrada, se descarta en silencio (no se reporta como UNKNOWN-por
    si acaso, eso seria el fuzzer generico que el proyecto prohibe).
    """
    low = name.lower()
    # nivel ALTA: igualdad exacta con la categoria
    for tipo, rx, _kw in CATEGORIES:
        if rx.match(low):
            return {"tipo": tipo, "confianza": "ALTA",
                    "justificacion": "nombre '%s' matchea keyword "
                                     "exacta de %s" % (name, tipo)}
    # nivel MEDIA: el nombre CONTIENE una keyword fuerte (compuesto)
    for tipo, _rx, kws in CATEGORIES:
        for kw in kws:
            if kw in low and low != kw:
                return {"tipo": tipo, "confianza": "MEDIA",
                        "justificacion": "nombre '%s' contiene keyword "
                                         "'%s' de %s" % (name, kw, tipo)}
    # nivel BAJA: sufijo generico de identificador, sin keyword de
    # categoria: se anota como candidato de objeto, confianza minima
    if GENERIC_ID_RE.search(low):
        return {"tipo": "OBJECT_ID", "confianza": "BAJA",
                "justificacion": "sufijo generico '_id' en '%s', sin "
                                 "keyword de categoria exacta" % name}
    return None


def infer_params(root: str,
                  handlers: Optional[List[Dict[str, Any]]] = None
                  ) -> Dict[str, Any]:
    """Escanea los handlers de GATES-AUDIT en busca de parametros
    financieros. Si `handlers` es None, corre gates_audit.audit(root).

    Solo mira el CUERPO de cada handler (brace-counting real via
    gates_audit._body_of, no una heuristica de lineas fijas).
    """
    if handlers is None:
        handlers = ga.audit(root).get("handlers", [])

    findings: List[Dict[str, Any]] = []
    seen = set()
    for h in handlers:
        callback_file = h.get("archivo_callback") or h.get("archivo")
        callback_line = h.get("linea_callback") or h.get("linea_hook")
        if not callback_file or not callback_line:
            continue
        path = os.path.join(root, callback_file)
        if not os.path.isfile(path):
            continue
        try:
            lines = open(path, encoding="utf-8",
                         errors="ignore").read().splitlines()
        except Exception:
            continue
        body, _end = ga._body_of(lines, max(callback_line - 1, 0))
        for m in SRC_RE.finditer(body):
            pname = m.group(1)
            cls = _classify(pname)
            if not cls:
                continue
            key = (callback_file, callback_line, pname)
            if key in seen:
                continue
            seen.add(key)
            linea_real = callback_line + body[:m.start()].count("\n")
            findings.append({
                "endpoint": h.get("accion") or h.get("callback") or "rest",
                "parametro": pname,
                "tipo": cls["tipo"],
                "confianza": cls["confianza"],
                "justificacion": cls["justificacion"],
                "archivo": callback_file,
                "linea": linea_real,
                "anonimo": bool(h.get("anonimo", False)),
                "veredicto": "FIN-PARAM-DETECTED",
            })

    resumen: Dict[str, int] = {}
    for f in findings:
        resumen[f["tipo"]] = resumen.get(f["tipo"], 0) + 1

    return {
        "plugin": os.path.basename(os.path.abspath(root)),
        "handlers_escaneados": len(handlers),
        "parametros": len(findings),
        "findings": findings,
        "resumen": resumen,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: fin_param_infer.py <dir_plugin> [--json]")
        sys.exit(1)
    res = infer_params(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1, ensure_ascii=False))
    else:
        print("FIN-PARAM: handlers=%d parametros=%d | %s" % (
            res["handlers_escaneados"], res["parametros"], res["resumen"]))
        for f in res["findings"]:
            anon = " [anonimo]" if f["anonimo"] else ""
            print("  [%s/%s] %s:%d %s -> %s%s" % (
                f["tipo"], f["confianza"], f["archivo"], f["linea"],
                f["parametro"], f["endpoint"], anon))
