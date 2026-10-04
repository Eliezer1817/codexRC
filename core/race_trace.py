#!/usr/bin/env python3
# ============================================================
# codexRC - RACE-TRACE (v0.70.0)
# ------------------------------------------------------------
# Detecta TOCTOU (check-then-act) en estado persistente de
# plugins WP: leer -> decidir -> escribir sin lock. Es la clase
# de bug que gana carreras con single-packet HTTP/2 y que casi
# ningun plugin WP aguanta (limites, cupones, stock, saldos).
#
# Filosofia del engine: NIVEL 1 estatico puro (regex + balance
# de llaves), nada se ejecuta, cero dependencias (Termux OK).
#
# Lo que busca, por funcion:
#   1) READ  de estado persistente: get_option/get_user_meta/
#      get_post_meta/get_transient/$wpdb->get_(var|row) SELECT
#      ->get_stock_quantity/->get_usage_count/->get_total/
#      ->get_balance/->get_meta(...)
#   2) WRITE de estado persistente: update_option/update_user_meta/
#      update_post_meta/$wpdb->(query|update|insert)/
#      ->set_stock_quantity/->increase_usage_count/...
#   3) EMPAREJA read->write sobre la MISMA clave o variable
#      (flujo lite: $var asignada en el read y usada en el write
#      o en el valor computado del write).
#   4) VENTANA: entre read y write hay un if/guard con la
#      variable => check-then-act clasico.
#
# Veredictos:
#   CANDIDATO-RACE      read->write emparejado en estado sensible
#                      (dinero/stock/cupon/limite/credito) sin
#                      mitigacion visible en la funcion
#   RACE-ATOMICO       el write es SQL incremento sobre columna
#                      (col = col + 1) => atomico, descartado
#   MITIGADO-TRANSIENT lock con get_transient/set_transient en
#                      el flujo => mitigacion de facto WP, blando
#   MITIGADO-LOCK      flock / LOCK_EX / get_lock de MySQL
#   DESCARTADO-LECTURA read y write sin ventana ni variable comun
#
# Severidad del candidato:
#   critica  handler nopriv (carrera ANONIMA via ajax)
#   alta     estado de dinero/stock/cupon/billetera
#   media    contador/limite/intentos (enumeracion o bypass)
#
# Uso:
#   python3 core/race_trace.py <dir_plugin> [--json]
# Integrado en PLUGIN-BATCH: rec["race_candidatos"] + anota
# hallazgos existentes con "_race" si comparten funcion.
# ============================================================
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.gates_audit import FUNC_RE, _php_files, _body_of  # noqa: E402

# ---------- estado persistente: lecturas ----------
READ_RE = re.compile(
    r"(get_option|get_site_option|get_user_meta|get_post_meta|"
    r"get_transient\s*\(\s*['\"][^'\"]*lock|get_transient|"
    r"->get_stock_quantity|->get_usage_count|->get_total\s*\(|"
    r"->get_balance|->get_meta\s*\(|->get_data\s*\(|"
    r"get_results|get_var|get_row|get_col)\s*\(")

# ---------- estado persistente: escrituras ----------
WRITE_RE = re.compile(
    r"(update_option|update_site_option|update_user_meta|"
    r"update_post_meta|add_option|add_user_meta|add_post_meta|"
    r"set_transient|delete_option|"
    r"->query\s*\(|->update\s*\(|->insert\s*\(|->replace\s*\(|"
    r"->set_stock_quantity|->increase_usage_count|"
    r"->decrease_usage_count|->set_total\s*\(|->set_balance|"
    r"->update_meta\s*\(|->save\s*\()")

# clave/valor sensible: lo que vale la pena ganar por carrera
SENSIBLE_RE = re.compile(
    r"balance|credit|wallet|funds|withdraw|payout|payment|price|"
    r"amount|total\s*=|stock|inventory|coupon|voucher|usage|"
    r"limit|quota|attempt|count|points|reward|remaining|"
    r"saldo|credito|billetera|pago|precio|monto|cupon|limite|"
    r"uso|intento|puntos|restante", re.I)

# mitigaciones
ATOMIC_SQL_RE = re.compile(
    r"(?:set|update)[^;]*\b\w+\s*=\s*\w+\s*[+\-]\s*\d+",
    re.I | re.S)
FLOCK_RE = re.compile(r"\bflock\s*\(|\bLOCK_EX\b|\bget_lock\s*\(|"
                      r"\bmutex\b|sem_acquire|->acquireLock", re.I)
TRANSIENT_LOCK_RE = re.compile(
    r"get_transient\s*\(\s*['\"][^'\"]*lock|"
    r"set_transient\s*\(\s*['\"][^'\"]*lock", re.I)

# asignacion de variable desde un read:  $x = get_option(...)
READ_ASSIGN_RE = re.compile(
    r"(\$\w+)\s*=\s*[^;]*?(?:get_option|get_site_option|get_user_meta|"
    r"get_post_meta|get_transient|get_results|get_var|get_row|get_col|"
    r"->get_stock_quantity|->get_usage_count|->get_total|"
    r"->get_balance|->get_meta|->get_data)\s*\(")
IF_GUARD_RE = re.compile(r"\bif\s*\(")
KEY_STR_RE = re.compile(r"['\"]([^'\"]+)['\"]")
VAR_USE_RE = re.compile(r"\$([A-Za-z_]\w*)")
SQL_ATOMIC_HINT = re.compile(
    r"\b(?:\w+\s*=\s*\w+\s*[+\-]\s*1|usage_count\s*=\s*usage_count)", re.I)

STATE_KEY = re.compile(
    r"(?:get|update|add|delete)_(?:option|site_option|user_meta|post_meta)\s*"
    r"\(\s*['\"]([^'\"]+)")


def _tipo_estado(clave: str) -> str:
    """Clasifica el tipo de estado por el nombre de la clave."""
    k = clave.lower()
    if re.search(r"balanc|credit|wallet|fund|withdraw|payout|saldo|"
                 r"billetera|pago|payment|price|amount|total|points|puntos",
                 k):
        return "dinero"
    if re.search(r"stock|inventar|inventor", k):
        return "stock"
    if re.search(r"coupon|voucher|cupon|promo", k):
        return "cupon"
    if re.search(r"limit|quota|attempt|intento|limite|usage|uso|max|count|"
                 r"contador|remain|restante", k):
        return "limite"
    return "otro"


def _sev_de_tipo(tipo: str, nopriv: bool, logged_only: bool) -> str:
    if nopriv:
        return "critica"      # carrera anonima
    if tipo in ("dinero", "stock", "cupon"):
        return "alta"
    if tipo == "limite":
        return "media"
    return "baja"


def _linea_guard(body_lines: List[str], start_i: int, end_i: int,
                 var: str) -> bool:
    """Hay un if usando $var entre el read y el write?"""
    for i in range(start_i, end_i + 1):
        ln = body_lines[i] if i < len(body_lines) else ""
        if IF_GUARD_RE.search(ln) and f"${var}" in ln:
            return True
    return False


def _scan_func(name: str, file_rel: str, body: str,
               line_sig: int, handler: Optional[Dict[str, Any]]) \
        -> List[Dict[str, Any]]:
    """Escanea una funcion y devuelve hallazgos RACE."""
    out: List[Dict[str, Any]] = []
    lines = body.split("\n")
    n = len(lines)
    nop = bool(handler and handler.get("nopriv"))
    logg = bool(handler and not handler.get("nopriv"))

    # mitigaciones globales de la funcion
    flock = bool(FLOCK_RE.search(body))
    tlock = bool(TRANSIENT_LOCK_RE.search(body))
    atomic_body = bool(ATOMIC_SQL_RE.search(body) or SQL_ATOMIC_HINT.search(body))

    # 1) todos los writes con su linea
    writes: List[Tuple[int, Any]] = []
    for i, ln in enumerate(lines):
        m = WRITE_RE.search(ln)
        if m:
            writes.append((i, m.group(1)))

    # 2) para cada write, buscar el read mas cercano hacia arriba
    for wi, wfn in writes:
        # write atomico en SQL: col = col + 1 => descartado.
        # $wpdb->query(prepare(...)) suele partirse en 2-3 lineas:
        # se mira el write + 2 lineas siguientes.
        wblock = "\n".join(lines[wi:wi + 3])
        wline = lines[wi]
        if ATOMIC_SQL_RE.search(wblock) or SQL_ATOMIC_HINT.search(wblock):
            out.append({
                "veredicto": "RACE-ATOMICO", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn, "razon": "SQL incrementa columna in-place",
            })
            continue

        # clave del write (para emparejar y clasificar)
        km = STATE_KEY.search(wline) or KEY_STR_RE.search(wline)
        clave = km.group(1) if km else wline.strip()[:60]
        tipo = _tipo_estado(clave + " " + wline)

        best: Optional[Dict[str, Any]] = None
        for ri in range(wi - 1, max(-1, wi - 60), -1):
            rline = lines[ri]
            rm = READ_RE.search(rline)
            if not rm:
                continue
            rfn = rm.group(1)
            # read de lock de transient = mitigacion, no estado
            if "lock" in rline.lower() and "transient" in rfn:
                break
            # emparejar: mismo nombre de funcion rw (get_option/update_option)
            rw_pair = {("get_option", "update_option"),
                      ("get_site_option", "update_site_option"),
                      ("get_user_meta", "update_user_meta"),
                      ("get_post_meta", "update_post_meta"),
                      ("get_transient", "set_transient"),
                      ("get_results", "query"), ("get_var", "query"),
                      ("get_row", "query"), ("get_col", "query")}
            paired = (rfn, wfn) in rw_pair
            # o variable asignada en el read y usada en el write
            av = READ_ASSIGN_RE.search(rline)
            var = av.group(1).lstrip("$") if av else None
            var_used = bool(var and re.search(r"\$%s\b" % re.escape(var),
                                              wline))
            if not (paired or var_used):
                continue
            # ventana de raza: guard con la variable entre read y write
            ventana = bool(var and _linea_guard(lines, ri + 1, wi - 1, var))
            # sensible: la clave, la linea del read, o la del write
            sensible = bool(SENSIBLE_RE.search(clave) or
                            SENSIBLE_RE.search(rline) or
                            SENSIBLE_RE.search(wline))
            best = {"ri": ri, "rfn": rfn, "var": var,
                    "ventana": ventana, "sensible": sensible}
            break

        if best is None:
            continue
        # v0.70.1 filtros de ruido:
        #  - estado "otro" (version, flags, caches genericas): sin valor
        #  - set_transient sin clave sensible: cache, no negocio
        #  - limite SIN guard (ventana_if): RMW de contador menor
        if tipo == "otro" or (wfn == "set_transient" and
                              not SENSIBLE_RE.search(clave)):
            out.append({
                "veredicto": "DESCARTADO-LECTURA", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn,
                "razon": "estado no sensible (version/cache/flag)",
            })
            continue
        if tipo == "limite" and not best["ventana"]:
            out.append({
                "veredicto": "DESCARTADO-VENTANA", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn,
                "razon": "contador RMW sin guard (check-then-act ausente)",
            })
            continue
        if atomic_body and best["var"] and SQL_ATOMIC_HINT.search(body):
            # el cuerpo incrementa por SQL en algun lado: probable atomico
            out.append({
                "veredicto": "RACE-ATOMICO", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn,
                "razon": "funcion usa incremento SQL sobre columna",
            })
            continue
        if flock:
            out.append({
                "veredicto": "MITIGADO-LOCK", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn, "razon": "flock/LOCK_EX/get_lock en la funcion",
            })
            continue
        if tlock:
            out.append({
                "veredicto": "MITIGADO-TRANSIENT", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn, "razon": "lock con transient en la funcion",
            })
            continue
        if not (best["ventana"] or best["sensible"]):
            out.append({
                "veredicto": "DESCARTADO-LECTURA", "funcion": name,
                "file": file_rel, "line": line_sig + wi,
                "write": wfn, "razon": "read->write sin ventana ni sensibilidad",
            })
            continue
        # CANDIDATO
        sev = _sev_de_tipo(tipo, nop, logg)
        out.append({
            "veredicto": "CANDIDATO-RACE",
            "funcion": name,
            "file": file_rel,
            "line": line_sig + wi,
            "read": {"fn": best["rfn"], "line": line_sig + best["ri"],
                     "var": ("$" + best["var"]) if best["var"] else None},
            "write": {"fn": wfn, "line": line_sig + wi},
            "estado": tipo,
            "clave": clave,
            "ventana_if": best["ventana"],
            "handler": (handler or {}).get("accion"),
            "nopriv": nop,
            "severity": sev,
            "poc_idea": ("single-packet HTTP/2: N requests concurrentes a "
                         f"{(handler or {}).get('accion', 'endpoint')} "
                         f"ganan la carrera {tipo} en '{clave}'"),
        })
    return out


def audit(root: str) -> Dict[str, Any]:
    """Escanear un plugin: devuelve dict con candidatos y resumen."""
    files = _php_files(root)
    funcs: List[Tuple[str, str, List[str], int]] = []  # name, rel, lines, ln
    srcs: Dict[str, List[str]] = {}
    for path in files:
        try:
            src = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        rel = os.path.relpath(path, root)
        lines = src.split("\n")
        srcs[rel] = lines
        for m in FUNC_RE.finditer(src):
            ln = src[:m.end()].count("\n")
            funcs.append((m.group(1), rel, lines, ln))

    # handlers ajax (alcance) reutilizando gates_audit
    handlers: Dict[str, Dict[str, Any]] = {}
    try:
        from core.gates_audit import audit as gates
        g = gates(root)
        for h in g.get("handlers", []):
            cb = h.get("callback") or ""
            if cb and not cb.startswith("closure@"):
                # gates_audit expone "anonimo", no "nopriv"
                handlers[cb] = {**h, "nopriv": bool(h.get("anonimo"))}
    except Exception:
        pass

    hallazgos: List[Dict[str, Any]] = []
    for name, rel, lines, ln in funcs:
        try:
            body, _end = _body_of(lines, ln)
        except Exception:
            continue
        if not body or len(body) < 40:
            continue
        h = handlers.get(name)
        hallazgos.extend(_scan_func(name, rel, body, ln, h))

    candidatos = [h for h in hallazgos if h["veredicto"] == "CANDIDATO-RACE"]
    candidatos.sort(key=lambda h: {"critica": 0, "alta": 1,
                                  "media": 2, "baja": 3}.get(h["severity"], 4))
    return {
        "candidatos": candidatos,
        "resumen": {
            "candidatos": len(candidatos),
            "criticos": sum(1 for c in candidatos
                            if c["severity"] == "critica"),
            "atomicos_descartados": sum(
                1 for h in hallazgos if h["veredicto"] == "RACE-ATOMICO"),
            "mitigados": sum(1 for h in hallazgos
                             if h["veredicto"].startswith("MITIGADO")),
            "descartados": sum(1 for h in hallazgos if h["veredicto"] in
                               ("DESCARTADO-LECTURA",)),
        },
        "hallazgos": hallazgos,
    }


def main() -> None:
    ap = __import__("argparse").ArgumentParser(
        description="RACE-TRACE: TOCTOU en estado persistente WP")
    ap.add_argument("root", help="directorio del plugin")
    ap.add_argument("--json", action="store_true", help="salida JSON")
    a = ap.parse_args()
    res = audit(a.root)
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return
    r = res["resumen"]
    print(f"RACE-TRACE {a.root}")
    print(f"  candidatos: {r['candidatos']}  "
          f"(criticos: {r['criticos']})  "
          f"atomicos: {r['atomicos_descartados']}  "
          f"mitigados: {r['mitigados']}")
    for c in res["candidatos"][:20]:
        icono = "💥" if c["severity"] in ("critica", "alta") else "•"
        print(f"  {icono} [{c['severity']}] {c['funcion']} "
              f"({c['file']}:{c['line']}) estado={c['estado']} "
              f"clave={c['clave'][:40]}"
              + (" nopriv" if c.get("nopriv") else ""))


if __name__ == "__main__":
    main()
