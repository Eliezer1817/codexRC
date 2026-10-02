#!/usr/bin/env python3
# ============================================================
# codexRC - GATES-AUDIT (v0.43.0)
# ------------------------------------------------------------
# Dictamina SOLO si los handlers de un plugin estan protegidos:
# mapea wp_ajax / wp_ajax_nopriv / wc_ajax / REST (permission_callback)
# a su callback, extrae el cuerpo de la funcion y busca compuertas
# (current_user_can / wp_verify_nonce / check_ajax_referer).
#
# Veredictos automaticos:
#   CANDIDATO-BAC   nopriv sin caps ni nonce (superficie anonima abierta)
#   REVISAR-AUTH    solo wp_ajax (logueado) sin caps ni nonce
#                   (cualquier subscriber puede llegar; vale si toca
#                   objetos sensibles: settings, users, archivos, dinero)
#   PROTEGIDO       tiene caps y/o nonce verificado
#   REST-ABIERTO    permission_callback __return_true (anonimo)
#
# Uso:
#   python3 core/gates_audit.py <dir_plugin> [--json]
# Integrado en PLUGIN-BATCH: anota cada hallazgo con su veredicto.
# Nivel 1: regex + balance de llaves; no ejecuta nada.
# ============================================================
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

CAPS_RE = re.compile(
    r"current_user_can|user_can|is_admin\s*\(|manage_options|"
    r"is_super_admin|wc_current_user_has_role|function_exists\s*\(\s*'"
    r"is_admin")
NONCE_RE = re.compile(r"wp_verify_nonce|check_ajax_referer|wp_nonce")
HOOK_RE = re.compile(
    r"add_action\s*\(\s*['\"](wp_ajax_(nopriv_)?[\w\-]+|wc_ajax_[\w\-]+)['\"]"
    r"\s*,\s*(.+?)\s*\)")
# loader propio (patron loader->add_action(hook, $obj, 'metodo'))
LOADER_HOOK_RE = re.compile(
    r"add_action\s*\(\s*['\"](wp_ajax_(nopriv_)?[\w\-]+|wc_ajax_[\w\-]+)"
    r"['\"]\s*,\s*\$\w+\s*,\s*['\"]([A-Za-z_]\w*)['\"]")
REST_RE = re.compile(r"register_rest_route\s*\(", re.I)
PERM_TRUE_RE = re.compile(r"permission_callback['\"]?\s*=>\s*"
                          r"(__return_true|'__return_true')")
FUNC_RE = re.compile(
    r"(?:public|protected|private|static|\s)*\s*function\s+(\w+)\s*\(")


def _php_files(root: str) -> List[str]:
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.lower().endswith(".php"):
                out.append(os.path.join(dirpath, f))
    return out


def _body_of(lines: List[str], start: int) -> Tuple[str, int]:
    """Extrae el cuerpo desde la linea con '{'. Devuelve (codigo, linea_fin)."""
    depth, started, out = 0, False, []
    for i in range(start, min(start + 800, len(lines))):
        out.append(lines[i])
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth <= 0:
            return "\n".join(out), i
        if not started and i - start > 4:  # firma multilinea rara
            break
    return "\n".join(out), start


def _resolve_callback(cb_expr: str) -> Optional[str]:
    """'func', array($this,'m'), ['Cls','m'], 'Cls::m' -> nombre navegable."""
    m = re.search(r"['\"](\w+)['\"]", cb_expr)
    return m.group(1) if m else None


def audit(root: str) -> Dict[str, Any]:
    handlers: List[Dict[str, Any]] = []
    funcs: Dict[str, Tuple[str, int]] = {}  # nombre -> (path, linea de firma)
    srcs: Dict[str, List[str]] = {}

    files = _php_files(root)
    for path in files:
        try:
            src = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        rel = os.path.relpath(path, root)
        lines = src.split("\n")
        srcs[rel] = lines
        for m in FUNC_RE.finditer(src):
            ln = src[:m.start()].count("\n")
            funcs[m.group(1)] = (rel, ln)

    # 1) hooks ajax: accion -> callback
    hook_targets: List[Dict[str, str]] = []
    for rel, lines in srcs.items():
        for i, line in enumerate(lines):
            loader_actions = {mm.group(1) for mm in LOADER_HOOK_RE.finditer(line)}
            for m in list(HOOK_RE.finditer(line)) + list(LOADER_HOOK_RE.finditer(line)):
                action = m.group(1)
                if m.re is HOOK_RE and action in loader_actions:
                    continue
                nopriv = "nopriv" in action
                if m.re is LOADER_HOOK_RE:
                    cb = m.group(3)          # metodo directo del loader
                else:
                    cb = _resolve_callback(m.group(3) or "")
                hook_targets.append({"action": action, "nopriv": nopriv,
                                     "cb": cb or "", "file": rel, "line": i + 1})

    # 2) para cada hook, hallar el cuerpo del callback y ver compuertas
    for h in hook_targets:
        rec: Dict[str, Any] = {"accion": h["action"], "archivo": h["file"],
                               "linea_hook": h["line"], "callback": h["cb"],
                               "anonimo": h["nopriv"]}
        cb = h["cb"]
        if cb and cb in funcs:
            frel, fln = funcs[cb]
            body, _end = _body_of(srcs[frel], fln)
            rec["archivo_callback"] = frel
            rec["linea_callback"] = fln + 1
            caps = bool(CAPS_RE.search(body))
            nonce = bool(NONCE_RE.search(body))
            rec["caps"] = caps
            rec["nonce"] = nonce
            if caps or nonce:
                rec["veredicto"] = "PROTEGIDO"
            elif h["nopriv"]:
                rec["veredicto"] = "CANDIDATO-BAC"
            else:
                rec["veredicto"] = "REVISAR-AUTH"
        else:
            # callback dinamico/heredado: dejar a revision manual
            rec["veredicto"] = "CALLBACK-NO-RESUELTO"
        handlers.append(rec)

    # 3) rutas REST abiertas
    rest_abiertas: List[Dict[str, str]] = []
    for rel, lines in srcs.items():
        for i, line in enumerate(lines):
            if REST_RE.search(line) or "permission_callback" in line:
                ventana = "\n".join(lines[i:i + 12])
                if PERM_TRUE_RE.search(ventana):
                    rest_abiertas.append({"archivo": rel, "linea": i + 1,
                                          "nota": "permission_callback __return_true"})


    # 5) ABILITY-SCAN (v0.51.0): Abilities API (WP 6.9+) — wp_register_ability
    #     cada ability lleva permission_callback; __return_true o ausente =
    #     ability invocable por cualquiera (superficie 2026, sin escanear)
    ABILITY_RE = re.compile(r"wp_register_ability\s*\(")
    abilities: List[Dict[str, Any]] = []
    for rel, lines in srcs.items():
        for i, line in enumerate(lines):
            if not ABILITY_RE.search(line):
                continue
            ventana = "\n".join(lines[i:i + 18])
            nombre = None
            nm = re.search(r"wp_register_ability\s*\(\s*['\"]([^'\"]+)", line)
            if nm:
                nombre = nm.group(1)
            perm_m = re.search(r"permission_callback['\"]?\s*=>\s*"
                               r"[^,)]+", ventana)
            perm = perm_m.group(0) if perm_m else ""
            if PERM_TRUE_RE.search(perm):
                ver_ab = "ABILITY-ABIERTA"
            elif not perm_m:
                ver_ab = "ABILITY-SIN-PERMISO"
            else:
                ver_ab = "ABILITY-PROTEGIDA"
            abilities.append({"ability": nombre, "archivo": rel,
                              "linea": i + 1, "permiso": perm.strip()[:80],
                              "veredicto": ver_ab})
    ver_abiertas = [a for a in abilities
                    if a["veredicto"] != "ABILITY-PROTEGIDA"]

    # 4) resumen
    ver = {}
    for h in handlers:
        ver[h["veredicto"]] = ver.get(h["veredicto"], 0) + 1

    ver["abilities_abiertas"] = len(ver_abiertas)
    return {"handlers": handlers, "rest_abiertas": rest_abiertas,
            "abilities": abilities, "abilities_abiertas": ver_abiertas,
            "resumen": {"total_hooks": len(handlers), "veredictos": ver,
                        "rest_abiertas": len(rest_abiertas),
                        "abilities": len(abilities),
                        "abilities_abiertas": len(ver_abiertas)}}


def scan_path(root: str) -> Dict[str, Any]:
    return audit(root)


def _line_in_handler(rec: Dict[str, Any], file_: str, line: int) -> Optional[Dict[str, Any]]:
    """True si file:line cae dentro del cuerpo dictaminado de un handler."""
    if rec.get("archivo_callback") != file_:
        return None
    start = rec.get("linea_callback", 0)
    # cuerpo heuristico: hasta 800 lineas
    if start <= line <= start + 800:
        return rec
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: gates_audit.py <dir_plugin> [--json]")
        sys.exit(1)
    root = sys.argv[1]
    res = audit(root)
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1))
    else:
        print(f"hooks: {res['resumen']['total_hooks']}  "
              f"veredictos: {res['resumen']['veredictos']}")
        for h in res["handlers"]:
            mark = "💥" if h["veredicto"] == "CANDIDATO-BAC" else ""
            print(f"  {mark}[{h['veredicto']}] {h['accion']} "
                  f"-> {h.get('callback', '?')} "
                  f"({h.get('archivo_callback', h['archivo'])}:"
                  f"{h.get('linea_callback', h['linea_hook'])}) "
                  f"caps={h.get('caps', '?')} nonce={h.get('nonce', '?')}")
        for r in res["rest_abiertas"]:
            print(f"  💥 [REST-ABIERTO] {r['archivo']}:{r['linea']} {r['nota']}")
