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

# ---------- v0.63.0 AUTHZ-PROOF CAPA 3: resolucion de hooks dinamicos ----------
# add_action($var, ...) / add_action('hook', $cb) / array($this, $m_var)
# y callbacks de closure en linea. Propagacion de constantes lite por
# archivo: ultima asignacion previa a la linea de uso (vars y $this->props).

ASSIGN_RE = re.compile(r"\$([\w]+|this->\w+)\s*=\s*([^;]+);")
AJAX_NAME_RE = re.compile(r"^(wp_ajax_(nopriv_)?[\w\-]+|wc_ajax_[\w\-]+)$")
DYN_HOOK_RE = re.compile(r"add_action\s*\(\s*([^,\n]+?)\s*,\s*([^,\n]+)")
SQ_RE = re.compile(r"'([^']*)'")
DQ_PLAIN_RE = re.compile(r'"([^"$]*)"')
DQ_RE = re.compile(r'"([^"]*)"')
VAR_USE_RE = re.compile(r"\$(\w+)")


def _const_map(lines):
    """var (o 'this->prop') -> (linea, expr) de la ultima asignacion."""
    m = {}
    for i, line in enumerate(lines):
        mm = ASSIGN_RE.search(line)
        if mm:
            m[mm.group(1)] = (i, mm.group(2).strip())
    return m


def _resolve_expr(expr, cmap, depth=0):
    """Evalua literales, $vars, $this->props, concatenacion e interpolacion."""
    if not expr or depth > 4:
        return None
    expr = expr.strip().rstrip(";").strip()
    m = SQ_RE.fullmatch(expr)
    if m:
        return m.group(1)
    m = DQ_PLAIN_RE.fullmatch(expr)
    if m:
        return m.group(1)
    m = DQ_RE.fullmatch(expr)
    if m:
        def _sub(mm):
            ent = cmap.get(mm.group(1)) or cmap.get("this->" + mm.group(1))
            return _resolve_expr(ent[1], cmap, depth + 1) if ent else ""
        return VAR_USE_RE.sub(_sub, m.group(1))
    if expr.startswith("$"):
        ent = cmap.get(expr[1:])
        if ent and ent[1].strip() != expr:
            return _resolve_expr(ent[1], cmap, depth + 1)
        return None
    if "." in expr and "array(" not in expr:
        parts = re.split(r"\s*\.\s*", expr)
        out = []
        for part in parts:
            v = _resolve_expr(part, cmap, depth + 1)
            if v is None:
                return None
            out.append(v)
        return "".join(out)
    return None




# ---------- v0.64.0 AUTHZ-PROOF CAPA 1: ROLE-SOLVER ----------
# El nonce prueba IDENTIDAD, no AUTORIZACION. Esta capa extrae que
# capability exige realmente cada handler, la traduce al ROL minimo
# estandar de WP que la posee, y si el handler hace acciones
# sensibles con un privilegio bajo -> PRIVILEGIO-DEBIL (candidato).

CAP_EXTRACT_RE = re.compile(
    r"current_user_can\s*\(\s*['\"]([a-z0-9_\-]+)['\"]"
    r"|(?:user_can|author_can)\s*\(\s*[^,]+,\s*['\"]([a-z0-9_\-]+)"
    r"['\"]", re.I)
ROLE_EXTRACT_RE = re.compile(r"wc_current_user_has_role\s*\(\s*['\"]"
                             r"([a-z0-9_\-]+)['\"]", re.I)
SENS_RE = re.compile(
    r"update_option|delete_option|wp_insert_post|wp_update_post|"
    r"wp_delete_post|wp_insert_user|wp_update_user|wp_delete_user|"
    r"wp_create_user|add_role|remove_role|set_role|wpdb->query|"
    r"wpdb->delete|wpdb->update|wpdb->insert|file_put_contents|"
    r"unlink\s*\(|fwrite|wp_mail\s*\(|system\s*\(|exec\s*\(|eval\s*\(|"
    r"move_uploaded_file|wp_insert_term|wp_delete_term|"
    r"wp_insert_comment|wp_delete_comment|wp_update_comment")
# capability estandar -> rol minimo que la posee (jerarquia WP)
CAP_ROLE = {
    "manage_options": "administrator", "edit_users": "administrator",
    "create_users": "administrator", "delete_users": "administrator",
    "remove_users": "administrator", "promote_users": "administrator",
    "edit_theme_options": "administrator", "install_plugins": "administrator",
    "install_themes": "administrator", "activate_plugins": "administrator",
    "edit_plugins": "administrator", "edit_themes": "administrator",
    "update_core": "administrator", "update_plugins": "administrator",
    "update_themes": "administrator", "delete_plugins": "administrator",
    "delete_themes": "administrator", "unfiltered_html": "administrator",
    "manage_network": "administrator", "switch_themes": "administrator",
    "edit_files": "administrator", "manage_options_for_": "administrator",
    "edit_others_posts": "editor", "edit_others_pages": "editor",
    "edit_published_pages": "editor", "publish_pages": "editor",
    "delete_others_pages": "editor", "delete_others_posts": "editor",
    "delete_published_pages": "editor", "moderate_comments": "editor",
    "manage_categories": "editor", "manage_links": "editor",
    "edit_pages": "editor", "delete_pages": "editor",
    "publish_posts": "author", "upload_files": "author",
    "edit_published_posts": "author", "delete_published_posts": "author",
    "delete_posts": "contributor", "edit_posts": "contributor",
    "edit_post": "contributor", "delete_post": "contributor",
    "read": "subscriber",
}
ROLE_ORDER = {"administrator": 0, "editor": 1, "author": 2,
              "contributor": 3, "subscriber": 4, "custom": 99}


def _roles_of_body(body):
    """caps_req y rol minimo (el mas EXIGENTE que permite pasar)."""
    caps = []
    for m in CAP_EXTRACT_RE.finditer(body):
        for g in m.groups():
            if g:
                caps.append(g)
                break
    roles_directos = ROLE_EXTRACT_RE.findall(body)
    if re.search(r"is_super_admin\s*\(", body):
        roles_directos.append("administrator")
    roles = [CAP_ROLE.get(c, "custom") for c in caps]
    roles += [r if r in ROLE_ORDER else "custom" for r in roles_directos]
    # chequeos multiples en AND: el rol que pasa TODOS es el mas alto
    rol = min(roles, key=lambda r: ROLE_ORDER.get(r, 99)) if roles else None
    sens = bool(SENS_RE.search(body))
    return caps, rol, sens




# ---------- v0.65.0 AUTHZ-PROOF CAPA 2: OBJECT-OWNER (IDOR estatico) ----------
# Sigue el id que llega del usuario hasta el acceso al objeto. Si el
# camino no pasa por ninguna verificacion de dueño (post_author ==,
# get_current_user_id comparado, current_user_can('edit_post', $id))
# y el rol exigido no es editor/admin -> CANDIDATO-IDOR (horizontal).

ID_SOURCE_RE = re.compile(
    r"\$(\w+)\s*=\s*[^;\n]*\$_(?:GET|POST|REQUEST)\s*\[", re.I)
RENAME_RE = re.compile(r"\$(\w+)\s*=\s*\$(\w+)\s*;")
SINK_CALL_RE = re.compile(
    r"\b(get_post|get_page|wp_update_post|wp_delete_post|"
    r"get_post_meta|update_post_meta|delete_post_meta|"
    r"get_userdata|get_user_by|wp_update_user|wp_delete_user|"
    r"get_user_meta|update_user_meta|delete_user_meta|"
    r"get_term_by|wp_delete_term|wp_get_attachment_url)\s*\(([^)]*)",
    re.I)
SINK_SUPERGLOBAL_RE = re.compile(
    r"\b(get_post|get_page|wp_update_post|wp_delete_post|"
    r"get_post_meta|update_post_meta|get_userdata|get_user_by|"
    r"get_user_meta|update_user_meta)\s*\(\s*[^)]*\$_(?:GET|POST|"
    r"REQUEST)\s*\[", re.I)
OWNER_RE = re.compile(
    r"post_author\s*[!=]=|[!=]=\s*\$?\w*->post_author|"
    r"[!=]=\s*get_current_user_id|get_current_user_id\s*\(\s*\)"
    r"[^;]{0,40}[!=]=|"
    r"current_user_can\s*\(\s*['\"]edit_(?:post|page|others_posts)|"
    r"current_user_can\s*\(\s*['\"]delete_(?:post|page)|"
    r"get_the_author_meta\s*\(\s*['\"]id", re.I)


def _idor_of_body(body):
    """(tainted, sinks, owner) del cuerpo de un handler."""
    tainted = {m.group(1) for m in ID_SOURCE_RE.finditer(body)}
    for _ in range(3):
        added = False
        for m in RENAME_RE.finditer(body):
            if m.group(2) in tainted and m.group(1) not in tainted:
                tainted.add(m.group(1))
                added = True
        if not added:
            break
    sinks = []
    for m in SINK_CALL_RE.finditer(body):
        args_vars = set(re.findall(r"\$(\w+)", m.group(2)))
        if args_vars & tainted:
            sinks.append({"func": m.group(1).lower(), "vars": sorted(args_vars & tainted)})
    if SINK_SUPERGLOBAL_RE.search(body):
        sinks.append({"func": "directo-superglobal", "vars": ["$_REQUEST"]})
    owner = bool(OWNER_RE.search(body))
    return tainted, sinks, owner


def _annotate_roles(rec, body, caps, nonce, nopriv):
    """Veredicto clasico + anotacion ROLE-SOLVER (capa 1)."""
    caps_req, rol, sens = _roles_of_body(body)
    rec["caps"] = caps
    rec["nonce"] = nonce
    rec["caps_req"] = caps_req
    rec["rol_minimo"] = rol
    rec["sensible"] = sens
    if caps or nonce:
        rec["veredicto"] = "PROTEGIDO"
        if caps and rol in ("subscriber", "contributor", "author") and sens:
            # exige un privilegio BAJO para una accion SENSIBLE:
            # el nonce prueba identidad, no autorizacion
            rec["veredicto"] = "PRIVILEGIO-DEBIL"
        elif not caps and sens and nopriv:
            rec["solo_nonce"] = True
    elif nopriv:
        rec["veredicto"] = "CANDIDATO-BAC"
    else:
        rec["veredicto"] = "REVISAR-AUTH"
    # capa 2: OBJECT-OWNER (IDOR horizontal estatico)
    tainted, sinks, owner = _idor_of_body(body)
    if sinks:
        rec["object_access"] = sinks
        rec["owner_check"] = owner
        if (not nopriv and not owner
                and rol not in ("administrator", "editor")
                and rec["veredicto"] in ("REVISAR-AUTH", "PRIVILEGIO-DEBIL")):
            # id controlado por el usuario toca objetos sin verificar
            # de quien son, con un rol que no legitima el acceso ajeno
            rec["veredicto"] = "CANDIDATO-IDOR"


def _action_args(line):
    """Primeros 2 argumentos de cada add_action(...) de la linea,
    cortando comas SOLO a profundidad 0 (respetar array($this, 'm'))."""
    out = []
    for mm in re.finditer(r"add_action\s*\(", line):
        depth, cur, args, closed = 0, [], [], False
        for ch in line[mm.end():]:
            if ch in "([{":
                depth += 1
                cur.append(ch)
            elif ch in ")]}":
                if depth == 0:
                    closed = True
                    break
                depth -= 1
                cur.append(ch)
            elif ch == "," and depth == 0:
                args.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        if not closed:
            continue
        args.append("".join(cur).strip())
        if len(args) >= 2 and args[0] and args[1]:
            out.append((args[0], args[1]))
    return out


def _hook_name_from_var(var_expr, cmap):
    """Resuelve el nombre del hook desde $var, concatenacion o interpolacion."""
    val = _resolve_expr(var_expr, cmap)
    if val and AJAX_NAME_RE.match(val):
        return val
    return None


REST_RE = re.compile(r"register_rest_route\s*\(", re.I)
PERM_TRUE_RE = re.compile(r"permission_callback['\"]?\s*=>\s*"
                          r"(__return_true|'__return_true')")
FUNC_RE = re.compile(
    r"(?:public\s+|protected\s+|private\s+|static\s+|"
    r"abstract\s+|final\s+)*function\s+(\w+)\s*\(")


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
    # v0.70.0 fix: array('Cls','m') devolvia la clase, no el metodo.
    am = re.search(r"\barray\s*\(\s*['\"]\w+['\"]\s*,\s*['\"](\w+)['\"]", cb_expr)
    if am:
        return am.group(1)
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
            # RC-000149: m.start() cae en el \n ANTERIOR (el prefijo
            # de FUNC_RE consume espacios/saltos) y con firma precedida
            # por '}' el _body_of devolvia cuerpo vacio (off-by-one
            # heredado, latente en codigo sin docblock). Se ancla al
            # final de la firma, que SI esta en la linea correcta.
            ln = src[:m.end()].count("\n")
            funcs[m.group(1)] = (rel, ln)

    # 1) hooks ajax: accion -> callback
    # v0.63.0 CAPA 3: cmap por archivo para resolver hooks dinamicos
    cmaps = {rel: _const_map(lines) for rel, lines in srcs.items()}

    def _cb_from_expr(cb_expr, rel, line_i):
        """Resuelve callback estatico, de variable o de closure."""
        cm = cmaps[rel]
        # array($this, $m_var) / $cb_var
        if "$" in cb_expr:
            mvar = re.search(r"\$this\s*,\s*\$(\w+)", cb_expr)
            if mvar:
                ent = cm.get(mvar.group(1))
                if ent and ent[0] < line_i:
                    return (_resolve_expr(ent[1], cm) or ""), None
            if re.search(r"^\s*\$\w+\s*$", cb_expr):
                ent = None
                mkey = re.search(r"\$(\w+)", cb_expr)
                if mkey:
                    ent = cm.get(mkey.group(1))
                if ent and ent[0] < line_i:
                    return (_resolve_expr(ent[1], cm) or ""), None
        if "function" in cb_expr or "fn (" in cb_expr:
            # closure en linea: el cuerpo esta AHI MISMO, se analiza despues
            return "", "closure"
        return _resolve_callback(cb_expr), None

    hook_targets: List[Dict[str, str]] = []
    for rel, lines in srcs.items():
        cm = cmaps[rel]
        for i, line in enumerate(lines):
            loader_actions = {mm.group(1) for mm in LOADER_HOOK_RE.finditer(line)}
            for m in list(HOOK_RE.finditer(line)) + list(LOADER_HOOK_RE.finditer(line)):
                action = m.group(1)
                if m.re is HOOK_RE and action in loader_actions:
                    continue
                nopriv = "nopriv" in action
                if m.re is LOADER_HOOK_RE:
                    cb, closure = m.group(3), None
                else:
                    cb, closure = _cb_from_expr(m.group(3) or "", rel, i)
                hook_targets.append({"action": action, "nopriv": nopriv,
                                     "cb": cb or "", "file": rel, "line": i + 1,
                                     "closure": closure})
            # v0.63.0 CAPA 3: add_action($hook_var, ...) — nombre de hook dinamico
            if HOOK_RE.search(line) or LOADER_HOOK_RE.search(line):
                pass  # ya procesado arriba
            else:
                seen_here = {t["action"] for t in hook_targets
                              if t["file"] == rel and t["line"] == i + 1}
                for hook_expr, cb_expr in _action_args(line):
                    action = _hook_name_from_var(hook_expr, cm)
                    if not action or action in seen_here:
                        continue
                    nopriv = "nopriv" in action
                    cb, closure = _cb_from_expr(cb_expr or "", rel, i)
                    hook_targets.append({"action": action, "nopriv": nopriv,
                                         "cb": cb or "", "file": rel, "line": i + 1,
                                         "closure": closure})

    # 2) para cada hook, hallar el cuerpo del callback y ver compuertas
    for h in hook_targets:
        rec: Dict[str, Any] = {"accion": h["action"], "archivo": h["file"],
                               "linea_hook": h["line"], "callback": h["cb"],
                               "anonimo": h["nopriv"]}
        if h.get("closure"):
            # closure en linea: el cuerpo vive en la misma linea del hook
            body, _end = _body_of(srcs[h["file"]], h["line"] - 1)
            rec["archivo_callback"] = h["file"]
            rec["linea_callback"] = h["line"]
            caps = bool(CAPS_RE.search(body))
            nonce = bool(NONCE_RE.search(body))
            _annotate_roles(rec, body, caps, nonce, h["nopriv"])
            rec["callback"] = "closure@" + h["file"] + ":" + str(h["line"])
            handlers.append(rec)
            continue
        cb = h["cb"]
        if cb and cb in funcs:
            frel, fln = funcs[cb]
            body, _end = _body_of(srcs[frel], fln)
            rec["archivo_callback"] = frel
            rec["linea_callback"] = fln + 1
            caps = bool(CAPS_RE.search(body))
            nonce = bool(NONCE_RE.search(body))
            _annotate_roles(rec, body, caps, nonce, h["nopriv"])
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


def _line_in_handler(rec: Dict[str, Any], file_: str, line: int,
                    root: str = ".") -> Optional[Dict[str, Any]]:
    """True si file:line cae dentro del cuerpo REAL del callback.

    Leccion RC-000270: la heuristica de 800 lineas se comia
    funciones vecinas y regalaba POI-UNAUTH de otros handlers
    (nopriv publico + sink en funcion admin del mismo archivo).
    Cuerpo honesto: conteo de llaves desde la declaracion.
    """
    if rec.get("archivo_callback") != file_:
        return None
    start = rec.get("linea_callback", 0)
    if line < start:
        return None
    path = (file_ if os.path.isabs(file_)
            else os.path.join(root, file_))
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    # declaracion: 'function' en la linea del callback (+/-1)
    decl = None
    for off in (0, -1, 1):
        idx = start - 1 + off
        if 0 <= idx < len(lines) and "function" in lines[idx]:
            decl = idx
            break
    if decl is None:
        return None
    depth = 0
    opened = False
    for idx in range(decl, min(decl + 2000, len(lines))):
        t = re.sub(r"'[^']*'|\"[^\"]*\"", "", lines[idx])
        t = re.sub(r"//[^\n]*", "", t)
        t = re.sub(r"/\*.*?\*/", "", t)
        opens, closes = t.count("{"), t.count("}")
        depth += opens - closes
        if opens and not opened:
            opened = True
        if opened and depth <= 0:
            # cierre real de la funcion: 1-based end = idx+1
            return rec if decl + 1 <= line <= idx + 1 else None
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
