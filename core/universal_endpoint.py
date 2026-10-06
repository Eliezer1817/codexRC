#!/usr/bin/env python3
# ============================================================
# codexRC - UNIVERSAL ENDPOINT GRAPH (v0.98.0)
# ------------------------------------------------------------
# Motor de DESCUBRIMIENTO Y NORMALIZACION de la superficie HTTP
# real de una aplicacion, independientemente del router usado
# (WP hooks, Slim-like, PSR-7 custom, array router, Laravel-like,
# generico por patron estructural).
#
# Disparador: auditoria de Amelia Booking (v0.97.0) -> GATES-AUDIT
# solo entiende hooks clasicos de WP; el router custom de Amelia
# dejaba la superficie real de API invisible para TAINT/FIN-LOGIC.
#
# FILOSOFIA (no negociable):
#   CANDIDATE != IMPACT
#   NO EVIDENCE -> NO CLAIM
#   endpoint descubierto != handler completamente resuelto
#   ENDPOINT-DISCOVERED no es VULNERABILITY
#   HANDLER-RESOLVED no es AUTHZ-PROTECTED
#
# Esta capa NO reemplaza GATES-AUDIT, TAINT-TRACE ni FIN-LOGIC.
# Es un puente: descubre, normaliza, conecta. Nivel 1: regex +
# balance de llaves/parentesis; no ejecuta nada (igual que el
# resto del analisis estatico de codexRC).
# ============================================================
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from core import handler_resolver as hres
from core import gates_audit as ga
from core.router_graph import RouterGraph

HTTP_VERBS = ("get", "post", "put", "patch", "delete", "options", "any")
VERB_CALL_RE = re.compile(
    r"(?:\$(\w+)|\b([A-Za-z_]\w*))\s*(->|::)\s*"
    r"(get|post|put|patch|delete|options|any|map|match|route)\s*\(",
    re.I)

# Segmento literal de ruta dentro de una expresion dinamica: un string
# entre comillas que EMPIEZA con '/' y contiene al menos un caracter
# de ruta despues (p.ej. '/stats', "/users/{id}"). Un '/' suelto
# ('/' . $key) NO cuenta como ruta.
_DYN_PATH_SEGMENT_RE = re.compile(r"""(['"])/[A-Za-z0-9_\-{}\[\]:+*.]+""")

METHOD_LITERAL_RE = re.compile(
    r"^['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|ANY)['\"]$", re.I)
METHOD_ARRAY_RE = re.compile(
    r"^\[\s*((?:['\"]\w+['\"]\s*,?\s*)+)\]$")

ARRAY_ROUTE_RE = re.compile(
    r"\$(\w+)\s*\[\s*['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|ANY)"
    r"['\"]\s*\]\s*\[\s*(['\"])((?:\\.|(?!\3).)*?)\3\s*\]\s*=\s*(.+?);",
    re.I)

ARRAY_LITERAL_METHOD_RE = re.compile(
    r"['\"]method['\"]\s*=>\s*['\"](\w+)['\"]", re.I)
ARRAY_LITERAL_PATH_RE = re.compile(
    r"['\"]path['\"]\s*=>\s*['\"]([^'\"]+)['\"]", re.I)
ARRAY_LITERAL_HANDLER_RE = re.compile(
    r"['\"]handler['\"]\s*=>\s*(.+?)(?:,\s*$|\]\s*,?\s*$|$)", re.I)

MIDDLEWARE_TOKEN_RE = re.compile(
    r"(\w*(?:Middleware|Guard|Policy))\s*::\s*class|"
    r"->\s*middleware\s*\(\s*['\"]([^'\"]+)['\"]|"
    r"->\s*(?:add|middleware)\s*\(\s*(?:new\s+)?([A-Za-z0-9_]+)|"
    r"['\"]([\w\-]*(?:auth|role|permission|login_required|guard|policy|"
    r"capability|nonce|token)[\w\-]*)['\"]", re.I)

AUTH_KEYWORD_RE = re.compile(
    r"\b(current_user_can|is_admin|wp_verify_nonce|check_ajax_referer|"
    r"login_required|permission|role|capability|guard|policy|auth\(\)|"
    r"isAuthenticated|requireAuth)\b", re.I)

PATH_PARAM_RES = [
    re.compile(r"\{(\w+)\}"),
    re.compile(r":(\w+)"),
    re.compile(r"<(\w+)>"),
    re.compile(r"\$(\w+)"),
]

REQUEST_PARAM_RE = re.compile(
    r"\$request\s*->\s*getParam\s*\(\s*['\"](\w+)['\"]")
REQUEST_BODY_PARAM_RE = re.compile(
    r"\$request\s*->\s*getParsedBody\s*\(\s*\)\s*\[\s*['\"](\w+)['\"]\s*\]")
REQUEST_QUERY_PARAM_RE = re.compile(
    r"\$request\s*->\s*getQueryParams\s*\(\s*\)\s*\[\s*['\"](\w+)['\"]\s*\]")
REQUEST_ATTR_RE = re.compile(
    r"\$request\s*->\s*getAttribute\s*\(\s*['\"](\w+)['\"]")
SUPERGLOBAL_RE = re.compile(
    r"\$_(GET|POST|REQUEST)\s*\[\s*['\"](\w+)['\"]\s*\]")

CLASS_METHOD_RE = re.compile(
    r"\[\s*([A-Za-z_][\w\\]*)\s*::\s*class\s*,\s*['\"](\w+)['\"]\s*\]")
THIS_METHOD_RE = re.compile(r"\[\s*\$this\s*,\s*['\"](\w+)['\"]\s*\]")
STATIC_STR_METHOD_RE = re.compile(r"^['\"]([\w\\]+)::(\w+)['\"]$")
PLAIN_FUNC_RE = re.compile(r"^['\"](\w+)['\"]$")


# ----------------------------------------------------------- utilidades


def _php_files(root: str) -> List[str]:
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.lower().endswith(".php"):
                out.append(os.path.join(dirpath, f))
    return out


def _read_lines(path: str) -> List[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def _find_matching_close(src: str, open_idx: int, open_c: str = "(",
                          close_c: str = ")") -> Optional[int]:
    depth = 0
    i = open_idx
    in_sq = in_dq = False
    while i < len(src):
        c = src[i]
        if in_sq:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_sq = False
        elif in_dq:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_dq = False
        else:
            if c == "'":
                in_sq = True
            elif c == '"':
                in_dq = True
            elif c == open_c:
                depth += 1
            elif c == close_c:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return None


def _split_top_level_args(args_src: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    in_sq = in_dq = False
    cur: List[str] = []
    i = 0
    while i < len(args_src):
        c = args_src[i]
        if in_sq:
            cur.append(c)
            if c == "\\" and i + 1 < len(args_src):
                cur.append(args_src[i + 1])
                i += 2
                continue
            if c == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            cur.append(c)
            if c == "\\" and i + 1 < len(args_src):
                cur.append(args_src[i + 1])
                i += 2
                continue
            if c == '"':
                in_dq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
            cur.append(c)
            i += 1
            continue
        if c == '"':
            in_dq = True
            cur.append(c)
            i += 1
            continue
        if c in "([{":
            depth += 1
            cur.append(c)
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            cur.append(c)
            i += 1
            continue
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _unquote(s: str) -> Optional[str]:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return None


def _looks_like_path(arg: Optional[str]) -> Tuple[bool, bool]:
    """(es_path, es_dinamico). Exige evidencia estructural: debe ser
    un literal que empiece con '/', o una expresion dinamica que
    CONTENGA un fragmento literal con '/'. Sin eso -> no es ruta
    (asi se descartan getters comunes: $request->get('name'),
    $cache->get('key'), etc. -- REGLA 22 ZERO-FP CONTRACT)."""
    if arg is None:
        return False, False
    lit = _unquote(arg)
    if lit is not None:
        return lit.startswith("/"), False
    # expresion dinamica: $prefix . '/path' , "{$x}/y", etc.
    # v0.99.1: el fragmento con '/' debe ser un LITERAL entre comillas
    # que EMPIECE con '/' (segmento de ruta real). Antes bastaba
    # cualquier '/' en la expresion, lo que aceptaba concatenaciones
    # de rutas de ARCHIVO (GIVE_PLUGIN_DIR . 'build/x.php'), de
    # URLs de SDK (merchantPath() . '/x') y claves de cache
    # ('question-' . $id . '/' . $key). Medido sobre 10 plugins
    # reales de wordpress.org (2026-10-06).
    if "$" in arg or "." in arg:
        if _DYN_PATH_SEGMENT_RE.search(arg):
            return True, True
    return False, False


# Receptores que son CLIENTES HTTP salientes (consumen una API remota),
# no routers que registran rutas entrantes: $this->_http->post(...),
# $client->get(...), $curl->post(...), $guzzle->get(...). Se evalua el
# ULTIMO segmento del receptor inmediatamente antes de ->verbo( .
_OUTBOUND_CLIENT_RECV_RE = re.compile(
    r"_*(?:http|client|curl|guzzle|requests?|transport|fetcher)\w*$", re.I)


def _handler_is_plain_data(expr: Optional[str]) -> bool:
    """True si el 'handler' es estructuralmente un DATO y no un callable:
    string literal plano (sin forma Clase@metodo) o array asociativo
    (contiene '=>'). Una variable pelada NO cuenta como dato: puede ser
    un callable de origen externo (HANDLER-UNRESOLVED, caso case6).
    Evita aceptar llamadas a clientes HTTP / caches con la forma
    ->post($path, ['k' => $v]) o ->get($key, 'grupo/x')."""
    if expr is None:
        return False
    e = expr.strip()
    if not e:
        return False
    lit = _unquote(e)
    if lit is not None:
        return "@" not in lit  # 'Ctrl@metodo' (Laravel) si es callable
    if (e.startswith("[") or e.lower().startswith("array(")) \
            and "=>" in e:
        return True
    return False


def _normalize_path(path_raw: str) -> str:
    out = path_raw
    for pat in PATH_PARAM_RES:
        out = pat.sub(lambda m: "{" + m.group(1) + "}", out)
    return out


def _route_params_from_path(path_norm: str) -> List[Dict[str, str]]:
    return [{"name": n, "kind": "ROUTE_PARAM"}
            for n in re.findall(r"\{(\w+)\}", path_norm)]


def _extract_middleware(call_src: str) -> List[Dict[str, Any]]:
    found = []
    seen = set()
    for m in MIDDLEWARE_TOKEN_RE.finditer(call_src):
        name = next((g for g in m.groups() if g), None)
        if not name or name in seen:
            continue
        seen.add(name)
        found.append({"type": "middleware", "name": name,
                     "confidence": "HIGH" if "Middleware" in name
                     or "Guard" in name or "Policy" in name else "MEDIUM"})
    return found


def _auth_signals(text: str) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for m in AUTH_KEYWORD_RE.finditer(text):
        tok = m.group(1)
        if tok in seen:
            continue
        seen.add(tok)
        out.append({"type": "keyword", "name": tok, "confidence": "MEDIUM"})
    return out


def _classify_handler_expr(expr: str) -> Dict[str, Any]:
    """Devuelve {'style':..., 'class':..., 'method':..., 'func':...}
    sin resolver aun el cuerpo."""
    expr = expr.strip()
    m = CLASS_METHOD_RE.search(expr)
    if m:
        return {"style": "class_method", "class": m.group(1).split("\\")[-1],
                "method": m.group(2)}
    m = THIS_METHOD_RE.search(expr)
    if m:
        return {"style": "this_method", "class": None, "method": m.group(1)}
    m = STATIC_STR_METHOD_RE.match(expr)
    if m:
        return {"style": "class_method", "class": m.group(1).split("\\")[-1],
                "method": m.group(2)}
    m = PLAIN_FUNC_RE.match(expr)
    if m:
        return {"style": "function", "class": None, "method": m.group(1)}
    if re.search(r"^\s*function\s*\(", expr) or re.search(
            r"^\s*(?:static\s*)?function\s*\(", expr):
        return {"style": "closure", "class": None, "method": None}
    if re.search(r"^\s*fn\s*\(", expr):
        return {"style": "arrow", "class": None, "method": None}
    if re.match(r"^\$\w+$", expr):
        return {"style": "variable", "class": None, "method": None}
    return {"style": "unknown", "class": None, "method": None}


def _extract_params_from_body(body: str) -> List[Dict[str, str]]:
    out = []
    for m in REQUEST_PARAM_RE.finditer(body):
        out.append({"name": m.group(1), "kind": "HTTP_PARAM"})
    for m in REQUEST_BODY_PARAM_RE.finditer(body):
        out.append({"name": m.group(1), "kind": "BODY_PARAM"})
    for m in REQUEST_QUERY_PARAM_RE.finditer(body):
        out.append({"name": m.group(1), "kind": "QUERY_PARAM"})
    for m in REQUEST_ATTR_RE.finditer(body):
        out.append({"name": m.group(1), "kind": "ATTRIBUTE"})
    for m in SUPERGLOBAL_RE.finditer(body):
        kind = {"GET": "QUERY_PARAM", "POST": "BODY_PARAM",
                "REQUEST": "HTTP_PARAM"}[m.group(1).upper()]
        out.append({"name": m.group(2), "kind": kind})
    # dedup conservando orden
    seen = set()
    dedup = []
    for p in out:
        key = (p["name"], p["kind"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(p)
    return dedup


# ----------------------------------------------------------- descubrimiento


def _discover_calls_in_file(rel: str, lines: List[str], src: str
                             ) -> List[Dict[str, Any]]:
    out = []
    for m in VERB_CALL_RE.finditer(src):
        recv = m.group(1) or m.group(2) or ""
        if _OUTBOUND_CLIENT_RECV_RE.match(recv):
            continue  # v0.99.1: cliente HTTP saliente, no router
        verb = m.group(4).lower()
        open_idx = src.find("(", m.end() - 1)
        if open_idx == -1:
            continue
        close_idx = _find_matching_close(src, open_idx)
        if close_idx is None:
            continue
        args_src = src[open_idx + 1:close_idx]
        args = _split_top_level_args(args_src)
        
        # Extend call_src up to the next semicolon to catch chained methods ->middleware()
        stmt_end = src.find(';', close_idx)
        if stmt_end != -1:
            call_src = src[m.start():stmt_end + 1]
        else:
            call_src = src[m.start():close_idx + 1]
        line_no = src[:m.start()].count("\n") + 1

        method = path_arg = handler_arg = None
        if verb in HTTP_VERBS:
            if not args:
                continue
            method = "ANY" if verb == "any" else verb.upper()
            path_arg = args[0]
            handler_arg = args[-1] if len(args) >= 2 else None
        elif verb in ("map", "match", "route"):
            if len(args) < 2:
                continue
            lit = _unquote(args[0])
            if lit and lit.upper() in ("GET", "POST", "PUT", "PATCH",
                                       "DELETE", "OPTIONS", "HEAD", "ANY"):
                method = lit.upper()
                path_arg = args[1] if len(args) > 1 else None
                handler_arg = args[2] if len(args) > 2 else None
            else:
                am = METHOD_ARRAY_RE.match(args[0])
                if am:
                    methods = re.findall(r"['\"](\w+)['\"]", args[0])
                    method = "|".join(x.upper() for x in methods)
                    path_arg = args[1] if len(args) > 1 else None
                    handler_arg = args[2] if len(args) > 2 else None
                else:
                    continue
        else:
            continue

        is_path, is_dyn = _looks_like_path(path_arg)
        if not is_path:
            continue  # ZERO-FP: sin evidencia estructural de ruta real
        if _handler_is_plain_data(handler_arg):
            continue  # v0.99.1: handler = dato, no callable (cliente HTTP/cache)

        middleware = []
        if len(args) >= 3 and verb in HTTP_VERBS:
            for mid_arg in args[1:-1]:
                middleware.extend(_extract_middleware(mid_arg))
        middleware.extend(_extract_middleware(call_src))
        # dedup middleware por nombre
        seen_mid = set()
        mid_dedup = []
        for mdw in middleware:
            if mdw["name"] in seen_mid:
                continue
            seen_mid.add(mdw["name"])
            mid_dedup.append(mdw)

        out.append({
            "method": method,
            "path_raw": _unquote(path_arg) if not is_dyn else path_arg,
            "path_dynamic": is_dyn,
            "handler_expr": handler_arg,
            "file": rel,
            "line": line_no,
            "router_source": "custom_router",
            "verb_matched": verb,
            "middleware": mid_dedup,
            "auth_signals": _auth_signals(call_src),
            "call_src": call_src,
        })
    return out


def _discover_array_routes(rel: str, src: str) -> List[Dict[str, Any]]:
    out = []
    for m in ARRAY_ROUTE_RE.finditer(src):
        # v0.99.1: 'options'/'post'/'get' son claves de array comunes en
        # config/WP ($data['options']['x'] = 'wp'). Sin un path que empiece
        # con '/' no hay evidencia de ruta HTTP.
        if not m.group(4).startswith("/"):
            continue
        if _handler_is_plain_data(m.group(5).strip()):
            continue
        line_no = src[:m.start()].count("\n") + 1
        out.append({
            "method": m.group(2).upper(),
            "path_raw": m.group(4),
            "path_dynamic": False,
            "handler_expr": m.group(5).strip(),
            "file": rel,
            "line": line_no,
            "router_source": "array_router",
            "verb_matched": "array_assign",
            "middleware": [],
            "auth_signals": _auth_signals(m.group(0)),
            "call_src": m.group(0),
        })
    return out


def _discover_array_literal_routes(rel: str, src: str) -> List[Dict[str, Any]]:
    """['method' => 'POST', 'path' => '/x', 'handler' => ...] -- se
    busca en bloques delimitados por '[' ... ']' (misma tecnica de
    balance de parentesis/corchetes que el resto del motor)."""
    out = []
    for m in re.finditer(r"\[", src):
        open_idx = m.start()
        close_idx = _find_matching_close(src, open_idx, "[", "]")
        if close_idx is None:
            continue
        block = src[open_idx:close_idx + 1]
        mm = ARRAY_LITERAL_METHOD_RE.search(block)
        mp = ARRAY_LITERAL_PATH_RE.search(block)
        if not (mm and mp):
            continue
        mh = ARRAY_LITERAL_HANDLER_RE.search(block)
        line_no = src[:open_idx].count("\n") + 1
        out.append({
            "method": mm.group(1).upper(),
            "path_raw": mp.group(1),
            "path_dynamic": False,
            "handler_expr": mh.group(1).strip().rstrip(",]") if mh else None,
            "file": rel,
            "line": line_no,
            "router_source": "array_router",
            "verb_matched": "array_literal",
            "middleware": [],
            "auth_signals": _auth_signals(block),
            "call_src": block[:200],
        })
    return out


def _discover_wordpress(root: str) -> List[Dict[str, Any]]:
    """Normaliza la superficie que GATES-AUDIT ya conoce (wp_ajax /
    wc_ajax) al mismo modelo universal. No reemplaza GATES-AUDIT:
    reutiliza su propio descubrimiento de hooks."""
    out = []
    try:
        audit_res = ga.audit(root)
    except Exception:
        return out
    for h in audit_res.get("handlers", []):
        accion = h.get("accion") or ""
        out.append({
            "method": "POST",
            "path_raw": f"/wp-admin/admin-ajax.php?action={accion}",
            "path_dynamic": False,
            "handler_expr": None,
            "file": h.get("archivo"),
            "line": h.get("linea_hook"),
            "router_source": ("wordpress_ajax" if "nopriv" not in accion
                              or True else "wordpress_ajax"),
            "verb_matched": "add_action",
            "middleware": [],
            "auth_signals": [],
            "call_src": accion,
            "_gates_record": h,
        })
    return out


# ----------------------------------------------------------- resolucion


def _locate_file_by_class(root: str, class_name: str,
                          php_files: List[str]) -> Optional[str]:
    pat = re.compile(r"\bclass\s+" + re.escape(class_name) + r"\b")
    for path in php_files:
        lines = _read_lines(path)
        for line in lines:
            if pat.search(line):
                return path
    return None


def _resolve_handler(root: str, route: Dict[str, Any],
                     php_files: List[str]) -> Dict[str, Any]:
    expr = route.get("handler_expr")
    if not expr:
        return {"resolved": False, "kind": "unresolved", "label": None,
                "file": None, "start_line": None, "end_line": None,
                "body": None}
    cls_info = _classify_handler_expr(expr)
    style = cls_info["style"]

    if style in ("class_method", "this_method") and cls_info.get("method"):
        method = cls_info["method"]
        cls = cls_info.get("class")
        target_file = route["file"]
        if cls:
            found = _locate_file_by_class(
                root, cls, php_files) or os.path.join(root, route["file"])
            target_file = os.path.relpath(found, root) if os.path.isabs(
                found) else found
        abs_path = (target_file if os.path.isabs(target_file)
                   else os.path.join(root, target_file))
        lines = _read_lines(abs_path)
        res = hres.resolve_method(lines, method, cls)
        label = f"{cls}::{method}" if cls else method
        return {"resolved": res["resolved"], "kind": res["kind"],
                "label": label, "file": target_file,
                "start_line": res["start_line"], "end_line": res["end_line"],
                "body": res["body"]}

    if style == "function" and cls_info.get("method"):
        func = cls_info["method"]
        pat = re.compile(
            r"(?:public\s+|protected\s+|private\s+|static\s+)*function\s+"
            + re.escape(func) + r"\s*\(")
        for path in php_files:
            lines = _read_lines(path)
            for i, line in enumerate(lines):
                if pat.search(line):
                    bounds = hres.body_bounds(lines, i)
                    rel = os.path.relpath(path, root)
                    if bounds:
                        s, e = bounds
                        return {"resolved": True, "kind": "function",
                                "label": func, "file": rel,
                                "start_line": s + 1, "end_line": e + 1,
                                "body": "\n".join(lines[s:e + 1])}
                    return {"resolved": False, "kind": "function",
                            "label": func, "file": rel,
                            "start_line": i + 1, "end_line": None,
                            "body": None}
        return {"resolved": False, "kind": "function", "label": func,
                "file": None, "start_line": None, "end_line": None,
                "body": None}

    if style in ("closure", "arrow"):
        abs_path = os.path.join(root, route["file"])
        lines = _read_lines(abs_path)
        res = hres.resolve_inline_closure(lines, route["line"])
        return {"resolved": res["resolved"], "kind": res["kind"],
                "label": "<closure>", "file": route["file"],
                "start_line": res["start_line"], "end_line": res["end_line"],
                "body": res["body"]}

    # variable / unknown: no hay suficiente evidencia estatica para
    # trazar el origen sin dataflow adicional -> HANDLER-UNRESOLVED
    return {"resolved": False, "kind": style, "label": expr,
            "file": None, "start_line": None, "end_line": None,
            "body": None}


# ----------------------------------------------------------- API principal


def discover(root: str, include_wordpress: bool = True) -> Dict[str, Any]:
    """Descubre, normaliza y deduplica la superficie HTTP de `root`.

    Devuelve {"endpoints": [...], "graph": {...}, "metrics": {...}}.
    Nunca inventa paths ni handlers: lo que no tiene evidencia queda
    como UNKNOWN / HANDLER-UNRESOLVED, pero el endpoint se conserva
    (REGLA 11: endpoint descubierto != handler resuelto).
    """
    php_files = _php_files(root)
    raw_routes: List[Dict[str, Any]] = []

    for path in php_files:
        rel = os.path.relpath(path, root)
        lines = _read_lines(path)
        src = "\n".join(lines)
        if not src:
            continue
        raw_routes.extend(_discover_calls_in_file(rel, lines, src))
        raw_routes.extend(_discover_array_routes(rel, src))
        raw_routes.extend(_discover_array_literal_routes(rel, src))

    if include_wordpress:
        raw_routes.extend(_discover_wordpress(root))

    graph = RouterGraph()
    endpoints: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    false_routes_considered = 0

    for r in raw_routes:
        resolved = _resolve_handler(root, r, php_files)
        # REGLA 24: un path dinamico NO se normaliza ni se inventa;
        # se conserva la expresion tal cual como evidencia.
        if r.get("path_dynamic"):
            path_norm = r["path_raw"]
        else:
            path_norm = (_normalize_path(r["path_raw"])
                         if r["path_raw"] else None)
        handler_label = resolved["label"] or r.get("call_src", "")[:60]
        key = (r["method"] or "UNKNOWN", path_norm or r["path_raw"] or "",
              handler_label or "")

        confidence = "HIGH"
        state = "KNOWN"
        if r.get("path_dynamic"):
            confidence = "LOW"
            state = "INFERRED"
        elif not resolved["resolved"]:
            confidence = "MEDIUM"
            state = "INFERRED"
        if r["method"] is None or path_norm is None:
            state = "UNKNOWN"

        params = list(r.get("route_params", []))
        if not r.get("path_dynamic"):
            params.extend(_route_params_from_path(path_norm or ""))
        if resolved.get("body"):
            params.extend(_extract_params_from_body(resolved["body"]))

        auth_signals = list(r.get("auth_signals", []))
        for mdw in r.get("middleware", []):
            auth_signals.append(mdw)
        if resolved.get("body"):
            auth_signals.extend(_auth_signals(resolved["body"]))

        if key in endpoints:
            ep = endpoints[key]
            if r["router_source"] not in ep["sources"]:
                ep["sources"].append(r["router_source"])
            continue

        router_node = graph.add_node(
            "router", r["router_source"], source=r["router_source"])
        route_node = graph.add_node(
            "route", f"{r['method']} {path_norm}",
            method=r["method"], path=path_norm)
        graph.add_edge(router_node, route_node, "DECLARES",
                      file=r["file"], line=r["line"], evidence=r.get(
                          "call_src", "")[:160])
        handler_node = graph.add_node(
            "handler", handler_label,
            resolved=resolved["resolved"],
            file=resolved.get("file") or r["file"],
            line=resolved.get("start_line") or r["line"])
        graph.add_edge(route_node, handler_node, "HANDLED_BY",
                      file=r["file"], line=r["line"])
        for mdw in r.get("middleware", []):
            mdw_node = graph.add_node("middleware", mdw["name"])
            graph.add_edge(route_node, mdw_node, "PASSES_THROUGH",
                          file=r["file"], line=r["line"])
            graph.add_edge(mdw_node, handler_node, "THEN")
        for p in params:
            p_node = graph.add_node("parameter", p["name"], param_kind=p["kind"])
            graph.add_edge(handler_node, p_node, "RECEIVES")

        endpoints[key] = {
            "endpoint_id": f"ep_{len(endpoints) + 1:04d}",
            "method": r["method"],
            "path": path_norm,
            "path_raw": r["path_raw"],
            "source": r["router_source"],
            "sources": [r["router_source"]],
            "router": r["router_source"],
            "handler": handler_label,
            "handler_resolved": resolved["resolved"],
            "handler_kind": resolved["kind"],
            "file": r["file"],
            "line": r["line"],
            "resolved_file": resolved.get("file"),
            "resolved_line": resolved.get("start_line"),
            "resolved_end_line": resolved.get("end_line"),
            "params": params,
            "middleware": r.get("middleware", []),
            "auth_signals": auth_signals,
            "auth": "UNKNOWN",
            "confidence": confidence,
            "state": state,
            "_gates_record": r.get("_gates_record"),
        }

    metrics = {
        "routers_found": len({e["source"] for e in endpoints.values()}),
        "endpoints_found": len(raw_routes),
        "endpoints_deduplicated": len(endpoints),
        "handlers_resolved": sum(1 for e in endpoints.values()
                                if e["handler_resolved"]),
        "handlers_unresolved": sum(1 for e in endpoints.values()
                                   if not e["handler_resolved"]),
        "params_found": sum(len(e["params"]) for e in endpoints.values()),
        "middleware_found": sum(len(e["middleware"])
                                for e in endpoints.values()),
        "confidence_high": sum(1 for e in endpoints.values()
                               if e["confidence"] == "HIGH"),
        "confidence_medium": sum(1 for e in endpoints.values()
                                 if e["confidence"] == "MEDIUM"),
        "confidence_low": sum(1 for e in endpoints.values()
                              if e["confidence"] == "LOW"),
        "false_routes_discarded": false_routes_considered,
    }

    return {"endpoints": list(endpoints.values()), "graph": graph.to_dict(),
            "metrics": metrics}


# ------------------------------------------------- adaptadores (REGLA 17-19)


def to_gates_handlers(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adapta endpoints universales al formato de 'handlers' que ya
    consumen gates_audit/fin_param_graph (archivo_callback, linea_callback,
    accion). NO reemplaza GATES-AUDIT ni duplica AUTHZ-PROOF: solo deja
    que otros motores iteren sobre la MISMA superficie con la MISMA
    interfaz, sin importar si vino de WP o de un router custom."""
    out = []
    for e in endpoints:
        if e.get("_gates_record"):
            out.append(e["_gates_record"])
            continue
        callback_file = e.get("resolved_file") or e.get("file")
        callback_line = e.get("resolved_line") or e.get("line")
        if not callback_file or not callback_line:
            continue
        out.append({
            "accion": e["handler"] or e["path"] or "unknown",
            "archivo": e["file"],
            "linea_hook": e["line"],
            "archivo_callback": callback_file,
            "linea_callback": callback_line,
            "nopriv": None,
            "veredicto": "UNIVERSAL-UNVERIFIED",
            "universal_endpoint_id": e["endpoint_id"],
            "universal_source": e["source"],
        })
    return out


def to_fin_param_sources(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Puente endpoint -> handler -> source context para FIN-LOGIC.
    Clasifica los parametros que el descubridor ya extrajo del handler
    con el MISMO clasificador que usa FIN-PARAM-INFER (fpi._classify):
    no se duplica FIN-LOGIC, se le entrega la superficie. Solo pasan los
    parametros con semantica financiera/estado reconocida."""
    from core import fin_param_infer as fpi
    out = []
    for e in endpoints:
        for p in e.get("params", []):
            cls = fpi._classify(p["name"])
            if not cls:
                continue
            out.append({
                "parametro": p["name"],
                "tipo": cls["tipo"],
                "confianza": cls["confianza"],
                "archivo": e.get("resolved_file") or e["file"],
                "linea": e.get("resolved_line") or e["line"],
                "endpoint": e["handler"] or e["path"],
            })
    return out


def surface_for_target(root: str) -> Dict[str, Any]:
    """Fachada pequena para el Hunter (REGLA 29): descubre la superficie
    y la deja lista para que GATES/TAINT/FIN-LOGIC la conecten. No monta
    nada dentro del Hunter todavia; eso llega despues de LAB+REGRESION."""
    res = discover(root)
    res["gates_handlers"] = to_gates_handlers(res["endpoints"])
    res["fin_param_sources"] = to_fin_param_sources(res["endpoints"])
    return res
