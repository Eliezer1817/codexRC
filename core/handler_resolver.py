#!/usr/bin/env python3
# ============================================================
# codexRC - HANDLER RESOLVER (v0.98.0)
# ------------------------------------------------------------
# Resuelve el cuerpo REAL de un handler (function / metodo /
# closure / arrow function) a partir de su declaracion.
#
# Reusa la filosofia de _line_in_handler (gates_audit v0.96.1,
# RC-000270): conteo de llaves desde la declaracion real.
# NUNCA una ventana arbitraria de +-800 lineas como sustituto
# de resolver el handler (ver REGLA 11 de v0.98.0).
#
# endpoint descubierto != handler completamente resuelto.
# Si no se puede resolver: HANDLER-UNRESOLVED, pero el
# endpoint universal sigue siendo valido (ver universal_endpoint.py).
# ============================================================
import re
from typing import Any, Dict, List, Optional, Tuple

METHOD_DECL_RE_TMPL = (
    r"(?:public\s+|protected\s+|private\s+|static\s+|"
    r"abstract\s+|final\s+)*function\s+(?:&\s*)?{name}\s*\(")
CLOSURE_DECL_RE = re.compile(r"function\s*(?:\([^)]*\))?\s*(?:use\s*\([^)]*\))?\s*\{")
ARROW_DECL_RE = re.compile(r"\bfn\s*\(")
CLASS_DECL_RE_TMPL = r"\bclass\s+{name}\b"


def _strip_noise(line: str) -> str:
    """Quita strings y comentarios para no confundir llaves de
    texto con llaves de estructura (misma tecnica de gates_audit)."""
    t = re.sub(r"'[^']*'|\"[^\"]*\"", "", line)
    t = re.sub(r"//[^\n]*", "", t)
    t = re.sub(r"/\*.*?\*/", "", t)
    return t


def find_class_decl(lines: List[str], class_name: str) -> Optional[int]:
    pat = re.compile(CLASS_DECL_RE_TMPL.format(name=re.escape(class_name)))
    for i, line in enumerate(lines):
        if pat.search(line):
            return i
    return None


def find_method_decl(lines: List[str], method_name: str,
                      search_from: int = 0,
                      search_until: Optional[int] = None) -> Optional[int]:
    """Linea 0-based de 'function <method_name>(' dentro de [search_from, search_until)."""
    pat = re.compile(METHOD_DECL_RE_TMPL.format(name=re.escape(method_name)))
    end = search_until if search_until is not None else len(lines)
    for i in range(search_from, min(end, len(lines))):
        if pat.search(lines[i]):
            return i
    return None


def body_bounds(lines: List[str], decl_line: int,
                max_lines: int = 4000) -> Optional[Tuple[int, int]]:
    """(start,end) 0-based inclusivo del cuerpo real, contando llaves
    desde la linea de declaracion. La apertura '{' puede estar unas
    pocas lineas despues (firma multilinea con type-hints)."""
    brace_line = None
    for idx in range(decl_line, min(decl_line + 12, len(lines))):
        t = _strip_noise(lines[idx])
        if "{" in t:
            brace_line = idx
            break
        if ";" in t and idx > decl_line:
            return None  # firma abstracta/interfaz, sin cuerpo
    if brace_line is None:
        return None
    depth = 0
    opened = False
    for idx in range(brace_line, min(brace_line + max_lines, len(lines))):
        t = _strip_noise(lines[idx])
        opens, closes = t.count("{"), t.count("}")
        depth += opens - closes
        if opens and not opened:
            opened = True
        if opened and depth <= 0:
            return decl_line, idx
    return None


def resolve_method(lines: List[str], method_name: str,
                    class_name: Optional[str] = None) -> Dict[str, Any]:
    """Resuelve 'Class::method' o 'method' dentro de un archivo ya leido
    (lista de lineas). Si class_name se da, acota la busqueda al cuerpo
    de esa clase para no pisar un metodo homonimo de otra clase."""
    search_from, search_until = 0, None
    if class_name:
        cdecl = find_class_decl(lines, class_name)
        if cdecl is not None:
            cbounds = body_bounds(lines, cdecl)
            if cbounds:
                search_from, search_until = cbounds[0], cbounds[1] + 1
    decl = find_method_decl(lines, method_name, search_from,
                            search_until)
    if decl is None:
        return {"resolved": False, "kind": "unresolved",
                "start_line": None, "end_line": None, "body": None}
    bounds = body_bounds(lines, decl)
    if not bounds:
        return {"resolved": False, "kind": "method",
                "start_line": decl + 1, "end_line": None, "body": None}
    start, end = bounds
    return {"resolved": True, "kind": "method",
            "start_line": start + 1, "end_line": end + 1,
            "body": "\n".join(lines[start:end + 1])}


def resolve_inline_closure(lines: List[str], approx_line_1based: int,
                           search_window: int = 6) -> Dict[str, Any]:
    """Resuelve una closure/arrow-fn declarada cerca de approx_line
    (p.ej. el mismo statement de registro de ruta)."""
    idx0 = max(approx_line_1based - 1, 0)
    for idx in range(idx0, min(idx0 + search_window, len(lines))):
        t = _strip_noise(lines[idx])
        if CLOSURE_DECL_RE.search(t) or re.search(r"function\s*\(", t):
            bounds = body_bounds(lines, idx)
            if bounds:
                start, end = bounds
                return {"resolved": True, "kind": "closure",
                        "start_line": start + 1, "end_line": end + 1,
                        "body": "\n".join(lines[start:end + 1])}
            return {"resolved": False, "kind": "closure",
                    "start_line": idx + 1, "end_line": None, "body": None}
        if ARROW_DECL_RE.search(t):
            # arrow fn: cuerpo de una sola expresion hasta ')' o ';' de cierre
            return {"resolved": True, "kind": "arrow",
                    "start_line": idx + 1, "end_line": idx + 1,
                    "body": lines[idx]}
    return {"resolved": False, "kind": "unresolved",
            "start_line": None, "end_line": None, "body": None}
