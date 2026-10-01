"""TAINT-TRACE: analisis de flujo de datos (taint) sobre codigo fuente PHP.

Sigue el valor de un parametro desde la FUENTE ($_GET/$_POST/$_REQUEST/
$_COOKIE/php://input/$_SERVER) a traves de asignaciones y concatenaciones
hasta el SINK peligroso:

  base de datos : $wpdb->query/get_var/get_row/get_results, mysql_query
  navegador     : echo/print/printf (XSS)
  objetos       : unserialize (object injection)
  archivos      : include/require/file_get_contents/file_put_contents (LFI)
  comandos      : system/exec/passthru/eval (RCE)
  red           : wp_remote_get/curl (SSRF)

Si el sink recibe un valor que NACE del usuario SIN sanitizador en el
camino, es hallazgo: la vulnerabilidad existe aunque la respuesta HTTP
no muestre nada (SQLi ciego, XSS reflejado en otra pagina, etc).

Sanitizadores que cortan el taint: intval/absint/sanitize_*/esc_sql/
esc_attr/esc_html/esc_url/wp_kses. $wpdb->prepare con placeholders y el
taint SOLO en los valores (no en la cadena de formato) = SEGURO.

Nivel 1 (heuristico, intra-archivo): analisis por linea con punto fijo
hasta que el taint deja de propagarse. Sin dependencias externas,
Python puro, sirve en Termux. Para nivel interprocedural sigue siendo
mejor Semgrep (SINK-SCAN); este tracer es el complemento vivo.

Uso:
    python3 core/taint_trace.py <archivo_o_directorio> [--json] [--top N]
    POST /api/taint  {"path": "..."}   (desde el backend)
"""

import json
import os
import re
import sys
from typing import Any, Dict, List

# ---------------------------------------------------------------- fuentes

SOURCES = [
    r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b",
    r"php://input", r"\$_FILES\b",
    r"\$_SERVER\[.(?:REQUEST_URI|HTTP_USER_AGENT|HTTP_REFERER|HTTP_X_)",
    r"\bget_query_var\s*\(", r"wp_get_raw_referer\s*\(",
]
_SRC_RE = re.compile("|".join(SOURCES))

# ------------------------------------------------------------- sanitizadores

SANITIZERS = r"(?:intval|absint|sanitize_text_field|sanitize_email|" \
             r"sanitize_key|sanitize_title|sanitize_user|sanitize_file_name|" \
             r"sanitize_html_class|esc_sql|esc_attr|esc_html|esc_url|" \
             r"esc_url_raw|wp_kses|wp_kses_post|intval\(|sanitize_meta)"

# ------------------------------------------------------------------- sinks

SINKS: List[Dict[str, Any]] = [
    {"type": "SQLI (base de datos)", "sev": "critica", "pat":
     r"(?:\$\w+->(?:query|get_var|get_row|get_results|get_col)\s*\(|"
     r"mysql_query\s*\(|mysqli_query\s*\(|->query\s*\()"},
    {"type": "XSS (navegador)", "sev": "alta", "pat":
     r"(?:\becho\s|\bprint\s*\(|\bprintf\s*\(|print_r\s*\(|var_dump\s*\()"},
    {"type": "OBJECT INJECTION", "sev": "critica", "pat":
     r"(?<!maybe_)\bunserialize\s*\("},
    {"type": "LFI / ARCHIVOS", "sev": "alta", "pat":
     r"(?:\b(?:include|include_once|require|require_once)\s*\(?\s*\$|"
     r"file_get_contents\s*\(\s*\$|fopen\s*\(\s*\$|readfile\s*\(\s*\$|"
     r"file_put_contents\s*\(|move_uploaded_file\s*\()"},
    {"type": "RCE (comandos)", "sev": "critica", "pat":
     r"(?:\beval\s*\(|\bsystem\s*\(|\bexec\s*\(|\bpassthru\s*\(|"
     r"shell_exec\s*\(|\bpopen\s*\(|proc_open\s*\()"},
    {"type": "SSRF (red)", "sev": "media", "pat":
     r"(?:wp_remote_(?:get|post|request)\s*\(|curl_exec\s*\()"},
]

_ASSIGN = re.compile(r"^\s*(?:global\s+[^;]+;\s*)?"
                     r"(\$[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=(?!=)")
_VAR = re.compile(r"\$[A-Za-z_]\w*")
_FOREACH = re.compile(r"foreach\s*\(\s*(" + "|".join(SOURCES) +
                     r")[^)]*?\bas\s+(\$[A-Za-z_]\w*)\s*(?:=>\s*"
                     r"(\$[A-Za-z_]\w*))?\s*\)")
_PREPARE_SAFE = re.compile(
    r"->prepare\s*\(\s*['\"][^'\"]*%[dsf]['\"]")


def _rhs_of(line: str) -> str:
    m = re.search(r"=(?!=)(.*)$", line)
    return m.group(1) if m else ""


def _sanitized_only(rhs: str, tainted_vars: set) -> bool:
    """True si el RHS es un sanitizador que envuelve SOLO vars tainteadas."""
    body = rhs.strip().rstrip(";").strip()
    m = re.match(r"^" + SANITIZERS + r"\s*\((.*)\)\s*$", body)
    if not m:
        return False
    inner = m.group(1)
    # dentro del sanitizador no debe haber sink ni concatenacion cruda
    if re.search(r"\.\s*\$|`\$", inner):
        return False
    return all(v in inner for v in _VAR.findall(inner)) or \
        bool(_VAR.findall(inner)) and not re.search(r"[.+\-*/]", inner)


class TaintTracer:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def trace_file(self, path: str) -> List[Dict[str, Any]]:
        try:
            lines = open(path, encoding="utf-8", errors="replace") \
                      .read().splitlines()
        except Exception:
            return []
        rel = os.path.relpath(path)
        tainted: set = set()
        origin: Dict[str, str] = {}
        findings: List[Dict[str, Any]] = []

        # extract() y register_globals: taint global del archivo
        src_all = "\n".join(lines)
        if re.search(r"\bextract\s*\(\s*\$_(?:GET|POST|REQUEST)", src_all):
            findings.append(self._f(rel, 0, "EXTRACT de input superglobal",
                                    "critica", "$_GET/$_POST",
                                    "extract() importa vars de usuario con "
                                    "nombres de variables incontrolables"))

        for _ in range(6):                       # punto fijo
            changed = False
            for no, line in enumerate(lines, 1):
                # foreach($_GET as $k => $v)
                for m in _FOREACH.finditer(line):
                    for g in (m.group(2), m.group(3)):
                        if g and g not in tainted:
                            tainted.add(g); origin[g] = "superglobal"
                            changed = True
                # asignaciones
                a = _ASSIGN.match(line)
                if a:
                    var, rhs = a.group(1), _rhs_of(line)
                    was = var in tainted
                    # 1) prepare con placeholders y taint SOLO en valores:
                    #    el primer argumento (formato) no debe tener vars
                    prep = re.search(r"->prepare\s*\(([^,]*),", line)
                    if prep and _PREPARE_SAFE.search(line) and \
                            not _VAR.findall(prep.group(1)):
                        if was:                      # prepare limpia el valor
                            tainted.discard(var); changed = True
                    # 2) sanitizador puro: corta el taint (nunca lo crea)
                    elif _sanitized_only(rhs, tainted):
                        if was:
                            tainted.discard(var); changed = True
                    # 3) fuente cruda en el RHS
                    elif _SRC_RE.search(rhs):
                        if not was:
                            tainted.add(var); origin[var] = "superglobal"
                            changed = True
                    # 4) propagacion desde vars ya tainteadas
                    elif any(v in tainted for v in _VAR.findall(rhs)):
                        if not was:
                            tainted.add(var)
                            origin[var] = "propagacion"
                            changed = True
                # sinks
                for f in self._sink_hits(line, no, rel, tainted, origin):
                    key = (f["file"], f["line"], f["type"])
                    if key not in {(x["file"], x["line"], x["type"])
                                   for x in findings}:
                        findings.append(f)
                        changed = True
            if not changed:
                break
        return findings

    def _sink_hits(self, line, no, rel, tainted, origin):
        out = []
        for sink in SINKS:
            m = re.search(sink["pat"], line)
            if not m:
                continue
            zone = line[m.start():]
            # prepare en la misma linea con placeholders = sink seguro
            if "->prepare(" in line and _PREPARE_SAFE.search(line):
                continue
            hit = [v for v in _VAR.findall(zone) if v in tainted
                   and v not in ("$wpdb", "$this")]
            if not hit:
                # taint por interpolacion directa del superglobal
                if _SRC_RE.search(zone):
                    hit = ["superglobal directo"]
                else:
                    continue
            out.append(self._f(rel, no, sink["type"], sink["sev"],
                               ", ".join(sorted(set(hit))[:3]), line.strip()))
        return out

    def _f(self, rel, no, ftype, sev, flow, code):
        return {"file": rel, "line": no, "type": ftype, "severity": sev,
                "flow": flow, "code": code[:200],
                "verdict": "flujo fuente->sink SIN sanitizador "
                           "(taint estatico, nivel 1)"}


def trace_path(path: str, top: int = 20) -> List[Dict[str, Any]]:
    tracer = TaintTracer()
    files: List[str] = []
    if os.path.isfile(path):
        files = [path]
    else:
        for root, _dirs, fs in os.walk(path):
            for f in fs:
                if f.endswith(".php"):
                    files.append(os.path.join(root, f))
    findings: List[Dict[str, Any]] = []
    for f in sorted(files):
        findings.extend(tracer.trace_file(f))
    order = {"critica": 0, "alta": 1, "media": 2}
    findings.sort(key=lambda x: (order.get(x["severity"], 3),
                                 x["file"], x["line"]))
    return findings[:top]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: taint_trace.py <archivo_o_dir> [--json] [--top N]")
        sys.exit(1)
    p = sys.argv[1]
    asjson = "--json" in sys.argv
    n = 20
    if "--top" in sys.argv:
        n = int(sys.argv[sys.argv.index("--top") + 1])
    res = trace_path(p, top=n)
    if asjson:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            print(f"[{r['severity'].upper():8}] {r['type']:22} "
                  f"{r['file']}:{r['line']}")
            print(f"           flujo: {r['flow']}")
            print(f"           {r['code'][:110]}")
        print(f"\n{len(res)} flujo(s) peligroso(s)")
