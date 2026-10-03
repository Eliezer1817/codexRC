"""SSA-lite: grafo de versiones def-use para TAINT-TRACE.

Cada asignacion crea una VERSION nueva de la variable (q#1, q#2, ...)
con: kind (SOURCE/SANITIZED/PREPARED/CONCAT/PLAIN), taint, parents
(versiones que aportaron valor) y linea. Un uso resuelve la version
viva mas reciente (asignada en linea <= uso, dentro del scope).

Entrega la CADENA de evidencia de un sink:
    v3 = CONCAT(v2, "%")
    v2 = SANITIZE(v1)
    v1 = SOURCE($_GET['q']) @ L40
en vez de "$q aparece cerca del sink".

Nivel 1 (documentado): intra-funcion, orden lineal (los back-edges de
loops se ignoran: una var reasignada en loop cuenta la version de la
asignacion previa). Closures sin nombre heredan el scope exterior.
"""
import os
import re
from typing import Any, Dict, List, Optional

_VAR = re.compile(r"\$[A-Za-z_]\w*")
_ASSIGN = re.compile(
    r"^\s*(?:global\s+[^;]+;\s*)?"
    r"(\$[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\.?=(?!=)(?!=)")
_FUNC_DECL = re.compile(
    r"^\s*(?:public|protected|private|static|final)?"
    r"\s*function\s+([A-Za-z_]\w*)\s*\(")

# mismo vocabulario que taint_trace (import diferido para evitar ciclo)
SOURCES_RE = None
SANITIZER_RE = None
PREPARE_RE = re.compile(r"->prepare\s*\(")
CONCAT_RE = re.compile(r"\.\s*=?\s*\$|\$\w+\s*\.\s*[^;]*\$")


def _lazy_res():
    global SOURCES_RE, SANITIZER_RE
    if SOURCES_RE is None:
        try:
            from core import taint_trace as tt
        except ImportError:
            import taint_trace as tt
        SOURCES_RE = tt._SRC_RE
        SANITIZER_RE = re.compile(
            r"^\s*" + tt.SANITIZERS + r"\s*\(", re.I)
    return SOURCES_RE, SANITIZER_RE


class Version:
    __slots__ = ("vid", "var", "line", "kind", "taint", "parents", "note")

    def __init__(self, vid, var, line, kind, taint, parents, note=""):
        self.vid, self.var, self.line = vid, var, line
        self.kind, self.taint = kind, taint
        self.parents, self.note = parents, note


class SSAFile:
    """Versiones de UN archivo, scope por funcion con nombre."""

    def __init__(self, src: str):
        _lazy_res()
        self.lines = src.splitlines()
        # scope: nombre de funcion -> {var: vid}; "" = top-level
        self.scopes: Dict[str, Dict[str, str]] = {"": {}}
        self.versions: Dict[str, Version] = {}
        self.order: List[str] = []          # vids en orden de nacimiento
        self._build()

    # ------------------------------------------------------------- build

    def _build(self):
        cur_scope = ""
        for no, line in enumerate(self.lines, 1):
            m = _FUNC_DECL.match(line)
            if m:
                cur_scope = m.group(1)
                self.scopes.setdefault(cur_scope, {})
                continue
            a = _ASSIGN.match(line)
            if not a:
                continue
            var = a.group(1)
            rhs = re.split(r"=(?!=)", line, 1)[-1]
            scope = self.scopes[cur_scope]
            rhs_vars = set(_VAR.findall(rhs))
            parents = [scope[v] for v in rhs_vars if v in scope]
            # .= encadena con la version previa de la MISMA var
            if ".=" in line and var in scope:
                pv = scope[var]
                if pv not in parents:
                    parents = [pv] + parents
            unversioned = [v for v in rhs_vars
                           if v not in scope and v != var]
            src_re, san_re = SOURCES_RE, SANITIZER_RE
            # sanitizador puro sobre la propia var (o sus padres)
            san = san_re.search(rhs)
            raw_src = bool(src_re.search(rhs))
            if san and not raw_src:
                kind, taint, note = "SANITIZED", False, "sanitizador"
            elif PREPARE_RE.search(rhs) and not raw_src:
                kind, taint, note = "PREPARED", False, "wpdb->prepare"
            elif raw_src:
                kind, taint, note = "SOURCE", True, "superglobal/input"
            elif parents:
                pt = [self.versions[p] for p in parents]
                tainted = any(v.taint for v in pt)
                if "." in rhs or any(v.kind.startswith("CONCAT")
                                     for v in pt):
                    kind = "CONCAT"
                elif any(v.kind == "SANITIZED" for v in pt):
                    kind = "DERIV-SAFE"
                else:
                    kind = "COPY"
                note = "<- " + ",".join(
                    sorted({self.versions[p].var for p in parents}))
                kind = kind if tainted else kind + "-CLEAN"
                taint = tainted
            elif unversioned:
                # vars de procedencia desconocida (params/globals/
                # interpolaciones sin asignacion visible): no se
                # puede probar limpieza -> bloquea la refutacion
                kind, taint, note = "UNKNOWN-VAR", False, \
                    "vars sin version: " + ",".join(sorted(unversioned)[:4])
            elif re.search(r"[A-Za-z_]\w*\s*\(", rhs):
                # llamada a funcion/metodo NO resuelta (interprocedural):
                # no se puede probar que es limpia -> bloquea la
                # refutacion (conservador, evita FN)
                kind, taint, note = "UNKNOWN-FN", False, \
                    "valor de funcion no resuelta"
            else:
                kind, taint, note = "CONST", False, "sin input"
            vid = f"{var}#{len(self.order) + 1}"
            self.versions[vid] = Version(
                vid, var, no, kind, taint, parents, note)
            self.order.append(vid)
            scope[var] = vid

    # ----------------------------------------------------------- consultas

    def live_version(self, var: str, line: int,
                     scope: str) -> Optional[Version]:
        """Version viva de $var en `line` (la ultima asignacion <= line,
        mirando tambien top-level como fallback de globals)."""
        best = None
        for sc in (scope, ""):
            for vid in self.order:
                v = self.versions[vid]
                if v.var != var or v.line > line:
                    continue
                if best is None or v.line > best.line:
                    best = v
            if best:
                return best
        return best

    def chain_of(self, var: str, line: int,
                 scope: str, _depth: int = 0) -> List[Dict[str, Any]]:
        """Cadena def-use completa de la version viva de $var en `line`."""
        v = self.live_version(var, line, scope)
        out: List[Dict[str, Any]] = []
        seen = set()
        while v and v.vid not in seen and _depth < 12:
            seen.add(v.vid)
            out.append({
                "var": v.var, "line": v.line, "kind": v.kind,
                "note": v.note,
            })
            if not v.parents:
                break
            v = self.versions[v.parents[0]]
            _depth += 1
        return out

    def tainted_or_unknown(self, vid: str, _depth: int = 0) -> bool:
        """BFS sobre el DAG de versiones: True si ALGUNA version
        alcanzable (por cualquier padre) trae fuente, funcion no
        resuelta, var sin version o taint directo."""
        seen = set()
        stack = [vid]
        while stack:
            cur = stack.pop()
            if cur in seen or _depth > 400:
                continue
            seen.add(cur)
            v = self.versions.get(cur)
            if v is None:
                return True          # version inexistente: conservador
            if v.taint or v.kind in ("SOURCE", "UNKNOWN-FN",
                                     "UNKNOWN-VAR"):
                return True
            stack.extend(v.parents)
        return False

    def scope_of_line(self, line: int) -> str:
        """Nombre de la funcion (scope) que contiene `line`."""
        best = ""
        for no, l in enumerate(self.lines, 1):
            if no > line:
                break
            m = _FUNC_DECL.match(l)
            if m:
                best = m.group(1)
        return best


def _resolve(path: str, rel: str) -> Optional[str]:
    """Encuentra el archivo real de un finding (path puede ser un
    archivo suelto o la raiz de un plugin; rel puede venir con
    prefijos ../ del relpath original)."""
    if os.path.isfile(path):
        return path
    if os.path.isfile(rel):
        return rel
    p = rel
    while p.startswith("../"):
        p = p[3:]
    c = os.path.join(path, p)
    if os.path.isfile(c):
        return c
    # sufijo: buscar por partes acumuladas
    parts = rel.replace("\\", "/").split("/")
    for i in range(len(parts)):
        c2 = os.path.join(path, *parts[i:])
        if os.path.isfile(c2):
            return c2
    return None


_SSA_CACHE: Dict[str, "SSAFile"] = {}


def enrich(path: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adjunta 'chain' (cadena SSA def-use) a cada finding de taint
    y marca ssa_refuted cuando ninguna version viva del sink traza a
    una fuente (FP por nombre). path = archivo o raiz de plugin."""
    for f in findings:
        fpath = _resolve(path, f.get("file", ""))
        if not fpath:
            continue
        ssa = _SSA_CACHE.get(fpath)
        if ssa is None:
            try:
                src = open(fpath, encoding="utf-8",
                           errors="replace").read()
                ssa = SSAFile(src)
            except Exception:
                continue
            _SSA_CACHE.clear()   # un archivo vivo a la vez
            _SSA_CACHE[fpath] = ssa
        line = f.get("line", 0)
        scope = ssa.scope_of_line(int(line))
        code = f.get("code", "")
        cands = _VAR.findall(code)
        chains = {}
        for v in set(cands):
            ch = ssa.chain_of(v, int(line), scope)
            if ch:
                chains[v] = ch
        # fuente DIRECTA en la linea del sink: cadena trivial, no
        # se refuta nunca
        if SOURCES_RE.search(code):
            f["chain"] = [{"var": "-", "line": int(line),
                          "kind": "SOURCE",
                          "note": "fuente directa en el sink"}]
            continue
        if chains:
            # la mas informativa: la que llega mas lejos a SOURCE
            best = max(chains.values(),
                       key=lambda c: sum(1 for s in c
                                         if s["kind"] == "SOURCE"))
            f["chain"] = best
            f["chain_all"] = chains
            has_src = any(step["kind"] == "SOURCE" for step in best) \
                or any(any(step["kind"] in (
                           "SOURCE", "UNKNOWN-FN", "UNKNOWN-VAR")
                           for step in ch)
                       for ch in chains.values())
            # BFS completo: el taint puede llegar por CUALQUIER padre
            # de la version viva, no solo por el camino mostrado
            if not has_src:
                live_ids = []
                for v in set(cands):
                    lv = ssa.live_version(v, int(line), scope)
                    if lv:
                        live_ids.append(lv.vid)
                has_src = any(ssa.tainted_or_unknown(i) for i in live_ids)
            if not has_src:
                # SSA-REFUTACION: ninguna version viva del sink traza
                # a una fuente (reasignacion limpia). FP por nombre.
                f["verdict"] = ("SSA-REFUTADO: la version viva en el "
                                "sink no traza a ninguna fuente "
                                "(reasignacion con valor limpio)")
                f["ssa_refuted"] = True
    return findings
