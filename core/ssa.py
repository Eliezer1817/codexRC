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


def def_use_proof(ssa: "SSAFile", line: int, var: str) -> Dict[str, Any]:
    """Prueba def-use estructurada de la version viva de $var en la
    linea del sink. SSA NO dictamina vulnerabilidad: entrega la
    genealogia completa del valor para que FISCAL/DEFENSA razonen.

    proof:
      DEF_USE_COMPLETE   hay SOURCE y NINGUN ancestro desconocido
      DEF_USE_INCOMPLETE hay ancestros desconocidos (no se puede
                         afirmar flujo completo aunque haya fuente)
      DEF_USE_NO_SOURCE  NI fuente NI desconocidos: reasignacion
                         limpia demostrada (refutacion DEFENSA)
      DEF_USE_UNRESOLVED la var no tiene versiones (fallback nivel 1)
    """
    scope = ssa.scope_of_line(line)
    v = ssa.live_version(var, line, scope)
    if v is None:
        return {"proof": "DEF_USE_UNRESOLVED", "value": None,
                "lineage": [], "source": None,
                "unknown_ancestors": [], "transformations": []}
    lineage, unknowns, kinds = [], [], []
    has_src = False
    seen, stack = set(), [v.vid]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        ver = ssa.versions.get(cur)
        if ver is None:
            continue
        lineage.append(cur)
        kinds.append(ver.kind)
        if ver.kind == "SOURCE":
            has_src = True
        if ver.kind in ("UNKNOWN-FN", "UNKNOWN-VAR"):
            unknowns.append(cur)
        stack.extend(ver.parents)
    if has_src and not unknowns:
        proof = "DEF_USE_COMPLETE"
    elif has_src or unknowns:
        proof = "DEF_USE_INCOMPLETE"
    elif _domina_el_sink(ssa, v, line):
        # solo es NO_SOURCE si la asignacion limpia DOMINA el sink:
        # si la version viva viene de una rama condicional, versiones
        # anteriores pueden seguir vivas en el merge (FP revisionary
        # options.php: $_REQUEST vivo tras if($setActiveTab='post_types'))
        proof = "DEF_USE_NO_SOURCE"
    else:
        proof = "DEF_USE_INCOMPLETE"
    return {"proof": proof, "value": v.vid, "lineage": lineage,
            "source": "HTTP_INPUT" if has_src else None,
            "unknown_ancestors": unknowns,
            "transformations": kinds}


def _domina_el_sink(ssa: "SSAFile", v: Version,
                    sink_line: int) -> bool:
    """La asignacion que define la version limpia ¿domina el sink?
    Sin CFG o sin parseo -> False (conservador: no se refuta)."""
    try:
        from core import cfg as _cfg
    except ImportError:
        import cfg as _cfg
    fpath = None
    for k in _SSA_CACHE:
        if _SSA_CACHE.get(k) is ssa:
            fpath = k
            break
    if not fpath:
        return False
    try:
        src = open(fpath, encoding="utf-8", errors="replace").read()
        r = _cfg.cfg_for_function(src, v.line)
        if not r:
            return False
        g, _f = r
        an = _cfg.line_node(g, v.line)
        sn = _cfg.line_node(g, sink_line)
        if an is None or sn is None:
            return False
        # mismo nodo (asignacion en la linea del sink) cuenta
        if an == sn:
            return True
        dom = g.dominators()
        return g.dominates(an, sn, dom)
    except Exception:
        return False


def proof_for_finding(path: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    """Prueba def-use del finding completo (todas las vars del sink).
    Fuente directa en la linea del sink = COMPLETE trivial."""
    try:
        fpath = _resolve(path, finding.get("file", ""))
        if not fpath:
            return {"proof": "DEF_USE_UNRESOLVED", "value": None,
                    "lineage": [], "source": None,
                    "unknown_ancestors": [], "transformations": []}
        if fpath not in _SSA_CACHE:
            _SSA_CACHE.clear()
            _SSA_CACHE[fpath] = SSAFile(
                open(fpath, encoding="utf-8", errors="replace").read())
        ssa = _SSA_CACHE[fpath]
    except Exception:
        return {"proof": "DEF_USE_UNRESOLVED", "value": None,
                "lineage": [], "source": None,
                "unknown_ancestors": [], "transformations": []}
    line = int(finding.get("line", 0))
    code = finding.get("code", "")
    if SOURCES_RE.search(code):
        return {"proof": "DEF_USE_COMPLETE", "value": "DIRECTO",
                "lineage": [f"sink@{line}"], "source": "HTTP_INPUT",
                "unknown_ancestors": [], "transformations": ["SOURCE"]}
    cands = set(_VAR.findall(code))
    proofs = [def_use_proof(ssa, line, v) for v in cands]
    proofs = [p for p in proofs if p["proof"] != "DEF_USE_UNRESOLVED"]
    if not proofs:
        return {"proof": "DEF_USE_UNRESOLVED", "value": None,
                "lineage": [], "source": None,
                "unknown_ancestors": [], "transformations": []}
    # fusion: la peor de las var (conservador): NO_SOURCE solo si TODAS
    # las vars lo son; COMPLETE solo si alguna es COMPLETE y ninguna
    # aporta incertidumbre peor... regla: elige por severidad
    # INCOMPLETE > NO_SOURCE > COMPLETE
    for p in proofs:
        if p["proof"] == "DEF_USE_INCOMPLETE":
            return p
    for p in proofs:
        if p["proof"] == "DEF_USE_NO_SOURCE":
            return p
    return proofs[0]


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
            if not has_src:
                # criterio UNICO def_use_proof (mismo que usan FISCAL/
                # DEFENSA en evidence.py): exige NO_SOURCE con
                # dominancia CFG para refutar
                pv = [def_use_proof(ssa, int(line), v)
                      for v in set(cands)]
                # vars sin versiones ($wpdb, helpers) no opinan:
                # solo cuentan las vars RESUELTAS del sink
                pv = [p for p in pv
                      if p["proof"] != "DEF_USE_UNRESOLVED"]
                has_src = not (pv and all(
                    p["proof"] == "DEF_USE_NO_SOURCE" for p in pv))
            if not has_src:
                # SSA-REFUTACION: ninguna version viva del sink traza
                # a una fuente (reasignacion limpia). FP por nombre.
                f["verdict"] = ("SSA-REFUTADO: la version viva en el "
                                "sink no traza a ninguna fuente "
                                "(reasignacion con valor limpio)")
                f["ssa_refuted"] = True
    return findings
