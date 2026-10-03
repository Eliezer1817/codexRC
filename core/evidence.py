#!/usr/bin/env python3
# ============================================================
# codexRC - EVIDENCE-CHAIN + ABOGADOS (v0.47.0)
# ------------------------------------------------------------
# Motor de razonamiento de evidencia (estilo RacerD/Infer):
# no pregunta "¿podria ser vulnerable?" sino
# "¿que evidencia tengo para afirmar que realmente lo es?".
#
# Por cada finding construye una CADENA DE EVIDENCIA:
#
#   SOURCE      ¿input controlable por el atacante?
#   FLOW        ¿como llega hasta el sink? (saltos incluidos)
#   AUTH        ¿que compuertas lo custodian? (nonce/caps/nopriv/REST)
#   SANITIZATION ¿existe sanitizacion efectiva en la ruta?
#   SINK        operacion peligrosa final
#   CORRELATION ¿que analizadores lo vieron? (TAINT/GATES/PATTERNS/DIFF)
#   DYNAMIC     evidencia dinamica (si existe)
#
# Sobre la cadena actuan ABOGADOS deterministas:
#   FISCAL   debe PROBAR: source controlado + taint al sink +
#            sin sanitizacion + alcance sin privilegios.
#   DEFENSA  busca REFUTACIONES: gate protegido, sanitizador,
#            prepare seguro, contexto admin-only, inalcanzable.
#   JUEZ     pesa evidencia y dicta. NO es un LLM: reglas fijas.
#
# Veredictos (escala RacerD: se reporta solo lo demostrable):
#   CONFIRMED           prueba estatica completa + dinamica reproducida
#   DEMOSTRADO-ESTATICO prueba estatica completa, falta dinamica
#   PROBABLE            flujo probado, alcance/dinamica sin resolver
#   CONTESTADO          defensa tiene refutacion parcial
#   DESCARTADO          refutacion fuerte (gate/sanitizado/admin-only)
#
# Cada cadena expone FALSADORES: que evidencia la tumbaria.
# Meta: el scanner que necesita MENOS confianza humana por finding.
# ============================================================
import json
import os
import hashlib
import re
import sys

try:
    from . import semantic_core
except ImportError:  # ejecucion directa: python3 core/evidence.py <root>
    import semantic_core
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.taint_trace import SINKS, SANITIZERS, _SRC_RE, _VAR  # noqa: E402

FUNC_RE = re.compile(r"function\s+([A-Za-z_]\w*)\s*\(")
HOOK_RE = re.compile(
    r"add_(?:action|filter)\s*\(\s*['\"]([a-z0-9_\-\.]+)['\"]"
    r"\s*,\s*(?:array\s*\(\s*[^)]*,\s*)?['\"]?([A-Za-z_]\w*)['\"]?")
SHORTCODE_RE = re.compile(r"add_shortcode\s*\(\s*['\"]([\w\-]+)['\"]\s*,\s*"
                          r"(?:array\s*\(\s*[^)]*,\s*)?['\"]?([A-Za-z_]\w*)")
REST_CB_RE = re.compile(r"register_rest_route\s*\(\s*['\"][^'\"]+['\"]\s*,\s*"
                        r"['\"][^'\"]*['\"]\s*,\s*array\s*\(")
PREPARE_SAFE = re.compile(r"->prepare\s*\(\s*['\"][^'\"]*%[dsf]['\"]")
SAN_RE = re.compile(r"\b(?:%s)\s*\(" % SANITIZERS)
CAPS_LINE = re.compile(r"\b(?:current_user_can|is_admin\s*\(|user_can|"
                       r"current_user_can_for_blog)\b")
NONCE_LINE = re.compile(r"\b(?:wp_verify_nonce|check_admin_referer|"
                        r"check_ajax_referer|wp_create_nonce)\b")

_ENTRY_WEIGHT = {
    "publico-nopriv": "ALCANCE SIN AUTENTICACION",
    "ajax-solo-logueado": "requiere sesion (cualquier rol)",
    "shortcode": "publico via shortcode",
    "rest-abierto": "REST sin permisos",
    "admin-only": "SOLO ADMIN",
    "cron": "solo cron",
    "top-level": "carga en toda peticion",
    "llamada-directa": "via llamada interna",
    "no-encontrado": "NO RESUELTO",
}


# ------------------------------------------------------------------ util

def _files(root: str) -> List[str]:
    if os.path.isfile(root):
        return [root]
    out = []
    for d, _sd, fs in os.walk(root):
        for f in fs:
            if f.endswith(".php"):
                out.append(os.path.join(d, f))
    return sorted(out)


def _read(path: str) -> List[str]:
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except Exception:
        return []


def _functions(lines: List[str]) -> List[Dict[str, Any]]:
    """Devuelve [{name, start, end}] con los cuerpos aproximados."""
    funcs: List[Dict[str, Any]] = []
    for i, line in enumerate(lines):
        m = FUNC_RE.search(line)
        if not m:
            continue
        depth, j = 0, i
        opened = False
        for j in range(i, min(len(lines), i + 400)):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                opened = True
            if opened and depth <= 0:
                break
        funcs.append({"name": m.group(1), "start": i, "end": j})
    return funcs


def _enclosing(funcs: List[Dict[str, Any]], line: int) -> Optional[Dict[str, Any]]:
    for f in funcs:
        if f["start"] <= line <= f["end"]:
            return f
    return None


# --------------------------------------------------- evidencia por seccion

def _source_evidence(lines: List[str]) -> Dict[str, Any]:
    """Clasifica las fuentes de input del archivo."""
    srcs: List[Dict[str, str]] = []
    for i, ln in enumerate(lines, 1):
        for m in _SRC_RE.finditer(ln):
            frag = m.group(0)
            if "GET" in frag or "POST" in frag or "REQUEST" in frag:
                ctl = "controllable"
            elif "COOKIE" in frag:
                ctl = "controllable"
            elif "_FILES" in frag:
                ctl = "controllable"
            elif "_SERVER" in frag:
                ctl = "header (semi)"
            else:
                ctl = "api-wp"
            srcs.append({"linea": i, "tipo": ctl, "codigo": ln.strip()[:120]})
            break
    full = any(s["tipo"] == "controllable" for s in srcs)
    return {"fuentes": srcs[:6],
            "controlable": full or bool(srcs)}


def _auth_evidence(root: str, rel: str, funcs: List[Dict[str, Any]],
                   line: int, gates: Dict[str, Any]) -> Dict[str, Any]:
    """Compuertas que custodian la linea del sink."""
    fn = _enclosing(funcs, line - 1)
    ev: Dict[str, Any] = {"handler": None, "compuertas": {}, "entrada": None}
    # 1) la linea vive dentro de un handler auditado?
    for h in gates.get("handlers", []):
        cb = h.get("callback")
        if cb and fn and cb == fn["name"]:
            ev["handler"] = h
            ev["compuertas"] = {"nonce": h.get("nonce", False),
                                "caps": h.get("caps", False),
                                "nopriv": h.get("anonimo", False),
                                "veredicto_gates": h.get("veredicto")}
            ev["entrada"] = _ENTRY_WEIGHT.get(
                "publico-nopriv" if h.get("anonimo") else "ajax-solo-logueado")
            return ev
    # 2) quien registra/carga esta funcion?
    name = fn["name"] if fn else None
    if name:
        # 2b) BFS de callers: hooked -> ... -> esta funcion (<=3 saltos)
        files_cache = {p: (_read(p), _functions(_read(p))) for p in _files(root)}
        frontier, seen, hops = [name], {name}, [name]
        for _depth in range(3):
            nxt = []
            for cur in frontier:
                for path, (clines, cfuncs) in files_cache.items():
                    joined = "\n".join(clines)
                    for m in re.finditer(r"(?:->|::)\s*" + re.escape(cur) +
                                         r"\s*\(|\b" + re.escape(cur) + r"\s*\(", joined):
                        ln = joined[:m.start()].count("\n") + 1
                        cfn = _enclosing(cfuncs, ln - 1)
                        if not cfn or cfn["name"] in seen:
                            continue
                        seen.add(cfn["name"])
                        for h in sorted(gates.get("handlers", []),
                                        key=lambda x: not x.get("anonimo")):
                            if h.get("callback") == cfn["name"]:
                                if h.get("anonimo"):
                                    ev["entrada"] = "ALCANCE SIN AUTENTICACION"
                                elif h.get("nonce") or h.get("caps"):
                                    ev["entrada"] = "PROTEGIDO (nonce/caps en caller)"
                                else:
                                    ev["entrada"] = "requiere sesion (cualquier rol)"
                                ev["salto"] = " -> ".join(hops + [cfn["name"]])
                                ev["hook"] = h.get("accion")
                                return ev
                        nxt.append(cfn["name"])
            frontier, hops = nxt, hops + nxt
            if not frontier:
                break
        for path in _files(root):
            body = "\n".join(_read(path))
            for m in HOOK_RE.finditer(body):
                if m.group(2) == name:
                    act = m.group(1)
                    if "nopriv" in act:
                        ev["entrada"] = "ALCANCE SIN AUTENTICACION"
                    elif act.startswith(("admin_", "load-", "plugins_loaded")):
                        ev["entrada"] = "SOLO ADMIN" if act.startswith("admin_") \
                            else "carga en toda peticion"
                    elif act.startswith("wp_ajax"):
                        ev["entrada"] = "requiere sesion (cualquier rol)"
                    else:
                        ev["entrada"] = f"hook {act}"
                    ev["compuertas"]["veredicto_gates"] = "hook-resuelto"
                    return ev
            for m in SHORTCODE_RE.finditer(body):
                if m.group(2) == name:
                    ev["entrada"] = "publico via shortcode"
                    return ev
            if REST_CB_RE.search(body) and (f"'{name}'" in body or f"\"{name}\"" in body):
                ventana = body[max(0, body.find("register_rest_route") - 200):
                               body.find("register_rest_route") + 800]
                if "__return_true" in ventana or "permission_callback" not in ventana:
                    ev["entrada"] = "REST sin permisos"
                    return ev
    else:
        # codigo top-level del archivo
        ev["entrada"] = "carga en toda peticion"
    if ev["entrada"] is None:
        ev["entrada"] = "NO RESUELTO"
    return ev


def _sanitization_evidence(lines: List[str], funcs: List[Dict[str, Any]],
                           line: int, tvars: List[str]) -> Dict[str, Any]:
    """Sanitizacion efectiva en la ruta hacia el sink."""
    fn = _enclosing(funcs, line - 1)
    lo = fn["start"] if fn else max(0, line - 40)
    hi = min(len(lines), (fn["end"] if fn else line) + 1)
    body = lines[lo:hi]
    ev = {"efectiva": False, "detalle": []}
    joined = "\n".join(body)
    sink_line = lines[line - 1] if 0 < line <= len(lines) else ""
    for v in tvars:
        # sanitizador envolviendo la var (en el cuerpo o en la linea del sink)
        pat = r"\b(?:%s)\s*\([^;)]{0,200}%s" % (SANITIZERS, re.escape(v))
        if re.search(pat, joined) or re.search(pat, sink_line):
            ev["detalle"].append(f"{v} sanitizado")
            ev["efectiva"] = True
        elif re.search(r"\b(?:int|absint|intval)\s*\([^;]*%s" % re.escape(v), joined):
            ev["detalle"].append(f"{v} casteado a entero")
            ev["efectiva"] = True
        # casteo INDIRECTO: v se construye con elementos ya casteados
        # (ej. $v[] = (int)$x; ... implode($v)) antes de llegar al sink
        elif re.search(r"%s\s*\[\s*\]\s*=\s*(?:\(int\)|\(float\)|absint\s*\(|intval\s*\()"
                      % re.escape(v), joined):
            ev["detalle"].append(f"{v} construido con elementos ya casteados "
                                 f"(ej. {v}[] = (int)...)")
            ev["efectiva"] = True
    if PREPARE_SAFE.search("\n".join(lines[max(0, line - 2):line + 1])):
        ev["detalle"].append("wpdb->prepare con placeholders en el sink")
        ev["efectiva"] = True
    if not ev["detalle"]:
        ev["detalle"] = ["ninguna en la ruta"]
    return ev


# ------------------------------------------------------------ abogados

def _fiscal(chain: Dict[str, Any]) -> List[Dict[str, Any]]:
    """El fiscal debe PROBAR cada requisito del ataque."""
    auth = chain["auth"]
    gate = auth.get("compuertas", {})
    claims = [
        {"requisito": "source controlado por atacante",
         "probado": bool(chain["source"]["controlable"]),
         "evidencia": chain["source"]["fuentes"][:2]},
        {"requisito": "taint alcanza el sink",
         "probado": True,
         "evidencia": f"flujo {chain['flow']['vars']} -> "
                     f"{chain['sink']['tipo']} ({chain['sink']['linea']})"},
        {"requisito": "sin sanitizacion efectiva",
         "probado": not chain["sanitization"]["efectiva"],
         "evidencia": "; ".join(chain["sanitization"]["detalle"])},
        {"requisito": "alcanzable sin privilegios",
         "probado": (auth.get("entrada", "") not in
                     ("SOLO ADMIN", "NO RESUELTO", None)
                     and not gate.get("caps")
                     and not gate.get("nonce")),
         "evidencia": f"entrada: {auth.get('entrada')}, "
                     f"nonce={gate.get('nonce')}, caps={gate.get('caps')}"},
    ]
    return claims


def _defensa(chain: Dict[str, Any]) -> List[Dict[str, Any]]:
    """La defensa busca refutaciones del finding."""
    refuts: List[Dict[str, Any]] = []
    gate = chain["auth"].get("compuertas", {})
    if gate.get("nonce") or gate.get("caps"):
        refuts.append({"refutacion": "gate protegido",
                       "fuerza": "fuerte",
                       "evidencia": f"nonce={gate.get('nonce')} "
                                    f"caps={gate.get('caps')}"})
    if chain["sanitization"]["efectiva"]:
        refuts.append({"refutacion": "sanitizacion en ruta",
                       "fuerza": "fuerte",
                       "evidencia": "; ".join(chain["sanitization"]["detalle"])})
    if "prepare" in " ".join(chain["sanitization"]["detalle"]):
        refuts.append({"refutacion": "prepare seguro",
                       "fuerza": "fuerte", "evidencia": "placeholders"})
    if chain["auth"].get("entrada") == "SOLO ADMIN":
        refuts.append({"refutacion": "contexto solo admin",
                       "fuerza": "fuerte", "evidencia": "hook admin_*"})
    if chain["auth"].get("entrada") == "NO RESUELTO":
        refuts.append({"refutacion": "alcance no resuelto",
                       "fuerza": "media",
                       "evidencia": "sin handler/hook/caller conocido"})
    return refuts


def _juez(chain: Dict[str, Any]) -> Dict[str, Any]:
    fiscal = [c for c in chain["fiscal"] if c["probado"]]
    defensa_fuerte = [r for r in chain["defensa"] if r["fuerza"] == "fuerte"]
    dyn = chain.get("dynamic", {})
    repro = bool(dyn.get("reproducido"))
    integridad = chain.get("file", {}).get("integrity",
                                            semantic_core.INTEGRITY_OK)
    if defensa_fuerte:
        verdicto = "DESCARTADO"
    elif len(fiscal) == 4 and repro:
        verdicto = "CONFIRMED"
    elif len(fiscal) == 4:
        verdicto = "DEMOSTRADO-ESTATICO"
        if semantic_core.blocks_demostrado(integridad):
            # INTEGRITY: evidencia de archivo equivocado o ambiguo nunca
            # alcanza veredicto alto (invariante RC-000127)
            verdicto = "PROBABLE"
    elif len(fiscal) >= 3:
        verdicto = "PROBABLE"
    else:
        verdicto = "CONTESTADO"
    falsadores = []
    if verdicto in ("DEMOSTRADO-ESTATICO", "PROBABLE"):
        falsadores = ["nonce/caps en el caller no visto",
                      "sanitizador en archivo intermedio del flujo",
                      "reproduccion dinamica que falle"]
    return {"verdicto": verdicto,
            "puntos_fiscal": f"{len(fiscal)}/4",
            "refutaciones_defensa": len(defensa_fuerte),
            "falsadores": falsadores}


# ------------------------------------------------------------- build

def _evidence_hash(chain: Dict[str, Any]) -> str:
    """Hash determinista para detectar cambios accidentales entre corridas
    (no es seguridad criptografica, es trazabilidad: sec. 11 del spec)."""
    partes = [
        str(chain["source"].get("fuentes")),
        str(chain["flow"].get("vars")),
        str(chain["auth"].get("entrada")),
        str(chain["sanitization"].get("detalle")),
        str(chain["sink"].get("tipo")) + str(chain["sink"].get("linea")),
        str(chain.get("correlation")),
        str(chain.get("dynamic")),
    ]
    return hashlib.sha256("|".join(partes).encode()).hexdigest()[:16]


def build_chain(root: str, finding: Dict[str, Any],
                gates: Optional[Dict[str, Any]] = None,
                analyzers: Optional[List[str]] = None) -> Dict[str, Any]:
    """Cadena de evidencia completa para UN finding."""
    rel = finding["file"]
    # SEMANTIC CORE (v0.58.0): identidad canonica + testigo de hash.
    # El basename NO es identidad: resolucion ambigua o hash no coincidente
    # = INTEGRITY, y bloquea el veredicto alto en el JUEZ.
    fid = semantic_core.resolve(root, rel)
    path = fid["path"] if fid["integrity"] != semantic_core.INTEGRITY_FAILURE \
        else os.path.join(root, rel)
    lines = _read(path) if os.path.isfile(path) else []
    funcs = _functions(lines)
    line = int(finding.get("line", 0))
    tvars = [v.strip() for v in re.split(r",\s*", finding.get("flow", "")) if v.strip()]
    gates = gates or {"handlers": []}
    chain: Dict[str, Any] = {
        "finding": finding,
        "file": {"file_id": fid["file_id"], "content_hash": fid["hash"],
                 "integrity": fid["integrity"]},
        "source": _source_evidence(lines),
        "flow": {"vars": tvars or ["(directo)"],
                 "saltos": "intra-archivo (nivel 1)"},
        "auth": _auth_evidence(root, rel, funcs, line, gates),
        "sanitization": _sanitization_evidence(lines, funcs, line, tvars),
        "sink": {"tipo": finding["type"], "linea": line,
                 "severidad": finding.get("severity"),
                 "codigo": finding.get("code", "")[:160]},
        "correlation": analyzers or ["TAINT-TRACE", "GATES-AUDIT"],
        "dynamic": finding.get("_dynamic", {"reproducido": False,
                                            "nota": "estatico: falta dinamico"}),
    }
    chain["fiscal"] = _fiscal(chain)
    chain["defensa"] = _defensa(chain)
    chain["juez"] = _juez(chain)
    chain["evidence_hash"] = _evidence_hash(chain)
    chain["verdict_history"] = [{
        "verdicto": chain["juez"]["verdicto"],
        "motivo": f"fiscal {chain['juez']['puntos_fiscal']}, "
                 f"defensa {chain['juez']['refutaciones_defensa']} fuerte(s)",
        "evidence_hash": chain["evidence_hash"],
    }]
    return chain


def annotate(root: str, findings: List[Dict[str, Any]],
            gates: Optional[Dict[str, Any]] = None,
            analyzers: Optional[List[str]] = None,
            max_chains: int = 25) -> List[Dict[str, Any]]:
    """Adjunta _chain (cadena completa) a cada finding."""
    gates = gates or {"handlers": []}
    for i, h in enumerate(findings):
        if i >= max_chains:
            h["_verdict"] = "SIN-CADENA (cuota)"
            continue
        try:
            ch = build_chain(root, h, gates, analyzers)
            # copia plana: evitar referencia circular (finding dentro de su cadena)
            ch["finding"] = {k: h.get(k) for k in
                             ("type", "file", "line", "severity", "flow")}
            h["_chain"] = ch
            h["_verdict"] = ch["juez"]["verdicto"]
            try:
                from core.observe import log_verdict
                log_verdict(ch, target=root)
            except Exception:
                pass  # CODEX-OBSERVE es best-effort, nunca bloquea la caza
        except Exception as e:
            h["_verdict"] = f"ERROR-CADENA: {e}"
    return findings


def render_chain(ch: Dict[str, Any]) -> str:
    """Formato Finding #N con secciones, para informes."""
    f = ch["finding"]
    out = [f"Finding {f.get('type')} {f.get('file')}:{f.get('line')}"]
    out.append("SOURCE")
    for s in ch["source"]["fuentes"][:2]:
        out.append(f"  -> {s['tipo']}: {s['codigo'][:80]}")
    out.append("AUTH")
    a = ch["auth"]
    out.append(f"  -> entrada: {a.get('entrada')}")
    g = a.get("compuertas", {})
    if g:
        out.append(f"  -> nonce={g.get('nonce')} caps={g.get('caps')} "
                   f"nopriv={g.get('nopriv')}")
    out.append("SANITIZATION")
    for d in ch["sanitization"]["detalle"][:3]:
        out.append(f"  -> {d}")
    out.append("SINK")
    out.append(f"  -> {ch['sink']['tipo']} @ linea {ch['sink']['linea']}")
    out.append("FISCAL " + " | ".join(
        f"{c['requisito']}: {'✓' if c['probado'] else '✗'}" for c in ch["fiscal"]))
    out.append("DEFENSA " + ("; ".join(r["refutacion"] for r in ch["defensa"])
                             or "sin refutaciones"))
    out.append(f"JUEZ -> {ch['juez']['verdicto']} "
               f"(fiscal {ch['juez']['puntos_fiscal']})")
    return "\n".join(out)


# ----------------------------------------------------------------- CLI

def _cli() -> None:
    if len(sys.argv) < 2:
        print("uso: evidence.py <plugin_root> [--json] [--top N]")
        sys.exit(1)
    root = sys.argv[1]
    from core.taint_trace import trace_path  # evita import circular arriba
    from core.gates_audit import audit as gates_audit
    findings = trace_path(root, top=50)
    gates = gates_audit(root)
    chains = [build_chain(root, f, gates) for f in findings]
    order = {"CONFIRMED": 0, "DEMOSTRADO-ESTATICO": 1, "PROBABLE": 2,
             "CONTESTADO": 3, "DESCARTADO": 4}
    chains.sort(key=lambda c: order.get(c["juez"]["verdicto"], 9))
    asjson = "--json" in sys.argv
    if asjson:
        print(json.dumps(chains, indent=1, default=str))
    else:
        for c in chains:
            print(render_chain(c))
            print()
        ver: Dict[str, int] = {}
        for c in chains:
            v = c["juez"]["verdicto"]
            ver[v] = ver.get(v, 0) + 1
        print("veredictos:", ver or "sin hallazgos")


if __name__ == "__main__":
    _cli()
