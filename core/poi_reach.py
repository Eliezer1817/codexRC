#!/usr/bin/env python3
"""POI-REACH (v0.96.1): Object Injection con alcance y gadget chain.

CVE-2026-2599 (Contact Form Entries): download_csv() hacia unserialize()
de input del usuario, sin allowed_classes, en handler anonimo -> RCE
9.8. La clase sigue pagando ($600-$2.600 segun installs, tabla
Patchstack). Lo que falta en los tools abiertos no es detectar
unserialize: es probar ALCANCE y EXPLOTABILIDAD.

Escalera cero-FP (cada peldano exige el anterior):
  POI-DETECTED   unserialize recibe taint del usuario sin sanitizador
                 (hereda el taint estatico de TAINT-TRACE, nivel 1)
  POI-UNAUTH     el sink vive en handler dictaminado por GATES-AUDIT
                 como superficie anonima (CANDIDATO-BAC o REST-ABIERTO)
                 o el archivo registra hooks nopriv con el sink dentro
  POI-CHAIN      POP-CANDIDATE en el mismo plugin: clase con metodo
                 magico (__destruct / __wakeup / __toString / __call /
                 __get) con propiedades = gadget alcanzable
  POI-REACH      las tres: candidato reportable (Demo en WP-LAB con
                 chain inerte queda pendiente, nunca en vivo)

Superficie priorizada (leccion CVE-2026-2599): handlers y funciones de
export / download / csv reciben parametros serializados y casi nunca
pasan por gates: se anotan como nota de prioridad, no como veredicto.

Sin alcance anonimo el veredicto honesto es POI-AUTH (logged): Patchstack
acepta roles bajos, pero el dictamen es del operador, no del motor.

Uso:
    python3 core/poi_reach.py <dir_plugin> [--json]
"""
import json
import os
import re
import sys
from typing import Any, Dict, List

MAGIC_METHODS = ("__destruct", "__wakeup", "__toString",
                 "__call", "__get", "__invoke")
SURFACE_RE = re.compile(
    r"(?:export|download|csv|backup|import_?data)", re.I)
CLASS_RE = re.compile(
    r"\bclass\s+(\w+)")
NOPRIV_FILE_RE = re.compile(
    r"wp_ajax_nopriv|permission_callback[^)]*__return_true")


def _php_files(root: str) -> List[str]:
    out = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".php"):
                out.append(os.path.join(dp, fn))
    return sorted(out)


def pop_candidates(root: str) -> List[Dict[str, Any]]:
    """Clases con metodo magico y propiedades: gadget potencial."""
    out: List[Dict[str, Any]] = []
    for path in _php_files(root):
        rel = os.path.relpath(path, root)
        try:
            src = open(path, encoding="utf-8",
                       errors="ignore").read()
        except Exception:
            continue
        for cm in CLASS_RE.finditer(src):
            cls = cm.group(1)
            # cuerpo heuristico: hasta la siguiente clase o 400 lineas
            rest = src[cm.end():]
            nxt = CLASS_RE.search(rest)
            body = rest[:nxt.start()] if nxt else rest
            methods = [m for m in MAGIC_METHODS
                       if re.search(r"function\s+" + m + r"\s*\(",
                                    body)]
            props = re.findall(r"(?:public|protected|var)\s+"
                               r"\$(\w+)", body)
            if methods and props:
                line = src[:cm.end()].count("\n") + 1
                out.append({"class": cls, "file": rel,
                            "line": line,
                            "magic": sorted(methods),
                            "props": props[:6]})
    return out


def poi_audit(root: str) -> Dict[str, Any]:
    """Componen TAINT-TRACE + GATES-AUDIT + POP: alcance del sink."""
    from core.taint_trace import trace_path
    import core.gates_audit as ga

    def _neutralizado(code: str) -> bool:
        # unserialize con allowed_classes => false / [] no instancía
        # objetos: patch estandar, NO es Object Injection (FP weforms)
        m = re.search(r"allowed_classes['\"]?\s*=>\s*"
                      r"(false|\[\s*\]|array\s*\(\s*\))", code)
        return m is not None

    sinks = [f for f in trace_path(root, top=500)
             if f["type"] == "OBJECT INJECTION"
             and not _neutralizado(f.get("code", ""))]
    gates = ga.audit(root)
    anon_handlers = [h for h in gates.get("handlers", [])
                     if h.get("veredicto") == "CANDIDATO-BAC"]
    rest_open = gates.get("rest_abiertas", [])
    anon = anon_handlers + rest_open
    pops = pop_candidates(root)

    out: List[Dict[str, Any]] = []
    for s in sinks:
        # TAINT-TRACE reporta rutas relativas al CWD; GATES-AUDIT
        # relativas al root del plugin: normalizar al root para que
        # el mapeo fuerte de handler (cuerpo exacto) funcione
        s["file"] = os.path.relpath(
            os.path.abspath(s["file"]), root)
        rec = dict(s)
        rec.pop("verdict", None)
        rec["peldanos"] = ["POI-DETECTED"]

        # alcance: sink dentro del cuerpo de un handler anonimo
        host = None
        for h in anon:
            if ga._line_in_handler(h, s["file"], s["line"],
                                   root=root):
                host = h
                break
        unauth_file = None
        if host is None and NOPRIV_FILE_RE.search(
                open(os.path.join(root, s["file"]),
                     encoding="utf-8", errors="ignore").read()):
            # archivo registra superficie anonima; alcance probable
            # pero sin mapear el cuerpo exacto: honesto, menos fuerte
            unauth_file = s["file"]
        if host:
            rec["peldanos"].append("POI-UNAUTH")
            rec["handler"] = host.get("accion") or "rest"
        elif unauth_file:
            # FP weforms: nopriv de OTROS metodos del archivo no da
            # alcance; solo pista, jamas peldano POI-UNAUTH
            rec["nopriv_file"] = True
            rec["handler"] = "nopriv-en-archivo (solo pista)"

        # gadget: POP-CANDIDATE en el mismo plugin
        if pops:
            rec["peldanos"].append("POI-CHAIN")
            rec["gadgets"] = pops[:3]

        # superficie priorizada: nota, no veredicto
        ctx = (s.get("code", "") + " " + os.path.basename(s["file"]))
        rec["export_surface"] = bool(SURFACE_RE.search(ctx))

        rec["verdict"] = ("POI-REACH" if "POI-UNAUTH" in rec["peldanos"]
                          and "POI-CHAIN" in rec["peldanos"]
                          else ("POI-AUTH" if "POI-CHAIN"
                                in rec["peldanos"] else "POI-DETECTED"))
        out.append(rec)

    return {"plugin": os.path.basename(os.path.abspath(root)),
            "sinks": len(sinks), "anon_handlers": len(anon),
            "rest_open": len(rest_open), "pop_candidates": pops,
            "findings": out,
            "summary": {
                "poi_reach": sum(1 for r in out
                                 if r["verdict"] == "POI-REACH"),
                "poi_auth": sum(1 for r in out
                                if r["verdict"] == "POI-AUTH"),
                "poi_detected": sum(1 for r in out
                                    if r["verdict"]
                                    == "POI-DETECTED")}}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: poi_reach.py <dir_plugin> [--json]")
        sys.exit(1)
    res = poi_audit(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1))
    else:
        sm = res["summary"]
        print(f"POI: sinks={res['sinks']} anon={res['anon_handlers']} "
              f"rest={res['rest_open']} pop={len(res['pop_candidates'])} "
              f"| REACH={sm['poi_reach']} AUTH={sm['poi_auth']} "
              f"DET={sm['poi_detected']}")
        for r in res["findings"]:
            print(f"  [{r['verdict']}] {r['file']}:{r['line']} "
                  f"{'>'.join(r['peldanos'])}"
                  + (" [export]" if r["export_surface"] else ""))
