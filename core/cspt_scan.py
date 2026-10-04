#!/usr/bin/env python3
"""CSPT-SCAN (v0.71.0): Client-Side Path Traversal.

Clase nueva (2025-2026): el JS del sitio concatena input del
usuario en la RUTA de un fetch()/axios -> se engana al navegador
autenticado para llamar endpoints que no deberia ("../" en el
path). Termina en SSRF-del-cliente, CSRF o XSS encadenado.

Detecta estaticamente el patron FUENTE (query/hash de URL) ->
SINK (fetch/axios/xhr con path concatenado) en los .js del
plugin/tema.

Uso:
    python3 core/cspt_scan.py <root>
"""
import json
import os
import re
import sys

SINKS = re.compile(
    r"(fetch\s*\(|axios\s*\.\s*(?:get|post|put|delete|request)\s*\("
    r"|\$\.(?:get|post|ajax)\s*\(|\.open\s*\(\s*['\"](?:GET|POST)['\"])",
    re.I)

FUENTES = re.compile(
    r"(location\.(?:search|hash|href)|URLSearchParams|new URL\s*\("
    r"|window\.location|document\.location|getQueryString"
    r"|searchParams\.get|params\[[^\]]+\]|params\.\w+|qs\.\w+)",
    re.I)

# var recogido del query y concatenado en la ruta
PICK_QUERY = re.compile(
    r"const\s+(\w+)\s*=\s*[^;\n]{0,80}?(?:searchParams|location\.search"
    r"|location\.hash|URLSearchParams)[^;\n]{0,80}", re.I)

CONCAT = re.compile(
    r"(?:fetch|axios\.\w+|\.open)\s*\(\s*[`'\"]?[^)`'\"]*?\$\{[\w.\[\]]+"
    r"|(?:fetch|axios\.\w+|\.open)\s*\(\s*[`'\"][^`'\"]*[`'\"]\s*\+"
    r"|fetch\s*\(\s*\w+\s*\+"
    r"|[\"'][\w/-]*\w[\"']\s*\+\s*\w+\s*\+?\s*[\"'](?:/|api|admin)",
    re.I)

SANITIZADO = re.compile(r"encodeURIComponent\s*\(", re.I)

NOISE_DIRS = re.compile(r"/(?:node_modules|vendor|min\.js|\.min\.js$)")


def _scan_file(path, rel):
    out = []
    try:
        txt = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return out
    lines = txt.split("\n")
    for i, line in enumerate(lines):
        if NOISE_DIRS.search(path):
            return out
        if not SINKS.search(line):
            continue
        ventana = "\n".join(lines[max(0, i - 3):i + 2])
        if not FUENTES.search(ventana):
            continue
        # la concatenacion debe estar EN la linea del sink (no vecina)
        if not (CONCAT.search(line) or PICK_QUERY.search(ventana)):
            continue
        # sanitizacion por funcion encodeURIComponent en la ventana
        if SANITIZADO.search(line):
            out.append({"veredicto": "MITIGADO-ENC", "file": rel,
                        "line": i + 1, "evidencia": line.strip()[:150]})
            continue
        # gravedad: fetch/axios sobre path variable = alta
        sev = "alta" if re.search(r"fetch\s*\(|axios", line, re.I) else "media"
        out.append({
            "veredicto": "CANDIDATO-CSPT", "severity": sev,
            "file": rel, "line": i + 1,
            "evidencia": line.strip()[:150],
            "ventana": ventana.strip()[:400],
        })
    return out


def audit(root):
    hallazgos = []
    for base, _dirs, files in os.walk(root):
        for f in files:
            if not f.endswith(".js"):
                continue
            p = os.path.join(base, f)
            rel = os.path.relpath(p, root)
            hallazgos += _scan_file(p, rel)
    criticos = sum(1 for h in hallazgos
                    if h["veredicto"] == "CANDIDATO-CSPT"
                    and h.get("severity") == "alta")
    return {
        "hallazgos": hallazgos,
        "candidatos": [h for h in hallazgos
                       if h["veredicto"] == "CANDIDATO-CSPT"],
        "resumen": {"total": len(hallazgos),
                    "candidatos": sum(1 for h in hallazgos
                                      if h["veredicto"] == "CANDIDATO-CSPT"),
                    "criticos": criticos},
    }


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    r = audit(root)
    print("CSPT-SCAN", root)
    print(f"  candidatos: {r['resumen']['candidatos']}"
          f"  (altos: {r['resumen']['criticos']})")
    for h in r["candidatos"][:20]:
        mark = "💥" if h["severity"] == "alta" else "•"
        print(f"  {mark} [{h['severity']}] {h['file']}:{h['line']}")
    if "--json" in sys.argv:
        print(json.dumps(r, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
