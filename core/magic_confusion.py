#!/usr/bin/env python3
"""MAGIC-CONFUSION (v0.96.0): extension vs contenido en rutas de media.

CVE-2026-65640 (WordPress Core <= 7.0.3, Author+ RCE 9.1): WP confia
en la EXTENSION del archivo; ImageMagick decide por MAGIC BYTES.
Un "png" que en realidad contiene PostScript (%!, \\x04%!,
\\xC5\\xD0\\xD3\\xC6, prefijo de formato tipo EPS:file.png) pasa los
checks de extension, llega a Imagick -> Ghostscript -> ejecucion.
Core parcheo 7.0.4 (commit 7daaa50) snifeando contenido ANTES de
construir el objeto Imagick. Los PLUGINS que procesan media por su
cuenta (galerias, optimizadores, importadores, cover-art) siguen
duplicando el patron.

Escalera cero-FP:
  CONFUSION-CANDIDATE   sink Imagick (readImage/readImageBlob/ping/
                        new Imagick) alimentado por variable que nace
                        de una PRIMITIVA DE ENTRADA: $_FILES,
                        wp_upload_bits, wp_handle_upload,
                        media_handle_upload, move_uploaded_file,
                        download_url, media_sideload, wp.downloadFile
  CONFUSION-UNGUARDED   el archivo del sink NO presenta gate de
                        contenido: wp_check_filetype_and_ext, finfo,
                        getimagesize, wp_get_image_mime, exif_imagetype
  CONFUSION-PREFIX      ademas, el path/file llega con posible
                        prefijo de formato (variable interpolada
                        antes de ':' o file.name sin sanear):
                        riesgo de forzar el coder (EPS:evil.png)

Veredicto final: MAGIC-CONFUSION solo con CANDIDATE + UNGUARDED.
Demo real queda en WP-LAB (payload PostScript INERTE: demostrar el
routing, nunca Ghostscript ejecutable en blanco de terceros).

Uso:
    python3 core/magic_confusion.py <dir_plugin> [--json]
"""
import json
import os
import re
import sys
from typing import Any, Dict, List

IMAGICK_SINK = re.compile(
    r"(?:new\s+Imagick\s*\(|"
    r"->(?:read|ping)[Ii]mage(?:Blob|File)?\s*\(|"
    r"\bImagick\s*\(\s*\$)")

ENTRY_PRIM = re.compile(
    r"(?:\$_FILES\s*\[|wp_upload_bits\s*\(|wp_handle_upload\s*\(|"
    r"media_handle_upload\s*\(|move_uploaded_file\s*\(|"
    r"download_url\s*\(|media_sideload|wp\.uploadFile|"
    r"\$_SERVER\s*\[\s*['\"]HTTP_)", re.I)

CONTENT_GATE = re.compile(
    r"(?:wp_check_filetype_and_ext|finfo_open|finfo_file|"
    r"getimagesize\s*\(|wp_get_image_mime|exif_imagetype|"
    r"wp_check_filetype\s*\()", re.I)

# variables que nacen de la primitiva y alimentan el sink
VAR = re.compile(r"\$(\w+)")


def _php_files(root: str) -> List[str]:
    out = []
    for dp, _dn, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".php"):
                out.append(os.path.join(dp, fn))
    return sorted(out)


def confusion_audit(root: str) -> Dict[str, Any]:
    files = _php_files(root)
    findings: List[Dict[str, Any]] = []
    for path in files:
        rel = os.path.relpath(path, root)
        try:
            src = open(path, encoding="utf-8",
                       errors="ignore").read()
        except Exception:
            continue
        if not IMAGICK_SINK.search(src):
            continue          # rapido: sin sink no hay historia
        gated = bool(CONTENT_GATE.search(src))
        lines = src.split("\n")
        # 1) variables que NACEN de primitivas de entrada (LHS de la
        #    asignacion) y punto fijo de propagacion ($file -> $path)
        entry_vars: Dict[str, str] = {}
        assign = re.compile(r"\$(\w+)\s*=\s*(.+)")
        while True:
            changed = False
            for ln in lines:
                m = assign.search(ln)
                if not m:
                    continue
                lhs, rhs = m.group(1), m.group(2)
                if lhs in entry_vars:
                    continue
                if ENTRY_PRIM.search(rhs):
                    entry_vars[lhs] = ln.strip()[:90]
                    changed = True
                elif any("$" + v in rhs for v in entry_vars):
                    entry_vars[lhs] = "propagacion: " + lhs
                    changed = True
            if not changed:
                break
        # 2) sinks alcanzados por esas variables (o por el superglobal
        #    crudo en la misma linea)
        for i, ln in enumerate(lines, 1):
            m = IMAGICK_SINK.search(ln)
            if not m:
                continue
            raw_entry = bool(ENTRY_PRIM.search(ln))
            via = None
            for v in VAR.findall(ln[m.start():]):
                if v in entry_vars:
                    via = v
                    break
            if not via and not raw_entry:
                continue      # sink no alimentado: no es candidato
            rec = {"file": rel, "line": i,
                   "code": ln.strip()[:200],
                   "peldanos": ["CONFUSION-CANDIDATE"]}
            if not gated:
                rec["peldanos"].append("CONFUSION-UNGUARDED")
            # prefijo de formato: interpolacion de path con ':' en la
            # misma linea (patron del CVE: forzar coder "EPS:file.png")
            if re.search(r"\$\w+\s*['\"]?\s*:\s*['\"]?\s*\w+\.(png|jpg|jpeg)",
                         ln) or ":{$" in ln:
                rec["peldanos"].append("CONFUSION-PREFIX")
            rec["content_gate"] = gated
            rec["entry_var"] = via or "superglobal-directo"
            rec["verdict"] = ("MAGIC-CONFUSION"
                              if "CONFUSION-UNGUARDED"
                              in rec["peldanos"]
                              else "CONFUSION-GUARDED")
            findings.append(rec)
    return {"plugin": os.path.basename(os.path.abspath(root)),
            "findings": findings,
            "summary": {
                "confusion": sum(1 for r in findings
                                 if r["verdict"]
                                 == "MAGIC-CONFUSION"),
                "guarded": sum(1 for r in findings
                               if r["verdict"]
                               == "CONFUSION-GUARDED")}}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: magic_confusion.py <dir_plugin> [--json]")
        sys.exit(1)
    res = confusion_audit(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(res, indent=1))
    else:
        sm = res["summary"]
        print(f"MAGIC: confusion={sm['confusion']} "
              f"guarded={sm['guarded']}")
        for r in res["findings"]:
            print(f"  [{r['verdict']}] {r['file']}:{r['line']} "
                  f"via={r['entry_var']} "
                  f"{'>'.join(r['peldanos'])}")
