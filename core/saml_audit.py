#!/usr/bin/env python3
"""SAML-DEFENSE (v0.71.0): auditor SAML/XML de PHP.

Los bypasses novedosos de 2025 ("The Fragile Lock", PortSwigger)
golpean implementaciones SAML: XML Signature Wrapping, entidad
externa (XXE), XInclude y validaciones de firma flojas.

Detecta estaticamente en PHP:
  - XXE: parseo de XML con input de usuario SIN flags LIBXML_NONET
  - Mitigaciones: LIBXML_NONET / entity_loader desactivado
  - SAML-WSW: processResponse() SIN chequeo posterior de
    getErrors()/isValid()/isAuthenticated() en el flujo
  - SAML-STRICT: settings con 'strict' => false
  - XInclude: ->xinclude() sobre DOM con input usuario

Uso:
    python3 core/saml_audit.py <root>
"""
import json
import os
import re
import sys

XML_SINKS = re.compile(
    r"(simplexml_load_string|simplexml_load_file|DOMDocument|xml_parse"
    r"|->loadXML\(|->load\(|xpath\()", re.I)

TAINT = re.compile(r"(\$_POST|\$_GET|\$_REQUEST|php://input|file_get_contents"
                   r"|\$HTTP_RAW_POST_DATA)", re.I)

NONET = re.compile(r"LIBXML_NONET|LIBXML_NOENT|libxml_use_internal_errors",
                  re.I)
LOADER_OFF = re.compile(
    r"libxml_set_external_entity_loader\s*\(\s*(?:null|false)"
    r"|libxml_disable_entity_loader\s*\(\s*true", re.I)
SAML_LIBS = re.compile(
    r"(OneLogin_Saml2|OneLogin\\Auth|SimpleSAML|AacotP_SAML|wp_saml_auth"
    r"|SAML2\()", re.I)
PROCESS = re.compile(r"(->processResponse\(|->process\(|->assertionProcess)",
                     re.I)
VALID_CHECK = re.compile(
    r"(->getErrors\(|->isValid\(|->isAuthenticated\(|->getLastError"
    r"|->hasErrors\()", re.I)
STRICT_OFF = re.compile(r"['\"]strict['\"]\s*=>\s*(?:false|FALSE|0)", re.I)
XINCLUDE = re.compile(r"->xinclude\s*\(", re.I)


def _scan_file(path, rel):
    out = []
    try:
        txt = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return out
    lines = txt.split("\n")
    file_mitigado_loader = LOADER_OFF.search(txt)
    file_es_saml = bool(SAML_LIBS.search(txt))

    # 1) SAML-STRICT
    if STRICT_OFF.search(txt) and SAML_LIBS.search(txt):
        out.append({"veredicto": "CANDIDATO-SAML-STRICT", "severity": "alta",
                    "file": rel, "line": 0,
                    "razon": "strict=>false desactiva las validaciones "
                             "de seguridad del toolkit SAML"})

    for i, line in enumerate(lines):
        # 2) XXE
        if XML_SINKS.search(line) and TAINT.search(line):
            if NONET.search(line) or NONET.search(
                    "\n".join(lines[i:i + 3])):
                out.append({"veredicto": "MITIGADO-XXE", "file": rel,
                            "line": i + 1, "razon": "flags LIBXML activos"})
            elif file_mitigado_loader:
                out.append({"veredicto": "MITIGADO-XXE", "file": rel,
                            "line": i + 1,
                            "razon": "entity_loader desactivado en archivo"})
            else:
                out.append({"veredicto": "CANDIDATO-XXE", "severity": "alta",
                            "file": rel, "line": i + 1,
                            "evidencia": line.strip()[:150],
                            "razon": "parseo XML con input usuario sin "
                                     "proteccion XXE"})
        # 3) XInclude
        if XINCLUDE.search(line) and TAINT.search(
                "\n".join(lines[max(0, i - 5):i + 1])):
            out.append({"veredicto": "CANDIDATO-XINCLUDE", "severity": "alta",
                        "file": rel, "line": i + 1,
                        "razon": "xinclude() sobre DOM con input usuario "
                                 "(entity expansion)"})
        # 4) SAML-WSW: process sin validacion despues
        #    SOLO en archivos que usan un toolkit SAML real
        if PROCESS.search(line) and file_es_saml:
            despues = "\n".join(lines[i + 1:i + 12])
            if not VALID_CHECK.search(despues):
                out.append({"veredicto": "CANDIDATO-SAML-WSW",
                            "severity": "critica", "file": rel,
                            "line": i + 1,
                            "evidencia": line.strip()[:150],
                            "razon": "processResponse() sin chequeo de "
                                     "errores/validez despues (posible "
                                     "Signature Wrapping)"})
    return out


def audit(root):
    hallazgos = []
    for base, _dirs, files in os.walk(root):
        for f in files:
            if not f.endswith(".php"):
                continue
            p = os.path.join(base, f)
            rel = os.path.relpath(p, root)
            hallazgos += _scan_file(p, rel)
    candid = [h for h in hallazgos if h["veredicto"].startswith("CANDIDATO")]
    return {
        "hallazgos": hallazgos,
        "candidatos": candid,
        "resumen": {
            "total": len(hallazgos),
            "candidatos": len(candid),
            "criticos": sum(1 for h in candid
                            if h.get("severity") == "critica"),
        },
    }


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    r = audit(root)
    print("SAML-DEFENSE", root)
    print(f"  candidatos: {r['resumen']['candidatos']}"
          f"  (criticos: {r['resumen']['criticos']})")
    for h in r["candidatos"][:20]:
        mark = ("💥" if h.get("severity") in ("critica", "alta") else "•")
        print(f"  {mark} [{h.get('severity', 'media')}] "
              f"{h['veredicto']} {h['file']}:{h['line']}")
    if "--json" in sys.argv:
        print(json.dumps(r, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
