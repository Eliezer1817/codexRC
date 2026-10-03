#!/usr/bin/env python3
# ============================================================
# codexRC - FP-MEMORIA (v0.66.0, AUTHZ-PROOF capa 5)
# ------------------------------------------------------------
# Memoria semantica de falsos positivos: cuando un hallazgo es
# refutado (por el OPERADOR o por la DEFENSA con prueba), se
# guarda su HUELLA ESTRUCTURAL. El siguiente hallazgo con la
# misma huella se auto-cierra sin gastar triaje.
#
# "El falso positivo se paga una sola vez, nunca mas."
#
# Huella (fingerprint) = estructura semantica normalizada del
# hallazgo: tipo, veredicto de gates, rol exigido, nonce, owner,
# sinks de objeto, marcadores del nombre de la accion y del
# codigo alrededor. SIN nombres de archivo, lineas ni plugin:
# dos hallazgos con la misma huella son la MISMA familia, aunque
# vivan en plugins distintos.
#
# Matching EXACTO de huella (sin wildcards): una huella cerrada
# solo cierra huellas identicas. Anti-ruido conservador.
#
# La memoria vive en el repo (.codexrc/intelligence/fp_memory.jsonl)
# y se propaga por git: toda instancia que hace pull aprende lo
# que las demas ya pagaron en triaje.
#
# CLI:
#   python3 core/fp_memory.py --stats
#   python3 core/fp_memory.py --list [FPM-0003]
# ============================================================
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

MEM_DIR = os.path.join(os.path.dirname(__file__), "..", ".codexrc",
                      "intelligence")
MEM_FILE = os.path.join(MEM_DIR, "fp_memory.jsonl")
os.makedirs(MEM_DIR, exist_ok=True)

# marcadores de codigo alrededor del sink (mismo catalogo que
# fp_autoclose + marcadores estructurales de UI de WP)
MARKERS = {
    "prepare": re.compile(r"->prepare\s*\(", re.I),
    "cast": re.compile(r"\b(?:absint|intval)\s*\("),
    "escape": re.compile(r"\b(?:esc_[a-z_]+|wp_kses[a-z_]*|sanitize_"
                         r"[a-z_]+)\s*\("),
    "mime_whitelist": re.compile(r"wp_check_filetype|allowed_ext|"
                                 r"allowed_mime", re.I),
    "in_array_strict": re.compile(r"in_array\s*\([^;]*,\s*true\s*\)"),
    "nonce": re.compile(r"wp_verify_nonce|check_ajax_referer|wp_nonce"),
    "menu_page": re.compile(r"add_(?:sub)?menu_page|add_options_page", re.I),
    "settings_reg": re.compile(r"register_setting|settings_fields|"
                               r"do_settings_sections", re.I),
    "enqueue": re.compile(r"wp_enqueue_(?:script|style)", re.I),
    "screen_option": re.compile(r"add_(?:help|screen)_option|"
                                r"current_screen", re.I),
}
# marcadores semanticos del NOMBRE de la accion ajax
ACTION_MARKERS = {
    "notice": re.compile(r"notice|dismiss", re.I),
    "review": re.compile(r"review|rating|feedback", re.I),
    "heartbeat": re.compile(r"heartbeat|poll", re.I),
    "newsletter": re.compile(r"newsletter|subscribe", re.I),
    "media": re.compile(r"media|attachment|upload|image", re.I),
}


def _type_of(h: Dict[str, Any]) -> str:
    t = str(h.get("type") or h.get("family") or "").lower()
    if "sqli" in t or "base de datos" in t:
        return "sqli"
    if "xss" in t:
        return "xss"
    if "subida" in t or "upload" in t:
        return "upload"
    if "juggling" in t or "floja" in t:
        return "juggling"
    if "bac" in t or "authz" in t:
        return "bac"
    return "other"


def _handler_of(h: Dict[str, Any], gates: Dict[str, Any]) -> Optional[Dict]:
    """Rec gates del handler donde vive el hallazgo (como diff_hunt)."""
    rel = str(h.get("file", ""))
    line = int(h.get("line", 0))
    best = None
    for g in gates.get("handlers", []):
        if g.get("archivo_callback", "") == rel and \
           g.get("linea_callback", 10**9) <= max(line, 1):
            if best is None or g.get("linea_callback", 0) > \
               best.get("linea_callback", 0):
                best = g
    return best


def _code_markers(code_root: str, h: Dict[str, Any]) -> List[str]:
    rel = str(h.get("file", ""))
    path = os.path.join(code_root, rel)
    out = []
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().split("\n")
        ln = max(1, int(h.get("line", 1)))
        ctx = "\n".join(lines[max(0, ln - 20):min(len(lines), ln + 10)])
        for name, rx in MARKERS.items():
            if rx.search(ctx):
                out.append(name)
    except Exception:
        pass
    return sorted(out)


def fingerprint_of(h: Dict[str, Any], code_root: str,
                   gates: Dict[str, Any]) -> Dict[str, Any]:
    """Huella semantica normalizada del hallazgo."""
    g = _handler_of(h, gates) or {}
    accion = str(g.get("accion", ""))
    return {
        "type": _type_of(h),
        "gate": g.get("veredicto"),
        "nopriv": bool(g.get("anonimo")),
        "rol": g.get("rol_minimo"),
        "caps": sorted(g.get("caps_req") or []),
        "nonce": bool(g.get("nonce")),
        "sensible": bool(g.get("sensible")),
        "owner": g.get("owner_check"),
        "sinks": sorted({s.get("func") for s in
                         (g.get("object_access") or []) if s.get("func")}),
        "action_markers": sorted(k for k, rx in ACTION_MARKERS.items()
                                 if rx.search(accion)),
        "code_markers": _code_markers(code_root, h),
    }


def _fp_key(fp: Dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(fp, sort_keys=True,
                                   ensure_ascii=False).encode()).hexdigest()


def _load() -> List[Dict[str, Any]]:
    out = []
    if os.path.isfile(MEM_FILE):
        with open(MEM_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    return out


def lookup(fp: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    key = _fp_key(fp)
    for e in _load():
        if e.get("fingerprint_sha") == key:
            return e
    return None


def learn(h: Dict[str, Any], code_root: str, gates: Dict[str, Any],
          refuted_by: str, reason: str,
          plugin: str = "", family: str = "") -> Optional[str]:
    """Guarda la huella de un FP refutado. Dedupe por huella."""
    fp = fingerprint_of(h, code_root, gates)
    if lookup(fp):
        return None  # ya pagado
    entries = _load()
    n = len(entries) + 1
    entry = {
        "id": f"FPM-{n:04d}",
        "family": family or f"{fp['type']}/{fp['gate']}",
        "created": "2026-10-03",
        "source": {"plugin": plugin, "refuted_by": refuted_by},
        "fingerprint": fp,
        "fingerprint_sha": _fp_key(fp),
        "reason": reason,
    }
    with open(MEM_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry["id"]


def annotate_all(hallazgos: List[Dict[str, Any]], code_root: str,
                 gates: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Marca con _fp los hallazgos cuya huella ya fue refutada."""
    mem = {e["fingerprint_sha"]: e for e in _load()}
    for h in hallazgos:
        if h.get("_fp"):
            continue
        try:
            fp = fingerprint_of(h, code_root, gates)
            e = mem.get(_fp_key(fp))
            if e:
                h["_fp"] = f"FP-MEMORIA:{e['id']}:{e['family']}"
        except Exception:
            pass
    return hallazgos


def stats() -> Dict[str, Any]:
    es = _load()
    fams = {}
    for e in es:
        fams[e["family"]] = fams.get(e["family"], 0) + 1
    return {"memorias": len(es), "familias": fams}


if __name__ == "__main__":
    if "--stats" in sys.argv:
        print(json.dumps(stats(), indent=1, ensure_ascii=False))
    elif "--list" in sys.argv:
        for e in _load():
            print(f"[{e['id']}] {e['family']} | {e['source']} | "
                  f"{e['reason'][:80]}")
    else:
        print("uso: --stats | --list")
