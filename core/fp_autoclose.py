#!/usr/bin/env python3
# ============================================================
# codexRC - FP-AUTO-CLOSE (v0.44.0)
# ------------------------------------------------------------
# Segunda capa de verificacion tras GATES-AUDIT: reconoce los
# patrones de falso positivo que se repiten lote tras lote y
# los dictamina solo, para que el operador/agente solo vea
# candidatos reales.
#
# Veredictos automaticos (_fp):
#   FP-GATE-PROTEGIDO     el hallazgo cae en un handler con
#                         caps y/o nonce (dictamen de GATES)
#   FP-SQLI-PREPARE       el sink usa $wpdb->prepare con
#                         placeholders (%s/%d) sobre el input
#   FP-SQLI-CAST          el input pasa por absint()/intval()
#   FP-XSS-ESCAPED        la linea del echo aplica esc_*/wp_kses
#   FP-UPLOAD-WHITELIST   la subida valida mime y/o extension
#   FP-STRICT-IN_ARRAY    in_array con strict=true (no juggling)
#   FP-GATE-NOPRIV-LOGIN  handler nopriv con is_user_logged_in
#                         o dispatcher que exige sesion dentro
#
# Nivel 1: ventanas de contexto con regex; no ejecuta nada.
# ============================================================
import os
import re
from typing import Any, Dict, List, Optional

PREPARE_RE = re.compile(r"prepare\s*\(", re.I)
PLACEHOLDER_RE = re.compile(r"%[sd]")
CAST_RE = re.compile(r"\b(?:absint|intval)\s*\(")
ESCAPE_RE = re.compile(r"\b(?:esc_[a-z_]+|wp_kses[a-z_]*|sanitize_[a-z_]+)\s*\(")
MIME_RE = re.compile(
    r"wp_check_filetype|mime_content_type|valid_ext|allowed_ext|"
    r"allowed_mime|valid_file_type|wp_get_mime_types", re.I)
STRICT_INARRAY_RE = re.compile(r"in_array\s*\([^;]*,\s*true\s*\)")
LOGGEDIN_RE = re.compile(r"is_user_logged_in|is_private_access|"
                         r"must_be_logged|require_login", re.I)

# handlers publicos por diseno (notices, reviews, formularios de
# visitantes): superficie anonima intencional, no un bug.
NOMBRE_RUIDO_RE = re.compile(
    r"(_notice|notice_|_dismiss|dismiss_|_review|review_|feedback|"
    r"rating|_nonce$|_heartbeat|_poll$|newsletter_signup)", re.I)


def _ctx(lines: List[str], line: int, before: int = 8,
         after: int = 4) -> str:
    a = max(0, line - 1 - before)
    b = min(len(lines), line + after)
    return "\n".join(lines[a:b])


def _type_of(h: Dict[str, Any]) -> str:
    return str(h.get("type") or h.get("family") or "").lower()


def annotate(h: Dict[str, Any], code_root: str) -> Optional[str]:
    """Devuelve un veredicto FP o None si el hallazgo sigue vivo."""
    gate = h.get("_gate", "")
    if gate == "PROTEGIDO":
        return "FP-GATE-PROTEGIDO"

    f = h.get("file", "")
    path = os.path.join(code_root, f)
    if not os.path.isfile(path):
        return None
    try:
        lines = open(path, encoding="utf-8", errors="ignore").read().split("\n")
    except Exception:
        return None
    ln = int(h.get("line", 0) or 0)
    if ln <= 0 or ln > len(lines):
        return None

    ctx = _ctx(lines, ln)
    typ = _type_of(h)
    sink_line = lines[ln - 1] if ln - 1 < len(lines) else ""

    # SQLi: prepare con placeholders o cast numerico en el flujo
    if "sqli" in typ or "base de datos" in typ:
        if PREPARE_RE.search(ctx) and PLACEHOLDER_RE.search(ctx):
            return "FP-SQLI-PREPARE"
        if CAST_RE.search(ctx):
            return "FP-SQLI-CAST"

    # XSS: la linea del sink aplica escape
    if "xss" in typ and ESCAPE_RE.search(sink_line):
        return "FP-XSS-ESCAPED"

    # Subida de archivos: whitelist de mime/extension en el flujo
    if ("subida" in typ or "upload" in typ):
        body = _ctx(lines, ln, before=60, after=10)
        if MIME_RE.search(body):
            return "FP-UPLOAD-WHITELIST"

    # Type juggling: in_array estricto o comparacion floja sin
    # impacto (la fuente no controla el segundo operando)
    if "juggling" in typ or "floja" in typ:
        if STRICT_INARRAY_RE.search(ctx):
            return "FP-STRICT-IN_ARRAY"

    # handlers nopriv por diseno: el propio callback exige sesion
    if LOGGEDIN_RE.search(ctx) and "nopriv" in str(h.get("_hook", "")):
        return "FP-GATE-NOPRIV-LOGIN"

    return None


def annotate_all(hallazgos: List[Dict[str, Any]],
                 code_root: str) -> List[Dict[str, Any]]:
    for h in hallazgos:
        try:
            fp = annotate(h, code_root)
        except Exception:
            fp = None
        if fp:
            h["_fp"] = fp
    return hallazgos


def es_ruido_publico(accion: str) -> bool:
    """Acciones publicas por diseno (notices/reviews/forms)."""
    return bool(NOMBRE_RUIDO_RE.search(accion or ""))
