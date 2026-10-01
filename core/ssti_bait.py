"""SSTI-BAIT: bateria dedicada de inyeccion de plantillas con FINGERPRINT.

Identifica el MOTOR de plantillas, no solo el hecho de que computa:
  Jinja2 / Twig      {{7*7}} -> 49          (Python/PHP)
  Jinja2 confirmado  {{7*'7'}} -> 7777777  (multiplicacion de string Python)
  FreeMarker/Java    ${7*7} -> 49
  Velocity           #set($x=7*7)$x -> 49
  ERB / EJS (Ruby)   <%= 7*7 %> -> 49
  Ruby interp        #{7*7} -> 49
  Smarty (PHP)       {math equation="7*7"} -> 49

SSTI = RCE en potencia: paga CRITICO en la tabla. Canarios 100% inertes
(aritmetica 7*7, cero comandos, cero datos ajenos).
"""

from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

CANARIES = [
    ("{{7*'7'}}", "7777777", "Jinja2 (Python) confirmado"),
    ("{{7*7}}", "49", "motor de plantillas {{ }} (Jinja2/Twig)"),
    ("${7*7}", "49", "FreeMarker / Java EL"),
    ("<%= 7*7 %>", "49", "ERB / EJS (Ruby/JS)"),
    ("#{7*7}", "49", "interpolacion Ruby / JS"),
    ("#set($x=7*7)$x", "49", "Velocity (Java)"),
    ("{math equation=\"7*7\"}", "49", "Smarty (PHP)"),
]


def _set_qs(url: str, extra: Dict[str, str]) -> str:
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    qs.update(extra)
    return urlunparse(p._replace(query=urlencode(qs)))


class SstiBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=12)
        except Exception:
            return None

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[ssti] === SSTI-BAIT: canarios de plantillas con fingerprint ===")
        findings: List[Dict[str, Any]] = []
        # params de texto/plantilla primero; luego todos los de valor
        targets = spider_out.get("param_targets", [])
        prioritized = sorted(targets, key=lambda t: -t.get("score", 0))[:8]
        for t in prioritized:
            for canary, expect, engine in CANARIES:
                r = self._get(_set_qs(t["url"], {t["param"]: canary}))
                if r is not None and expect in (r.text or ""):
                    findings.append({
                        "type": "SSTI (inyeccion de plantillas)",
                        "severity": "critica",
                        "target": _set_qs(t["url"], {t["param"]: canary}),
                        "param": t["param"],
                        "evidence": f"el servidor COMPUTA plantillas: "
                                    f"{canary} -> {expect} · motor: {engine} "
                                    f"(RCE en potencia, no explotado)",
                        "verdict": f"confirmado: {engine}",
                    })
                    self.emit(f"[ssti] 💥 SSTI: {t['param']} en "
                              f"{urlparse(t['url']).path} · {engine}")
                    break
        n = len(findings)
        self.emit(f"[ssti] === SSTI-BAIT: {n} motor(es) de plantilla vulnerables ===")
        return findings
