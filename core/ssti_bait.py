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
    # --- motores adicionales (v1.00) ---
    ("${7*7}", "49", "Mako (Python)"),
    ("#{7*7}", "49", "Pug / Jade (Node.js)"),
    ("{{7*7}}", "49", "Handlebars (Node.js)"),
    ("*{7*7}", "49", "Thymeleaf (Java)"),
    ("[[${7*7}]]", "49", "Pebble (Java)"),
    ("{{=7*7}}", "49", "DotLiquid (.NET)"),
    ("${7*7}", "49", "Groovy / GString (Java)"),
]

# canarios ciegos (time-based): cuando el output no se refleja, medir
# retardo. Cada motor tiene su forma de invocar un sleep/loop.
BLIND_CANARIES = [
    ("{{7*'7'*50000}}", "Jinja2 (Python) blind — bucle de string"),
    ("${7*7*99999}", "FreeMarker (Java) blind — multiplicacion pesada"),
    ("#{for i in range(99999)}#{/for}", "Pug blind — bucle"),
    ("#set($x=0)#foreach($i in [1..99999])#set($x=$x+1)#end",
     "Velocity blind — bucle"),
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

    def _timed_get(self, url: str):
        """GET con medición de tiempo para deteccion blind."""
        import time
        t0 = time.perf_counter()
        r = self._get(url)
        elapsed = round(time.perf_counter() - t0, 2)
        return r, elapsed

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[ssti] === SSTI-BAIT: canarios de plantillas con fingerprint ===")
        findings: List[Dict[str, Any]] = []
        # params de texto/plantilla primero; luego todos los de valor
        targets = spider_out.get("param_targets", [])
        prioritized = sorted(targets, key=lambda t: -t.get("score", 0))[:8]

        for t in prioritized:
            # --- 1) deteccion reflectada (canarios con output esperado)
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
            else:
                # --- 2) deteccion ciega (time-based): si no hay reflejo,
                # medir si un canario de bucle pesado detiene la respuesta
                _, t_base = self._timed_get(t["url"])
                for canary, engine in BLIND_CANARIES:
                    _, elapsed = self._timed_get(
                        _set_qs(t["url"], {t["param"]: canary}))
                    if elapsed >= t_base + 3.0:
                        # confirmacion: repetir para descartar jitter
                        _, elapsed2 = self._timed_get(
                            _set_qs(t["url"], {t["param"]: canary}))
                        if elapsed2 >= t_base + 3.0:
                            findings.append({
                                "type": "SSTI blind (time-based)",
                                "severity": "critica",
                                "target": _set_qs(t["url"],
                                                  {t["param"]: canary}),
                                "param": t["param"],
                                "evidence": f"el canario {canary} detiene "
                                    f"la respuesta {elapsed}s y {elapsed2}s "
                                    f"vs baseline {t_base}s · {engine}",
                                "verdict": f"probable: {engine}",
                            })
                            self.emit(f"[ssti] 💥 SSTI blind: {t['param']} en "
                                      f"{urlparse(t['url']).path} · {engine}")
                            break

        n = len(findings)
        self.emit(f"[ssti] === SSTI-BAIT: {n} motor(es) de plantilla vulnerables ===")
        return findings
