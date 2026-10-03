"""
codexRC - XSSHunter
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

class XSSHunter:
    """Corpus XSS por reflexion. Dos sondas por objetivo:
    1) marcador puro -> detecta reflexion y contexto exacto
    2) marcador + '">< -> mide que caracteres sobreviven crudos
    De ahi deduce gravedad SIN nunca disparar un payload funcional."""

    def __init__(self, session: requests.Session, log: Log,
                 delay: float = 0.15, timeout: float = 15.0,
                 workers: int = 1):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout
        self.workers = max(1, min(int(workers or 1), 8))
        self.api_specs: Dict[str, str] = {}

    def _parallel(self, fn, items):
        """OVERDRIVE: mapea fn sobre items. Con workers=1 queda secuencial
        (comportamiento clasico); con N, N sondas en vuelo a la vez. La red
        es el cuello de botella, no el CPU: incluso en Termux multiplica el
        rendimiento casi lineal. Devuelve solo los resultados no-None."""
        items = list(items)
        if self.workers <= 1 or len(items) <= 1:
            return [r for r in (fn(i) for i in items) if r]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            return [r for r in ex.map(fn, items) if r]

    @staticmethod
    def _mark() -> str:
        return "kxss" + secrets.token_hex(4) + "z"

    def _pause(self) -> None:
        time.sleep(self.delay)

    def _context(self, text: str, mark: str) -> Optional[str]:
        i = text.find(mark)
        if i < 0:
            return None
        pre = text[max(0, i - 60):i]
        post = text[i + len(mark): i + len(mark) + 40]
        if re.search(r"<script[^>]*>[^<>]*$", pre, re.I):
            return "js-string"
        m = re.search(r"=\s*([\"'])[^\"']*$", pre)
        if m:
            return "attr-dq" if m.group(1) == '"' else "attr-sq"
        if re.search(r"/\*[^*]*$", pre) or re.search(r"<!--[^>]*$", pre):
            return "comment"
        if post.lstrip().startswith("<") or re.search(r"<[a-z][\w:.-]*\s*$", pre, re.I):
            return "tag"
        return "body"

    def _probe(self, url: str, param: str, value: str,
               method: str = "GET", base_data: Optional[Dict[str, str]] = None) -> Optional[requests.Response]:
        self._pause()
        try:
            if method == "POST":
                data = dict(base_data or {})
                data[param] = value
                return self.session.post(url, data=data, timeout=self.timeout)
            parts = urlparse(url)
            q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
            q.append((param, value))
            return self.session.get(urlunparse(parts._replace(query=urlencode(q))),
                                    timeout=self.timeout)
        except Exception as exc:
            self.log(f"[xss] XX {urlparse(url).path}?{param}= · red: {str(exc)[:60]}")
            return None

    def _verdict(self, ctx: Optional[str], raw: Dict[str, bool]) -> Tuple[str, str]:
        """Devuelve (gravedad, razon)."""
        if ctx in ("body", "tag") and raw.get("<"):
            return "alta", "escape de HTML factible: < sobrevive crudo"
        if ctx == "attr-dq" and raw.get('"'):
            return "alta", "escape de atributo factible: comilla doble cruda"
        if ctx == "attr-sq" and raw.get("'"):
            return "alta", "escape de atributo factible: comilla simple cruda"
        if ctx == "js-string" and (raw.get("'") or raw.get('"')):
            return "media", "cadena JS rompible: comilla cruda dentro de script"
        if ctx == "comment":
            return "media", "reflejado dentro de comentario HTML"
        if any(raw.values()):
            return "baja", "algunos caracteres crudos pero sin escape claro"
        return "info", "reflejado pero sanitizado/codificado"

    def _evidence(self, text: str, mark: str, window: int = 60) -> str:
        i = text.find(mark)
        if i < 0:
            return ""
        a = max(0, i - window)
        return text[a: i + len(mark) + window].replace("\n", " ").strip()

    def _finding(self, kind: str, target: str, param: str, method: str,
                 gravedad: str, razon: str, evidence: str, ctx: Optional[str]) -> Dict[str, Any]:
        return {
            "type": kind,
            "target": target,
            "param": param,
            "method": method,
            "context": ctx,
            "severity": gravedad,
            "reason": razon,
            "evidence": evidence[:300],
            "veredicto": {
                "gravedad": gravedad,
                "primeros": "desconocido: revisar si ya esta reportado antes de enviar",
                "reglas": "OK: sonda pasiva de reflexion, sin ejecucion ni payloads",
            },
        }

    def test_param(self, url: str, param: str, method: str = "GET",
                   base_data: Optional[Dict[str, str]] = None,
                   label: str = "") -> Optional[Dict[str, Any]]:
        mark = self._mark()
        r = self._probe(url, param, mark, method, base_data)
        # v0.62.8 FP-FILTER: reflejo en pagina de BLOQUEO (403/429/503,
        # Cloudflare eco la URL en su HTML de bloqueo) no es reflejo del sitio
        # (leccion greenlightdispensary 03/10: 16 FPs MEDIA por eco de WAF).
        if r is not None and getattr(r, "status_code", 0) in (403, 429, 503):
            self.log(f"[xss] {method} {urlparse(url).path}?{param}= · reflejo "
                     f"DESCARTADO: pagina de bloqueo WAF (estado {r.status_code})")
            return None
        if r is None or mark not in (r.text or ""):
            self.log(f"[xss] {method} {urlparse(url).path}?{param}= · sin reflexion")
            return None
        ctx = self._context(r.text, mark)

        mark2 = self._mark()
        r2 = self._probe(url, param, mark2 + "'\"><", method, base_data)
        raw = {"'": False, '"': False, ">": False, "<": False}
        if r2 is not None:
            j = (r2.text or "").find(mark2)
            if j >= 0:
                tail = r2.text[j + len(mark2): j + len(mark2) + 4]
                raw = {"'": tail.startswith("'"), '"': tail[1:2] == '"',
                       ">": tail[2:3] == ">", "<": tail[3:4] == "<"}

        gravedad, razon = self._verdict(ctx, raw)
        ev = self._evidence(r.text, mark)
        tag = "💥"
        self.log(f"{tag} [xss] {method} {urlparse(url).path}?{param}= · REFLEJADA · "
                 f"contexto: {ctx} · crudos: " + "".join(c for c, ok in raw.items() if ok))
        finding = self._finding("XSS reflejado", _norm(url), param, method, gravedad,
                                f"{razon} · contexto {ctx}", ev, ctx)
        finding["raw"] = raw          # que caracteres sobrevivieron (para VERITAS)
        return finding

    # ---------- bateria 1: parametros GET ----------
    def test_params(self, targets: List[Dict[str, Any]], max_params: int = 60) -> List[Dict[str, Any]]:
        self.log("[xss] === bateria GET: parametros de URL ===")
        tgts = targets[:max_params]
        findings: List[Dict[str, Any]] = []
        lane = "hilos"
        if self.workers > 1 and len(tgts) >= 6:
            try:
                from core.async_lane import AsyncLane   # import lazy: sin ciclo
                findings = AsyncLane(self).run(tgts)
                lane = "async"
            except ImportError:
                findings = self._parallel(
                    lambda t: self.test_param(t["url"], t["param"]), tgts)
                self.log("[xss] SLIPSTREAM no disponible (falta httpx) · usando hilos")
            except Exception as exc:
                self.log(f"[xss] carril async fallo ({str(exc)[:60]}) · reintento con hilos")
                findings = self._parallel(
                    lambda t: self.test_param(t["url"], t["param"]), tgts)
        elif tgts:
            findings = self._parallel(
                lambda t: self.test_param(t["url"], t["param"]), tgts)
        self.log(f"[xss] GET terminado · {len(findings)} reflexiones encontradas "
                 f"(carril {lane}, {self.workers} workers)")
        return findings

    # ---------- bateria 2: formularios ----------
    def test_forms(self, spider_out: Dict[str, Any], max_forms: int = 40) -> List[Dict[str, Any]]:
        self.log("[xss] === bateria FORMULARIOS: reinyeccion campo por campo ===")
        pares = [(form, field)
                 for form in spider_out.get("forms", [])[:max_forms]
                 for field in form["fields"][:8]]

        def _probe_form(par):
            form, field = par
            f = self.test_param(form["url"], field, form["method"].upper(),
                                base_data={x: "x" for x in form["fields"]})
            if f:
                f["type"] = "XSS en formulario"
            return f

        findings = self._parallel(_probe_form, pares)
        self.log(f"[xss] FORMS terminado · {len(findings)} reflexiones encontradas")
        return findings

    # ---------- bateria 3: cabeceras ----------
    def test_headers(self, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.log("[xss] === bateria CABECERAS: User-Agent / Referer / X-Forwarded-For ===")
        findings: List[Dict[str, Any]] = []
        base_url = spider_out.get("base_url", "")
        if not base_url:
            return findings
        urls = [base_url] + [urljoin(base_url, p) for p in spider_out.get("pages", [])[:6]]
        for header in ("User-Agent", "Referer", "X-Forwarded-For"):
            mark = self._mark()
            hit_url = None
            r = None
            for u in urls:
                self._pause()
                try:
                    r = self.session.get(u, headers={header: mark}, timeout=self.timeout)
                except Exception as exc:
                    self.log(f"[xss] header {header} · red: {str(exc)[:60]}")
                    continue
                if mark in (r.text or ""):
                    hit_url = u
                    break
            if hit_url is None:
                self.log(f"[xss] header {header} · sin reflexion en {len(urls)} paginas")
                continue
            ctx = self._context(r.text, mark)
            gravedad, razon = self._verdict(ctx, {"'": False, '"': False, ">": False, "<": False})
            ev = self._evidence(r.text, mark)
            self.log(f"💥 [xss] header {header} · REFLEJADO en {urlparse(hit_url).path} · contexto: {ctx}")
            findings.append(self._finding(
                f"XSS via header {header}", str(r.url), header, "HEADER",
                "media" if ctx == "body" else gravedad,
                f"{razon} · contexto {ctx} · tipico en paginas de error o logs visibles",
                ev, ctx))
        self.log(f"[xss] HEADERS terminado · {len(findings)} reflexiones encontradas")
        return findings

    # ---------- bateria 4: DOM (estatico) ----------
    def test_dom(self, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.log("[xss] === bateria DOM: sinks + sources en JavaScript ===")
        findings: List[Dict[str, Any]] = []
        for cand in spider_out.get("dom_candidates", []):
            self.log(f"💥 [dom] {cand['source']} · sink {cand['sink']} alimenta con {cand['source_pattern']}")
            findings.append({
                "type": "XSS-DOM potencial",
                "target": cand["source"],
                "param": cand["source_pattern"],
                "method": "DOM",
                "context": "dom",
                "severity": "media",
                "reason": f"sink {cand['sink']} + fuente controlable {cand['source_pattern']}",
                "evidence": f"sink: {cand['sink']} | fuente: {cand['source_pattern']}",
                "veredicto": {
                    "gravedad": "media",
                    "primeros": "desconocido: revisar antes de reportar",
                    "reglas": "OK: analisis estatico del JS publico del sitio",
                },
            })
        if not findings:
            self.log("[dom] ningun sink alimentado por fuente controlable")
        return findings
