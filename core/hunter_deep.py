"""
codexRC - DeepHunter
Caza profunda multi-vector. Extraida de hunter.py (v0.57.2).
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

    # ---- PASSWORD-LEAK: VALORES de contrasena/hash, no solo nombres de campo ----
    # Formatos reales que los vendors pagan como "sensitive data exposure":
    # phpass (WordPress), bcrypt, argon2, hex MD5/SHA, password con valor en JSON.
    HASH_PATTERNS = (
        (re.compile(r"\$P\$[./0-9A-Za-z]{20,}|\$H\$9[./0-9A-Za-z]{20,}"),
         "hash phpass (WordPress)"),
        (re.compile(r"\$2[aby]\$[0-9]{2}\$[./0-9A-Za-z]{53}"), "hash bcrypt"),
        (re.compile(r"\$argon2(id)?\$[A-Za-z0-9=,$+/]{10,}"), "hash argon2"),
        (re.compile(r"[\"'](user_pass|password_hash|pwd_hash|pass_hash)[\"']?\s*:\s*[\"'][0-9a-fA-F]{32,64}[\"']"),
         "hash hexadecimal (MD5/SHA)"),
        (re.compile(r"[\"'](password|user_pass|passwd|user_password)[\"']?\s*:\s*[\"'][^\"'\s*]{4,}[\"']"),
         "password con valor en JSON"),
    )

    def _pw_leak(self, text: str) -> list:
        """Detecta VALORES de contrasena/hash en una respuesta (deteccion,
        nunca extraccion del valor). Devuelve etiquetas del tipo de filtracion."""
        if not text:
            return []
        low = text[:20000]
        return [label for pat, label in self.HASH_PATTERNS if pat.search(low)]

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
            # FP-GUARD core-js (leccion xenpaid 02/10/2026): el scheduler de
            # microtareas de core-js instala addEventListener("message")
            # propio (polyfill de postMessage/MessageChannel) y NUNCA acepta
            # mensajes externos. Este detector viejo lo reportaba igual y esa
            # pieza falsa contaminaba las cadenas de impacto (chain.py).
            alrededor = text[max(0, m.start() - 3000): m.start() + 3000]
            if ("importScripts" in alrededor or "core-js" in (text or "")[:200000]
                    or "__core-js" in (text or "")):
                continue
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
                "verdict": "sin CSP: cualquier XSS reflejado/DOM se ejecuta sin freno",
                "verificado": True,
                "auto_check": "cabecera Content-Security-Policy leida en vivo"})
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
                "verdict": "CSP debil: un XSS puede ejecutarse dentro de estas reglas",
                "verificado": True,
                "auto_check": "politica CSP completa leida y analizada en vivo"})
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
                pw_p = self._pw_leak(rp.text)
                pii_p = self._pii(rp.text)
                if pw_p and not pii_p:
                    # la sonda vecina devolvio contrasena/hash sin otros campos
                    # personales: sigue siendo leak de datos
                    findings.append({
                        "severity": "alta", "type": "Password leak (lectura A->B)",
                        "param": label.replace("body:", "body ").replace("=1", ""),
                        "target": spec[1],
                        "evidence": "respuesta vecina contiene " + ", ".join(pw_p)
                                    + " (valores NO extraidos)",
                        "verdict": "confirmado por lectura: hash/contrasena de otro "
                                   "registro accesible",
                        "leak": True, "leak_fields": pw_p})
                    self.log(f"[idor] 💥 PASSWORD LEAK vecino: "
                             f"{urlparse(spec[1]).path} ({', '.join(pw_p)})")
                    continue
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
                # PASSWORD-LEAK: la API autenticada entrega VALORES de
                # contrasena/hash: eso se paga (sensitive data exposure).
                pw_a = self._pw_leak(ra.text)
                if pw_a:
                    findings.append({
                        "severity": "alta", "type": "Password leak en API",
                        "param": "-", "target": u,
                        "evidence": "la respuesta contiene " + ", ".join(pw_a)
                                    + " (valores NO extraidos)",
                        "verdict": "confirmado por lectura: hash/contrasena "
                                   "accesible a la sesion actual",
                        "leak": True, "leak_fields": pw_a})
                    self.log(f"[api] 💥 PASSWORD LEAK: {urlparse(u).path} "
                             f"entrega {', '.join(pw_a)}")
                    continue
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
