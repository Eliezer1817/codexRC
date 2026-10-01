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
import secrets
import time

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
            if path.endswith(SKIP_EXT):
                # los .js si se analizan (endpoints ocultos), el resto se ignora
                if path.endswith(".js") and len(js_seen) < max_js_files:
                    js_seen.add(_norm(full))
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

    def __init__(self, session: requests.Session, log: Log,
                 delay: float = 0.15, timeout: float = 15.0):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout

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
            try:
                ra = self.session.get(u, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue
            if ra.status_code != 200:
                if ra.status_code in (401, 403):
                    self.log(f"[api] /{urlparse(u).path} exige sesion (correcto)")
                continue
            pii_a = self._pii_keys(ra.text)
            # contraste anonimo: mismos datos sin sesion?
            self._pause()
            try:
                rn = requests.get(u, timeout=self.timeout, allow_redirects=False)
                anon_ok = rn.status_code == 200
                pii_n = self._pii_keys(rn.text) if anon_ok else []
            except Exception:
                anon_ok, pii_n = False, []
            if anon_ok and pii_n:
                findings.append({
                    "severity": "alta", "type": "BAC en API",
                    "param": "-", "target": u,
                    "evidence": f"responde datos privados SIN sesion "
                                f"(campos: {', '.join(pii_n)})",
                    "verdict": "confirmado por contraste anonimo"})
                self.log(f"[api] 💥 BAC: {urlparse(u).path} entrega datos privados "
                         f"SIN sesion ({', '.join(pii_n)})")
            elif anon_ok:
                findings.append({"severity": "info", "type": "API publica",
                                 "param": "-", "target": u,
                                 "evidence": "200 anonimo sin campos privados",
                                 "verdict": "mapeada"})
                self.log(f"[api] API publica: {urlparse(u).path}")
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
                 delay: float = 0.15, timeout: float = 15.0):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout

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
        paga = {
            "alta": "POSIBLE: Patchstack solo paga XSS site-wide con JS; validar si se inyecta en todo el sitio",
            "media": "POCO PROBABLE: requiere encadenar (site-wide o stored)",
            "baja": "NO PAGA solo por reflejar sanitizado",
            "info": "NO PAGA (solo informativo)",
        }[gravedad]
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
                "paga": paga,
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
        findings: List[Dict[str, Any]] = []
        for t in targets[:max_params]:
            f = self.test_param(t["url"], t["param"])
            if f:
                findings.append(f)
        self.log(f"[xss] GET terminado · {len(findings)} reflexiones encontradas")
        return findings

    # ---------- bateria 2: formularios ----------
    def test_forms(self, spider_out: Dict[str, Any], max_forms: int = 40) -> List[Dict[str, Any]]:
        self.log("[xss] === bateria FORMULARIOS: reinyeccion campo por campo ===")
        findings: List[Dict[str, Any]] = []
        for form in spider_out.get("forms", [])[:max_forms]:
            for field in form["fields"][:8]:
                f = self.test_param(form["url"], field, form["method"].upper(),
                                    base_data={x: "x" for x in form["fields"]})
                if f:
                    f["type"] = "XSS en formulario"
                    findings.append(f)
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
                    "paga": "POSIBLE si se logra ejecutar JS propio: validar manualmente",
                    "primeros": "desconocido: revisar antes de reportar",
                    "reglas": "OK: analisis estatico del JS publico del sitio",
                },
            })
        if not findings:
            self.log("[dom] ningun sink alimentado por fuente controlable")
        return findings
