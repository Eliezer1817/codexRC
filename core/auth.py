"""
codexRC - Authentication Module (Termux friendly)
Supports 3 methods:
1. Session Cookies (recommended)
2. Automatic form login (username + password) with better CSRF & form detection
3. Bearer / JWT / Custom Authorization header
"""

from typing import Optional, Dict, Any, Tuple
import requests
from bs4 import BeautifulSoup

from core.ghostgate import clasificar_respuesta
from pathlib import Path
from urllib.parse import urljoin, urlparse
import json
import re
import time


class AuthManager:
    def __init__(self, user_agent: Optional[str] = None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            )
        })
        self.authenticated = False
        self.auth_method: Optional[str] = None
        self.last_login_response: Optional[requests.Response] = None
        self.login_debug: Dict[str, Any] = {}
        self._spa_cache_origin: Optional[str] = None
        self._spa_cache_data: Optional[Dict[str, Any]] = None

    def load_cookies_from_file(self, filepath: str) -> bool:
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Cookie file not found: {filepath}")

        content = path.read_text(encoding="utf-8").strip()

        if content.startswith("{"):
            data = json.loads(content)
            if isinstance(data, dict):
                self.set_cookies(data)
                return True

        if "=" in content and not content.startswith("# Netscape") and "\t" not in content:
            for part in content.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    self.session.cookies.set(name.strip(), value.strip())
            self.authenticated = True
            self.auth_method = "cookies"
            return True

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 7:
                domain, flag, path_c, secure, expires, name, value = parts[:7]
                self.session.cookies.set(name, value, path=path_c)

        self.authenticated = True
        self.auth_method = "cookies"
        return True

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        self.authenticated = True
        self.auth_method = "cookies"

    def _extract_csrf(self, soup: BeautifulSoup) -> Tuple[Optional[str], Optional[str]]:
        csrf_names = [
            "csrf_token", "csrfmiddlewaretoken", "_token",
            "authenticity_token", "__RequestVerificationToken",
            "csrf", "_csrf", "_csrf_token", "csrf-token",
            "__csrf_magic", "csrfkey", "token"
        ]

        for name in csrf_names:
            tag = soup.find("input", {"name": re.compile(f"^{name}$", re.I)})
            if tag and tag.get("value"):
                return tag.get("name"), tag["value"]

        for name in ["csrf-token", "_csrf", "csrf_token"]:
            meta = soup.find("meta", {"name": name}) or soup.find("meta", {"name": re.compile(name, re.I)})
            if meta and meta.get("content"):
                return name, meta["content"]

        for inp in soup.find_all("input", {"type": "hidden"}):
            name = (inp.get("name") or "").lower()
            value = inp.get("value") or ""
            if any(k in name for k in ["csrf", "token", "nonce"]) and len(value) > 8:
                return inp.get("name"), value

        return None, None

    def _detect_login_fields(self, soup: BeautifulSoup) -> Dict[str, str]:
        result = {"username_field": "username", "password_field": "password"}

        pwd = soup.find("input", {"type": "password"})
        if pwd and pwd.get("name"):
            result["password_field"] = pwd["name"]

        candidates = []
        for inp in soup.find_all("input"):
            itype = (inp.get("type") or "text").lower()
            name = (inp.get("name") or "").lower()
            if itype in ("text", "email") and name:
                if any(k in name for k in ["user", "email", "login", "account", "id"]):
                    candidates.append(inp["name"])

        if candidates:
            result["username_field"] = candidates[0]
        else:
            # Fallback: si junto al password hay un solo campo de texto/email,
            # ese es el campo de usuario (formularios con nombres no obvios).
            text_inputs = [
                inp for inp in soup.find_all("input")
                if (inp.get("type") or "text").lower() in ("text", "email") and inp.get("name")
            ]
            if len(text_inputs) == 1:
                result["username_field"] = text_inputs[0]["name"]

        return result

    def _extract_username(self, soup: BeautifulSoup) -> Optional[str]:
        """Busca un nombre visible en una página autenticada, sin leer secretos."""
        selectors = [
            "[data-user-name]", "[data-username]", "[data-user]",
            ".username", ".user-name", ".user_name", ".profile-name",
            "[class*='username']", "[class*='user-name']",
            "meta[name='user']", "meta[name='username']",
        ]
        for selector in selectors:
            tag = soup.select_one(selector)
            if not tag:
                continue
            value = tag.get("content") or tag.get("data-user-name") or tag.get_text(" ", strip=True)
            if value and 1 < len(value) <= 160:
                return value.strip()

        text = soup.get_text(" ", strip=True)
        match = re.search(r"(?:welcome|hello|hola|bienvenido(?:a)?)\s*[,:-]?\s*([\w.@+-]{2,100})", text, re.I)
        return match.group(1) if match else None

    def verify_session(self, verification_url: str) -> Dict[str, Any]:
        """Comprueba una URL y determina si la sesión fue redirigida al login."""
        result: Dict[str, Any] = {
            "url": verification_url,
            "verified": False,
            "authenticated": False,
            "status_code": None,
            "final_url": None,
            "username": None,
            "login_detected": False,
            "redirect_chain": [],
            "response_time": None,
            "content_type": None,
            "signals": [],
            "cookie_names": sorted(self.session.cookies.get_dict().keys()),
            "profile": None,
            "error": None,
        }
        started = time.perf_counter()
        try:
            response = self.session.get(verification_url, timeout=20, allow_redirects=True)
            # APIs tipo POST (comun en apps JavaScript): si la ruta no tiene
            # GET (404/405), reintentar con POST {} como hace la propia app.
            if response.status_code in (404, 405):
                try:
                    _origin = "{0.scheme}://{0.netloc}".format(urlparse(verification_url))
                    response = self.session.post(
                        verification_url, json={},
                        headers={
                            "Content-Type": "application/json",
                            "Accept": "application/json",
                            "Origin": _origin,
                            "Referer": _origin + "/",
                        },
                        timeout=20, allow_redirects=True,
                    )
                except Exception:
                    pass
            result["response_time"] = round(time.perf_counter() - started, 3)
            result["status_code"] = response.status_code
            result["final_url"] = str(response.url)
            result["content_type"] = response.headers.get("Content-Type")
            result["redirect_chain"] = [str(item.url) for item in response.history] + [str(response.url)]

            _ct = (response.headers.get("Content-Type") or "").lower()
            _es_json = "json" in _ct or response.text.lstrip()[:1] == "{"
            if _es_json:
                # respuesta de API: HTML no sirve en apps JavaScript
                body = response.text.lower()
                compact = response.text.replace(" ", "")[:400].lower()
                api_ok = (
                    response.status_code < 400
                    and "unauthorized" not in body[:200]
                    and '"state":"error"' not in compact
                )
                result["login_detected"] = False
                result["verified"] = True
                result["authenticated"] = api_ok
                result["signals"].append("api_json_response")
                # datos del usuario logueado (perfil de la cuenta)
                try:
                    _j = response.json()
                    _s = json.dumps(_j, default=str)
                    result["profile"] = _j if len(_s) <= 4000 else {"_perfil_grande": _s[:4000]}
                except Exception:
                    result["profile"] = None
                _uname = self._find_username(result["profile"])
                if _uname:
                    result["username"] = _uname
                    result["signals"].append("username_detected")
                if api_ok:
                    result["reason"] = "api_authenticated"
                else:
                    result["reason"] = "api_unauthorized_or_error"
            else:
                soup = BeautifulSoup(response.text, "html.parser")
                path = urlparse(str(response.url)).path.lower()
                login_detected = any(marker in path for marker in ("login", "signin", "sign-in", "auth"))
                login_detected = login_detected or bool(soup.find("input", {"type": "password"}))
                result["login_detected"] = login_detected
                result["username"] = self._extract_username(soup)
                result["verified"] = response.status_code < 400
                result["authenticated"] = result["verified"] and not login_detected
                if response.status_code < 400:
                    result["signals"].append("http_ok")
                if response.history:
                    result["signals"].append("redirected")
                if result["username"]:
                    result["signals"].append("username_detected")
                if login_detected:
                    result["signals"].append("login_page_detected")
                if result["authenticated"]:
                    result["reason"] = "protected_page_reached"
                elif login_detected:
                    result["reason"] = "redirected_to_login_or_login_form_detected"
                else:
                    result["reason"] = "verification_request_failed"
        except Exception as exc:
            result["error"] = str(exc)
            result["reason"] = "verification_exception"
        self.authenticated = bool(result["authenticated"])
        return result

    def login_with_credentials(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: Optional[str] = None,
        password_field: Optional[str] = None,
        extra_fields: Optional[Dict[str, str]] = None,
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
        auto_detect_fields: bool = True,
        verify_url: Optional[str] = None,
    ) -> bool:
        """Login autenticado v2 con relevo GHOSTGATE.

        Flujo:
        1. GET al login con requests normal.
        2. Si Cloudflare bloquea -> relevo GHOSTGATE-LITE (huella Chrome real);
           si pasa, sus cookies se inyectan en la sesion.
        3. Si hay formulario -> submit clásico (con CSRF).
        4. Si no hay formulario (SPA) -> intento de login API por JSON.
        5. Verificacion final de sesion.
        """
        extra_fields = extra_fields or {}
        self.login_debug = {"steps": []}

        def step(nombre: str, detalle: Any) -> None:
            self.login_debug["steps"].append({"paso": nombre, "detalle": detalle})

        # ---------- 1. Obtener la pagina de login ----------
        resp = self.session.get(login_url, timeout=20, allow_redirects=True)
        login_html = resp.text

        # ---------- 2. Cloudflare: diagnostico + relevo GHOSTGATE ----------
        diagnostico = clasificar_respuesta(resp)
        step("diagnostico_cf", diagnostico["tipo"])

        if diagnostico["challenge"] or diagnostico["tipo"] in ("WAF_BLOCK", "BLOQUEO_IP"):
            from core.ghostgate import ghostgate_relay, HAS_CURL_CFFI, HAS_CLOUDSCRAPER
            if not HAS_CURL_CFFI and not HAS_CLOUDSCRAPER:
                self.login_debug["resultado"] = "cloudflare_bloquea_sin_relevo"
                self.login_debug["razon"] = (
                    "Cloudflare bloquea (" + diagnostico["tipo"] + ") y no hay relevo "
                    "disponible. En Termux ejecuta: pip install cloudscraper"
                )
                self.authenticated = False
                return False

            relevo = ghostgate_relay(login_url)
            step("ghostgate_relay", {"tipo": relevo["tipo"], "ok": relevo["ok"], "razon": relevo["razon"]})
            self.login_debug["ghostgate"] = relevo["razon"]

            if not relevo["ok"]:
                self.login_debug["resultado"] = "cloudflare_persiste"
                self.login_debug["razon"] = relevo["razon"]
                self.authenticated = False
                return False

            # El relevo paso: inyectar cookies + User-Agent en la sesion del escaneo
            for name, value in relevo["cookies"].items():
                self.session.cookies.set(name, value)
            self.session.headers["User-Agent"] = relevo["user_agent"]
            login_html = relevo["html"]
            step("ghostgate_cookies", sorted(relevo["cookies"].keys()))

        soup = BeautifulSoup(login_html, "html.parser")

        # ---------- 3. Detectar los campos del formulario ----------
        form = soup.find("form")
        has_password_input = bool(soup.find("input", {"type": "password"}))

        # Turnstile incrustado en el form: requiere resolucion humana (GHOSTGATE completo)
        if not form and not has_password_input:
            # ---------- 4. SPA / API JSON login ----------
            # 4a. Auto-descubrimiento: buscar en el JavaScript de la SPA el
            #     endpoint real de login (ej. post("/auth/doSignin") + apiUrl).
            descubiertos = self._discover_spa_login_endpoints(login_url, soup)
            step("endpoints_descubiertos", descubiertos or "ninguno")
            # si hay endpoints descubiertos usamos solo esos; la pagina HTML
            # no sirve como API (responde HTML y genera falsos positivos).
            api_urls = descubiertos[:3] if descubiertos else [login_url]
            step("modo", "spa_api_json (login por API)")
            # candidatos de campo de usuario: el explicito primero, luego comunes
            user_keys = [username_field] if username_field else []
            user_keys += [k for k in ("username", "email", "login") if k not in user_keys]
            json_attempts = [
                {ukey: username, "password": password} for ukey in user_keys
            ]
            from urllib.parse import urlparse as _up
            _origin = "{0.scheme}://{0.netloc}".format(_up(login_url))
            headers_json = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "Origin": _origin,
                "Referer": login_url,
            }
            for api_url in api_urls:
                for payload in json_attempts:
                    try:
                        login_resp = self.session.post(
                            api_url, json=payload, headers=headers_json,
                            timeout=20, allow_redirects=True,
                        )
                    except Exception as exc:
                        step("api_json_error", f"{api_url}: {exc}")
                        continue
                    self.last_login_response = login_resp
                    body = login_resp.text.lower()
                    compact = login_resp.text.replace(" ", "")[:600].lower()
                    _ct = (login_resp.headers.get("Content-Type") or "").lower()
                    es_json = "json" in _ct or login_resp.text.lstrip()[:1] == "{"
                    exito = es_json and (
                        (login_resp.status_code < 400 and "password" not in body[:500])
                        or '"state":"success"' in compact
                        or '"success":true' in compact
                    )
                    if exito:
                        self._finish_login(True, "api_json", login_resp)
                        return True
            self.login_debug["resultado"] = "login_api_fallo"
            self.login_debug["endpoints_probados"] = api_urls
            self.login_debug["razon"] = (
                "La pagina no tiene formulario HTML. Se probaron estos endpoints "
                f"de API: {api_urls}. Si el endpoint se descubrio bien y el "
                "servidor rechazo credenciales, revisa usuario/contraseña. "
                "Si no se encontro endpoint, usa GHOSTGATE completo (navegador "
                "real) y pega las cookies en 'Cookies'."
            )
            self.authenticated = False
            return False

        if auto_detect_fields and (username_field is None or password_field is None):
            detected = self._detect_login_fields(soup)
            username_field = username_field or detected["username_field"]
            password_field = password_field or detected["password_field"]
        username_field = username_field or "username"
        password_field = password_field or "password"

        turnstile = bool(soup.find(class_=re.compile("turnstile", re.I))) or "cf-turnstile" in login_html.lower()
        if turnstile:
            step("turnstile_detectado", True)
            self.login_debug["resultado"] = "turnstile_requiere_globo"
            self.login_debug["razon"] = (
                "El formulario usa Cloudflare Turnstile. Hay que esperar la "
                "auto-resolucion del widget en un navegador real (GHOSTGATE "
                "completo) y luego usar la sesion resultante."
            )
            self.authenticated = False
            return False

        csrf_name, csrf_value = self._extract_csrf(soup)

        payload = {username_field: username, password_field: password}
        if csrf_name and csrf_value:
            payload[csrf_name] = csrf_value
        payload.update(extra_fields)

        action = login_url
        method = "post"
        if form:
            if form.get("action"):
                action = urljoin(login_url, form["action"])
            method = (form.get("method") or "post").lower()

        self.login_debug.update({
            "login_url": login_url,
            "action": action,
            "method": method,
            "username_field": username_field,
            "password_field": password_field,
            "csrf_name": csrf_name,
            "payload_keys": list(payload.keys()),
        })

        if method == "get":
            login_resp = self.session.get(action, params=payload, timeout=20, allow_redirects=True)
        else:
            login_resp = self.session.post(action, data=payload, timeout=20, allow_redirects=True)
        self.last_login_response = login_resp

        # ---------- 5. Deteccion de exito ----------
        text_lower = login_resp.text.lower()
        final_url = str(login_resp.url).lower()

        if success_indicator:
            success = success_indicator.lower() in text_lower or success_indicator.lower() in final_url
        elif failure_indicator:
            success = failure_indicator.lower() not in text_lower
        else:
            still_on_login = any(x in final_url for x in ["login", "signin", "auth", "session"])
            has_login_form = bool(BeautifulSoup(login_resp.text, "html.parser").find("input", {"type": "password"}))
            redirected_away = urlparse(str(login_resp.url)).path != urlparse(login_url).path
            good_status = login_resp.status_code < 400
            success = good_status and (redirected_away or not has_login_form) and not still_on_login

        self._finish_login(success, "credentials", login_resp)

        # ---------- 6. Verificacion opcional de sesion ----------
        if success and verify_url:
            check = self.verify_session(verify_url)
            self.login_debug["verificacion"] = {
                "url": verify_url,
                "authenticated": check["authenticated"],
                "reason": check.get("reason"),
            }
            if not check["authenticated"]:
                self.authenticated = False
                self.login_debug["resultado"] = "verificacion_post_login_fallo"
                return False

        return success

    # ------------------------------------------------------------------
    # Auto-descubrimiento SPA (cacheado por origen: un sitio, un escaneo)
    # ------------------------------------------------------------------
    def _scan_spa_js(self, page_url: str, soup=None, tope: int = 150) -> Dict[str, Any]:
        """Escanea todo el JavaScript de una SPA (scripts + chunks multinivel).

        Devuelve {"api_prefix": str, "posts": [endpoints POST], "js_files": N}.
        Cacheado por origen de la pagina.
        """
        import re as _re
        from collections import deque as _dq
        from concurrent.futures import ThreadPoolExecutor as _tpe
        import requests as _rq
        origin = "{0.scheme}://{0.netloc}".format(urlparse(page_url))
        if self._spa_cache_origin == origin and self._spa_cache_data:
            return self._spa_cache_data
        if soup is None:
            r = self.session.get(page_url, timeout=20)
            soup = BeautifulSoup(r.text, "html.parser")
        api_prefix = ""
        posts = []
        vistos_post = set()

        def escanear_js(js: str) -> None:
            nonlocal api_prefix
            m = _re.search(r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']', js)
            if m and not api_prefix:
                api_prefix = m.group(1)
            for mm in _re.finditer(r'\.post\(\s*["\'`]([^"\'`]+)["\'`]', js):
                ep = mm.group(1)
                if not ep.startswith("http") and ep not in vistos_post:
                    vistos_post.add(ep)
                    posts.append(ep)

        # scripts nivel 1: los src relativos se resuelven contra la RAIZ
        # del sitio (base href="/"), no contra la URL de la pagina.
        cola = []
        base = soup.find("base")
        base_href = base.get("href") if base else "/"
        for tag in soup.find_all("script"):
            s = tag.get("src")
            if s:
                if s.startswith("http"):
                    cola.append(s)
                elif base_href.startswith("http"):
                    cola.append(urljoin(base_href, s))
                else:
                    cola.append(origin + "/" + s.lstrip("/"))
            elif tag.string and len(tag.string) < 500000:
                escanear_js(tag.string)

        _headers = dict(self.session.headers)
        vistos_urls = set(cola)
        pendientes = _dq(cola)
        archivos = 0

        def _traer(url_js):
            try:
                r = _rq.get(url_js, timeout=12, headers=_headers)
                if len(r.content) > 2_500_000 or "<html" in r.text[:500].lower():
                    return None
                return (url_js, r.text)
            except Exception:
                return None

        while pendientes and archivos < tope:
            lote = []
            while pendientes and len(lote) < 12:
                lote.append(pendientes.popleft())
            with _tpe(max_workers=8) as ex:
                resultados = [x for x in ex.map(_traer, lote) if x]
            for url_js, texto in resultados:
                archivos += 1
                escanear_js(texto)
                for c in _re.findall(r'["\']\./?((?:chunk|main|scripts)-[\w\-]+\.js)["\']', texto):
                    full = urljoin(url_js, "./" + c)
                    if full not in vistos_urls:
                        vistos_urls.add(full)
                        pendientes.append(full)

        data = {"api_prefix": api_prefix, "posts": posts, "js_files": archivos}
        self._spa_cache_origin = origin
        self._spa_cache_data = data
        return data

    def _armar_url_api(self, page_url: str, ep: str) -> str:
        origin = "{0.scheme}://{0.netloc}".format(urlparse(page_url))
        data = self._spa_cache_data or {}
        api_prefix = data.get("api_prefix") or ""
        if api_prefix and not api_prefix.startswith("/"):
            api_prefix = "/" + api_prefix
        if not ep.startswith("/"):
            ep = "/" + ep
        return origin + api_prefix + ep

    def _discover_spa_login_endpoints(self, login_url: str, soup) -> list:
        """Endpoints de ACCION de login (doSignin) descubiertos en el JS.
        Los get* (getSignin) son de config y no sirven para loguearse."""
        data = self._scan_spa_js(login_url, soup)
        candidatos = []
        for ep in data["posts"]:
            low = ep.lower()
            if any(k in low for k in ("signin", "sign-in", "login", "doauth")):
                candidatos.append(ep)
        accion = [e for e in candidatos if not e.lower().rstrip("/").split("/")[-1].startswith("get")]
        finales = []
        for ep in accion:
            full = self._armar_url_api(login_url, ep)
            if full not in finales:
                finales.append(full)
        return finales

    def discover_account_urls(self, page_url: str) -> list:
        """Endpoints de API que devuelven datos de la cuenta (verificar sesion)."""
        data = self._scan_spa_js(page_url)
        claves = ("account", "profile", "balance", "init", "me", "user", "wallet")
        candidatos = []
        for ep in data["posts"]:
            segs = [s for s in ep.lower().split("/") if s]
            if segs and any(any(k == s or k in s for k in claves) for s in segs):
                candidatos.append(ep)

        def prioridad(ep):
            low = ep.lower()
            segs = low.rstrip("/").split("/")
            ultimo = segs[-1] if segs else ""
            if "account" in low and ("init" in ultimo or "getaccount" in low or ultimo == "me"):
                return 0
            if "account" in low:
                return 1
            if "profile" in low or ultimo == "me":
                return 2
            if "init" in ultimo:
                return 3
            return 4

        candidatos.sort(key=prioridad)
        finales = []
        for ep in candidatos:
            full = self._armar_url_api(page_url, ep)
            if full not in finales:
                finales.append(full)
        return finales[:4]

    def fetch_user_profile(self, page_url: str) -> Dict[str, Any]:
        """Trae los datos personales del usuario logueado desde endpoints
        de SOLO LECTURA (get* de settings/perfil). Nunca llama a do* (acciones)."""
        data = self._scan_spa_js(page_url)
        origin = "{0.scheme}://{0.netloc}".format(urlparse(page_url))
        out: Dict[str, Any] = {}
        for ep in data.get("posts", []):
            low = ep.lower()
            ultimo = low.rstrip("/").split("/")[-1]
            if not ultimo.startswith("get"):
                continue  # solo lectura: nunca llamar a do* (cambian datos)
            if not any(k in low for k in ("settings", "profile", "getpartner", "getuserinfo")):
                continue
            url = self._armar_url_api(page_url, ep)
            h = dict(self.session.headers)
            h.update({"Content-Type": "application/json", "Accept": "application/json",
                      "Origin": origin, "Referer": origin + "/"})
            try:
                r = self.session.post(url, json={}, headers=h, timeout=15)
                if r.status_code == 200 and r.text.lstrip()[:1] == "{":
                    try:
                        j = r.json()
                    except Exception:
                        continue
                    if len(json.dumps(j, default=str)) <= 6000:
                        out[ep] = j
                    if self._find_username(j):
                        break  # ya aparecio el nombre
            except Exception:
                continue
            if len(out) >= 2:
                break
        return out

    def probe_account_candidates(self, urls: list) -> list:
        """Sin sesion, descarta endpoints publicos (200 anonimo = no sirven
        para verificar sesion). Devuelve solo los que exigen sesion (401/403)."""
        import requests as _rq
        protegidos = []
        _headers = dict(self.session.headers)
        for u in urls:
            try:
                _origin = "{0.scheme}://{0.netloc}".format(urlparse(u))
                h = dict(_headers)
                h.update({"Content-Type": "application/json",
                          "Accept": "application/json",
                          "Origin": _origin, "Referer": _origin + "/"})
                r = _rq.get(u, timeout=15, headers=h)
                if r.status_code in (404, 405):
                    r = _rq.post(u, json={}, timeout=15, headers=h)
                if r.status_code in (401, 403):
                    protegidos.append(u)
            except Exception:
                continue
        return protegidos

    def discover_login_url(self, site_url: str) -> Optional[str]:
        """Con SOLO la URL del sitio encuentra la pagina de login.
        Devuelve la URL o None si no la encuentra."""
        try:
            origin = "{0.scheme}://{0.netloc}".format(urlparse(site_url))
            r = self.session.get(origin, timeout=20)
        except Exception:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        # 1. la raiz ya tiene formulario clasico
        if soup.find("input", {"type": "password"}):
            return origin
        # 2. candidatos de ruta (desde el JS + rutas estandar)
        # rutas estandar primero (mas predecibles), luego las del JS
        candidatos = []
        for p in ("login", "signin", "auth/signin", "auth/login", "auth/sign-in",
                  "account/login", "log-in", "iniciar-sesion", "entrar", "wp-login.php"):
            if p not in candidatos:
                candidatos.append(p)
        try:
            data = self._scan_spa_js(origin, soup)
        except Exception:
            data = {"posts": []}
        for ep in data.get("posts", []):
            low = ep.lower()
            if any(k in low for k in ("login", "signin", "sign-in")) and ep not in candidatos:
                candidatos.append(ep)
        for p in candidatos:
            full = p if p.startswith("http") else origin + "/" + p.strip("/")
            try:
                rr = self.session.get(full, timeout=15, allow_redirects=True)
            except Exception:
                continue
            if rr.status_code >= 400:
                continue
            _ct = (rr.headers.get("Content-Type") or "").lower()
            if "json" in _ct or rr.text.lstrip()[:1] == "{":
                continue  # respuesta de API: no es una pagina de login
            ssoup = BeautifulSoup(rr.text, "html.parser")
            if ssoup.find("input", {"type": "password"}):
                return str(rr.url)
            # shell de SPA: si el JS expone endpoint de login, esta ruta sirve
            if len(ssoup.find_all("script")) >= 2:
                try:
                    if self._discover_spa_login_endpoints(full, ssoup):
                        return full
                except Exception:
                    continue
        return None

    def _find_username(self, obj: Any, depth: int = 0) -> Optional[str]:
        """Busca recursivamente el nombre/usuario dentro de un JSON de perfil."""
        if depth > 6 or obj is None:
            return None
        if isinstance(obj, dict):
            # identificadores personales primero (nunca son metadatos)
            for k in ("username", "login", "email"):
                v = obj.get(k)
                if isinstance(v, str) and 2 <= len(v) <= 100:
                    return v
            for k in ("full_name", "first_name", "firstname", "name", "nickname"):
                v = obj.get(k)
                if isinstance(v, str) and 2 <= len(v) <= 100:
                    # "name" dentro de un objeto con "code"/"precision" es
                    # una moneda, pais o idioma (ej: US Dollar), no una persona
                    if k in ("name", "nickname") and ("code" in obj or "precision" in obj):
                        continue
                    return v
            for v in obj.values():
                r = self._find_username(v, depth + 1)
                if r:
                    return r
        elif isinstance(obj, list):
            for v in obj[:20]:
                r = self._find_username(v, depth + 1)
                if r:
                    return r
        return None

    def _finish_login(self, success: bool, method_name: str, resp) -> None:
        self.authenticated = success
        self.auth_method = method_name if success else None
        self.login_debug["success"] = success
        self.login_debug["final_url"] = str(resp.url)
        self.login_debug["status_code"] = resp.status_code

    def set_bearer_token(self, token: str) -> None:
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = True
        self.auth_method = "bearer"

    def set_custom_header(self, header_name: str, header_value: str) -> None:
        self.session.headers[header_name] = header_value
        self.authenticated = True
        self.auth_method = "custom_header"

    def get_session(self) -> requests.Session:
        return self.session

    def is_authenticated(self) -> bool:
        return self.authenticated

    def get_auth_info(self) -> Dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "method": self.auth_method,
            "cookies": dict(self.session.cookies),
            "headers": {k: v for k, v in self.session.headers.items()
                        if k.lower() in ("authorization", "cookie", "user-agent")},
            "login_debug": self.login_debug,
        }

    def save_session(self, filepath: str) -> None:
        data = {
            "cookies": dict(self.session.cookies),
            "headers": {k: v for k, v in self.session.headers.items()
                        if k.lower() in ("authorization", "cookie")},
            "method": self.auth_method,
        }
        Path(filepath).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load_session(self, filepath: str) -> bool:
        path = Path(filepath)
        if not path.exists():
            return False
        data = json.loads(path.read_text(encoding="utf-8"))
        self.set_cookies(data.get("cookies", {}))
        for k, v in data.get("headers", {}).items():
            self.session.headers[k] = v
        self.auth_method = data.get("method")
        self.authenticated = True
        return True
