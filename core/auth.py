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
            "error": None,
        }
        started = time.perf_counter()
        try:
            response = self.session.get(verification_url, timeout=20, allow_redirects=True)
            result["response_time"] = round(time.perf_counter() - started, 3)
            result["status_code"] = response.status_code
            result["final_url"] = str(response.url)
            result["content_type"] = response.headers.get("Content-Type")
            result["redirect_chain"] = [str(item.url) for item in response.history] + [str(response.url)]
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

    def _discover_spa_login_endpoints(self, login_url: str, soup) -> list:
        """Auto-descubre el endpoint de login de una SPA en su JavaScript.

        Busca patrones tipo .post("/auth/doSignin") y el prefijo de API
        (apiUrl:"/api") en los scripts de la pagina (2 niveles: scripts
        directos + chunks lazy referenciados). Devuelve URLs absolutas.
        """
        import re as _re
        from urllib.parse import urljoin as _uj, urlparse as _up
        origin = "{0.scheme}://{0.netloc}".format(_up(login_url))
        api_prefix = ""
        candidatos = []
        vistos = set()

        def escanear_js(js: str) -> None:
            nonlocal api_prefix
            m = _re.search(r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']', js)
            if m and not api_prefix:
                api_prefix = m.group(1)
            for mm in _re.finditer(r'\.post\(\s*["\'`]([^"\'`]+)["\'`]', js):
                ep = mm.group(1)
                low = ep.lower()
                if any(k in low for k in ("signin", "sign-in", "login", "doauth")) \
                        and not ep.startswith("http") and ep not in vistos:
                    vistos.add(ep)
                    candidatos.append(ep)

        # scripts con src (nivel 1) + inline.
        # OJO: las SPA resuelven los src relativos contra la RAIZ del sitio
        # (base href="/"), no contra la URL de la pagina. Si se resuelven
        # contra /auth/ muchos servidores devuelven el HTML shell con 200.
        cola = []
        base = soup.find("base")
        base_href = base.get("href") if base else "/"
        for tag in soup.find_all("script"):
            s = tag.get("src")
            if s:
                if s.startswith("http"):
                    cola.append(s)
                elif base_href.startswith("http"):
                    cola.append(_uj(base_href, s))
                else:
                    cola.append(origin + "/" + s.lstrip("/"))
            elif tag.string and len(tag.string) < 500000:
                escanear_js(tag.string)

        # niveles 2..N: chunks lazy referenciados dentro de los JS.
        # El endpoint de login suele estar en un chunk de nivel 3: se recorre
        # el grafo completo (hasta `tope` archivos, en lotes paralelos).
        from collections import deque as _dq
        from concurrent.futures import ThreadPoolExecutor as _tpe
        import requests as _rq

        tope = 150
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
                    full = _uj(url_js, "./" + c)
                    if full not in vistos_urls:
                        vistos_urls.add(full)
                        pendientes.append(full)

        if not candidatos:
            return []
        if api_prefix and not api_prefix.startswith("/"):
            api_prefix = "/" + api_prefix
        # solo endpoints de ACCION (doSignin); los get* (getSignin) son de
        # configuracion y NO sirven para loguearse (dan falsos positivos).
        accion = [e for e in candidatos if not e.lower().rstrip("/").split("/")[-1].startswith("get")]
        orden = accion
        finales = []
        for ep in orden:
            if not ep.startswith("/"):
                ep = "/" + ep
            full = origin + (api_prefix or "") + ep
            if full not in finales:
                finales.append(full)
        return finales

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
