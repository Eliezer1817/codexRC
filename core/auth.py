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
from pathlib import Path
from urllib.parse import urljoin, urlparse
import json
import re


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
    ) -> bool:
        extra_fields = extra_fields or {}
        self.login_debug = {}

        resp = self.session.get(login_url, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        if auto_detect_fields and (username_field is None or password_field is None):
            detected = self._detect_login_fields(soup)
            username_field = username_field or detected["username_field"]
            password_field = password_field or detected["password_field"]

        username_field = username_field or "username"
        password_field = password_field or "password"

        csrf_name, csrf_value = self._extract_csrf(soup)

        payload = {
            username_field: username,
            password_field: password,
        }
        if csrf_name and csrf_value:
            payload[csrf_name] = csrf_value

        payload.update(extra_fields)

        form = soup.find("form")
        action = login_url
        method = "post"
        if form:
            if form.get("action"):
                action = urljoin(login_url, form["action"])
            method = (form.get("method") or "post").lower()

        self.login_debug = {
            "login_url": login_url,
            "action": action,
            "method": method,
            "username_field": username_field,
            "password_field": password_field,
            "csrf_name": csrf_name,
            "payload_keys": list(payload.keys()),
        }

        if method == "get":
            login_resp = self.session.get(action, params=payload, timeout=20, allow_redirects=True)
        else:
            login_resp = self.session.post(action, data=payload, timeout=20, allow_redirects=True)

        self.last_login_response = login_resp

        success = False
        text_lower = login_resp.text.lower()
        final_url = login_resp.url.lower()

        if success_indicator:
            success = success_indicator.lower() in text_lower or success_indicator.lower() in final_url
        elif failure_indicator:
            success = failure_indicator.lower() not in text_lower
        else:
            still_on_login = any(x in final_url for x in ["login", "signin", "auth", "session"])
            has_login_form = bool(BeautifulSoup(login_resp.text, "html.parser").find("input", {"type": "password"}))
            redirected_away = urlparse(login_resp.url).path != urlparse(login_url).path
            good_status = login_resp.status_code < 400
            success = good_status and (redirected_away or not has_login_form) and not still_on_login

        self.authenticated = success
        self.auth_method = "credentials" if success else None
        self.login_debug["success"] = success
        self.login_debug["final_url"] = login_resp.url
        self.login_debug["status_code"] = login_resp.status_code

        return success

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
