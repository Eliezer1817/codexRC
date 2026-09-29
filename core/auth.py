"""
codexRC - Authentication Module
Supports 3 methods:
1. Session Cookies (recommended)
2. Automatic form login (username + password)
3. Bearer / JWT / Custom Authorization header
"""

from typing import Optional, Dict, Any
import requests
from bs4 import BeautifulSoup
from pathlib import Path
import json


class AuthManager:
    def __init__(self):
        self.session = requests.Session()
        self.authenticated = False
        self.auth_method: Optional[str] = None
        self.last_login_response: Optional[requests.Response] = None

    # ------------------------------------------------------------------
    # Method 1: Cookies
    # ------------------------------------------------------------------
    def load_cookies_from_file(self, filepath: str) -> bool:
        """
        Load cookies from a Netscape-format or simple key=value file.
        Recommended method for complex logins (MFA, captchas, etc.).
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Cookie file not found: {filepath}")

        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        # Simple format: name=value; name2=value2
        if "=" in content and not content.startswith("#"):
            for part in content.split(";"):
                part = part.strip()
                if "=" in part:
                    name, value = part.split("=", 1)
                    self.session.cookies.set(name.strip(), value.strip())
        else:
            # Basic Netscape support (very simplified)
            for line in content.splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    name, value = parts[5], parts[6]
                    self.session.cookies.set(name, value)

        self.authenticated = True
        self.auth_method = "cookies"
        return True

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set cookies from a dictionary."""
        for name, value in cookies.items():
            self.session.cookies.set(name, value)
        self.authenticated = True
        self.auth_method = "cookies"

    # ------------------------------------------------------------------
    # Method 2: Automatic form login
    # ------------------------------------------------------------------
    def login_with_credentials(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict[str, str]] = None,
        success_indicator: Optional[str] = None,
    ) -> bool:
        """
        Attempt automatic login by:
        1. Fetching the login page
        2. Extracting CSRF token if present
        3. Posting credentials
        """
        extra_fields = extra_fields or {}

        # 1. Get login page
        resp = self.session.get(login_url, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        # 2. Try to find CSRF token (common names)
        csrf_token = None
        csrf_names = [
            "csrf_token", "csrfmiddlewaretoken", "_token",
            "authenticity_token", "__RequestVerificationToken",
            "csrf", "_csrf"
        ]
        for name in csrf_names:
            tag = soup.find("input", {"name": name})
            if tag and tag.get("value"):
                csrf_token = tag["value"]
                break

        # 3. Build payload
        payload = {
            username_field: username,
            password_field: password,
        }
        if csrf_token:
            # Use the name we found
            for name in csrf_names:
                if soup.find("input", {"name": name}):
                    payload[name] = csrf_token
                    break

        payload.update(extra_fields)

        # 4. Detect form action
        form = soup.find("form")
        action = login_url
        if form and form.get("action"):
            action = form["action"]
            if action.startswith("/"):
                from urllib.parse import urljoin
                action = urljoin(login_url, action)

        # 5. Send login
        login_resp = self.session.post(action, data=payload, timeout=15, allow_redirects=True)
        self.last_login_response = login_resp

        # 6. Basic success check
        if success_indicator:
            success = success_indicator.lower() in login_resp.text.lower()
        else:
            # Heuristic: if we still see the login form, probably failed
            success = "login" not in login_resp.url.lower() and login_resp.status_code < 400

        if success:
            self.authenticated = True
            self.auth_method = "credentials"
        else:
            self.authenticated = False

        return self.authenticated

    # ------------------------------------------------------------------
    # Method 3: Bearer / Token / Custom header
    # ------------------------------------------------------------------
    def set_bearer_token(self, token: str) -> None:
        """Set Authorization: Bearer <token>"""
        self.session.headers["Authorization"] = f"Bearer {token}"
        self.authenticated = True
        self.auth_method = "bearer"

    def set_custom_header(self, header_name: str, header_value: str) -> None:
        """Set any custom header (e.g. X-API-Key, Authorization, etc.)"""
        self.session.headers[header_name] = header_value
        self.authenticated = True
        self.auth_method = "custom_header"

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------
    def get_session(self) -> requests.Session:
        return self.session

    def is_authenticated(self) -> bool:
        return self.authenticated

    def get_auth_info(self) -> Dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "method": self.auth_method,
            "cookies": dict(self.session.cookies),
            "headers": dict(self.session.headers),
        }

    def save_session(self, filepath: str) -> None:
        """Save current session (cookies + headers) for later reuse."""
        data = {
            "cookies": dict(self.session.cookies),
            "headers": {k: v for k, v in self.session.headers.items()
                        if k.lower() in ("authorization", "cookie")},
            "method": self.auth_method,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_session(self, filepath: str) -> bool:
        """Load previously saved session."""
        path = Path(filepath)
        if not path.exists():
            return False
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.set_cookies(data.get("cookies", {}))
        for k, v in data.get("headers", {}).items():
            self.session.headers[k] = v
        self.auth_method = data.get("method")
        self.authenticated = True
        return True
