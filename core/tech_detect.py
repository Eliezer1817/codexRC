"""
codexRC - Basic Technology Detection
Lightweight fingerprinting from headers, HTML, cookies and common paths.
"""

from typing import List, Dict, Any, Optional
import re
from bs4 import BeautifulSoup
import requests


class TechDetector:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def detect(self, url: str, html: Optional[str] = None, headers: Optional[Dict] = None) -> List[Dict[str, Any]]:
        techs = []

        if html is None or headers is None:
            try:
                resp = self.session.get(url, timeout=15)
                html = resp.text
                headers = dict(resp.headers)
            except Exception as e:
                return [{"name": "error", "detail": str(e)}]

        headers_l = {k.lower(): v for k, v in (headers or {}).items()}
        soup = BeautifulSoup(html or "", "lxml")

        # Server header
        server = headers_l.get("server")
        if server:
            techs.append({"name": "Server", "version": server, "source": "header"})

        # X-Powered-By
        powered = headers_l.get("x-powered-by")
        if powered:
            techs.append({"name": powered.split("/")[0].strip(), "version": powered, "source": "header"})

        # Generator meta
        gen = soup.find("meta", {"name": "generator"})
        if gen and gen.get("content"):
            content = gen["content"]
            techs.append({"name": content.split(" ")[0], "version": content, "source": "meta-generator"})

        # Common signatures
        signatures = [
            (r"wp-content|wordpress", "WordPress", None),
            (r"drupal", "Drupal", None),
            (r"joomla", "Joomla", None),
            (r"laravel", "Laravel", None),
            (r"react", "React", None),
            (r"vue\.js|vuejs", "Vue.js", None),
            (r"angular", "Angular", None),
            (r"jquery[.-]?([0-9.]+)", "jQuery", 1),
            (r"bootstrap[.-]?([0-9.]+)", "Bootstrap", 1),
            (r"nginx", "nginx", None),
            (r"apache", "Apache", None),
        ]

        text = (html or "").lower()
        for pattern, name, group in signatures:
            m = re.search(pattern, text, re.I)
            if m:
                version = m.group(group) if group and m.lastindex else None
                # Avoid duplicates
                if not any(t["name"].lower() == name.lower() for t in techs):
                    techs.append({"name": name, "version": version, "source": "content"})

        # Cookies hints
        cookies = self.session.cookies.get_dict() if self.session else {}
        for cname in cookies:
            cl = cname.lower()
            if "wordpress" in cl or "wp_" in cl:
                if not any(t["name"] == "WordPress" for t in techs):
                    techs.append({"name": "WordPress", "version": None, "source": "cookie"})
            if "laravel_session" in cl:
                if not any(t["name"] == "Laravel" for t in techs):
                    techs.append({"name": "Laravel", "version": None, "source": "cookie"})

        return techs
