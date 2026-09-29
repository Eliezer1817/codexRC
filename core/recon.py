"""
codexRC - Basic Recon Module
Collects headers, status, redirects, cookies, security headers and basic info.
"""

from typing import Dict, Any, Optional
import requests
from urllib.parse import urlparse


SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]


class Recon:
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()

    def run(self, url: str) -> Dict[str, Any]:
        result = {
            "url": url,
            "final_url": None,
            "status_code": None,
            "headers": {},
            "security_headers": {},
            "missing_security_headers": [],
            "cookies": {},
            "redirect_chain": [],
            "server": None,
            "error": None,
        }

        try:
            resp = self.session.get(url, timeout=20, allow_redirects=True)
            result["final_url"] = str(resp.url)
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["cookies"] = dict(resp.cookies)
            result["server"] = resp.headers.get("Server")

            # Security headers analysis
            headers_l = {k.lower(): v for k, v in resp.headers.items()}
            for h in SECURITY_HEADERS:
                if h in headers_l:
                    result["security_headers"][h] = headers_l[h]
                else:
                    result["missing_security_headers"].append(h)

            # Simple redirect chain (limited)
            if resp.history:
                result["redirect_chain"] = [str(r.url) for r in resp.history] + [str(resp.url)]

        except Exception as e:
            result["error"] = str(e)

        return result
