"""
codexRC - Deep Scan Module
Auditoria profunda: deteccion de WAF/CDN, certificado TLS y mapeo de dominios.
Todo en Python puro para que corra igual en Termux (armv7l) sin binarios extra.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import socket
import ssl
import requests
from urllib.parse import urlparse


# (nombre, cabeceras que lo delatan, palabras clave del banner Server)
WAF_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "cf-mitigated", "x-wf-sucuri"], ["cloudflare"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], ["sucuri"]),
    ("Imperva / Incapsula", ["x-iinfo", "x-cdn: imperva", "visid"], ["imperva", "incapsula"]),
    ("Akamai", ["x-akamai-transformed", "akamaighost"], ["akamai"]),
    ("AWS CloudFront", ["x-amz-cf-id", "via:1.1 cloudfront", "via: 1.1 cloudfront"], ["cloudfront"]),
    ("Fastly", ["x-served-by: cache-", "x-fastly-request-id"], ["fastly"]),
    ("ModSecurity", ["mod_security"], ["mod_security", "modsecurity"]),
    ("Wordfence", ["x-wordfence"], ["wordfence"]),
    ("Azure Front Door", ["x-azure-ref", "x-azure-fdid"], ["azurefd", "front door"]),
    ("Vercel", ["x-vercel-id", "server: vercel"], ["vercel"]),
    ("Wix", ["x-wix-request-id", "x-seen-by: wix"], ["wix"]),
    ("Squarespace", ["server: squarespace"], ["squarespace"]),
    ("Netskope", ["ns-partyid"], ["netskope"]),
    ("StackPath", ["x-stackpath", "servername: stackpath"], ["stackpath"]),
    ("Fly.io", ["server: fly"], ["fly.io"]),
]


def detect_waf(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Detecta WAF/CDN a partir de las cabeceras de respuesta."""
    flat = " ".join(f"{k.lower()}: {str(v).lower()}" for k, v in (headers or {}).items())
    server = ""
    for k, v in (headers or {}).items():
        if k.lower() == "server":
            server = str(v).lower()
            break

    for name, header_keys, _ in WAF_SIGNATURES:
        for h in header_keys:
            if h in flat:
                return {"detected": True, "waf": name, "evidence": f"header: {h}"}

    for name, _, needles in WAF_SIGNATURES:
        for n in needles:
            if n in server:
                return {"detected": True, "waf": name, "evidence": f"Server: {server}"}

    return {"detected": False, "waf": None, "evidence": None}


def tls_audit(url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Audita el certificado TLS del host (emisor, validez, protocolo)."""
    host = urlparse(url).hostname
    if not host:
        return {"enabled": False, "error": "sin host"}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()

        not_after = cert.get("notAfter", "")
        expires = None
        days_left = None
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expires - datetime.utcnow()).days
        except (ValueError, TypeError):
            pass

        issuer = ""
        subject = ""
        for rdn in cert.get("issuer", ()):
            for k, v in rdn:
                if k == "organizationName" and not issuer:
                    issuer = v
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                if k == "commonName" and not subject:
                    subject = v

        sans = []
        for typ, value in cert.get("subjectAltName", ()):
            if typ == "DNS" and len(sans) < 25:
                sans.append(value)

        grade = "B"
        if days_left is not None and days_left > 30 and proto in ("TLSv1.3", "TLSv1.2"):
            grade = "A"

        return {
            "enabled": True,
            "protocol": proto,
            "issuer": issuer or "desconocido",
            "subject": subject or host,
            "sans": sans,
            "expires": not_after,
            "days_left": days_left,
            "valid": days_left is None or days_left > 0,
            "grade": grade,
        }
    except Exception as exc:
        return {"enabled": False, "error": str(exc)[:200]}


def cookie_flags(headers: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analiza flags de seguridad de las cookies desde Set-Cookie crudo."""
    raw = ""
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            raw = v
            break
    if not raw:
        return []

    out = []
    try:
        for part in raw.split(","):
            if "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            if not name or name.lower().startswith(("expires", "path", "domain", "max-age", "samesite", "secure")):
                continue
            low = part.lower()
            out.append({
                "name": name[:40],
                "secure": "secure" in low,
                "httponly": "httponly" in low,
                "samesite": ("samesite=strict" in low and "strict") or ("samesite=lax" in low and "lax") or ("samesite=none" in low and "none") or None,
            })
            if len(out) >= 15:
                break
    except Exception:
        pass
    return out


class DomainMap:
    """Mapeo de DNS: IPs del host + subdominios publicos via crt.sh."""

    def __init__(self, timeout: float = 14.0, max_subdomains: int = 30):
        self.timeout = timeout
        self.max_subdomains = max_subdomains

    def run(self, url: str) -> Dict[str, Any]:
        host = (urlparse(url).hostname or "").lower().split(":")[0]
        out: Dict[str, Any] = {
            "host": host,
            "ips": [],
            "subdomains": {"count": 0, "sample": []},
            "notes": [],
        }
        if not host:
            out["notes"].append("sin host en la URL")
            return out

        # ===== IPs del host =====
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
            out["ips"] = ips[:10]
        except Exception as exc:
            out["notes"].append(f"dns: {str(exc)[:120]}")

        # ===== subdominios via crt.sh (CT logs) =====
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{host}&output=json",
                timeout=self.timeout,
                headers={"User-Agent": "Mozilla/5.0 codexRC"},
            )
            if r.ok:
                rows = r.json()[:400]
                names = set()
                for row in rows:
                    for n in str(row.get("name_value", "")).split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith("." + host) or n == host:
                            names.add(n)
                ordered = sorted(names)
                out["subdomains"] = {"count": len(ordered), "sample": ordered[: self.max_subdomains]}
            else:
                out["notes"].append(f"crt.sh HTTP {r.status_code}")
        except Exception as exc:
            out["notes"].append(f"crt.sh: {str(exc)[:120]}")

        return out
