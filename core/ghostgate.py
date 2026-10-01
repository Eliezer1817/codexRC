"""
codexRC - Modulo GHOSTGATE (Cloudflare relay, Termux friendly)

CF-Ghost diagnostica. GhostGate accede.

Flujo integrado al login autenticado:
1. El request normal del escaneo llega a una pagina protegida por Cloudflare.
2. Este modulo clasifica la respuesta (JS_CHALLENGE / TURNSTILE / WAF_BLOCK /
   BLOQUEO_IP / UNDER_ATTACK / SIN_CF).
3. Si hay challenge y curl_cffi esta instalado, reintenta con la huella TLS
   exacta de Chrome 136 (impersonacion de navegador real).
4. Si pasa, entrega las cookies al requests.Session del escaneo.
5. Si no pasa (IP quemado / Turnstile), informa que se necesita GHOSTGATE
   completo: delegar el acceso a un navegador real con IP limpia.

Basado en la metodologia GHOSTGATE (repo Eliezer1817/GhostGate).
"""

from typing import Any, Dict, Optional

# curl_cffi es opcional: si no esta en Termux, se degrada a requests puro.
try:
    from curl_cffi import requests as creq
    HAS_CURL_CFFI = True
except ImportError:  # pragma: no cover
    creq = None
    HAS_CURL_CFFI = False

IMPERSONATE = "chrome136"  # huella mas moderna probada en los experimentos

REAL_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/136.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


def clasificar(status_code: int, headers: Dict[str, str], text: str) -> Dict[str, Any]:
    """Clasificador CF-Ghost: devuelve tipo de bloqueo y si hay challenge."""
    body = (text or "")[:4000]
    h = {k.lower(): v for k, v in (headers or {}).items()}
    resultado = {"cloudflare": "cf-ray" in h, "tipo": "SIN_CF", "challenge": False}

    if "just a moment" in body.lower() or h.get("cf-mitigated") == "challenge":
        resultado["challenge"] = True
        resultado["tipo"] = "TURNSTILE" if "turnstile" in body.lower() else "JS_CHALLENGE"
        return resultado
    if "attention required" in body:
        resultado["challenge"] = True
        resultado["tipo"] = "BLOQUEO_IP"
        return resultado
    if status_code in (403, 429) and "cf-ray" in h:
        resultado["tipo"] = "WAF_BLOCK"
        return resultado
    if status_code == 503 and "cf-ray" in h:
        resultado["tipo"] = "UNDER_ATTACK_MODE"
        return resultado
    if "cf-ray" in h:
        resultado["tipo"] = "SIN_CHALLENGE"
    return resultado


def clasificar_respuesta(resp) -> Dict[str, Any]:
    """Clasifica un objeto response de requests/curl_cffi."""
    try:
        return clasificar(resp.status_code, dict(resp.headers), resp.text or "")
    except Exception:
        return {"cloudflare": False, "tipo": "SIN_CF", "challenge": False}


def ghostgate_relay(url: str, timeout: int = 25) -> Dict[str, Any]:
    """Reintenta una URL con huella TLS de Chrome real (GHOSTGATE-LITE).

    Devuelve:
        {"ok": bool, "tipo": str, "cookies": {name: value},
         "user_agent": str, "status": int, "html": str, "razon": str}
    """
    resultado: Dict[str, Any] = {
        "ok": False, "tipo": "DESCONOCIDO", "cookies": {},
        "user_agent": REAL_HEADERS["User-Agent"], "status": None,
        "html": "", "razon": "",
    }

    if not HAS_CURL_CFFI:
        resultado["tipo"] = "CURL_CFFI_NO_INSTALADO"
        resultado["razon"] = (
            "curl_cffi no esta instalado (pip install curl_cffi). "
            "Sin huella de navegador real no se puede intentar el paso."
        )
        return resultado

    try:
        resp = creq.get(
            url,
            impersonate=IMPERSONATE,
            headers=REAL_HEADERS,
            timeout=timeout,
            allow_redirects=True,
        )
        diagnostico = clasificar(resp.status_code, dict(resp.headers), resp.text)
        resultado["tipo"] = diagnostico["tipo"]
        resultado["status"] = resp.status_code
        resultado["html"] = resp.text
        cookies = {}
        try:
            for c in resp.cookies.jar:
                cookies[c.name] = c.value
        except Exception:
            cookies = dict(resp.cookies)
        resultado["cookies"] = cookies

        if diagnostico["tipo"] in ("SIN_CHALLENGE", "SIN_CF") and resp.status_code < 400:
            resultado["ok"] = True
            resultado["razon"] = "Paso con huella Chrome real (GHOSTGATE-LITE)"
        elif diagnostico["tipo"] in ("TURNSTILE", "BLOQUEO_IP"):
            resultado["razon"] = (
                "Sigue bloqueado tras el relevo. Se necesita GHOSTGATE completo: "
                "delegar el acceso a un navegador real con IP de buena reputacion."
            )
        else:
            resultado["razon"] = f"Challenge persiste ({diagnostico['tipo']})."
    except Exception as exc:
        resultado["tipo"] = "ERROR_RELEVO"
        resultado["razon"] = f"Excepcion en el relevo: {exc}"

    return resultado
