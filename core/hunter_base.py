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
import json
import secrets
import time
import concurrent.futures

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

__all__ = [
    "Log", "SKIP_EXT", "JS_SINK_RE", "JS_SOURCE_RE", "JS_ENDPOINT_RE",
    "FORM_INPUT_TYPES", "_norm",
]
