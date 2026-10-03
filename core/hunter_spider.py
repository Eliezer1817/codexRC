"""
codexRC - Spider
Arana de descubrimiento: mapa paginas/params/endpoints. Extraida de
hunter.py (v0.57.2) para mantener el modulo navegable; la fachada
core/hunter.py re-exporta todo y nada se rompe afuera.
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

from core.hunter_base import (
    Log, SKIP_EXT, JS_SINK_RE, JS_SOURCE_RE, JS_ENDPOINT_RE,
    FORM_INPUT_TYPES, _norm,
)


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
            if path.endswith(".js"):
                # los .js se analizan aparte (endpoints ocultos + chunks lazy);
                # nunca se encolan como pagina
                if len(js_seen) < max_js_files:
                    js_seen.add(_norm(full))
                return
            if path.endswith(SKIP_EXT):
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
            "js_files": sorted(js_seen)[:max_js_files],
            "dom_candidates": dom_candidates[:20],
        }
