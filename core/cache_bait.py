"""CACHE-BAIT: bateria dedicada de cache poisoning y cache deception.

Todo PASIVO (no se envenena la cache de nadie):
  1. ENTRADAS UNKEYED: cabeceras de routing que muchos caches/CDN no
     incluyen en la clave (X-Forwarded-Host, X-Rewrite-URL, Forwarded...).
     Si se REFLEJAN sin validar, cualquiera puede fijar contenido en la
     cache para TODOS los usuarios. Se reporta como candidata.
  2. WEB CACHE DECEPTION: pedir rutas privadas con extension de asset
     (/api/user/profile.css). Si el servidor responde 200 con los mismos
     datos privados y content-type cacheable, un proxy puede guardar
     paginas PRIVADAS y servirlas a extraños.
  3. PROBE EN MULTIPLES PAGINAS descubiertas por la arana (no solo la base).

Basado en las tecnicas de la guia practica de cache poisoning web
(unkeyed inputs + cache deception), adaptadas a solo-lectura.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Forwarded-Server",
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Forwarded-Prefix",
]

PRIVATE_PATH = re.compile(r"(api|account|profile|user|admin|private|me\b|"
                          r"dashboard|settings|billing)", re.I)
ASSET_SUFFIX = ".css"
CACHEABLE_CT = re.compile(r"(text/css|text/html|application/javascript)",
                          re.I)


class CacheBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)

    def _get(self, url: str, headers: Dict[str, str] = None):
        try:
            return self.session.get(url, timeout=12, headers=headers or {})
        except Exception:
            return None

    # --------------------------------------------------- 1 unkeyed

    def unkeyed(self, url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        canary = "cw-unkeyed-probe"
        for h in UNKEYED_HEADERS:
            r = self._get(url, {h: canary})
            if r is None:
                continue
            if canary in (r.text or "") or any(canary in v
                                              for v in r.headers.values()):
                out.append({
                    "type": "Entrada unkeyed (cache poisoning candidato)",
                    "severity": "alta", "target": url, "param": h,
                    "evidence": f"la cabecera {h} se refleja SIN validar "
                                "(candidata a fijar contenido en cache para "
                                "todos los usuarios)",
                    "verdict": "candidata: deteccion pasiva, nada envenenado",
                })
                self.emit(f"[cache] 💥 {h} reflejado sin validar en "
                          f"{urlparse(url).path}: cache poisoning en puerta")
        return out

    # ------------------------------------------- 2 cache deception

    def cache_deception(self, pages: List[str]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen = set()
        for u in pages:
            p = urlparse(u)
            if not PRIVATE_PATH.search(p.path) or len(seen) >= 4:
                continue
            base = f"{p.scheme}://{p.netloc}{p.path}"
            if base in seen:
                continue
            seen.add(base)
            orig = self._get(u)
            wcd = self._get(base + ASSET_SUFFIX)
            if orig is None or wcd is None:
                continue
            same = (wcd.status_code == 200
                    and (orig.text or "")[:300] == (wcd.text or "")[:300]
                    and orig.status_code == 200)
            ct = wcd.headers.get("Content-Type", "")
            # ANTI-FP: cabeceras que PROHIBEN el cache matan el hallazgo.
            # Caso real (bitevolut /dashboard.css): el catch-all de la SPA
            # sirve la misma carcasa HTML con content-type "cacheable", pero
            # con no-store + cf-cache-status BYPASS nada se guarda ni se
            # sirve a otros: falso positivo.
            cc = (wcd.headers.get("Cache-Control") or "").lower()
            cfs = (wcd.headers.get("CF-Cache-Status") or "").upper()
            prohibido = ("no-store" in cc or "private" in cc
                         or cfs in ("BYPASS", "DYNAMIC"))
            blando = "no-cache" in cc or "max-age=0" in cc
            if same and prohibido:
                self.emit(f"[cache] candidato {p.path}{ASSET_SUFFIX} "
                          f"DESCARTADO (anti-FP): {cc or cfs} prohibe cache")
                continue
            if same and CACHEABLE_CT.search(ct) and not blando:
                out.append({
                    "type": "Web cache deception (candidato)",
                    "severity": "alta", "target": base + ASSET_SUFFIX,
                    "param": "-",
                    "evidence": f"{p.path}{ASSET_SUFFIX} sirve los MISMOS datos "
                                f"privados con content-type cacheable ({ct}): "
                                f"un proxy puede guardar la pagina privada y "
                                f"servirla a otros",
                    "verdict": "candidato: verificar cabeceras de cache",
                })
                self.emit(f"[cache] 💥 cache deception en puerta: "
                          f"{p.path}{ASSET_SUFFIX} entrega datos privados")
        return out

    # -------------------------------------------------------------- run

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[cache] === CACHE-BAIT: unkeyed + cache deception (pasivo) ===")
        findings: List[Dict[str, Any]] = []
        pages = [url] + [t["url"] for t in
                         spider_out.get("param_targets", [])[:6]]
        spider_pages = spider_out.get("pages") or []
        if isinstance(spider_pages, list):
            pages += [p if isinstance(p, str) else p.get("url", "")
                      for p in spider_pages[:10]]
        seen: List[str] = []
        for p in pages:
            if p and p not in seen:
                seen.append(p)
        for u in seen[:6]:
            findings += self.unkeyed(u)
        findings += self.cache_deception(seen)
        n = len(findings)
        self.emit(f"[cache] === CACHE-BAIT: {n} candidata(s) ===")
        return findings
