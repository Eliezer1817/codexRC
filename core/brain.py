"""CEREBRO: la capa de inteligencia determinista del Hunter.

Dos funciones, cero IA (a proposito: exactitud, costo cero, depurable):

  1. FINGERPRINT  identifica que es el blanco ANTES de gastar sondas:
     WordPress (+ plugins y theme via wp-content), Angular/React/Vue/Next,
     Laravel, servidores (headers X-Powered-By / Server). Si detecta un
     vendor con historial de CVEs, lo grita: pista de vendor-farming.

  2. PRIORIZACION puntua cada objetivo del spider (endpoint + parametro)
     y ordena la cola de caza: admin-ajax, uploads, ids, settings, api...
     arriba; utm_*, fbclid, previews y assets abajo. Cada objetivo recibe
     un PRESUPUESTO de sondas proporcional a su valor, para no martillar.

Las baterias consumen la cola ya rankeada: el mismo presupuesto total se
concentra donde duele. Todo determinista: mismo blanco, mismas decisiones.
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------- señales

WP_MARKERS = ["wp-content", "wp-includes", "wp-json", "wp-block",
              "wp-emoji", "wp-rocket", "xmlrpc.php"]

FRAMEWORK_SIGNS = [
    ("Angular",   [r"ng-version", r"ng-app", r"ngNonBindable", r"angular\.min\.js",
                   r"nginject", r"@angular"]),
    ("React",     [r"react(?:\.min)?\.js", r"__NEXT_DATA__", r"react-dom",
                   r"_reactRoot", r"data-reactroot"]),
    ("Next.js",   [r"__NEXT_DATA__", r"/_next/static", r"next/link"]),
    ("Vue",       [r"vue(?:\.min|\.global|-prod)?(?:\.dev)?\.js", r"data-v-[0-9a-f]{8}",
                   r"v-bind", r"createApp\("]),
    ("Laravel",   [r"laravel_session", r"XSRF-TOKEN", r"csrf-token.{0,40}laravel"]),
    ("jQuery",    [r"jquery[.-]?v?([0-9.]+)"]),
]

# vendors con historial de CVEs aceptados (Patchstack/etc): pista de farming
KNOWN_VENDORS = ["villatheme", "wpswings", "woothemes", "yith", "elementor",
                 "contact-form-7", "wpforms", "rank-math", "yoast", "woocommerce",
                 "metagauss", "jetpack", "all-in-one-seo", "litespeed", "wp-rocket"]

# ------------------------------------------------------- pesos de puntaje

# keywords en el PATH del endpoint (los que duelen arriba)
PATH_WEIGHTS = {
    "admin": 9, "admin-ajax": 10, "wp-admin": 9, "ajax": 8,
    "upload": 9, "import": 8, "export": 7, "settings": 8, "options": 7,
    "config": 8, "user": 8, "users": 8, "account": 8, "profile": 7,
    "login": 7, "auth": 7, "token": 8, "api": 6, "rest": 6,
    "checkout": 8, "payment": 8, "order": 7, "cart": 6,
    "id": 6, "search": 6, "file": 7, "download": 7, "path": 6,
    "redirect": 5, "page": 4, "post": 5, "edit": 6, "delete": 7,
}

# keywords en el NOMBRE del parametro
PARAM_WEIGHTS = {
    "id": 8, "user": 8, "uid": 8, "user_id": 9, "post": 7, "page_id": 8,
    "cat": 6, "q": 6, "s": 4, "search": 6, "name": 5, "email": 7,
    "file": 8, "path": 7, "url": 7, "redirect": 6, "next": 5, "return": 5,
    "token": 8, "key": 7, "amount": 7, "price": 7, "action": 6, "type": 3,
    "cat_id": 7, "order": 6, "item": 5, "ref": 3, "lang": 2, "view": 3,
}

# basura de tracking: no merecen ni una sonda
JUNK_PARAMS = re.compile(
    r"^(utm_[a-z]+|fbclid|gclid|msclkid|dclid|mc_[a-z]+|_ga|yclid|igshid|"
    r"ref_src|cmpid|spm|mc_cid)$", re.I)

STATIC_EXT = re.compile(r"\.(css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|"
                        r"ttf|eot|mp4|pdf|xml|txt|map)$", re.I)


class Brain:
    def __init__(self, session, emit, timeout: int = 15):
        self.session = session
        self.emit = emit or (lambda m: None)
        self.timeout = timeout

    # ------------------------------------------------------- fingerprint

    def fingerprint(self, url: str) -> Dict[str, Any]:
        fp: Dict[str, Any] = {"cms": None, "frameworks": [], "plugins": [],
                              "theme": None, "server": None, "vendors": []}
        body, headers = "", {}
        try:
            r = self.session.get(url, timeout=self.timeout)
            body, headers = (r.text or "")[:60000], dict(r.headers)
        except Exception:
            pass
        try:                                   # robots.txt revela mucho de WP
            r2 = self.session.get(url.rstrip("/") + "/robots.txt",
                                  timeout=self.timeout)
            if r2.status_code == 200:
                body += "\n" + (r2.text or "")[:8000]
        except Exception:
            pass

        fp["server"] = headers.get("Server") or headers.get("X-Powered-By")

        if any(m in body for m in WP_MARKERS):
            fp["cms"] = "WordPress"
        plugins = sorted(set(re.findall(
            r"wp-content/plugins/([a-z0-9\-_]+)/", body, re.I)))
        fp["plugins"] = plugins[:25]
        m = re.search(r"wp-content/themes/([a-z0-9\-_]+)/", body, re.I)
        if m:
            fp["theme"] = m.group(1)

        for fw, signs in FRAMEWORK_SIGNS:
            for s in signs:
                if re.search(s, body, re.I):
                    fp["frameworks"].append(fw)
                    break

        # vendor-farming: plugins de vendors con CVEs pagos en su historial
        for p in plugins:
            if any(v in p.lower() for v in KNOWN_VENDORS):
                fp["vendors"].append(p)
        return fp

    # -------------------------------------------------------- scoring

    @staticmethod
    def score_target(url: str, param: str) -> Tuple[int, str]:
        """Puntaje 0-20 + razon humana. >=8 vale sondas completas."""
        path = (urlparse(url).path or "").lower()
        p = param.lower()
        if JUNK_PARAMS.match(p) or STATIC_EXT.search(path):
            return 0, "tracking/asset: no se gastan sondas"
        score, why = 0, []
        for kw, w in PATH_WEIGHTS.items():
            if re.search(rf"(^|[/_\-.]){re.escape(kw)}([/_\-.]|$)", path):
                score += w
                why.append(f"path:{kw}({w})")
                break
        for kw, w in PARAM_WEIGHTS.items():
            if p == kw or p.endswith("_" + kw) or p.startswith(kw + "_"):
                score += w
                why.append(f"param:{kw}({w})")
                break
        if "ajax" in path and p in ("action", "nonce"):
            score = max(score, 10)
        score = min(score, 20)
        return score, " + ".join(why) if why else "generico"

    # ----------------------------------------------------- presupuesto

    @staticmethod
    def budget_for(score: int) -> int:
        if score >= 8:
            return 14          # sondas completas (toda la bateria)
        if score >= 4:
            return 8           # reducida
        return 3               # minima: solo descarte rapido

    # -------------------------------------------------------------- run

    def run(self, url: str, spider_out: Dict[str, Any]) -> Dict[str, Any]:
        self.emit("[brain] === CEREBRO: fingerprint + priorizacion de la caza ===")
        fp = self.fingerprint(url)

        # --- reporte del fingerprint
        if fp["cms"]:
            self.emit(f"[brain] CMS detectado: {fp['cms']}"
                      + (f" · theme {fp['theme']}" if fp["theme"] else ""))
        if fp["plugins"]:
            self.emit(f"[brain] plugins ({len(fp['plugins'])}): "
                      + ", ".join(fp["plugins"][:10])
                      + (" ..." if len(fp["plugins"]) > 10 else ""))
        if fp["vendors"]:
            self.emit("[brain] 💥 vendor con historial de CVEs detectado: "
                      + ", ".join(fp["vendors"])
                      + " · priorizar handlers AJAX de ese plugin")
        if fp["frameworks"]:
            self.emit(f"[brain] frameworks: {', '.join(sorted(set(fp['frameworks'])))}")
        if fp["server"]:
            self.emit(f"[brain] servidor: {fp['server']}")

        # --- ranking de objetivos
        scored = []
        for t in spider_out.get("param_targets", []):
            s, why = self.score_target(t.get("url", ""), t.get("param", ""))
            if s == 0:
                continue
            scored.append({**t, "score": s, "why": why,
                           "budget": self.budget_for(s)})
        scored.sort(key=lambda x: -x["score"])

        total = len(spider_out.get("param_targets", []))
        self.emit(f"[brain] {total} objetivos crudos -> {len(scored)} con valor "
                  f"({total - len(scored)} descartados como tracking/assets)")
        for t in scored[:6]:
            self.emit(f"[brain]   [{t['score']:2d}] {t['param']} en "
                      f"{urlparse(t['url']).path or '/'} · {t['why']}")
        if scored:
            self.emit(f"[brain] cola ordenada por valor; presupuesto max "
                      f"{scored[0]['budget']} sondas para el lider")

        return {"fingerprint": fp, "ranked_targets": scored}
