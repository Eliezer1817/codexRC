"""VERITAS: verificacion de XSS con navegador real (Chrome headless).

La reflexion puede mentir: el servidor refleja el marcador, pero el
navegador real lo sanea, lo escapa, lo mata el CSP o nunca llega a un
sink ejecutable. VERITAS no cree en reflexiones: re-lanza cada candidato
con un CANARIO INERTE (solo cambia document.title, nada visible, nada
que exfiltre, no modifica datos) dentro de Chrome headless y mira si el
DOM final contiene el canario en <title>. Si ejecuto -> confirmado. Si
no -> era un falso positivo y baja de gravedad.

Herramienta general de auditoria con autorizacion previa del operador."""
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


def _find_browser() -> Optional[str]:
    """Busca un navegador Chromium ejecutable en cualquier plataforma:
    Linux (chrome/chromium), Windows (chrome.exe/msedge.exe, rutas de
    instalacion), macOS (Google Chrome.app / Chromium.app)."""
    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "chrome", "msedge", "microsoft-edge"):
        p = shutil.which(name)
        if p:
            return p
    if sys.platform == "darwin":
        for p in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                  "/Applications/Chromium.app/Contents/MacOS/Chromium",
                  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                  os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")):
            if os.path.exists(p):
                return p
    if os.name == "nt":
        bases = [os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                 os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                 os.environ.get("LOCALAPPDATA", "")]
        names = [r"\Google\Chrome\Application\chrome.exe",
                 r"\Google\Chrome\Beta\Application\chrome.exe",
                 r"\Microsoft\Edge\Application\msedge.exe",
                 r"\Chromium\Application\chrome.exe"]
        for b in bases:
            for n in names:
                p = b + n
                if p and os.path.exists(p):
                    return p
    # Termux (Android): chromium del repo tur-test/termux-x11 vive en
    # $PREFIX/bin; normalmente ya esta en PATH pero lo aseguramos
    prefix = os.environ.get("PREFIX", "")
    if prefix:
        for n in ("chromium-browser", "chromium", "chrome"):
            p = os.path.join(prefix, "bin", n)
            if os.path.exists(p):
                return p
    return None


class Veritas:
    def __init__(self, log, timeout: float = 30.0, max_verify: int = 8):
        self.log = log
        self.timeout = timeout
        self.max_verify = max_verify
        self.chrome = _find_browser()

    def available(self) -> bool:
        return bool(self.chrome)

    # ------------------------------------------------------------------ --
    #  candidatos: solo reflexiones GET del corpus (en URL se puede re-lanzar
    #  con payload; formularios POST y DOM estatico quedan sin verificar)
    def _is_candidate(self, f: Dict[str, Any]) -> bool:
        return (f.get("method") == "GET"
                and "XSS" in (f.get("type") or "")
                and f.get("severity") in ("alta", "media")
                and not f.get("verificado"))

    def verify_all(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {"confirmados": 0, "descartados": 0, "sin_verificar": 0}
        if not self.available():
            self.log("[veritas] Chrome headless no disponible: los hallazgos "
                     "quedan como reflexiones sin verificar")
            return counts
        cands = [f for f in findings if self._is_candidate(f)][:self.max_verify]
        if not cands:
            self.log("[veritas] no hay candidatos verificables por URL")
            return counts
        self.log(f"[veritas] === VERITAS: {len(cands)} reflexiones -> navegador real "
                 f"(canario inerte document.title) ===")
        for f in cands:
            res = self._verify_one(f)
            if res is True:
                counts["confirmados"] += 1
            elif res is False:
                counts["descartados"] += 1
            else:
                counts["sin_verificar"] += 1
        self.log(f"[veritas] ══ VERDICTO: {counts['confirmados']} confirmados por "
                 f"ejecucion real · {counts['descartados']} falsos positivos "
                 f"descartados · {counts['sin_verificar']} sin verificacion tecnica")
        return counts

    # ------------------------------------------------------------------ --
    def _payloads(self, f: Dict[str, Any], m: str) -> List[str]:
        """Variantes de canario segun contexto y caracteres crudos que
        sobrevivieron la reflexion. Todas inertes: solo document.title."""
        raw = f.get("raw") or {}
        ctx = f.get("context") or "body"
        var: List[str] = []
        if ctx == "js":
            if raw.get("'"):
                var.append(f"';document.title='{m}';//")
            if raw.get('"'):
                var.append(f'";document.title="{m}";//')
            if raw.get("<") and raw.get(">"):
                var.append(f"'><script>document.title='{m}'</script>")
        else:  # body, tag, comentario, header
            if raw.get("<") and raw.get(">"):
                var.append(f"><script>document.title='{m}'</script>")
                var.append(f"<script>document.title='{m}'</script>")
            if raw.get('"'):
                var.append(f'" onerror="document.title=\'{m}\'" src="x')
                var.append(f'" autofocus onfocus="document.title=\'{m}\'')
            if raw.get("'") and not raw.get('"'):
                var.append(f"' onerror='document.title=\"{m}\"' src='x")
        return var[:3]

    @staticmethod
    def _set_param(url: str, param: str, value: str) -> str:
        p = urlparse(url)
        q = [(k, v) for k, v in parse_qsl(p.query) if k != param]
        q.append((param, value))
        return urlunparse(p._replace(query=urlencode(q)))

    def _dump(self, url: str) -> Optional[str]:
        """DOM serializado tras ejecutar el JS de la pagina (tiempo virtual
        garantiza que el script corra antes del volcado)."""
        profile = tempfile.mkdtemp(prefix="veritas_")
        try:
            r = subprocess.run(
                [self.chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
                 "--disable-dev-shm-usage", "--dump-dom",
                 "--virtual-time-budget=4000", f"--user-data-dir={profile}", url],
                capture_output=True, text=True, timeout=self.timeout)
            return r.stdout or None
        except Exception as exc:
            self.log(f"[veritas] navegador fallo: {str(exc)[:70]}")
            return None
        finally:
            shutil.rmtree(profile, ignore_errors=True)

    def _verify_one(self, f: Dict[str, Any]) -> Optional[bool]:
        """True = ejecuto (confirmado). False = no ejecuto (falso positivo).
        None = no se pudo verificar (red, timeout): dejar como estaba."""
        m = "vrt" + secrets.token_hex(4) + "x"
        base = f.get("target") or ""
        param = f.get("param") or ""
        if not base or not param:
            return None
        var = self._payloads(f, m)
        if not var:
            # sin datos de que caracteres sobreviven: no arriesgar un
            # descarte injusto; el hallazgo queda como estaba
            self.log(f"[veritas] {param} en {urlparse(base).path} → sin datos "
                     "de crudos: queda sin verificar (no se descarta)")
            return None
        for payload in var:
            url = self._set_param(base, param, payload)
            dom = self._dump(url)
            if dom is None:
                return None
            # el canario SOLO cuenta si aparecio en <title>: la reflexion
            # del payload contiene el mismo texto y no debe enganiar
            if re.search(rf"<title[^>]*>[^<]*{m}", dom):
                f["verificado"] = True
                f["severity"] = "alta"
                f["reason"] = (f.get("reason") or "") + \
                    " · CONFIRMADO: el canario ejecuto en Chrome headless"
                self.log(f"🥳 [veritas] {param} en {urlparse(base).path} → "
                         f"EJECUTA de verdad (title canary: {m})")
                return True

        # ninguna variante ejecuto: falso positivo
        f["verificado"] = False
        f["descartado_fp"] = True
        f["severity"] = "baja"
        f["reason"] = (f.get("reason") or "") + \
            " · NO ejecuto en navegador real: falso positivo descartado"
        self.log(f"[veritas] {param} en {urlparse(base).path} → refleja pero "
                 "NO ejecuta: descartado (falso positivo)")
        return False
