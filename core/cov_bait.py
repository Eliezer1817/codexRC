"""COV-BAIT: caza guiada por COBERTURA DE CODIGO en el navegador real.

La idea mas dificil del arsenal: en vez de mirar solo respuestas HTTP,
enchufamos Chrome via CDP (protocolo de depuracion) y medimos QUE
FUNCIONES de JavaScript ejecuta cada sonda. Si una sonda ejecuta codigo
que nadie ejecuto antes, encontro un CAMINO ESCONDIDO de la app.

Etapa 1 (esta version): medir cobertura por sonda.
  - Profiler.startPreciseCoverage: rangos de codigo ejecutados con conteo
  - baseline: navegacion a la semilla = cobertura "publica"
  - sondas: cada URL objetivo y cada parametro oculto (adminmode, debug...)
    reporta SOLO las funciones NUEVAS ejecutadas por primera vez
  - un parametro oculto que EJECUTA codigo nuevo es muchisima senal mas
    fuerte que una reaccion de tamaño/status

Etapa 2 (futuro): mutar inputs para maximizar cobertura nueva (fuzzing
con feedback, estilo XBOW).

Requisitos: navegador Chromium (el mismo que VERITAS) + websocket-client
(python puro: sirve en Termux). Sin navegador: se salta con aviso, la
caza sigue.
"""

import atexit
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import websocket            # websocket-client, python puro
    _HAS_WS = True
except Exception:
    _HAS_WS = False

COV_PARAMS = ["adminmode", "debug", "admin", "test", "dev", "internal",
              "preview", "staff", "full", "manage", "bypass", "role"]

EXT_BLACKLIST = (".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff")


def _find_browser() -> Optional[str]:
    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "chrome", "msedge"):
        p = shutil.which(name)
        if p:
            return p
    if os.name == "nt":
        for b in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                  os.environ.get("LOCALAPPDATA", "")):
            for n in (r"\Google\Chrome\Application\chrome.exe",):
                if b and os.path.exists(b + n):
                    return b + n
    return None


class _CDP:
    """Cliente CDP minimo: JSON-RPC sobre websocket."""

    def __init__(self, ws_url: str):
        self.ws = websocket.create_connection(ws_url, timeout=20,
                                            suppress_origin=True)
        self._id = 0

    def call(self, method: str, params: Dict[str, Any] = None,
             timeout: float = 12) -> Dict[str, Any]:
        self._id += 1
        rid = self._id
        self.ws.send(json.dumps({"id": rid, "method": method,
                                 "params": params or {}}))
        end = time.time() + timeout
        while time.time() < end:
            try:
                self.ws.settimeout(max(0.5, end - time.time()))
                msg = json.loads(self.ws.recv())
            except Exception:
                continue
            if msg.get("id") == rid:
                return msg.get("result", {})
        raise TimeoutError(f"CDP {method}")

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


class CovBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)
        self.proc: Optional[subprocess.Popen] = None
        self.cdp: Optional[_CDP] = None
        self.port = 0
        atexit.register(self.stop)

    # --------------------------------------------------- navegador

    def _start(self) -> bool:
        if not _HAS_WS:
            self.emit("[cov] sin websocket-client: pip install websocket-client")
            return False
        browser = _find_browser()
        if not browser:
            self.emit("[cov] sin navegador Chromium: COV-BAIT se salta")
            return False
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.tmp = tempfile.mkdtemp(prefix="cov_profile_")
        self.proc = subprocess.Popen(
            [browser, "--headless=new", "--no-sandbox", "--disable-gpu",
             f"--remote-debugging-port={self.port}",
             f"--user-data-dir={self.tmp}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(30):                       # esperar al DevTools
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{self.port}/json", timeout=2) as r:
                    targets = json.loads(r.read())
                break
            except Exception:
                time.sleep(0.4)
        else:
            self.emit("[cov] el navegador no levanto DevTools")
            self.stop()
            return False
        page = next((t for t in targets if t.get("type") == "page"), None)
        if not page or not page.get("webSocketDebuggerUrl"):
            self.stop()
            return False
        self.cdp = _CDP(page["webSocketDebuggerUrl"])
        self.cdp.call("Page.enable")
        self.cdp.call("Profiler.enable")
        self.emit(f"[cov] navegador instrumentado via CDP (puerto {self.port})")
        return True

    def stop(self):
        try:
            if self.cdp:
                self.cdp.close()
        except Exception:
            pass
        if self.proc:
            try:
                self.proc.kill()
            except Exception:
                pass
        shutil.rmtree(getattr(self, "tmp", ""), ignore_errors=True)
        self.proc, self.cdp = None, None

    # --------------------------------------------------- cobertura

    def _snapshot(self) -> Set[Tuple[str, str, int, int]]:
        res = self.cdp.call("Profiler.takePreciseCoverage")
        cov: Set[Tuple[str, str, int, int]] = set()
        for script in res.get("result", []):
            url = script.get("url") or "(inline)"
            for fn in script.get("functions", []):
                for r in fn.get("ranges", []):
                    if r.get("count", 0) > 0:
                        cov.add((url, fn.get("functionName") or "(anon)",
                                 r.get("startOffset", 0),
                                 r.get("endOffset", 0)))
        return cov

    def _probe(self, url: str, settle: float = 0.8) -> Set[Tuple]:
        """Navega a la sonda y devuelve SU cobertura (arranca de cero)."""
        self.cdp.call("Profiler.startPreciseCoverage",
                      {"callCount": True, "detailed": False})
        try:
            self.cdp.call("Page.navigate", {"url": url})
        except Exception:
            pass
        time.sleep(settle)
        return self._snapshot()

    def _diff(self, current: Set[Tuple],
              seen: Set[Tuple]) -> Tuple[List[Dict[str, Any]], int]:
        new = current - seen
        funcs = [{"function": f, "script": u} for (u, f, _s, _e) in sorted(new)]
        return funcs, len(new)

    # -------------------------------------------------------------- run

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[cov] === COV-BAIT: cobertura de codigo por sonda ===")
        findings: List[Dict[str, Any]] = []
        if not self._start():
            return findings
        try:
            base_page = url.split("?")[0]
            if base_page.lower().endswith(EXT_BLACKLIST):
                self.emit("[cov] la semilla es un asset: se salta")
                return findings

            # 1) baseline: la cobertura "publica" de la app
            seen = self._probe(url, settle=1.2)
            self.emit(f"[cov] baseline: {len(seen)} rangos de codigo publicos")

            # 2) parametros ocultos sobre la semilla: ¿ejecutan codigo nuevo?
            import urllib.parse as up
            p = up.urlparse(url)
            qs = dict(up.parse_qsl(p.query))
            for param in COV_PARAMS:
                if param in qs:
                    continue
                probe = up.urlunparse(p._replace(
                    query=up.urlencode({**qs, param: "1"})))
                cur = self._probe(probe)
                funcs, n = self._diff(cur, seen)
                seen |= cur
                if n > 0:
                    names = [f["function"] for f in funcs[:6]]
                    findings.append({
                        "type": "Parametro oculto EJECUTA codigo nuevo",
                        "severity": "alta", "target": probe, "param": param,
                        "evidence": f"{param}=1 ejecuta {n} rango(s) de JS "
                                     f"que la app nunca ejecuto antes: "
                                     + ", ".join(names),
                        "verdict": "confirmado por cobertura en navegador",
                    })
                    self.emit(f"[cov] 💥 {param}=1 EJECUTA codigo nuevo "
                              f"({n} rangos): {'/'.join(names[:3])}")

            # 3) URLs descubiertas: cobertura de paginas enteras
            pages = spider_out.get("pages") or []
            checked = 0
            for pg in pages:
                if checked >= 5:
                    break
                u = pg if isinstance(pg, str) else pg.get("url", "")
                if not u or u.split("?")[0] == base_page or \
                        u.lower().endswith(EXT_BLACKLIST):
                    continue
                checked += 1
                cur = self._probe(u, settle=1.0)
                funcs, n = self._diff(cur, seen)
                seen |= cur
                if n >= 3:                    # pagina con logica propia nueva
                    names = [f["function"] for f in funcs[:6]]
                    findings.append({
                        "type": "Pagina con caminos de codigo propios",
                        "severity": "media", "target": u, "param": "-",
                        "evidence": f"esta pagina ejecuta {n} rangos de JS "
                                    "nuevos respecto del baseline: "
                                    + ", ".join(names),
                        "verdict": "mapeado por cobertura",
                    })
                    self.emit(f"[cov] 🧐 {u} trae {n} rangos de JS nuevos")
        finally:
            self.stop()
        n = len(findings)
        self.emit(f"[cov] === COV-BAIT: {n} camino(s) escondido(s) ===")
        return findings
