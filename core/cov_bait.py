"""COV-BAIT v2: caza guiada por COBERTURA DE CODIGO + MOTOR DE MUTACION.

Etapa 1: medir cobertura por sonda (baseline, params ocultos, paginas).
Etapa 2 (nuevo): FUZZING CON FEEDBACK estilo XBOW:
  - corpus de inputs: arranca con la query de la semilla y los params
    ocultos que ejecutaron codigo nuevo en la etapa 1
  - mutaciones deterministas (añadir param, mutar valor, quitar param)
  - cada sonda se mide en el navegador: si EJECUTA rangos nuevos, el
    input entra al corpus como PADRE y las mutaciones siguen desde ahi
    (hill-climbing por cobertura)
  - presupuesto fijo de sondas + freno por estancamiento (12 sondas sin
    cobertura nueva = para) + anti-bucles (hash de inputs ya probados)
  - reporta las COMBINACIONES que desbloquean funciones escondidas,
    con los nombres de las funciones ejecutadas

Todo determinista: rng con semilla fija, resultados reproducibles.
Requisitos: navegador Chromium + websocket-client (python puro, Termux ok).
"""

import atexit
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import websocket            # websocket-client, python puro
    _HAS_WS = True
except Exception:
    _HAS_WS = False

COV_PARAMS = ["adminmode", "debug", "admin", "test", "dev", "internal",
              "preview", "staff", "full", "manage", "bypass", "role",
              "level", "mode", "state", "view", "type", "ver"]

MUT_VALUES = ["1", "0", "2", "-1", "true", "false", "null", "x",
              "admin", "test", "all", "999999", "1e309", "[]", "{}",
              "on", "yes", "god", "root", "master"]

COV_MUT_BUDGET = 36          # sondas de mutacion por caza
HINT_VALUES = ["1", "x", "true", "admin"]   # primeros valores por param pista
COV_MUT_STAGN = 12           # sondas sin ganancia antes de parar
EXT_BLACKLIST = (".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff")


def _find_browser() -> Optional[str]:
    for name in ("google-chrome", "google-chrome-stable", "chromium",
                 "chromium-browser", "chrome", "msedge"):
        p = shutil.which(name)
        if p:
            return p
    if os.name == "nt":
        base = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        for n in (r"\Google\Chrome\Application\chrome.exe",):
            if os.path.exists(base + n):
                return base + n
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
             "--disable-dev-shm-usage", "--disable-extensions",
             "--disable-background-networking", "--disable-sync",
             "--no-first-run", "--disable-translate", "--mute-audio",
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

    def _probe(self, url: str, settle: float = 0.6) -> Set[Tuple]:
        """Navega a la sonda y devuelve SU cobertura (arranca de cero)."""
        self.cdp.call("Profiler.startPreciseCoverage",
                      {"callCount": True, "detailed": False})
        try:
            self.cdp.call("Page.navigate", {"url": url})
        except Exception:
            pass
        time.sleep(settle)
        return self._snapshot()

    def _url_with(self, base_url: str, params: Dict[str, str]) -> str:
        p = urllib.parse.urlparse(base_url)
        return urllib.parse.urlunparse(p._replace(
            query=urllib.parse.urlencode(params)))

    @staticmethod
    def _ihash(params: Dict[str, str]) -> int:
        return hash(frozenset(params.items()))

    @staticmethod
    def _fnames(new: Set[Tuple]) -> List[str]:
        seen, out = set(), []
        for (u, f, _s, _e) in sorted(new):
            if f not in seen:
                seen.add(f)
                out.append(f)
        return out

    # -------------------------------------------- etapa 2: mutacion

    def _mutate(self, parent: Dict[str, str],
                rng: random.Random) -> Dict[str, str]:
        op, child = rng.random(), dict(parent)
        if not child or op < 0.5:                 # añadir param
            child[rng.choice(COV_PARAMS)] = rng.choice(MUT_VALUES)
        elif op < 0.85:                           # mutar valor
            k = rng.choice(list(child))
            child[k] = rng.choice(MUT_VALUES)
        else:                                     # quitar param
            child.pop(rng.choice(list(child)), None)
        return child

    def _param_hints(self, base_url: str,
                     seen: Set[Tuple]) -> List[str]:
        """Pistas de nombres de params LEIDOS del propio JS de la app.

        Feedback real: el codigo dice que params mira (URLSearchParams.get,
        getParameter, query['x']). Sondeo esos primero = hill-climbing
        informado en vez de mutar a ciegas.
        """
        sources = sorted({u for (u, _f, _s, _e) in seen
                           if u != "(inline)" and u.startswith("http")})
        sources.insert(0, base_url)
        hints: List[str] = []
        for su in sources:
            try:
                r = self.session.get(su, timeout=8)
                src = r.text or ""
            except Exception:
                continue
            for m in re.findall(
                    r'(?:\.get|getParameter|params)\(\s*["\']'
                    r'([\w\-]{2,30})["\']\s*\)', src):
                if m not in hints:
                    hints.append(m)
        return hints[:12]

    def _mutation_run(self, base_url: str, corpus: List[Dict[str, str]],
                      seen: Set[Tuple]) -> Tuple[List[Dict[str, Any]],
                                                 Set[Tuple]]:
        findings: List[Dict[str, Any]] = []
        tried = {self._ihash(c) for c in corpus}
        probes = 0
        hints = self._param_hints(base_url, seen)
        self.emit(f"[cov2] motor de mutacion: {len(corpus)} padre(s), "
                  f"pistas del codigo: {hints[:8]}"
                  + ("" if len(hints) <= 8 else " ..."))

        # fase A: expansión estructurada guiada por pistas (BFS con
        # prioridad a los padres mas profundos recien descubiertos)
        queue = list(reversed(corpus[1:])) or [corpus[0]]
        expanded = set()
        while probes < COV_MUT_BUDGET and queue:
            parent = queue.pop(0)
            ph = self._ihash(parent)
            if ph in expanded:
                continue
            expanded.add(ph)
            cand = [p for p in dict.fromkeys(hints + COV_PARAMS)
                    if p not in parent]
            for param in cand:
                gained = False
                for v in HINT_VALUES:
                    if probes >= COV_MUT_BUDGET:
                        break
                    child = {**parent, param: v}
                    h = self._ihash(child)
                    if h in tried:
                        continue
                    tried.add(h)
                    probes += 1
                    cov = self._probe(self._url_with(base_url, child))
                    new = cov - seen
                    if not new:
                        continue
                    seen |= cov
                    corpus.append(child)
                    queue.insert(0, child)       # profundizar desde aqui
                    names = self._fnames(new)[:6]
                    findings.append({
                        "type": "Mutacion EJECUTA codigo nuevo",
                        "severity": "alta" if len(new) >= 2 else "media",
                        "target": self._url_with(base_url, child),
                        "param": "&".join(f"{k}={v}" for k, v in child.items()),
                        "evidence": f"input {child} ejecuta {len(new)} "
                                    "rango(s) de JS que la app nunca "
                                    "ejecuto antes: " + ", ".join(names),
                        "verdict": "confirmado por cobertura en navegador",
                    })
                    self.emit(f"[cov2] 💥 sonda {probes}: {child} → "
                              f"+{len(new)} rangos: {'/'.join(names[:3])}")
                    gained = True
                    break
                if probes >= COV_MUT_BUDGET:
                    break

        # fase B: mutacion aleatoria con el presupuesto restante
        rng = random.Random(1337)
        stagnation = 0
        while probes < COV_MUT_BUDGET and stagnation < COV_MUT_STAGN:
            idx = len(corpus) - 1 if rng.random() < 0.6 \
                else rng.randrange(len(corpus))
            child = self._mutate(corpus[idx], rng)
            h = self._ihash(child)
            if h in tried:
                continue
            tried.add(h)
            probes += 1
            cov = self._probe(self._url_with(base_url, child))
            new = cov - seen
            if not new:
                stagnation += 1
                continue
            stagnation, _ = 0, None
            seen |= cov
            corpus.append(child)
            names = self._fnames(new)[:6]
            findings.append({
                "type": "Mutacion EJECUTA codigo nuevo",
                "severity": "alta" if len(new) >= 2 else "media",
                "target": self._url_with(base_url, child),
                "param": "&".join(f"{k}={v}" for k, v in child.items()),
                "evidence": f"input {child} ejecuta {len(new)} rango(s) "
                            "de JS que la app nunca ejecuto antes: "
                            + ", ".join(names),
                "verdict": "confirmado por cobertura en navegador",
            })
            self.emit(f"[cov2] 💥 sonda {probes}: {child} → +{len(new)} "
                      f"rangos: {'/'.join(names[:3])}")

        self.emit(f"[cov2] mutacion terminada: {probes} sondas, "
                  f"{len(findings)} desbloqueo(s)")
        return findings, seen

    # -------------------------------------------------------------- run

    def run(self, url: str, spider_out: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.emit("[cov] === COV-BAIT: cobertura + mutacion ===")
        findings: List[Dict[str, Any]] = []
        if not self._start():
            return findings
        try:
            base_url = url.split("?")[0]
            if base_url.lower().endswith(EXT_BLACKLIST):
                self.emit("[cov] la semilla es un asset: se salta")
                return findings

            # 1) baseline: la cobertura "publica" de la app
            seen = self._probe(url, settle=1.2)
            self.emit(f"[cov] baseline: {len(seen)} rangos de codigo publicos")

            qs = dict(urllib.parse.parse_qsl(
                urllib.parse.urlparse(url).query))
            corpus: List[Dict[str, str]] = [dict(qs)] if qs else [{}]
            tried_hidden = set(qs)

            # 2) params ocultos simples: ¿ejecutan codigo nuevo?
            for param in COV_PARAMS:
                if param in tried_hidden or len(corpus) > 8:
                    continue
                probe_params = {**qs, param: "1"}
                cur = self._probe(self._url_with(base_url, probe_params))
                new = cur - seen
                seen |= cur
                if not new:
                    continue
                corpus.append(probe_params)          # padre para mutar
                names = self._fnames(new)[:6]
                findings.append({
                    "type": "Parametro oculto EJECUTA codigo nuevo",
                    "severity": "alta",
                    "target": self._url_with(base_url, probe_params),
                    "param": param,
                    "evidence": f"{param}=1 ejecuta {len(new)} rango(s) de "
                                "JS que la app nunca ejecuto antes: "
                                + ", ".join(names),
                    "verdict": "confirmado por cobertura en navegador",
                })
                self.emit(f"[cov] 💥 {param}=1 EJECUTA codigo nuevo "
                          f"({len(new)} rangos): {'/'.join(names[:3])}")

            # 3) paginas descubiertas: cobertura de paginas enteras
            pages = spider_out.get("pages") or []
            checked = 0
            for pg in pages:
                if checked >= 5:
                    break
                u = pg if isinstance(pg, str) else pg.get("url", "")
                if not u or u.split("?")[0] == base_url or \
                        u.lower().endswith(EXT_BLACKLIST):
                    continue
                checked += 1
                cur = self._probe(u, settle=1.0)
                new = cur - seen
                seen |= cur
                if len(new) >= 3:
                    names = self._fnames(new)[:6]
                    findings.append({
                        "type": "Pagina con caminos de codigo propios",
                        "severity": "media", "target": u, "param": "-",
                        "evidence": f"esta pagina ejecuta {len(new)} rangos "
                                    "de JS nuevos: " + ", ".join(names),
                        "verdict": "mapeado por cobertura",
                    })

            # 4) ETAPA 2: mutacion con feedback sobre el corpus
            mut_findings, seen = self._mutation_run(base_url, corpus, seen)
            findings.extend(mut_findings)

            # resumen de cobertura final
            self.emit(f"[cov] cobertura total mapeada: {len(seen)} rangos; "
                      f"{len(findings)} camino(s) escondido(s)")
        finally:
            self.stop()
        self.emit(f"[cov] === COV-BAIT: {len(findings)} hallazgo(s) ===")
        return findings
