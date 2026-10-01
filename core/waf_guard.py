# -*- coding: utf-8 -*-
"""
codexRC - GHOST-SHIELD (evasion WAF con memoria, v0.24.0)
=========================================================
Capa de evasion del lado del COMPORTAMIENTO (no del payload). Los WAF
modernos castigan patrones de trafico antes que payloads sueltos; esta capa
hace tres cosas:

  1. JITTER: ninguna sonda sale con el mismo intervalo. Cada request duerme
     delay * uniforme(0.5, 1.8) antes de salir, rompiendo el patron de
     bot perfecto de intervalo fijo.

  2. DETECCION DE BLOQUEO: cada respuesta pasa por el clasificador. Firma
     dura (403/503 + WAF conocido o pagina de challenge) o blanda (429
     rate-limit). Ante bloqueo duro se sugiere GHOSTGATE en el log.

  3. COOLDOWN CON MEMORIA: el origen bloqueado entra en cooldown
     exponencial (30s * 2^n, tope 10 min) y el estado SE PERSISTE EN DISCO:
     la memoria de quien nos bloqueo sobrevive jobs, reinicios y dias.
     Mientras un origen esta en cooldown, sus sondas se saltan en vez de
     seguir martillando y quemando la IP. Cuando el WAF nos deja pasar de
     nuevo (respuesta sana), el exponente se resetea.

Arquitectura: la capa vive DENTRO de la sesion HTTP (GuardedSession), no en
cada bateria. Cualquier sonda del corpus que use la sesion (arana, GET,
forms, headers, XSS-PRO, IDOR, BLIND...) queda cubierta sin tocar su codigo.
El carril async (SLIPSTREAM) engancha el mismo WafGuard en sus sondas httpx.

Solo lectura: esta capa no altera payloads ni escribe en el blanco.
"""
import json
import random
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests


class CooldownActive(Exception):
    """El origen esta en cooldown WAF: la sonda se salta en vez de insistir."""


class WafGuard:
    """Clasificador + memoria de bloqueos por origen. Compatible con
    responses de requests y de httpx (misma interfaz status/headers/text)."""

    # firmas de challenge / WAF en el cuerpo (en minusculas)
    BODY_SIGS = (
        "just a moment", "checking your browser", "cf-chl", "cf_chl_",
        "attention required", "access denied", "sucuri", "captcha-delivery",
        "px-captcha", "blocked by the security", "im-under-attack",
        "ddos protection by", "security check", "verify you are human",
    )
    # cabeceras tipicas de WAF/CDN con challenge
    HDR_SIGS = ("cf-ray", "cf-mitigated", "x-sucuri-id", "x-waf",
                "server: cloudflare", "x-cdn: cloudflare")

    BURN_THRESHOLD = 4   # bloqueos duros seguidos -> origen quemado
    BURN_TTL = 3600.0    # purga: tras 1h quemado, el origen vuelve a tener chances

    def __init__(self, log, state_path: str = "waf_state.json",
                 hard_base: float = 30.0, soft_base: float = 15.0,
                 cooldown_cap: float = 600.0, max_wait: float = 45.0):
        self.log = log
        self.state_path = Path(state_path)
        self.hard_base = hard_base      # cooldown duro base (exponencial)
        self.soft_base = soft_base      # cooldown blando base (rate limit)
        self.cooldown_cap = cooldown_cap
        self.max_wait = max_wait       # espera maxima de una sonda antes de saltarse
        self._lock = threading.Lock()
        # origen -> {"blocks": n, "until": epoch, "last": "firma", "hits": n}
        self.state: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ---------- persistencia ----------
    def _load(self):
        try:
            if self.state_path.exists():
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                now = time.time()
                # no revivir cooldowns ya vencidos al arrancar
                self.state = {o: v for o, v in data.items()
                              if v.get("until", 0) > now or v.get("blocks", 0) > 0}
        except Exception:
            self.state = {}

    def _save(self):
        try:
            self.state_path.write_text(
                json.dumps(self.state, indent=1), encoding="utf-8")
        except Exception:
            pass  # la memoria es best-effort; la caza nunca muere por esto

    # ---------- clasificacion ----------
    @staticmethod
    def _origin(url: str) -> str:
        return urlparse(url).netloc.lower()

    def _classify(self, resp) -> Optional[str]:
        """None = respuesta normal. 'hard' = bloqueo WAF. 'soft' = rate limit."""
        try:
            code = resp.status_code
            body = (resp.text or "")[:4000].lower()
            hdrs = {k.lower(): (v or "").lower()
                    for k, v in resp.headers.items()}
            waf_seen = (any(s in body for s in self.BODY_SIGS)
                        or any(k in hdrs for k in ("cf-ray", "cf-mitigated",
                                                  "x-sucuri-id", "x-waf"))
                        or hdrs.get("server", "").startswith("cloudflare"))
            if code in (403, 503) and waf_seen:
                return "hard"
            if code == 429:
                return "soft"
            if code == 403 and any(s in body for s in self.BODY_SIGS):
                return "hard"
        except Exception:
            return None
        return None

    # ---------- api de sondas ----------
    def observe(self, url: str, resp) -> Optional[str]:
        """Llamar tras CADA respuesta. Registra bloqueo y programa cooldown.
        Respuestas sanas resetean el exponente del origen."""
        origin = self._origin(url)
        cls = self._classify(resp)
        with self._lock:
            st = self.state.setdefault(origin, {"blocks": 0, "until": 0.0,
                                               "last": "-", "hits": 0})
            if cls is None:
                was_hot = st.get("burned") or st["blocks"] >= self.BURN_THRESHOLD
                st["until"] = 0.0
                st["burned"] = False
                if was_hot:
                    self.log(f"[waf] {origin} responde sano otra vez · origen rehabilitado")
                elif st["blocks"] and st.get("hits", 0):
                    self.log(f"[waf] origen {origin} responde sano · memoria reseteada")
                st["blocks"] = 0
                return None
            st["blocks"] += 1
            st["hits"] += 1
            base = self.hard_base if cls == "hard" else self.soft_base
            cd = min(base * (2 ** min(st["blocks"], 6)), self.cooldown_cap)
            st["until"] = time.time() + cd
            st["last"] = f"{cls} · {getattr(resp, 'status_code', '?')}"
            self._save()
        if cls == "hard":
            self.log(f"[waf] 💥 WAF BLOQUEO a {origin} · cooldown {cd:.0f}s "
                     f"(intento {st['blocks']}) · si persiste tras el cooldown: "
                     f"GHOSTGATE (navegador real, IP limpia)")
            if st["blocks"] >= self.BURN_THRESHOLD:
                st["burned"] = True
                st["burned_at"] = time.time()
                self._save()
                self.log(f"[waf] 🚨 {origin} QUEMADO tras {st['blocks']} bloqueos: "
                         f"el Hunter descarta este origen (sondas instantaneamente "
                         f"saltadas). GHOSTGATE o cambiar de IP para volver a entrar.")
        else:
            self.log(f"[waf] rate-limit (429) en {origin} · pausa {cd:.0f}s")
        return cls

    def cooldown_left(self, url: str) -> float:
        with self._lock:
            st = self.state.get(self._origin(url))
            if not st:
                return 0.0
            return max(0.0, st.get("until", 0.0) - time.time())

    def hold(self, url: str, max_wait: Optional[float] = None) -> bool:
        """ANTES de cada sonda. Espera el cooldown (hasta max_wait). True =
        adelante; False = seguiria en cooldown, mejor saltarse."""
        with self._lock:
            st = self.state.get(self._origin(url))
            if st and st.get("burned"):
                # purga cumplida: el origen merece otra oportunidad
                if time.time() - st.get("burned_at", 0) > self.BURN_TTL:
                    st["burned"] = False
                    st["blocks"] = 0
                    st["until"] = 0.0
                    self._save()
                    self.log(f"[waf] purga cumplida: {self._origin(url)} vuelve a tener chances")
                else:
                    return False   # origen quemado: saltar sin esperar nada
        left = self.cooldown_left(url)
        if left <= 0:
            return True
        wait = min(left, max_wait if max_wait is not None else self.max_wait)
        if wait > 0:
            time.sleep(wait)
        return self.cooldown_left(url) <= 0

    def skip_reason(self, url: str) -> Optional[str]:
        left = self.cooldown_left(url)
        return f"origen en cooldown WAF ({left:.0f}s)" if left > 0 else None


class GuardedSession(requests.Session):
    """Sesion HTTP con GHOST-SHIELD dentro: jitter antes de cada request,
    clasificacion despues de cada respuesta. Hereda cookies/cabeceras de la
    sesion original para no perder la autenticacion."""

    def __init__(self, guard: WafGuard, jitter: float = 0.15):
        super().__init__()
        self.guard = guard
        self.jitter = jitter

    @classmethod
    def wrap(cls, session: requests.Session, guard: WafGuard,
             jitter: float = 0.15) -> "GuardedSession":
        g = cls(guard, jitter)
        g.cookies.update(session.cookies)
        g.headers.update(session.headers)
        if getattr(session, "auth", None):
            g.auth = session.auth
        return g

    def request(self, method, url, *args, **kwargs):  # type: ignore[override]
        origin = self._origin(url)
        if not self.guard.hold(url):
            raise CooldownActive(
                f"origen {origin} en cooldown WAF "
                f"({self.guard.cooldown_left(url):.0f}s): sonda saltada")
        # jitter: intervalo aleatorio, nunca patron fijo de bot
        if self.jitter:
            time.sleep(self.jitter * random.uniform(0.5, 1.8))
        resp = super().request(method, url, *args, **kwargs)
        self.guard.observe(url, resp)
        return resp

    @staticmethod
    def _origin(url: str) -> str:
        return urlparse(str(url)).netloc.lower()
