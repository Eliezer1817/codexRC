# -*- coding: utf-8 -*-
"""
codexRC - SLIPSTREAM (carril async, v0.23.0)
============================================
Segunda etapa del motor de velocidad OVERDRIVE. La bateria GET del corpus
(corpus/XSSHunter.test_params) disparada por un event loop: un SOLO hilo de
Python mantiene hasta `concurrency` sondas en vuelo simultaneamente via
I/O asincrono (httpx). En I/O de red el cuello de botella es el servidor,
no el CPU: el event loop no crea hilos ni cambia contexto, solo multiplexa
sockets, por lo que 64 sondas en vuelo pesan menos que 8 hilos y el
throughput sube de forma casi lineal hasta saturar al servidor objetivo.

Detalles que preservan la filosofia de la casa:
  * Sesion heredada: el AsyncClient nace con las cookies y cabeceras de la
    sesion autenticada del escaneo (caza logueada igual que siempre).
  * Marcadores inertes: mismas sondas de lectura, ningun payload funcional.
  * Politica de cortesia: cada tarea espera `delay` tras recibir respuesta
    (igual que el modo secuencial), pero las esperas se solapan, por lo que
    la tasa efectiva es `concurrency / delay`. En blancos delicados subir
    `delay` o bajar workers baja la tasa de forma predecible.
  * Fallback transparente: si httpx no esta disponible (p.ej. instalacion
    minima en Termux), test_params usa el camino clasico de hilos.
"""
import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.hunter import _norm


class AsyncLane:
    """Carril async de la bateria GET. Reutiliza los helpers de analisis del
    XSSHunter (contexto, veredicto, evidencia, findings) para que los
    hallazgos sean identicos a los del camino secuencial/de hilos."""

    def __init__(self, hunter, concurrency: Optional[int] = None):
        self.h = hunter
        conc = concurrency if concurrency is not None else hunter.workers * 8
        self.concurrency = max(4, min(int(conc), 64))
        # GHOST-SHIELD: si la sesion es vigilada, el carril async usa
        # el mismo WafGuard (misma memoria de bloqueos y cooldowns).
        from core.waf_guard import GuardedSession
        self.guard = hunter.session.guard if isinstance(
            hunter.session, GuardedSession) else None

    # ---------- sonda de un objetivo (logica identica a test_param) ----------
    async def _probe_one(self, client, sem, tgt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        h = self.h
        url, param = tgt["url"], tgt["param"]
        async with sem:
            try:
                if self.guard is not None:
                    # cooldown WAF: esperar (async) o saltar la sonda
                    left = self.guard.cooldown_left(url)
                    if left > 0:
                        if left > 45:
                            h.log(f"[xss] ⏭ {urlparse(url).path}?{param}= · "
                                  f"origen en cooldown WAF ({left:.0f}s), sonda saltada")
                            return None
                        await asyncio.sleep(left)
                mark = h._mark()
                r = await self._probe(client, url, param, mark)
                if r is None or mark not in (r or ""):
                    h.log(f"[xss] GET {urlparse(url).path}?{param}= · sin reflexion")
                    return None
                ctx = h._context(r, mark)

                mark2 = h._mark()
                r2 = await self._probe(client, url, param, mark2 + "'\"><")
                raw = {"'": False, '"': False, ">": False, "<": False}
                if r2 is not None:
                    j = r2.find(mark2)
                    if j >= 0:
                        tail = r2[j + len(mark2): j + len(mark2) + 4]
                        raw = {"'": tail.startswith("'"), '"': tail[1:2] == '"',
                               ">": tail[2:3] == ">", "<": tail[3:4] == "<"}

                gravedad, razon = h._verdict(ctx, raw)
                ev = h._evidence(r, mark)
                h.log(f"💥 [xss] GET {urlparse(url).path}?{param}= · REFLEJADA · "
                      f"contexto: {ctx} · crudos: " + "".join(c for c, ok in raw.items() if ok))
                return h._finding("XSS reflejado", _norm(url), param, "GET",
                                  gravedad, f"{razon} · contexto {ctx}", ev, ctx)
            except Exception as exc:
                h.log(f"[xss] XX {urlparse(url).path}?{param}= · async: {str(exc)[:60]}")
                return None
            finally:
                # cortesia/jitter: pausa por sonda con variacion aleatoria
                # (misma ley que GuardedSession.request)
                if h.delay:
                    import random as _rnd
                    mult = _rnd.uniform(0.5, 1.8) if self.guard is not None else 1.0
                    await asyncio.sleep(h.delay * mult)

    # ---------- GET async de un parametro ----------
    async def _probe(self, client, url: str, param: str, value: str) -> Optional[str]:
        parts = urlparse(url)
        q = [(k, v) for k, v in parse_qsl(parts.query) if k != param]
        q.append((param, value))
        target = urlunparse(parts._replace(query=urlencode(q)))
        r = await client.get(target)
        if self.guard is not None:
            self.guard.observe(url, r)
        return r.text

    # ---------- orquestacion ----------
    def run(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ejecuta la bateria GET en el carril async. Devuelve findings en
        el mismo formato que el camino clasico."""
        try:
            import httpx
        except ImportError:
            raise

        cookies = {c.name: c.value for c in self.h.session.cookies}
        headers = {k: v for k, v in self.h.session.headers.items()}
        self.h.log(f"[xss] SLIPSTREAM: carril async · {self.concurrency} sondas en vuelo")

        async def _main():
            async with httpx.AsyncClient(
                    cookies=cookies, headers=headers, timeout=self.h.timeout,
                    follow_redirects=True) as client:
                sem = asyncio.Semaphore(self.concurrency)
                tasks = [self._probe_one(client, sem, t) for t in targets]
                return [f for f in await asyncio.gather(*tasks) if f]

        return asyncio.run(_main())

