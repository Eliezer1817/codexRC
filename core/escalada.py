"""ESCALADA: que hacer DESPUES del aviso critico.

El CHAIN (v0.28) dice "tenes una cadena critica" y ahi se quedaba: el
operador se quedaba en el blanco sin saber el siguiente paso. ESCALADA
(v0.38) continua solo, con reglas deterministas y canarios inertes:

  PASO A - VERITAS DIRIGIDO: re-verifica en navegador real SOLO las
           piezas XSS de la cadena (las que armaron el caso), no todo.
  PASO B - TECHO DE IMPACTO: pide el blanco con la sesion heredada y
           revisa las flags de las cookies: sin HttpOnly + XSS
           ejecutable = camino a HIJACK de sesion (el techo).
  PASO C - KIT PoC: genera la pagina atacante LOCAL (poc/<host>.html)
           con iframe + hash canario + postMessage canario. El operador
           la abre en su maquina y VE si la cadena aterriza. Canariz
           inerte: banner visible, cero exfiltracion.
  PASO D - PLAYBOOK: pasos ordenados que faltan, segun las piezas que
           tenga la cadena (persistencia, admins, reporte).

Todo es lectura y render inerte: nada de datos reales, nada sale del
equipo del operador. Si no hay cadenas criticas, no corre.
"""

import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.deep_scan import cookie_flags

CANARY_JS = "document.title='CANARY_ESCALADA_OK'"
CANARY_BANNER = ("<div style='background:#0f0;color:#000;font:bold 18px "
                 "monospace;padding:6px'>CANARY_ESCALADA_OK</div>")


def _session_cookie_names() -> set:
    return {"phpsessid", "session", "sess", "sid", "jsessionid", "asp.net_"
            "sessionid", "laravel_session", "wordpress_logged_in",
            "auth", "token", "jwt"}


class Escalador:
    def __init__(self, emit, session=None, timeout: float = 15.0):
        self.emit = emit or (lambda m: None)
        self.session = session
        self.timeout = timeout

    # ------------------------------------------------------------------ A
    def _veritas_dirigido(self, url: str, findings: List[Dict[str, Any]]) -> dict:
        """Re-verifica en navegador real SOLO las piezas XSS de la cadena."""
        out = {"available": False, "confirmed": 0, "checked": 0}
        try:
            from core.veritas import Veritas
            ver = Veritas(self.emit, timeout=30.0, max_verify=4)
            if not ver.available():
                out["note"] = "Chrome no disponible en este entorno"
                return out
            out["available"] = True
            piezas = [f for f in findings
                      if "xss" in f.get("type", "").lower()
                      or "postmessage" in f.get("type", "").lower()]
            # piezas DOM (location.hash): canario <img onerror> en el fragmento;
            # por innerHTML los <script> NO ejecutan, el onerror si.
            dom = [f for f in piezas
                   if "hash" in str(f.get("param", "")).lower()
                   or "dom" in f.get("type", "").lower()]
            reflejadas = [f for f in piezas if f not in dom]
            checked = confirmed = 0
            for f in dom:
                canary = ("<img src=x onerror=\""
                          f"document.title='{CANARY_JS.split('=')[-1].strip(chr(39))}'"
                          "\">")
                probe = f"{url}#{canary}"
                dump = ver._dump(probe)
                checked += 1
                if dump and "CANARY_ESCALADA_OK" in dump:
                    confirmed += 1
                    f["verificado"] = True
                    self.emit(f"[escalada] 💥 pieza DOM CONFIRMADA en "
                              "navegador real (canario inerte ejecuto)")
            if reflejadas:
                res = ver.verify_all(reflejadas)
                confirmed += res.get("confirmados", 0)
                checked += res.get("checked", len(reflejadas)) if isinstance(
                    res.get("checked"), int) else 0
            if not piezas:
                out["note"] = "la cadena no tiene piezas XSS que verificar"
                return out
            out["checked"] = checked
            out["confirmed"] = confirmed
        except Exception as exc:                       # aislado: nunca tumba
            out["note"] = f"veritas aislado: {str(exc)[:120]}"
        return out

    # ------------------------------------------------------------------ B
    def _techo_httponly(self, url: str) -> dict:
        """Flags de cookies del blanco con la sesion heredada."""
        out = {"checked": False, "hijack_path": None, "cookies": []}
        if self.session is None:
            out["note"] = "sin sesion heredada: sin chequeo de cookies"
            return out
        try:
            r = self.session.get(url, timeout=self.timeout,
                                 allow_redirects=True, verify=False)
            flags = cookie_flags(dict(r.headers))
            names = _session_cookie_names()
            for c in flags:
                cname = str(c.get("name", "")).lower()
                es_sesion = (any(n in cname for n in names)
                             or not c.get("httponly", False)
                             and cname)
                out["cookies"].append({
                    "name": c.get("name"), "httponly": bool(c.get("httponly")),
                    "secure": bool(c.get("secure")),
                    "samesite": c.get("samesite")})
                if es_sesion and not c.get("httponly", False):
                    out["hijack_path"] = (
                        f"cookie '{c.get('name')}' SIN HttpOnly: un XSS "
                        "ejecutable la lee desde JS = robo de sesion")
        except Exception as exc:
            out["note"] = f"chequeo aislado: {str(exc)[:120]}"
        out["checked"] = True
        return out

    # ------------------------------------------------------------------ C
    def _kit_poc(self, url: str, chain: Dict[str, Any],
                 poc_dir: str) -> Optional[str]:
        """Pagina atacante LOCAL: iframe + hash canario + postMessage."""
        try:
            host = urlparse(url).netloc.replace(":", "_") or "blanco"
            path = os.path.join(poc_dir, f"poc_{host}.html")
            piezas = " | ".join(chain.get("parts", []))
            has_pm = "postmessage" in piezas.lower()
            has_dom = "dom" in piezas.lower() or "hash" in piezas.lower()
            pm_block = ""
            if has_pm:
                import json as _json
                banner_js = _json.dumps(CANARY_BANNER)
                pm_block = f"""
  // PIEZA postMessage: enviar el canario inerte al iframe (varias formas)
  function probePM() {{
    var f = document.getElementById('v');
    var shapes = [
      {banner_js},
      {{data: {banner_js}}},
      {{message: {banner_js}}},
      {{type: 'canary', data: {banner_js}}}
    ];
    shapes.forEach(function (s, i) {{
      setTimeout(function () {{
        try {{ f.contentWindow.postMessage(s, '*'); }} catch (e) {{}}
      }}, 800 * (i + 1));
    }});
  }}
  probePM();
"""
            if has_dom:
                import html as _html
                payload = ('<img src=x onerror="'
                           f"document.title='CANARY_ESCALADA_OK'" '">')
                hash_line = (f'<p>2. <a href="{url}#'
                             f'{_html.escape(payload, quote=True)}" '
                             f'target="_blank">link con hash canario '
                             f"inerte</a> (abrir logueado)</p>")
            else:
                hash_line = ""
            html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Kit PoC - {host}</title></head>
<body style="font-family:monospace;background:#000;color:#0f0;padding:12px">
<h3>KIT PoC LOCAL - {host}</h3>
<p>Cadena: <b>{chain.get('name', '?')}</b> ({piezas})</p>
<p>Canario inerte: si ves <b>CANARY_ESCALADA_OK</b> dentro del sitio en el
iframe de abajo, la cadena aterriza. Nada sale de tu maquina.</p>
<p>1. iframe del blanco con sesion propia (logueate en otra pestana primero):</p>
<iframe id="v" src="{url}" style="width:100%;height:480px;background:#fff"></iframe>
{hash_line}
<p>3. Al abrir el iframe o el link, buscar el banner verde
<b>CANARY_ESCALADA_OK</b> dentro de la pagina del sitio.</p>
<script>
{pm_block}
</script>
</body></html>"""
            os.makedirs(poc_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(html)
            return path
        except Exception as exc:
            self.emit(f"[escalada] kit PoC aislado: {str(exc)[:120]}")
            return None

    # ------------------------------------------------------------------ D
    def _playbook(self, chain: Dict[str, Any], veritas: dict,
                  techo: dict, poc_path: Optional[str]) -> List[str]:
        pasos: List[str] = []
        piezas = " ".join(chain.get("parts", [])).lower()
        if veritas.get("available") and veritas.get("confirmed"):
            pasos.append("VERIFICADO en navegador real: la pieza XSS "
                         "ejecuto con canario inerte.")
        elif veritas.get("available"):
            pasos.append("VERITAS dirigido corrio y NO confirmo: revisar "
                         "si el sink requiere interaccion (click, scroll).")
        else:
            pasos.append("Correr VERITAS con Chrome disponible para "
                         "confirmar la ejecucion (hoy no estaba el navegador).")
        if techo.get("hijack_path"):
            pasos.append(f"TECHO ALCANZABLE: {techo['hijack_path']}. "
                         "Con eso la cadena es hijack de sesion = critico "
                         "probable.")
        elif techo.get("checked") and techo.get("cookies"):
            pasos.append("Cookies presentes con HttpOnly: el techo baja a "
                         "lectura de datos en sesion (API privada como la "
                         "victima).")
        elif techo.get("checked"):
            pasos.append("La peticion no devolvio Set-Cookie (sesion ya "
                         "activa): revisar la cookie a mano en DevTools -> "
                         "Application -> Cookies (columna HttpOnly). Sin "
                         "HttpOnly = camino a hijack; con HttpOnly = techo "
                         "en lectura de datos en sesion.")
        if poc_path:
            pasos.append(f"Abrir en TU maquina el kit PoC local: {poc_path} "
                         "- login en una pestana y ver si el canario "
                         "aterriza dentro del sitio.")
        if "postmessage" in piezas:
            pasos.append("Probar el canal sin click: iframe + postMessage "
                         "desde el kit PoC (convierte XSS con click en "
                         "sin click).")
        if "dom" in piezas or "hash" in piezas:
            pasos.append("Chequear persistencia: si un campo del perfil "
                         "(nombre/email) se refleja sin limpiar en /account, "
                         "el XSS pasa a almacenado = critico garantizado.")
        pasos.append("Con confirmacion, armar el informe (con aprobacion "
                     "del operador) y decidir destino: programa pagante o "
                     "divulgacion privada.")
        return pasos

    # ------------------------------------------------------------------
    def run(self, url: str, chains: List[Dict[str, Any]],
            findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        poc_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "poc")
        criticas = [c for c in chains
                    if str(c.get("severity", "")).lower() in
                    ("critica", "critical", "alta")]
        if not criticas:
            self.emit("[escalada] sin cadenas criticas: nada que escalar")
            return {"escalations": [], "poc_files": []}
        escalations = []
        poc_files = []
        for chain in criticas:
            self.emit(f"[escalada] ⚡ cadena '{chain.get('name', '?')}': "
                      "escalandola hasta el techo")
            veritas = self._veritas_dirigido(url, findings)
            self.emit(f"[escalada] VERITAS dirigido: {veritas.get('confirmed', 0)}"
                      f"/{veritas.get('checked', 0)} confirmadas"
                      + (f" ({veritas['note']})" if veritas.get("note") else ""))
            techo = self._techo_httponly(url)
            if techo.get("hijack_path"):
                self.emit(f"[escalada] 💥 TECHO: {techo['hijack_path']}")
                chain["severity"] = "critica"
            poc_path = self._kit_poc(url, chain, poc_dir)
            if poc_path:
                poc_files.append(poc_path)
                self.emit(f"[escalada] kit PoC local generado: {poc_path}")
            playbook = self._playbook(chain, veritas, techo, poc_path)
            escalations.append({
                "chain": chain.get("name", "?"),
                "veritas": veritas,
                "techo": {k: v for k, v in techo.items() if k != "cookies"},
                "cookies": techo.get("cookies", []),
                "poc": poc_path,
                "playbook": playbook,
                "verdict": ("HIJACK ALCANZABLE" if techo.get("hijack_path")
                            else "XSS EN SESION (leer API privada)"
                            if veritas.get("confirmed")
                            else "PENDIENTE DE CONFIRMACION"),
            })
        return {"escalations": escalations, "poc_files": poc_files}
