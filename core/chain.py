"""ENCADENAR HALLAZGOS: el valor real esta en las CADENAS, no en piezas.

Un XSS solo suele ser P3. Ese mismo XSS en un sitio con CSP debil es un
robo de sesion. Un IDOR con email + un endpoint de settings es un posible
account takeover. Patchstack y compañía pagan por IMPACTO COMBINADO.

Reglas deterministas sobre hallazgos YA verificados (corre tras VERITAS):
  1. XSS + CSP debil en el mismo blanco -> XSS ejecutable, sesion robable
  2. XSS + ruta admin mapeada -> el vector puede golpear al admin
  3. XSS almacenado/blind + panel admin -> captura de sesion de admin
  4. IDOR repetido en varios id -> filtracion MASIVA, no caso puntual
  5. IDOR con datos personales + endpoint settings/token -> encaminado a
     account takeover
  6. SQLi + panel admin en el blanco -> extraccion de credenciales
  7. SQLi + BAC en el mismo blanco -> doble via a datos privados

Las cadenas no tocan los hallazgos originales: se reportan aparte con su
propia severidad combinada y razon humana lista para el informe.
"""

from typing import Any, Dict, List

XSS_TYPES = ("XSS", "xss", "blind-xss", "dom-clobber", "proto-pollution",
             "mXSS", "dangling", "stored", "base-tag", "path-reflection",
             "postMessage", "script-src", "csp-bypass")


def _is_xss(f: Dict[str, Any]) -> bool:
    t = f.get("type", "")
    return ("xss" in t.lower()) or (t in XSS_TYPES and "csp" not in t)


def _is_csp_weak(f: Dict[str, Any]) -> bool:
    ev = (f.get("evidence") or "").lower()
    return "csp" in f.get("type", "").lower() or "unsafe-inline" in ev \
        or "csp debil" in str(f.get("verdict", "")).lower()


def _is_leak(f: Dict[str, Any]) -> bool:
    return "idor" in f.get("type", "").lower() or "bac" in f.get("type", "").lower()


def _is_sqli(f: Dict[str, Any]) -> bool:
    return bool(f.get("sqli")) or "sql" in f.get("type", "").lower()


def _mentions(f: Dict[str, Any], *kws: str) -> bool:
    hay = (f.get("evidence", "") + " " + str(f.get("verdict", ""))).lower()
    return any(k in hay for k in kws)


class Chainer:
    def __init__(self, emit):
        self.emit = emit or (lambda m: None)

    def run(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        chains: List[Dict[str, Any]] = []
        xss = [f for f in findings if _is_xss(f)]
        leaks = [f for f in findings if _is_leak(f)]
        sqli = [f for f in findings if _is_sqli(f)]
        csp_weak = [f for f in findings if _is_csp_weak(f)]
        admin = [f for f in findings
                 if "ruta protegida" in f.get("type", "").lower()
                 or "/admin" in f.get("target", "")]

        def add(name, severity, parts, reason):
            chains.append({"name": name, "severity": severity,
                           "parts": [p["type"] for p in parts],
                           "reason": reason})

        # Una cadena XSS solo es CRITICA si alguna pieza ejecuto en navegador
        # real (verificado por VERITAS o kit PoC). Sin confirmacion = teorica:
        # se reporta ALTA "pendiente de confirmar" (leccion vellius 02/10: el
        # sink location.hash->innerHTML nunca ejecuto pese al CSP ausente).
        xss_ok = any(p.get("verificado") for p in xss)
        if xss and csp_weak:
            pzs = xss[:2] + csp_weak[:1]
            if xss_ok:
                add("XSS ejecutable (CSP no lo frena)", "critica", pzs,
                    "El CSP permite inline y una pieza EJECUTO en navegador "
                    "real: el payload corre sin restricciones y el XSS deja "
                    "de ser teorico. Sesiones robables.")
                self.emit("[chain] 💥 XSS verificado + CSP debil = XSS ejecutable, sesion robable")
            else:
                # leccion xenpaid 02/10/2026: cadenas construidas sobre piezas
                # SIN verificar salieron "alta" y eran falsas (eco RSC + core-js).
                # Ahora: nombre HIPOTESIS + severidad media. Solo sube si VERITAS
                # o el kit PoC confirman ejecucion real.
                add("HIPOTESIS: XSS + CSP ausente (nada ha ejecutado)", "media", pzs,
                    "CSP ausente pero NINGUNA pieza XSS verificada en "
                    "navegador real (leccion vellius: sink DOM teorico que "
                    "nunca ejecuto; leccion xenpaid: el eco escapado de "
                    "Next.js/RSC refleja sin ejecutar). Es una hipotesis: "
                    "confirmar con VERITAS/kit PoC antes de reportar.")
                self.emit("[chain] XSS teorico + CSP debil = HIPOTESIS media "
                          "pendiente de VERITAS (no se reporta como hallazgo)")
        if xss and admin:
            pzs = xss[:1] + admin[:1]
            if xss_ok:
                add("XSS alcance a panel admin", "critica", pzs,
                    "Hay panel admin en el mismo blanco y el XSS EJECUTO: un "
                    "XSS dirigido (o ciego via GHOSTHOOK) puede capturar la "
                    "sesion del administrador.")
                self.emit("[chain] 💥 XSS verificado + panel admin = captura de sesion admin")
            else:
                add("HIPOTESIS: XSS + panel admin (pendiente verificar)", "media", pzs,
                    "Panel admin en el blanco con XSS SIN confirmar en "
                    "navegador: hipotesis hasta que VERITAS/kit PoC confirmen "
                    "ejecucion real (leccion xenpaid 02/10/2026).")
                self.emit("[chain] XSS teorico + panel admin = HIPOTESIS media pendiente de verificar")
        if sqli and admin:
            add("SQLi hacia el panel admin", "critica", sqli[:1] + admin[:1],
                "SQLi + panel en el mismo blanco: extraccion de credenciales "
                "de la base y toma de control del admin.")
            self.emit("[chain] 💥 SQLi + panel admin = credenciales extraibles, toma de control")
        if len(leaks) >= 2:
            ident = {f.get("evidence", "").split("identidad: ")[-1][:24]
                     for f in leaks if "identidad" in f.get("evidence", "")}
            if len(ident) >= 2:
                add("Filtracion MASIVA (IDOR generalizado)", "critica", leaks[:3],
                    "Se leyeron registros de varias identidades distintas: "
                    "no es un caso puntual, se pueden enumerar todos.")
                self.emit("[chain] 💥 IDOR en varias identidades = filtracion masiva")
        for lk in leaks:
            if _mentions(lk, "email", "phone", "card", "balance", "token", "password"):
                sensitive = [f for f in findings
                             if _mentions(f, "settings", "token", "password", "reset")
                             and f is not lk]
                if sensitive:
                    add("Filtracion con camino a account takeover", "critica",
                        [lk] + sensitive[:1],
                        "Datos privados al alcance + endpoints de settings/token "
                        "en el mismo blanco: encaminado a takeover de cuentas.")
                    self.emit("[chain] 💥 datos privados + endpoint sensible = camino a takeover")
                break
        if sqli and leaks:
            add("Doble via a datos privados", "alta", sqli[:1] + leaks[:1],
                "SQLi y BAC en el mismo blanco: dos caminos independientes "
                "hacia la informacion de usuarios.")

        for c in chains:
            self.emit(f"[chain] cadena '{c['name']}' · severidad combinada: {c['severity']}")
        if not chains:
            self.emit("[chain] sin cadenas combinables en esta caza")
        self.emit(f"[chain] === ENCADENADO: {len(chains)} cadena(s) ===")
        return chains
