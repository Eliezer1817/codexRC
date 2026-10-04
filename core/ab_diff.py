#!/usr/bin/env python3
# ============================================================
# codexRC - AB-DIFF universal (v0.68.0)
# ------------------------------------------------------------
# DIFF de sesiones para sitios NO-WordPress (el concepto de la
# capa 4 de AUTHZ-PROOF portado a cualquier web). Consume
# objetos Identity de REG-BOT: jamas sabe si la cuenta nacio
# en WP, Laravel, Django, Express o una app propia.
#
# Tres niveles (decision AUTOMATICA segun el blanco):
#   Nivel 1: registro libre -> sesiones ANON / A (duena de X) / B
#   Nivel 2: sin registro pero credenciales propias -> ANON / OWN
#   Nivel 3: nada -> ANON solo (fugas sin autenticacion)
#
# Relaciones (lo que hace el diff CONCLUYENTE):
#   A = propietario del objeto X (recursos descubiertos desde la
#       sesion de A, con los datos de A dentro)
#   B = usuario independiente
#   A->X permitido, B->X permitido   = evidencia BAC/IDOR
#   A->X permitido, B->X bloqueado   = gate correcto (REFUTADO)
#   ANON->X permitido                = DEMO-UNAUTH (lo mas grave)
#
# Reglas de seguridad permanentes:
#   - SOLO lectura A->B: peticiones GET, cero payloads de exploit
#   - presupuesto de peticiones acotado (MAX_CALLS)
#   - descarta blanco si REG-BOT dice phone/kyc
#
# CLI:
#   python3 core/ab_diff.py https://sitio.com
#   python3 core/ab_diff.py https://sitio.com --own email:pass
#   python3 core/ab_diff.py https://sitio.com --mock http://127.0.0.1:8899
# ============================================================
import json
import re
import sys
import time
from typing import Any, Dict, List, Optional

import requests

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".."))

from core import state
from core.reg_bot import (IdentityGenerator, MockMailProvider, RegBot,
                          SessionHandler, identity_signed, new_identity)

MAX_CALLS = 60          # presupuesto total de GETs del diff
MAX_ENDPOINTS = 25      # superficie maxima a difar
TIMEOUT = 20
BLOCKED = (401, 403, 404, 405)

_URL_RE = re.compile(
    r'(?:https?://[^/\'"<>]+)?(/(?:api|v[0-9]|user|users|account|me|profile'
    r'|panel|admin|app|data)[A-Za-z0-9\-_./%]*)')


def _sess(ident: Optional[Dict[str, Any]] = None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = ("Mozilla/5.0 (Linux; Android 13) "
                               "AppleWebKit/537.36")
    if ident:
        for k, v in (ident.get("cookies") or {}).items():
            s.cookies.set(k, v)
    return s


def _get(s: requests.Session, url: str,
         budget: Dict[str, int]) -> Optional[requests.Response]:
    if budget["n"] >= MAX_CALLS:
        return None
    budget["n"] += 1
    try:
        return s.get(url, timeout=TIMEOUT, allow_redirects=False)
    except Exception:
        return None


def _same(a: Optional[requests.Response], b: Optional[requests.Response]) -> bool:
    if a is None or b is None:
        return False
    return (a.status_code == b.status_code and
            a.text[:400] == b.text[:400])


# ------------------------------------------------------------
# descubrimiento de superficie (lectura, sin adivinar)
# ------------------------------------------------------------

def discover_endpoints(s: requests.Session, root: str,
                       budget: Dict[str, int],
                       depth: int = 1) -> List[str]:
    """URLs referenciadas por la propia app (links + strings tipo
    /api/... dentro de JSON/HTML). Nada de wordlists ciegas."""
    found: List[str] = []
    seen_pages = {root}
    pages = [root]
    for _ in range(depth):
        nxt = []
        for url in pages:
            r = _get(s, url, budget)
            if r is None or r.status_code >= 400:
                continue
            for m in _URL_RE.finditer(r.text):
                u = m.group(1).split("?")[0].rstrip("/")
                full = root.rstrip("/") + u if u.startswith("/") else u
                if full.startswith(root) and full not in found and \
                        full not in seen_pages:
                    found.append(full)
                    nxt.append(full)
                    if len(found) >= MAX_ENDPOINTS:
                        return found
            # links clasicos
            for m in re.finditer(r'href=["\']([^"\']+)["\']', r.text):
                href = m.group(1)
                if href.startswith("/") and not href.startswith("//"):
                    full = root.rstrip("/") + href.split("?")[0]
                    if full.startswith(root) and full not in seen_pages:
                        seen_pages.add(full)
                        nxt.append(full)
        pages = nxt
    return found[:MAX_ENDPOINTS]


def _markers(ident: Dict[str, Any]) -> List[str]:
    cred = ident.get("credentials", {})
    return [x for x in (cred.get("email", ""), cred.get("username", ""))
            if len(x) >= 4]


def _hits_markers(body: str, markers: List[str]) -> List[str]:
    return [m for m in markers if m and m in (body or "")]


# ------------------------------------------------------------
# motor de diff
# ------------------------------------------------------------

def build_sessions(target: str,
                   own: Optional[Dict[str, str]] = None,
                   mail_provider=None,
                   log=print) -> Dict[str, Any]:
    """Decide el nivel y arma las sesiones + relaciones."""
    target = target.rstrip("/")
    budget = {"n": 0}
    out: Dict[str, Any] = {"target": target, "level": 3, "sessions": {},
                           "relations": {}, "notes": []}
    # Nivel 1: registro libre
    bot = RegBot(target, mail_provider=mail_provider, log=log)
    try:
        idents = bot.register(n=2)
    except Exception as e:
        log("  [AB-DIFF] REG-BOT fallo: {}".format(e))
        idents = []
    if len(idents) >= 2 and all(identity_signed(i) for i in idents):
        a, b = idents[0], idents[1]
        out["level"] = 1
        out["sessions"] = {"A": a, "B": b}
        # relacion: A duena de sus objetos, B independiente
        out["relations"] = {"owner": "A", "independent": "B"}
        return out
    if any(i.get("verification_state") == "captcha" for i in idents):
        out["notes"].append("CAPTCHA-PENDING: handoff al operador")
    # Nivel 2: credenciales propias
    if own:
        ident = new_identity(own.get("email", "own@own"), {})
        ident["credentials"].update({"email": own.get("email", ""),
                                     "username": own.get("email", ""),
                                     "password": own.get("password", "")})
        if bot.login(ident):
            out["level"] = 2
            out["sessions"] = {"OWN": ident}
            out["relations"] = {"owner": "OWN", "independent": None}
            return out
        out["notes"].append("login propio fallo")
    # Nivel 3: anonimo (fugas sin autenticacion)
    out["level"] = 3
    return out


def run(target: str, own: Optional[Dict[str, str]] = None,
        mail_provider=None, log=print) -> Dict[str, Any]:
    target = target.rstrip("/")
    built = build_sessions(target, own, mail_provider, log)
    budget = {"n": 0}
    sessions = built["sessions"]
    verdicts: List[Dict[str, Any]] = []

    # sesiones HTTP vivas
    http = {"ANON": _sess()}
    for name, ident in sessions.items():
        http[name] = _sess(ident)

    if built["level"] == 3:
        # Nivel 3: superficie publica que deberia estar cerrada
        eps = discover_endpoints(http["ANON"], target, budget, depth=2)
        log("  [AB-DIFF] N3: {} endpoints publicos".format(len(eps)))
        for ep in eps:
            r = _get(http["ANON"], ep, budget)
            if r is None:
                continue
            private = re.search(r'(email|password|token|api[_-]?key|ssn'
                                r'|credit|balance)', r.text, re.I)
            if r.status_code == 200 and private and len(r.text) > 40:
                verdicts.append({
                    "endpoint": ep, "veredicto": "DEMO-UNAUTH",
                    "evidencia": {"anon": {"status": r.status_code,
                                            "body": r.text[:120]}},
                })
            time.sleep(0.2)
    else:
        owner_name = built["relations"]["owner"]
        owner_ident = sessions[owner_name]
        owner_http = http[owner_name]
        # superficie descubierta DESDE la sesion del dueno (A)
        root_pages = [target]
        if built["level"] == 1 and owner_ident.get("registration_recipe", {}).get("login_url"):
            root_pages.append(owner_ident["registration_recipe"]["login_url"])
        eps: List[str] = []
        for p in root_pages:
            eps += discover_endpoints(owner_http, p, budget, depth=2)
        eps = list(dict.fromkeys(eps))[:MAX_ENDPOINTS]
        log("  [AB-DIFF] N{}: {} endpoints con sesion de {}".format(
            built["level"], len(eps), owner_name))
        mk = _markers(owner_ident)
        for ep in eps:
            rA = _get(owner_http, ep, budget)
            if rA is None:
                continue
            own_data = bool(_hits_markers(rA.text, mk))
            rAnon = _get(http["ANON"], ep, budget)
            if rAnon is not None and rAnon.status_code == 200 and \
                    _hits_markers(rAnon.text, mk):
                verdicts.append({
                    "endpoint": ep, "veredicto": "DEMO-UNAUTH",
                    "evidencia": {"anon": {"status": rAnon.status_code,
                                           "body": rAnon.text[:120]},
                                  owner_name: {"status": rA.status_code}},
                })
                continue
            if built["level"] == 1:
                rB = _get(http["B"], ep, budget)
                if rB is None:
                    continue
                b_sees_a = bool(_hits_markers(rB.text, mk))
                if rB.status_code == 200 and b_sees_a and own_data:
                    verdicts.append({
                        "endpoint": ep, "veredicto": "DEMO-BAC",
                        "evidencia": {
                            "A_owner": {"status": rA.status_code,
                                        "ve_datos_de": "A"},
                            "B_independiente": {"status": rB.status_code,
                                                "ve_datos_de": "A"},
                            "anon": {"status": rAnon.status_code
                                     if rAnon is not None else None}},
                    })
                elif rB.status_code in BLOCKED and own_data:
                    verdicts.append({
                        "endpoint": ep, "veredicto": "REFUTADO",
                        "evidencia": {"B": {"status": rB.status_code,
                                            "bloqueado": True}},
                    })
            time.sleep(0.2)

    result = {"target": target, "level": built["level"],
              "endpoints": budget["n"], "veredictos": verdicts,
              "notes": built["notes"], "ts": time.strftime("%Y-%m-%d %H:%M")}
    # persistir en hechos (estado del operador)
    out_file = state.hechos("ab_diff_results.jsonl")
    with open(out_file, "a") as fh:
        fh.write(json.dumps(result) + "\n")
    return result


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def _cli() -> int:
    args = sys.argv[1:]
    if not args:
        print("uso: ab_diff.py <url> [--own email:pass] "
              "[--mock http://lab-url]")
        return 2
    url = args[0]
    own = None
    if "--own" in args:
        email, _, pwd = args[args.index("--own") + 1].partition(":")
        own = {"email": email, "password": pwd}
    provider = None
    if "--mock" in args:
        provider = MockMailProvider(args[args.index("--mock") + 1])
    res = run(url, own=own, mail_provider=provider)
    print(json.dumps(res, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
