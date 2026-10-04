#!/usr/bin/env python3
# ============================================================
# codexRC - REG-BOT (v0.68.0, AB-DIFF universal)
# ------------------------------------------------------------
# PROVEEDOR UNIVERSAL DE IDENTIDADES/SESIONES DE PRUEBA.
# Desacoplado de WordPress: AUTHZ-PROOF consume objetos
# Identity estandarizados y jamas sabe si la cuenta nacio en
# WordPress, Laravel, Django, Express o una app propia.
#
# Submodulos (separacion de responsabilidades):
#   FORM-DISCOVERY      lee el formulario (no lo adivina)
#   CONSTRAINT-SOLVER   resuelve restricciones del servidor
#   IDENTITY-GENERATOR  identidad plausible y unica por sitio
#   REGISTRATION-FLOW   registro multi-paso con reintentos
#   VERIFICATION-FLOW   codigo numerico O enlace magico (polling corto)
#   SESSION-HANDLER     captura cookies/csrf/tokens
#   RECIPE-MEMORY       memoria de receta por sitio
#
# Objeto Identity estandarizado:
#   Identity = {
#     "id", "credentials", "cookies", "csrf", "tokens",
#     "verification_state", "registration_recipe", "capabilities"
#   }
#
# Relaciones para A/B (lo que AUTHZ-PROOF realmente necesita):
#   A = propietario del objeto X
#   B = usuario independiente
#   A->X permitido, B->X permitido  = evidencia de BAC/IDOR
#
# Reglas de seguridad (permanentes):
#   - pide telefono/documentos/KYC -> DESCARTAR el blanco
#   - CAPTCHA que GHOSTGATE no pasa -> CAPTCHA-PENDING (cola de
#     handoff al operador, NUNCA un sistema para vencer CAPTCHA)
#   - el mailbox ninja es mail.tm (API, sin telefono); en labor
#     se usa MockMailProvider local
#
# Identidades y recetas viven en CODEXRC_HOME (estado privado
# del operador, NO se comparten por git: contienen credenciales).
#
# CLI:
#   python3 core/reg_bot.py https://sitio.com           # registrar 1 ninja
#   python3 core/reg_bot.py https://sitio.com --n 2     # A y B
#   python3 core/reg_bot.py https://sitio.com --recipes # recetas guardadas
# ============================================================
import hashlib
import html as html_mod
import json
import os
import random
import re
import string
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

import sys as _sys, os as _os
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), ".."))

from core import state

# ------------------------------------------------------------
# Buzones ninja
# ------------------------------------------------------------

class MailTmProvider:
    """mail.tm: API gratuita, sin telefono.

    shape de la API (compatible con el mock del laboratorio):
      create_mailbox() -> (email, token)
      get_messages(email, token) -> [{"subject", "text", "html"}]
    """
    BASE = "https://api.mail.tm"
    DOMAINS_CACHE: List[str] = []

    def _req(self, method: str, path: str, **kw) -> requests.Response:
        r = requests.request(method, self.BASE + path, timeout=20, **kw)
        if r.status_code == 429:
            time.sleep(3)
            r = requests.request(method, self.BASE + path, timeout=20, **kw)
        return r

    def create_mailbox(self) -> Tuple[str, str]:
        if not MailTmProvider.DOMAINS_CACHE:
            d = self._req("GET", "/domains").json()
            MailTmProvider.DOMAINS_CACHE = [
                x["domain"] for x in d.get("hydra:member", d.get("member", []))
                if x.get("isActive", True)]
        dom = random.choice(MailTmProvider.DOMAINS_CACHE)
        user = "ninja" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        addr = user + "@" + dom
        pwd = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        r = self._req("POST", "/accounts",
                      json={"address": addr, "password": pwd})
        r.raise_for_status()
        t = self._req("POST", "/token", json={"address": addr, "password": pwd})
        t.raise_for_status()
        return addr, t.json()["token"]

    def get_messages(self, email: str, token: str) -> List[Dict[str, str]]:
        r = self._req("GET", "/messages",
                     headers={"Authorization": "Bearer " + token})
        if r.status_code != 200:
            return []
        data = r.json()
        out = []
        for m in data.get("hydra:member", data.get("member", []))[:10]:
            detail = self._req("GET", "/messages/" + m["id"],
                               headers={"Authorization": "Bearer " + token})
            body = detail.json() if detail.status_code == 200 else {}
            out.append({"subject": m.get("subject", ""),
                        "text": body.get("text", "") or "",
                        "html": body.get("html", [""])[0] if isinstance(
                            body.get("html"), list) else (body.get("html") or "")})
        return out


class MockMailProvider:
    """Laboratorio: mailbox local expuesto por el sitio de prueba.

    El sitio de prueba (lab_ab_site) responde:
      GET /mockmail/<email> -> [{"subject","text","html"}]
    """
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")

    def create_mailbox(self) -> Tuple[str, str]:
        addr = "ninja" + "".join(random.choices(string.digits, k=8)) + "@lab.test"
        return addr, "mock"

    def get_messages(self, email: str, token: str) -> List[Dict[str, str]]:
        try:
            r = requests.get(self.base + "/mockmail/" + email, timeout=10)
            return r.json() if r.status_code == 200 else []
        except Exception:
            return []


# ------------------------------------------------------------
# Identity: el contrato estandarizado
# ------------------------------------------------------------

def new_identity(email: str, recipe: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": hashlib.sha1(email.encode()).hexdigest()[:12],
        "credentials": {"email": email, "username": "", "password": ""},
        "cookies": {},
        "csrf": {},
        "tokens": {},
        "verification_state": "pending",
        "registration_recipe": recipe,
        "capabilities": [],
    }


def identity_signed(ident: Dict[str, Any]) -> bool:
    """AUTHZ-PROOF solo pregunta esto: la identidad esta viva?"""
    return ident.get("verification_state") == "verified" and bool(ident.get("cookies"))


# ------------------------------------------------------------
# FORM-DISCOVERY: lee el formulario, no lo adivina
# ------------------------------------------------------------

# descartes duros (regla permanente)
_PHONE_RE = re.compile(r"(phone|tel[eé]fono|m[oó]vil|whatsapp|movil|sms"
                       r"|c[eé]lula)", re.I)
_KYC_RE = re.compile(r"(document|passport|dni|c[eé]dula|kyc|identity"
                     r"|curp|ssn|tax.id)", re.I)
_USER_RE = re.compile(r"(user(name)?|login|alias|apodo|nick|handle|cuenta)", re.I)
_NAME_RE = re.compile(r"(first.?name|nombre|last.?name|apellido|full.?name"
                     r"|\bname\b)", re.I)
_CAPTCHA_RE = re.compile(r"(captcha|recaptcha|hcaptcha|turnstile|geetest"
                         r"|cf-challenge)", re.I)


class FormDiscovery:
    """Descubre el flujo de registro de un sitio desconocido.

    Salida:
      forms: lista de pasos; cada paso = {
        action, method, fields: [{name, type, required, label, hint}],
        honeypots: [name], captcha: bool, discard: None|"phone"|"kyc"
      }
      reg_url, login_url, has_registration
    """

    def __init__(self, session: requests.Session):
        self.session = session

    def discover(self, url: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"reg_url": None, "login_url": None,
                               "has_registration": False, "forms": []}
        try:
            r = self.session.get(url, timeout=20)
        except Exception:
            return out
        page = r.text
        # enlaces tipicos de registro/login (relativos o absolutos)
        for m in re.finditer(r'href=["\']([^"\']+)["\']', page):
            href = html_mod.unescape(m.group(1))
            low = href.lower()
            if out["reg_url"] is None and re.search(
                    r"(register|signup|sign-up|registro|alta|crear.?cuenta)", low):
                out["reg_url"] = self._abs(url, href)
            if out["login_url"] is None and re.search(
                    r"(login|signin|sign-in|acceder|ingresar)", low):
                out["login_url"] = self._abs(url, href)
        # formularios inline que parecen registro
        for f in self._parse_forms(page):
            kinds = {x["type"] for x in f["fields"]}
            if "password" in kinds and ("email" in kinds or "text" in kinds):
                f["action"] = self._abs(url, f["action"])
                out["forms"].append(f)
                if out["reg_url"] is None:
                    out["reg_url"] = url
        if out["reg_url"] and not out["forms"]:
            # seguir el enlace y leer el formulario remoto
            try:
                r2 = self.session.get(out["reg_url"], timeout=20)
                for f in self._parse_forms(r2.text):
                    f["action"] = self._abs(out["reg_url"], f["action"])
                    out["forms"].append(f)
            except Exception:
                pass
        out["has_registration"] = bool(out["reg_url"])
        return out

    def _abs(self, base: str, href: str) -> str:
        if href.startswith("http"):
            return href
        if href.startswith("/"):
            p = re.match(r"(https?://[^/]+)", base)
            return p.group(1) + href if p else href
        return base.rstrip("/") + "/" + href

    def _parse_forms(self, page: str,
                  include_all: bool = False) -> List[Dict[str, Any]]:
        forms = []
        for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", page,
                              re.I | re.S):
            attrs, body = fm.group(1), fm.group(2)
            action = (re.search(r'action=["\']([^"\']*)["\']', attrs)
                      or [None, ""]).group(1) if 'action=' in attrs.lower() else ""
            method = "post" if re.search(r'method=["\']?post', attrs, re.I) else "get"
            fields, honeypots, discard, captcha = [], [], None, False
            for im in re.finditer(r"<(input|select|textarea)\b([^>]*)>", body, re.I):
                tag_attrs = im.group(2)
                def attr(n: str) -> str:
                    mm = re.search(n + r'=["\']([^"\']*)["\']', tag_attrs, re.I)
                    return html_mod.unescape(mm.group(1)) if mm else ""
                name, ftype = attr("name"), (attr("type") or "text").lower()
                if not name:
                    continue
                if ftype in ("hidden", "submit", "button", "file"):
                    if ftype == "hidden":
                        honeypots.append(name)  # se reenvia tal cual
                    continue
                label = attr("placeholder") or attr("aria-label") or attr("title")
                # hint del propio HTML: required, pattern, minlength
                hint = " ".join(x for x in (attr("pattern"), attr("placeholder"),
                                            attr("title")) if x)
                if _CAPTCHA_RE.search(name + " " + (label or "") + " " + hint):
                    captcha = True
                    continue
                if ftype == "tel" or _PHONE_RE.search(name + " " + (label or "")):
                    discard = "phone"
                    continue
                if _KYC_RE.search(name + " " + (label or "")):
                    discard = "kyc"
                    continue
                if ftype in ("email", "password", "text", "number",
                             "select", "textarea", "checkbox", "radio"):
                    fields.append({"name": name, "type": ftype,
                                   "required": "required" in tag_attrs.lower(),
                                   "label": label or name, "hint": hint})
            if fields and (include_all or
                           any(x["type"] == "password" for x in fields)):
                forms.append({"action": action, "method": method,
                              "fields": fields, "honeypots": honeypots,
                              "captcha": captcha, "discard": discard})
        return forms


# ------------------------------------------------------------
# CONSTRAINT-SOLVER + IDENTITY-GENERATOR
# ------------------------------------------------------------

_FIRST = ["Marcos", "Lucas", "Ana", "Paula", "Diego", "Sofia", "Martin",
          "Camila", "Julieta", "Bruno", "Ivan", "Noelia"]
_LAST = ["Vera", "Rojas", "Molina", "Ferreyra", "Oviedo", "Cardozo",
         "Benitez", "Duarte", "Aguirre", "Peralta"]


class IdentityGenerator:
    """Identidad plausible y unica por sitio (nunca la del operador)."""

    def __init__(self, site: str):
        self.seed = int(hashlib.sha1(site.encode()).hexdigest()[:8], 16)

    def person(self) -> Dict[str, str]:
        rng = random.Random(self.seed ^ int(time.time()))
        return {"first": rng.choice(_FIRST), "last": rng.choice(_LAST)}

    def username(self, taken_cb=None) -> str:
        """Alias unico con sufijo numerico; reintenta si el servidor
        responde que ya existe (hasta 5 veces, condicionado a
        respuesta REAL del servidor)."""
        p = self.person()
        base = (p["first"] + p["last"]).lower()[:10]
        for i in range(5):
            cand = base + str(random.Random().randrange(1000, 9999))
            if taken_cb is None or not taken_cb(cand):
                return cand
        return base + "".join(random.choices(string.digits, k=6))

    def password(self) -> str:
        """Siempre cumple las politicas estrictas comunes:
        >=10, mayuscula, minuscula, digito y simbolo. Unica, se
        guarda solo en el workspace privado del operador."""
        rng = random.Random()
        body = "".join(rng.choices(string.ascii_lowercase, k=6))
        return "{}!{}{}K".format(body.capitalize(), rng.randrange(10, 99),
                                 rng.choice("@#$%&"))


class ConstraintSolver:
    """Traduce hints del formulario a valores validos."""

    @staticmethod
    def solve_field(field: Dict[str, Any], gen: IdentityGenerator,
                    person: Dict[str, str], email: str,
                    username: str) -> str:
        label = (field["label"] + " " + field["hint"]).lower()
        ftype = field["type"]
        if ftype == "email":
            return email
        if ftype == "password":
            return gen.password()
        if ftype in ("checkbox", "radio"):
            return "on"
        if _USER_RE.search(label) or ftype == "text" and _USER_RE.search(field["name"]):
            return username
        if _NAME_RE.search(label):
            if "first" in label or "nombre" in label or "last" not in label and "apellido" not in label:
                return person["first"]
            return person["last"]
        if "confirm" in label and "password" in label:
            return ""  # el flow rellena tras conocer la password
        return person["first"] + " " + person["last"] if ftype == "text" else ""

    @staticmethod
    def username_field(fields: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for f in fields:
            if f["type"] == "text" and (_USER_RE.search(f["name"]) or
                                        _USER_RE.search(f["label"])):
                return f
        return None


# ------------------------------------------------------------
# VERIFICATION-FLOW: codigo O enlace, polling corto
# ------------------------------------------------------------

_CODE_RE = re.compile(r"\b(\d{4,8})\b")
_LINK_RE = re.compile(r'https?://[^\s"\'<>]+(?:verify|confirm|activate|validar'
                     r'|confirmar|activar)[^\s"\'<>]*', re.I)
_EXPIRED_RE = re.compile(r"(expir|vencid|invalid|caduc)", re.I)


class VerificationFlow:
    """Lee el buzon ninja y completa la verificacion.

    - polling corto (cada 6s) desde el momento del registro:
      los codigos caducan en minutos, no se puede llegar tarde
    - codigo numerico (4-8 digitos) o enlace magico (se abre solo)
    - si el sitio dice "codigo expirado" -> pide reenvio (hasta 3)
    """

    POLL_SECS = 6
    MAX_WAIT_SECS = 180
    MAX_RESENDS = 3

    def __init__(self, session: requests.Session, mail_provider,
                 log=print):
        self.session = session
        self.mail = mail_provider
        self.log = log

    def verify(self, email: str, mail_token: str,
               verify_url: Optional[str],
               resend_cb=None, code_field: str = "code") -> str:
        """-> 'verified' | 'link-followed' | 'timeout'"""
        deadline = time.time() + self.MAX_WAIT_SECS
        seen = set()
        while time.time() < deadline:
            for msg in self.mail.get_messages(email, mail_token):
                key = msg["subject"] + msg["text"][:80]
                if key in seen:
                    continue
                seen.add(key)
                link = (_LINK_RE.search(msg["html"]) or
                        _LINK_RE.search(msg["text"]))
                if link:
                    try:
                        self.session.get(link.group(0), timeout=20)
                        self.log("  [VERIF] enlace magico seguido")
                        return "link-followed"
                    except Exception:
                        pass
                codes = _CODE_RE.findall(re.sub(r'\s+', ' ', msg["text"] or msg["html"]))
                if codes and verify_url:
                    code = codes[-1]  # el ultimo suele ser el vigente
                    state = self._submit_code(verify_url, code, email,
                                               code_field)
                    if state == "expired" and resend_cb:
                        for _ in range(self.MAX_RESENDS):
                            resend_cb()
                            time.sleep(self.POLL_SECS)
                            state = self._retry_after_resend(email, mail_token)
                            if state == "verified":
                                return "verified"
                        return "timeout"
                    if state == "verified":
                        return "verified"
            time.sleep(self.POLL_SECS)
        return "timeout"

    def _submit_code(self, url: str, code: str, email: str,
                      code_field: str = "code") -> str:
        data = {code_field: code, "email": email}
        try:
            r = self.session.post(url, data=data, timeout=20,
                                  allow_redirects=True)
            if r.status_code in (200, 302) and not _EXPIRED_RE.search(r.text[:2000]):
                return "verified"
            if _EXPIRED_RE.search(r.text[:2000]):
                return "expired"
        except Exception:
            pass
        return "unknown"

    def _retry_after_resend(self, email: str, token: str) -> str:
        for msg in self.mail.get_messages(email, token):
            codes = _CODE_RE.findall(msg["text"] or msg["html"])
            if codes:
                # el flow llama de nuevo con el verify_url conocido
                return "new-code"
        return "unknown"


# ------------------------------------------------------------
# SESSION-HANDLER
# ------------------------------------------------------------

class SessionHandler:
    """Captura cookies/csrf/tokens en el objeto Identity."""

    @staticmethod
    def capture(ident: Dict[str, Any], session: requests.Session,
                response: Optional[requests.Response] = None,
                page: str = "") -> None:
        ident["cookies"] = {c.name: c.value for c in session.cookies}
        # tokens csrf tipicos en pagina o headers
        for m in re.finditer(
                r'name=["\']?(csrf[-_a-z]*|_token|authenticity_token)["\']?'
                r'\s+value=["\']([^"\']+)["\']', page, re.I):
            ident["csrf"][m.group(1)] = m.group(2)
        if response is not None:
            tok = response.headers.get("X-CSRF-Token")
            if tok:
                ident["csrf"]["header"] = tok
            auth = response.headers.get("Authorization")
            if auth:
                ident["tokens"]["bearer"] = auth
        for m in re.finditer(
                r'(?:token|jwt|bearer)["\']?\s*[:=]\s*["\']([A-Za-z0-9._\-]{16,})',
                page, re.I):
            if "jwt" not in ident["tokens"]:
                ident["tokens"]["jwt"] = m.group(1)


# ------------------------------------------------------------
# RECIPE-MEMORY: memoria por sitio
# ------------------------------------------------------------

class RecipeMemory:
    """Receta por sitio: que campos, que verificacion uso, que alias
    funciono. Volver a cazar el mismo sitio no re-aprende nada.

    Vive en CODEXRC_HOME/regbot/recipes.json (credenciales de
    identidades de prueba: PRIVADO del operador, nunca en git).
    """

    def __init__(self):
        self.dir = state.path("regbot")
        os.makedirs(self.dir, exist_ok=True)
        self.file = os.path.join(self.dir, "recipes.json")

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.file):
            try:
                return json.load(open(self.file))
            except Exception:
                return {}
        return {}

    def save_recipe(self, site: str, recipe: Dict[str, Any],
                    identities: List[Dict[str, Any]]) -> None:
        db = self._load()
        entry = db.setdefault(site, {"recipes": [], "identities": []})
        entry["recipes"].append(recipe)
        # identidades dedupe por id
        known = {i["id"] for i in entry["identities"]}
        for ident in identities:
            if ident["id"] not in known:
                entry["identities"].append(ident)
        json.dump(db, open(self.file, "w"), indent=1)

    def get_identities(self, site: str,
                       fresh_only: bool = False) -> List[Dict[str, Any]]:
        entry = self._load().get(site, {})
        idents = entry.get("identities", [])
        if fresh_only:
            idents = [i for i in idents if identity_signed(i)]
        return idents

    def last_recipe(self, site: str) -> Optional[Dict[str, Any]]:
        r = self._load().get(site, {}).get("recipes", [])
        return r[-1] if r else None


# ------------------------------------------------------------
# REGISTRATION-FLOW: orquesta todo (multi-paso)
# ------------------------------------------------------------

class RegBot:
    """REG-BOT: registra identidades ninja en un sitio desconocido.

    Uso:
        bot = RegBot("https://sitio.com", mail_provider)
        idents = bot.register(n=2)   # A y B (relacion: A duena de X,
                                     # B independiente)
    Estados de identidad:
      verified  -> lista para AUTHZ-PROOF
      captcha   -> CAPTCHA-PENDING (cola de handoff, no se vence)
      discarded -> phone/kyc (regla permanente)
    """

    MAX_STEPS = 5  # formularios multi-paso

    def __init__(self, site: str, mail_provider=None, log=print,
                 ua: str = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36"):
        self.site = site.rstrip("/")
        self.mail = mail_provider or MailTmProvider()
        self.log = log
        self.memory = RecipeMemory()
        self.gen = IdentityGenerator(self.site)
        self.ua = ua

    # -- API principal --------------------------------------

    def register(self, n: int = 2) -> List[Dict[str, Any]]:
        idents: List[Dict[str, Any]] = []
        session = requests.Session()
        session.headers["User-Agent"] = self.ua
        disc = FormDiscovery(session)
        info = disc.discover(self.site)
        if not info["has_registration"]:
            self.log("  [REG-BOT] sin registro visible")
            return idents
        if info.get("forms") and info["forms"][0]["discard"]:
            self.log("  [REG-BOT] DESCARTADO: exige {} (regla permanente)".format(
                info["forms"][0]["discard"]))
            return idents
        for step in info["forms"][:self.MAX_STEPS]:
            if step["captcha"]:
                self.log("  [REG-BOT] CAPTCHA-PENDING (handoff al operador)")
                return idents  # cola de handoff, nunca vencer CAPTCHA
        recipe = {"site": self.site, "reg_url": info["reg_url"],
                  "login_url": info["login_url"],
                  "steps": len(info["forms"]), "verification": "unknown",
                  "worked_at": time.strftime("%Y-%m-%d %H:%M")}
        for i in range(n):
            self.log("  [REG-BOT] identidad {}/{}".format(i + 1, n))
            ident = self._register_one(requests.Session(), info)
            if not ident:
                break
            ident["registration_recipe"] = dict(recipe,
                                               verification=ident["verification_state"])
            idents.append(ident)
        if idents:
            self.memory.save_recipe(self.site, recipe, idents)
        return idents

    # -- un registro ----------------------------------------

    def _register_one(self, session: requests.Session,
                      info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            email, mail_token = self.mail.create_mailbox()
        except Exception as e:
            self.log("  [REG-BOT] mailbox fallo: {}".format(e))
            return None
        ident = new_identity(email, {})
        ident["credentials"]["email"] = email
        person = self.gen.person()
        username = self.gen.username()
        ident["credentials"]["username"] = username
        # paso 1: el formulario principal
        form = info["forms"][0]
        data = {}
        passwd = None
        for f in form["fields"]:
            if f["type"] == "password":
                if passwd is None:
                    passwd = self.gen.password()
                    ident["credentials"]["password"] = passwd
                data[f["name"]] = passwd
                continue
            data[f["name"]] = ConstraintSolver.solve_field(
                f, self.gen, person, email, username)
        for h in form["honeypots"]:
            data[h] = ""
        url = form["action"] or info["reg_url"]
        try:
            r = session.post(url, data=data, timeout=25, allow_redirects=True)
        except Exception as e:
            self.log("  [REG-BOT] submit fallo: {}".format(e))
            return None
        SessionHandler.capture(ident, session, r, r.text)
        if r.status_code in (403, 429) or _CAPTCHA_RE.search(r.text[:3000]):
            # VISION-GATE (v0.69.0): clasifica el checkpoint y REG-BOT
            # decide. El LLM nunca conduce; sin clave -> comportamiento
            # determinista original (handoff).
            verdict = self._vision_gate(r.text)
            if verdict:
                ident["vision"] = verdict
            if verdict and verdict.get("action") == "CONTINUE":
                self.log("  [REG-BOT] VISION-GATE: falso positivo de "
                         "heuristica -> continuar solo")
            else:
                self.log("  [REG-BOT] CAPTCHA-PENDING en submit "
                         "(handoff)" + self._vision_log(verdict))
                ident["verification_state"] = "captcha"
                return ident
        # "usuario ya existe" -> reintento con otro alias (respuesta REAL)
        if re.search(r"(ya exist|already|taken|disponible|ocupado|exists)",
                     r.text[:4000], re.I):
            for _ in range(5):
                username = self.gen.username()
                data = self._swap_username(data, form, username)
                r = session.post(url, data=data, timeout=25, allow_redirects=True)
                if not re.search(r"(ya exist|already|taken|exists)", r.text[:4000], re.I):
                    break
            ident["credentials"]["username"] = username
        # formulario de verificacion: se LEE de la respuesta del
        # registro (codigo/otp/pin/enlace), no se adivina
        verify_url, code_field = self._find_verify_form(session, r)
        SessionHandler.capture(ident, session, r, r.text)
        ver = VerificationFlow(session, self.mail, self.log)
        state = ver.verify(email, mail_token, verify_url,
                           code_field=code_field)
        ident["verification_state"] = ("verified" if state in ("verified", "link-followed")
                                       else "timeout")
        SessionHandler.capture(ident, session, r, r.text)
        self.log("  [REG-BOT] {} -> {}".format(email, ident["verification_state"]))
        return ident

    def _vision_gate(self, html):
        """Clasifica el challenge via Gemini (VISION-GATE). Nunca
        lanza: cualquier fallo devuelve None y la caza conserva su
        comportamiento determinista."""
        try:
            from core import vision_gate
        except ImportError:
            return None
        if not os.environ.get("GEMINI_API_KEY"):
            return None
        try:
            return vision_gate.classify(html=html, url=self.site)
        except Exception:
            return None

    @staticmethod
    def _vision_log(v):
        """Resumen de una linea para el log del job."""
        if not v:
            return ""
        return (" [VISION {} conf={:.2f} {}]".format(
            v.get("challenge_type", "?"),
            float(v.get("confidence", 0) or 0),
            v.get("state", "?")))

    def _find_verify_form(self, session, r) -> Tuple[Optional[str], str]:
        """Busca en la respuesta del registro el formulario donde va
        el codigo (o el mensaje que dice 'te enviamos un enlace')."""
        disc = FormDiscovery(session)
        for vf in disc._parse_forms(r.text, include_all=True):
            for fld in vf["fields"]:
                if re.search(r"(code|otp|pin|verif|c[oó]digo|token)",
                             fld["name"] + " " + fld["label"], re.I):
                    action = vf["action"] or r.url
                    if action.startswith("/"):
                        m = re.match(r"(https?://[^/]+)", r.url)
                        action = m.group(1) + action if m else action
                    return action, fld["name"]
        return None, "code"

    def _swap_username(self, data: Dict[str, str], form: Dict[str, Any],
                       username: str) -> Dict[str, str]:
        uf = ConstraintSolver.username_field(form["fields"])
        data = dict(data)
        if uf:
            data[uf["name"]] = username
        return data

    # -- login de una identidad existente (Nivel 2 del AB-DIFF) -

    def login(self, ident: Dict[str, Any],
              login_url: Optional[str] = None) -> bool:
        session = requests.Session()
        session.headers["User-Agent"] = self.ua
        disc = FormDiscovery(session)
        info = disc.discover(self.site)
        url = login_url or info["login_url"] or self.site
        try:
            page = session.get(url, timeout=20).text
        except Exception:
            return False
        forms = disc._parse_forms(page)
        if not forms:
            return False
        f = forms[0]
        data = {h: "" for h in f["honeypots"]}
        for fld in f["fields"]:
            if fld["type"] == "password":
                data[fld["name"]] = ident["credentials"]["password"]
            elif fld["type"] == "email":
                data[fld["name"]] = ident["credentials"]["email"]
            elif _USER_RE.search(fld["name"] + fld["label"]):
                data[fld["name"]] = ident["credentials"]["username"]
        action = f["action"] or url
        if action.startswith("/"):
            action = self.site + action
        try:
            r = session.post(action, data=data, timeout=25,
                             allow_redirects=True)
        except Exception:
            return False
        ok = r.status_code == 200 and not re.search(
            r"(incorrect|invalid|wrong|error)", r.text[:2000], re.I)
        SessionHandler.capture(ident, session, r, r.text)
        if ok:
            ident["verification_state"] = "verified"
        return ok


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def _cli() -> int:
    args = sys.argv[1:]
    if not args:
        print("uso: reg_bot.py <url> [--n 2] [--mock http://lab] [--recipes]")
        return 2
    url = args[0]
    if "--recipes" in args:
        mem = RecipeMemory()
        print(json.dumps({k: {"identidades": len(v.get("identities", []))}
                          for k, v in json.load(
                              open(mem.file)).items()} if os.path.exists(mem.file)
                         else {}, indent=1))
        return 0
    n = int(args[args.index("--n") + 1]) if "--n" in args else 2
    provider = None
    if "--mock" in args:
        provider = MockMailProvider(args[args.index("--mock") + 1])
    bot = RegBot(url, mail_provider=provider)
    idents = bot.register(n=n)
    for i in idents:
        print(json.dumps({k: i[k] for k in ("id", "credentials",
                                            "verification_state")}, indent=1))
    return 0 if idents else 1


if __name__ == "__main__":
    sys.exit(_cli())
