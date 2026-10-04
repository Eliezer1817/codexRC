#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VISION-GATE (v0.69.0): clasificador visual de challenges via Gemini.

Filosofia (mismas reglas del JUEZ): el LLM clasifica, NUNCA conduce.
Vision-Gate recibe screenshot opcional + fragmento de DOM redactado
y devuelve EXCLUSIVAMENTE el JSON del esquema. REG-BOT decide que
hacer con el veredicto; el modelo jamas toca el navegador.

Seguridad:
- hacia el modelo via solo imagen + texto redactado (regex tapa
  emails/telefonos/tokens largos). Cero credenciales, cookies o
  secretos de sesion.
- sin GEMINI_API_KEY o con API caida -> action=ERROR y REG-BOT
  conserva el comportamiento determinista actual (CAPTCHA-PENDING
  en cola de handoff). Nunca cuelga la caza.

Estados (taxonomia del diseño):
  no_challenge | supported_checkpoint | unsupported_checkpoint
  | ambiguous | requires_human

Acciones ejecutables por REG-BOT:
  CONTINUE       seguir solo (falso positivo de la heuristica)
  GHOSTGATE      delegar a navegador real (sugerencia; REG-BOT loguea)
  DISCARD        descartar blanco (solo con confidence >= 0.8)
  REQUIRES_HUMAN cola de handoff al operador
  ERROR          no se pudo clasificar -> comportamiento por defecto

CLI de prueba:
  python3 core/vision_gate.py --html page.html
  python3 core/vision_gate.py --image shot.png --url http://...
"""

import base64
import json
import os
import re
import sys
from typing import Any, Dict, Optional

import requests

API_URL = ("https://generativelanguage.googleapis.com/v1beta/models/"
           "{model}:generateContent")
# gemini-2.0/2.5-flash fueron retirados para usuarios nuevos
# (404 "no longer available"). 3.8-flash es el vigente pero se
# satura (503 high demand): se intenta en orden y se cae al
# siguiente ante 404/503/overload. VISION_MODEL fuerza uno fijo.
MODELS = ([os.environ["VISION_MODEL"]]
          if os.environ.get("VISION_MODEL")
          else ["gemini-3.8-flash", "gemini-flash-latest"])
TIMEOUT = 40

# ------------------------------------------------------------------
# redaccion: nada de PII ni secretos hacia el modelo
# ------------------------------------------------------------------
_RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
_RE_PHONE = re.compile(r"\+?\d[\d\s().-]{7,}\d")
_RE_TOKEN = re.compile(r"\b[a-zA-Z0-9_\-]{32,}\b")


def redact(text: str) -> str:
    """Tapa emails, telefonos y tokens largos antes de salir."""
    text = _RE_EMAIL.sub("[EMAIL-REDACTADO]", text)
    text = _RE_TOKEN.sub("[TOKEN-REDACTADO]", text)
    text = _RE_PHONE.sub("[TEL-REDACTADO]", text)
    return text


def dom_snippet(html: str, max_chars: int = 3000) -> str:
    """Contexto DOM minimo: texto visible + tags de challenge."""
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html,
                  flags=re.S | re.I)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text,
                  flags=re.S | re.I)
    # conservar pistas de challenge aunque el texto no las muestre
    hints = re.findall(
        r"(?:captcha|recaptcha|hcaptcha|turnstile|geetest|challenge)"
        r"[^<>]{0,60}", html[:20000], re.I)
    visible = re.sub(r"<[^>]+>", " ", text)
    visible = re.sub(r"\s+", " ", visible).strip()
    out = "DOM: " + visible[:max_chars]
    if hints:
        out += "\nPISTAS-CHALLENGE: " + " | ".join(hints[:5])
    return redact(out)


# ------------------------------------------------------------------
# contrato de salida: JSON estructurado obligatorio
# ------------------------------------------------------------------
SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "challenge_detected": {"type": "BOOLEAN"},
        "challenge_type": {
            "type": "STRING",
            "enum": ["none", "recaptcha_v2", "recaptcha_v3",
                     "hcaptcha", "turnstile", "cloudflare_interstitial",
                     "geetest", "rate_limit", "login_wall", "other"],
        },
        "confidence": {"type": "NUMBER"},
        "state": {
            "type": "STRING",
            "enum": ["no_challenge", "supported_checkpoint",
                     "unsupported_checkpoint", "ambiguous",
                     "requires_human"],
        },
        "action": {
            "type": "STRING",
            "enum": ["CONTINUE", "GHOSTGATE", "DISCARD",
                     "REQUIRES_HUMAN", "ERROR"],
        },
        "reason": {"type": "STRING"},
    },
    "required": ["challenge_detected", "challenge_type", "confidence",
                 "state", "action", "reason"],
}

SYSTEM_PROMPT = """Eres VISION-GATE, componente visual de codexRC.

Tu funcion es analizar checkpoints de workflows autorizados de
registro (REG-BOT) y clasificar si hay un challenge de seguridad.

Reglas absolutas:
- No inventes elementos que no ves.
- No afirmes que una accion tuvo exito sin evidencia observable.
- Devuelve EXCLUSIVAMENTE el esquema JSON solicitado, sin texto
  libre, sin consejos, sin decirle al usuario donde hacer clic.
- El codigo de REG-BOT decide que hacer; tu solo clasificas.

Taxonomia (campo state):
- no_challenge: la pagina es contenido normal, sin challenge.
- supported_checkpoint: challenge visible y de tipo conocido que
  el sistema puede delegar a un navegador real (GHOSTGATE):
  checkbox de recaptcha v2, hcaptcha simple, turnstile visible,
  interstitial de cloudflare.
- unsupported_checkpoint: challenge que el sistema no puede
  delegar (recaptcha v3 invisible, geetest con puzzle multiple,
  challenge que exige SMS/telefono/documentos).
- ambiguous: la evidencia es contradictoria o insuficiente.
- requires_human: challenge visible que exige interaccion
  humana directa (puzzle complejo, seleccion de imagenes).

Accion sugerida (campo action):
- CONTINUE si no hay challenge (o es falso positivo del texto).
- GHOSTGATE si es un checkpoint delegable a navegador real.
- DISCARD si exige SMS/telefono/KYC (blanco descartado por regla).
- REQUIRES_HUMAN si necesita al operador.
- ERROR solo si no puedes analizar la entrada.

Ejemplos de entrada -> salida (few-shot):

[E1] DOM: "Unidad de verificacion de seguridad... complete el
recaptcha para continuar" PISTAS: recaptcha render explicito
=> {"challenge_detected": true, "challenge_type": "recaptcha_v2",
    "confidence": 0.93, "state": "supported_checkpoint",
    "action": "GHOSTGATE",
    "reason": "recaptcha v2 visible, delegable a navegador real"}

[E2] DOM: "Bienvenido, crea tu cuenta" campos nombre/email/password
PISTAS: (ninguna)
=> {"challenge_detected": false, "challenge_type": "none",
    "confidence": 0.97, "state": "no_challenge",
    "action": "CONTINUE",
    "reason": "formulario de registro normal sin challenge"}

[E3] DOM: "Verifique su telefono para activar la cuenta (+___)"
PISTAS: sms verification required
=> {"challenge_detected": true, "challenge_type": "other",
    "confidence": 0.95, "state": "unsupported_checkpoint",
    "action": "DISCARD",
    "reason": "exige SMS/telefono, blanco descartado por regla"}

[E4] DOM: "Checking your browser before accessing" + bloqueo
de cloudflare PISTAS: cf-challenge
=> {"challenge_detected": true,
    "challenge_type": "cloudflare_interstitial",
    "confidence": 0.94, "state": "supported_checkpoint",
    "action": "GHOSTGATE",
    "reason": "interstitial de cloudflare delegable"}

[E5] DOM: "El formulario contiene un elemento canvas interactivo
sin etiquetas visibles" PISTAS: geetest
=> {"challenge_detected": true, "challenge_type": "geetest",
    "confidence": 0.6, "state": "ambiguous",
    "action": "REQUIRES_HUMAN",
    "reason": "evidencia insuficiente sobre el tipo exacto"}

Prioriza siempre la evidencia observable del DOM/screenshot
sobre las pistas textuales cuando entren en conflicto."""


# ------------------------------------------------------------------
# llamada a Gemini con salida estructurada
# ------------------------------------------------------------------
def classify(image_path: Optional[str] = None,
              html: Optional[str] = None,
              url: Optional[str] = None,
              timeout: int = TIMEOUT) -> Dict[str, Any]:
    """Clasifica un checkpoint. Devuelve el veredicto del esquema.

    Sin clave, sin imagen y sin DOM -> ERROR (REG-BOT conserva su
    comportamiento determinista; nunca cuelga).
    """
    # el auto-detector de secretos puede comerse el prefijo "AQ."
    # del formato nuevo de claves Google (guarda 50 chars sin "AQ.").
    # Normalizamos: si la clave no empieza por prefijos conocidos se
    # reintenta con "AQ." ante un rechazo de la API (fallback, nunca
    # altera claves AIza/AQ. validas).
    key = (os.environ.get("GEMINI_API_KEY")
           or os.environ.get("GOOGLE_API_KEY", "")).strip()
    if not key:
        return _err("sin GEMINI_API_KEY/GOOGLE_API_KEY configurada")
    if not image_path and not html:
        return _err("sin evidencia: se requiere imagen o DOM")

    parts: list = []
    ctx = "URL del checkpoint: " + redact(url or "(desconocida)")
    if html:
        ctx += "\n" + dom_snippet(html)
    parts.append({"text": "Clasifica este checkpoint de REG-BOT.\n"
                          + ctx})

    if image_path:
        try:
            with open(image_path, "rb") as fh:
                data = base64.b64encode(fh.read()).decode()
        except OSError as exc:
            return _err("no se pudo leer la imagen: {}".format(exc))
        mime = ("image/png" if image_path.lower().endswith(".png")
                else "image/jpeg")
        parts.append({"inline_data": {"mime_type": mime, "data": data}})

    payload = {
        "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": parts}],
        "generationConfig": {
            "response_mime_type": "application/json",
            "response_schema": SCHEMA,
            "temperature": 0,
            "maxOutputTokens": 2000,
        },
    }
    keys = [key]
    if not key.startswith(("AIza", "AQ.")):
        keys.append("AQ." + key)   # formato Google nuevo despojado

    r = None
    last_err = ""
    for model in MODELS:
        payload["generationConfig"]["maxOutputTokens"] = 2000
        for k in keys:
            try:
                r = requests.post(
                    API_URL.format(model=model), json=payload,
                    timeout=timeout,
                    headers={"x-goog-api-key": k})
            except requests.RequestException as exc:
                return _err("API inaccesible: {}".format(exc))
            if r.status_code == 200:
                break
            try:
                last_err = r.json().get("error", {}).get(
                    "message", "")[:120]
            except Exception:
                last_err = r.text[:120]
            # solo reintentamos con la clave alternativa si la API
            # rechazo la clave; un 404/503 de modelo no cambia con eso
            if "API key not valid" not in last_err:
                break
        if r is not None and r.status_code == 200:
            break
        # 404 (modelo retirado) o 503 (saturado) -> modelo siguiente
        if r is not None and r.status_code not in (404, 503, 429):
            break
    if r is None or r.status_code != 200:
        return _err("API {}: {}".format(
            r.status_code if r is not None else 0, last_err))

    try:
        parts = r.json()["candidates"][0]["content"]["parts"]
        cand = next(p["text"] for p in parts
                    if isinstance(p, dict) and p.get("text"))
        try:
            out = json.loads(cand)
        except ValueError:
            m = re.search(r"\{.*\}", cand, re.S)   # JSON truncado/sucio
            if not m:
                raise
            out = json.loads(m.group(0))
    except (KeyError, IndexError, StopIteration, ValueError) as exc:
        return _err("respuesta no parseable: {}".format(exc))

    # validacion dura: el veredicto solo se acepta si es legal
    ok = (out.get("action") in ("CONTINUE", "GHOSTGATE", "DISCARD",
                               "REQUIRES_HUMAN", "ERROR")
          and out.get("state") in ("no_challenge", "supported_checkpoint",
                                   "unsupported_checkpoint", "ambiguous",
                                   "requires_human"))
    if not ok:
        return _err("veredicto fuera de esquema: {}".format(out))
    try:
        out["confidence"] = float(out.get("confidence", 0))
    except (TypeError, ValueError):
        out["confidence"] = 0.0
    out["model"] = model
    return out


def _err(reason: str) -> Dict[str, Any]:
    return {"challenge_detected": None, "challenge_type": "none",
            "confidence": 0.0, "state": "no_challenge",
            "action": "ERROR", "reason": reason, "model": None}


# ------------------------------------------------------------------
# decision determinista de REG-BOT (aqui NO hay LLM)
# ------------------------------------------------------------------
def decide(verdict: Dict[str, Any]) -> str:
    """Traduce el veredicto a la accion que REG-BOT ejecuta.

    Conservador por diseno: solo CONTINUE y DISCARD actuan solos
    (DISCARD exige confidence >= 0.8); el resto conserva la cola
    de handoff actual.
    """
    action = verdict.get("action", "ERROR")
    conf = verdict.get("confidence", 0.0) or 0.0
    if action == "CONTINUE":
        return "CONTINUE"
    if action == "DISCARD" and conf >= 0.8:
        return "DISCARD"
    if action == "GHOSTGATE":
        return "GHOSTGATE-SUGERIDO"   # REG-BOT lo loguea, no ejecuta
    return "HANDOFF"                  # REQUIRES_HUMAN/ambiguo/ERROR


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="VISION-GATE")
    ap.add_argument("--image", help="screenshot del checkpoint")
    ap.add_argument("--html", help="archivo HTML del checkpoint")
    ap.add_argument("--url", default=None)
    args = ap.parse_args()
    page = None
    if args.html:
        page = open(args.html, encoding="utf-8",
                    errors="replace").read()
    v = classify(image_path=args.image, html=page, url=args.url)
    print(json.dumps(v, ensure_ascii=False, indent=2))
    print("decision REG-BOT:", decide(v))
