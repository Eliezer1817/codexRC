"""RESEARCH-MEMORY (v0.81.1): memoria de investigacion por
target.

Guarda por host, en CODEXRC_HOME/memory/research/<host>/:
  dossier.jsonl   una linea por ventana (sesion) observada
  latest.json     la ultima ventana completa

REGLAS DE HONESTIDAD:
  1. Solo observaciones: se guarda lo visto, lo ejecutado y lo
     descartado CON SU NOTA. Nunca inferencias sin contrato.
  2. Las conclusiones CADUCAN POR VENTANA: una hipotesis
     contradicha ayer no revive sola hoy, pero tampoco es
     verdad eterna. Al re-entrar, el grafo se siembra fresco y
     lo previo entra como ANOTACION de ventana.
  3. El UNICO reuso automatico es con evidencia fuerte:
     baseline IDENTICO (mismas huellas) dentro del TTL. Mismo
     observable = mismas condiciones observadas; distinto
     baseline = ventana nueva, corrida nueva.
"""

import datetime
import json
import os
import urllib.parse

from state import home

TTL_HOURS_DEFAULT = 6.0


def _host(url):
    return (urllib.parse.urlsplit(url).netloc or
            url).lower().rstrip(".") or "unknown"


def mem_dir(url):
    d = os.path.join(home(), "memory", "research", _host(url))
    os.makedirs(d, exist_ok=True)
    return d


def save(record):
    """Persiste una ventana. Devuelve la ruta del dossier."""
    d = mem_dir(record["target"])
    with open(os.path.join(d, "dossier.jsonl"), "a") as f:
        f.write(json.dumps(record, default=str) + "\n")
    p = os.path.join(d, "latest.json")
    with open(p, "w") as f:
        json.dump(record, f, indent=1, default=str)
    return p


def load(url):
    p = os.path.join(mem_dir(url), "latest.json")
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except (ValueError, OSError):
            return None
    return None


def dossier(url):
    p = os.path.join(mem_dir(url), "dossier.jsonl")
    out = []
    if os.path.exists(p):
        for line in open(p):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def window_age_hours(record, now=None):
    try:
        t = datetime.datetime.fromisoformat(record["window"])
    except (KeyError, ValueError):
        return 1e9
    now = now or datetime.datetime.utcnow()
    if t.tzinfo is not None:
        t = t.replace(tzinfo=None)
    return (now - t).total_seconds() / 3600.0


def reusable(prev, baseline_hashes, ttl_hours=None):
    """Reuso determinista: solo si el baseline observado es
    IDENTICO (mismas huellas, mismo disparador) y la ventana
    previa esta dentro del TTL."""
    if not prev:
        return False
    ttl = (ttl_hours if ttl_hours is not None
           else TTL_HOURS_DEFAULT)
    if ttl <= 0:
        return False
    if window_age_hours(prev) > ttl:
        return False
    pb = prev.get("baseline") or {}
    if pb.get("trigger") != "baseline_ambiguous":
        return False
    return pb.get("huellas") == list(baseline_hashes)


def annotate(graph, prev):
    """Marca cada hipotesis con su estado en la ventana previa.
    NO copia el status: el grafo actual se juzga con la
    evidencia actual. Lo previo es contexto, no veredicto."""
    if not prev or not graph:
        return graph
    for node in graph["nodes"]:
        pn = next((h for h in prev.get("hipotesis", [])
                   if h["id"] == node["id"]), None)
        if pn:
            node["prior"] = {"window": prev.get("window"),
                             "status": pn.get("status")}
    return graph


def meta(url):
    """Resumen del dossier para el informe."""
    ds = dossier(url)
    return {"ventanas": len(ds),
            "ultima": (ds[-1].get("window") if ds else None),
            "ultimo_veredicto": (ds[-1].get("verdicto")
                                 if ds else None)}
