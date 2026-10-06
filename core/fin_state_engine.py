#!/usr/bin/env python3
"""FIN-STATE-ENGINE (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 4.

Representa y compara estados observables:

    STATE_0 -> REQUEST_A -> STATE_1 -> REQUEST_B -> STATE_2

Un "snapshot" es SOLO informacion observable y segura: status HTTP,
huella del body (hash, no el contenido crudo si es grande/sensible),
headers relevantes, y los "campos de negocio" (precio, cantidad,
estado, balance, contador, inventario...) que ya trae la respuesta
JSON. No persiste secretos.

El "diff" compara dos snapshots campo por campo y clasifica cada
cambio contra una expectativa declarada por quien pidio el experimento
(el planner/probe, que SI sabe que esperaba que pasara):

  NO_CHANGE            antes == despues
  EXPECTED_CHANGE      cambio, y calza con lo que se esperaba
  UNEXPECTED_CHANGE     cambio, pero NADIE declaro una expectativa
                        para ese campo (señal a revisar, no veredicto)
  CONTRADICTORY_CHANGE  cambio, y CONTRADICE la expectativa declarada
                        (ej. se esperaba rechazo/no-cambio y el campo
                        se movio: la señal mas fuerte de las cuatro)

Sin expectativa declarada, un cambio nunca es mas que UNEXPECTED: este
motor no inventa que "deberia" pasar, solo compara lo que REALMENTE
paso contra lo que el experimento declaro que esperaba.

Uso programatico (no hay CLI util standalone: este modulo es libreria
para fin_logic_probe/fin_replay_engine/fin_race_engine):
    snap = snapshot(status, body_dict, headers)
    d = diff(before, after, expected={"total": ("lt", 0)})
"""
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

RELEVANT_HEADERS = {"set-cookie", "x-ratelimit-remaining", "etag",
                    "x-request-id"}

MISSING = object()  # centinela: el campo no existia en ese snapshot


def snapshot(status: int, body: Any,
             headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Estado observable de UNA respuesta. `body` es el dict de negocio
    (ej. {"price":100,"qty":2,"total":200,"status":"pending"})."""
    fields = body if isinstance(body, dict) else {}
    raw = json.dumps(fields, sort_keys=True, default=str).encode()
    rel_headers = {k: v for k, v in (headers or {}).items()
                  if k.lower() in RELEVANT_HEADERS}
    return {
        "http_status": status,
        "body_fingerprint": hashlib.sha1(raw).hexdigest()[:16],
        "headers": rel_headers,
        "fields": fields,
    }


def _matches_expected(value: Any, expected: Any) -> bool:
    """expected puede ser un literal (igualdad exacta) o una tupla
    (op, umbral) con op en eq/ne/gt/ge/lt/le."""
    if isinstance(expected, tuple) and len(expected) == 2:
        op, umbral = expected
        try:
            if op == "eq":
                return value == umbral
            if op == "ne":
                return value != umbral
            if op == "gt":
                return value > umbral
            if op == "ge":
                return value >= umbral
            if op == "lt":
                return value < umbral
            if op == "le":
                return value <= umbral
        except TypeError:
            return False
        return False
    return value == expected


def diff(before: Dict[str, Any], after: Dict[str, Any],
          expected: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Compara dos snapshots. `expected` mapea nombre_de_campo ->
    valor esperado o (op, umbral), SOLO para los campos que el
    experimento declaro que le interesaban.
    """
    expected = expected or {}
    bf, af = before.get("fields", {}), after.get("fields", {})
    keys = set(bf) | set(af)

    changes: List[Dict[str, Any]] = []
    for k in sorted(keys):
        b = bf.get(k, MISSING)
        a = af.get(k, MISSING)
        if b == a:
            change_type = "NO_CHANGE"
        elif k in expected:
            change_type = ("EXPECTED_CHANGE"
                          if _matches_expected(a, expected[k])
                          else "CONTRADICTORY_CHANGE")
        else:
            change_type = "UNEXPECTED_CHANGE"
        changes.append({
            "field": k,
            "before": None if b is MISSING else b,
            "after": None if a is MISSING else a,
            "change_type": change_type,
        })

    resumen = {ct: sum(1 for c in changes if c["change_type"] == ct)
              for ct in ("NO_CHANGE", "EXPECTED_CHANGE", "UNEXPECTED_CHANGE",
                        "CONTRADICTORY_CHANGE")}

    return {
        "before_status": before.get("http_status"),
        "after_status": after.get("http_status"),
        "before_fingerprint": before.get("body_fingerprint"),
        "after_fingerprint": after.get("body_fingerprint"),
        "changes": changes,
        "resumen": resumen,
        "hubo_cambio_real": before.get("body_fingerprint") !=
                            after.get("body_fingerprint"),
    }


def sequence(snapshots: List[Dict[str, Any]],
             expected_list: Optional[List[Dict[str, Any]]] = None
             ) -> List[Dict[str, Any]]:
    """Diffs consecutivos de una secuencia STATE_0..STATE_N (para
    stateful testing: A -> B -> C). expected_list[i] son las
    expectativas del paso i (snapshots[i] -> snapshots[i+1])."""
    out = []
    for i in range(len(snapshots) - 1):
        exp = (expected_list[i] if expected_list and i < len(expected_list)
              else None)
        out.append(diff(snapshots[i], snapshots[i + 1], expected=exp))
    return out
