#!/usr/bin/env python3
"""FIN-REPLAY-ENGINE (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 6.

Pregunta concreta: "¿esta operacion es idempotente cuando deberia
serlo?" Envia la MISMA request dos veces seguidas y compara el efecto
de la primera aplicacion contra el de la segunda usando FIN-STATE-ENGINE
(no reimplementa el diff, lo importa).

  REQUEST_A -> STATE_1 (primera aplicacion: efecto esperado, es el
               control implicito: asi se ve "funcionar una vez")
  REQUEST_A -> STATE_2 (segunda aplicacion IDENTICA: si el campo de
               beneficio se mueve OTRA VEZ en la misma direccion,
               la operacion no es idempotente)

Escalera:
  REPLAY-CANDIDATE  el campo de beneficio cambio en AMBAS aplicaciones
                    (ej. balance 100 -> 150 -> 200: dos acreditaciones
                    por una sola accion del cliente).
  REPLAY-IMPACT     el patron se REPRODUCE en una segunda tanda
                    independiente (reset + repetir el experimento
                    completo) Y el efecto es un beneficio genuino
                    (no ruido de contador interno sin valor).

Sin reset_fn (reproduccion independiente imposible) el techo es
REPLAY-CANDIDATE, nunca REPLAY-IMPACT: igual que el resto del motor,
un solo disparo no alcanza para declarar impacto.

Uso programatico (sin CLI: es libreria para fin_logic_probe):
    from core.fin_replay_engine import replay_once, replay_with_reproduction
"""
import sys
import os
from typing import Any, Callable, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import fin_state_engine as fse  # noqa: E402


StepFn = Callable[[], Tuple[int, Dict[str, Any]]]


def _unwrap(body: Dict[str, Any]) -> Dict[str, Any]:
    """Nuestros labs devuelven {'ok':bool,'order':{...}}; si no hay
    envoltorio 'order', se usa el body tal cual."""
    if isinstance(body, dict) and "order" in body:
        return body["order"]
    return body if isinstance(body, dict) else {}


def replay_once(get_state: StepFn, do_action: StepFn,
                 benefit_field: str) -> Dict[str, Any]:
    """Una tanda: baseline -> accion A -> accion A (identica).

    No requiere HTTP real: `get_state`/`do_action` son funciones sin
    argumentos que devuelven (status, body) -- el llamador decide como
    arma el request (permite testear con un mock determinista).
    """
    st0, b0 = get_state()
    snap0 = fse.snapshot(st0, _unwrap(b0))
    st1, b1 = do_action()
    snap1 = fse.snapshot(st1, _unwrap(b1))
    st2, b2 = do_action()
    snap2 = fse.snapshot(st2, _unwrap(b2))

    d1 = fse.diff(snap0, snap1)  # 1ra aplicacion: observacion, sin expectativa impuesta
    # 2da aplicacion: la expectativa HONESTA es que NO deberia volver a
    # moverse (si fuera asi, el 1er diff ya nos dice cuanto se movio)
    val_after_1st = snap1["fields"].get(benefit_field)
    d2 = fse.diff(snap1, snap2, expected={benefit_field: val_after_1st})

    moved_1st = any(c["field"] == benefit_field and
                    c["change_type"] != "NO_CHANGE" for c in d1["changes"])
    moved_2nd = any(c["field"] == benefit_field and
                    c["change_type"] == "CONTRADICTORY_CHANGE"
                    for c in d2["changes"])

    veredicto = "REPLAY-CANDIDATE" if (moved_1st and moved_2nd) else "DESCARTADO"
    return {
        "veredicto": veredicto,
        "benefit_field": benefit_field,
        "baseline": snap0["fields"], "after_1st": snap1["fields"],
        "after_2nd": snap2["fields"],
        "diff_1st": d1, "diff_2nd": d2,
        "moved_1st": moved_1st, "moved_2nd": moved_2nd,
    }


def replay_with_reproduction(reset_fn: Optional[Callable[[], None]],
                              get_state: StepFn, do_action: StepFn,
                              benefit_field: str) -> Dict[str, Any]:
    """Si hay reset_fn, repite la tanda completa de forma INDEPENDIENTE
    para exigir reproduccion antes de declarar REPLAY-IMPACT."""
    r1 = replay_once(get_state, do_action, benefit_field)
    if r1["veredicto"] != "REPLAY-CANDIDATE":
        return {"veredicto": "DESCARTADO", "ronda_1": r1}

    if reset_fn is None:
        return {"veredicto": "REPLAY-CANDIDATE", "ronda_1": r1,
                "nota": "sin reset_fn no se puede reproducir de forma "
                        "independiente: techo REPLAY-CANDIDATE"}

    reset_fn()
    r2 = replay_once(get_state, do_action, benefit_field)
    if r2["veredicto"] == "REPLAY-CANDIDATE":
        return {"veredicto": "REPLAY-IMPACT", "ronda_1": r1, "ronda_2": r2,
                "evidencia": "el patron de doble beneficio se reprodujo "
                            "en 2 tandas independientes (reset entre "
                            "medio)"}
    return {"veredicto": "REPLAY-CANDIDATE", "ronda_1": r1, "ronda_2": r2,
           "nota": "no se reprodujo en la segunda tanda: queda candidato, "
                   "no impacto"}
