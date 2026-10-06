#!/usr/bin/env python3
"""FIN-FP-MEMORIA (v0.97.0): BUSINESS LOGIC STATE ENGINE v2, FASE 9.

Integra FIN-LOGIC con FP-MEMORIA (core/fp_memory.py) SIN reescribirla:
reusa fp_memory.lookup()/_load()/_fp_key() tal cual, y solo se apoya en
fp_memory.learn_fingerprint() (aditiva, no toca el learn() original de
injection/BAC) para guardar huellas con forma distinta.

Huella estructural de FIN-LOGIC (seccion 17 del pedido): NUNCA nombres
de archivo/endpoint/plugin. Solo:
  - nivel del experimento (L0/L1/L2/STATE/REPLAY/RACE)
  - tipos semanticos de parametro involucrados (AMOUNT, QTY, ...)
  - relacion del grafo si aplica (MULTIPLY/ADD/SUBTRACT/DIVIDE/ASSIGN)
  - invariant_id si aplica (ya es un hash de CONTENIDO, no de ruta)
  - transicion de estado (from/to) si aplica
  - el veredicto que se intento declarar

Dos experimentos en DOS plugins distintos con la MISMA huella son la
misma familia de patron: si ya se refuto una vez (DESCARTADO con
motivo claro), la siguiente vez que aparezca esa huella NO se vuelve
a gastar triaje completo -- se anota como ya conocida.
"""
import os
import sys
from typing import Any, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import fp_memory  # noqa: E402


def fingerprint_of_experiment(experiment: Dict[str, Any],
                              resultado: Dict[str, Any]) -> Dict[str, Any]:
    tipo = experiment.get("tipo")
    tipos = sorted(set([tipo])) if tipo else []
    edge = experiment.get("source_edge") or {}
    return {
        "engine": "fin-logic-v2",
        "level": experiment.get("level"),
        "tipos": tipos,
        "relation": edge.get("relation"),
        "invariant_id": experiment.get("invariant_id"),
        "transition": experiment.get("transition"),
        "veredicto_intentado": resultado.get("veredicto"),
    }


def is_known_fp(experiment: Dict[str, Any],
                resultado: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """None si no hay memoria; si no, la entrada FPM-xxxx que ya pago
    este patron antes."""
    fp = fingerprint_of_experiment(experiment, resultado)
    return fp_memory.lookup(fp)


def learn_fp(experiment: Dict[str, Any], resultado: Dict[str, Any],
             refuted_by: str, reason: str, plugin: str = "") -> Optional[str]:
    fp = fingerprint_of_experiment(experiment, resultado)
    return fp_memory.learn_fingerprint(
        fp, refuted_by=refuted_by, reason=reason, plugin=plugin,
        family="fin-logic/%s" % experiment.get("level"))
