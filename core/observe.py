"""CODEX-OBSERVE (Fase 1, alcance reducido).

Registro minimo de eventos semanticos de EVIDENCE-CHAIN: a que decision
llego el motor, con que evidencia, en que version/commit. Fase 1 de la
especificacion CODEX-OBSERVE/INTEL/REGRESS del operador. NO se implementan
las fases de motor de anomalias, differential/metamorphic/fuzz testing ni
CODEX-INTEL: para una herramienta de caza de bugs pagables el ROI de esa
infraestructura es bajo comparado con el tiempo de construirla; lo que
protege plata real es el Regression Corpus (core/regress.py), no el
logging exhaustivo. Si en el futuro aparecen inconsistencias reales de
verdict entre corridas, esto se puede ampliar.
"""
import json
import os
import subprocess
import time
import uuid
from typing import Any, Dict, Optional

EVENTS_DIR = os.path.join(os.path.dirname(__file__), "..", ".codexrc",
                          "intelligence", "events")
os.makedirs(EVENTS_DIR, exist_ok=True)

_RUN_ID = str(uuid.uuid4())[:12]


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(__file__), stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return "unknown"


_GIT_COMMIT = _git_commit()
MODULE_VERSION = "0.49.1"


def log_event(event: str, **fields: Any) -> Dict[str, Any]:
    """Un evento semantico (VERDICT_CREATED, FALLBACK_USED, etc.) con
    provenance de version/commit, siguiendo sec. 2 y 3 de la especificacion."""
    rec = {
        "run_id": _RUN_ID,
        "event_id": str(uuid.uuid4())[:12],
        "ts": time.time(),
        "event": event,
        "module_version": MODULE_VERSION,
        "git_commit": _GIT_COMMIT,
        **fields,
    }
    day = time.strftime("%Y-%m-%d")
    path = os.path.join(EVENTS_DIR, f"{day}.jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def log_verdict(chain: Dict[str, Any], target: Optional[str] = None) -> None:
    """Evento VERDICT_CREATED enlazado al evidence_hash de la cadena
    (integra con Evidence Chain segun sec. 3 y 10 del doc)."""
    log_event(
        "VERDICT_CREATED",
        target=target,
        file=chain.get("finding", {}).get("file"),
        line=chain.get("finding", {}).get("line"),
        verdict=chain.get("juez", {}).get("verdicto"),
        evidence_hash=chain.get("evidence_hash"),
    )
