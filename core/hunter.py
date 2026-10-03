"""
codexRC - Hunter (FACHADA, v0.57.5)
El modulo original de 96KB se partio en submodulos por responsabilidad:
  core/hunter_base.py   constantes + helpers compartidos
  core/hunter_spider.py Spider (mapeo)
  core/hunter_deep.py   DeepHunter (caza profunda)
  core/hunter_xss.py    XSSHunter (reflexion)
  core/hunter_blind.py  BlindXSS
  core/hunter_xsspro.py XSSPro
Esta fachada re-exporta TODO para que los imports existentes
(backend/app.py, core/async_lane.py, CLI) no cambien ni una linea.
"""

from core.hunter_base import (
    Log, SKIP_EXT, JS_SINK_RE, JS_SOURCE_RE, JS_ENDPOINT_RE,
    FORM_INPUT_TYPES, _norm,
)
from core.hunter_spider import Spider
from core.hunter_deep import DeepHunter
from core.hunter_xss import XSSHunter
from core.hunter_blind import BlindXSS
from core.hunter_xsspro import XSSPro

__all__ = [
    "Log", "SKIP_EXT", "JS_SINK_RE", "JS_SOURCE_RE", "JS_ENDPOINT_RE",
    "FORM_INPUT_TYPES", "_norm", "Spider", "DeepHunter",
    "XSSHunter", "BlindXSS", "XSSPro",
]
