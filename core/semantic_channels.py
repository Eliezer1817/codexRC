"""Canales de observacion de SEMANTIC-CACHE (v0.80).

Regla del diseno aprobado: dos canales NO son
"independientes" solo porque tienen nombres diferentes.

independence_status:
  VERIFIED  solo con evidencia de dispositivos distintos
            (topologia). v0.80 NO la produce.
  PARTIAL   canal_type distinto (mecanismo de observacion
            distinto) aunque el dispositivo no sea
            verificable.
  UNKNOWN   mismo canal_type, o sin poder establecer nada.

Ningun canal afirma estados internos: cada observacion
cita que se midio y como.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap


import time

from core import cache_fingerprint as F
from core.semantic_models import (ChannelObservation,
                                  ProbeGenealogy)

_ID = [0]


def _next_id(prefix):
    _ID[0] += 1
    return "%s-%03d" % (prefix, _ID[0])


class ChannelRegistry:
    """Registro de observaciones con independencia honesta."""

    def __init__(self):
        self.channels = []

    def observe(self, channel_type, observed, connection_id,
                evidence=""):
        if channel_type not in ("RESPONSE_DIRECT",
                                "STATE_PERSISTENCE",
                                "SEMANTIC_CONTRACT"):
            raise ValueError("canal desconocido: %s"
                             % channel_type)
        ind = "UNKNOWN"
        if channel_type == "SEMANTIC_CONTRACT":
            # una regla RFC no es una observacion
            ind = "UNKNOWN"
        else:
            prev = [c for c in self.channels
                    if c.channel_type != "SEMANTIC_CONTRACT"]
            if not prev:
                ind = "PARTIAL" if channel_type == \
                    "STATE_PERSISTENCE" else "UNKNOWN"
            elif all(c.channel_type != channel_type
                     for c in prev):
                ind = "PARTIAL"
        ch = ChannelObservation(
            channel_id=_next_id("ch"), channel_type=channel_type,
            connection_id=connection_id, observed=observed,
            independence_status=ind,
            independence_evidence=(
                "mecanismo de observacion distinto; "
                "dispositivo no verificable desde el motor"
                if ind == "PARTIAL" else
                ("referencia a regla auditable, no "
                 "observacion" if channel_type ==
                 "SEMANTIC_CONTRACT" else
                 "mismo tipo de canal")))
        self.channels.append(ch)
        return ch

    def disagreement(self, ch_a, ch_b, dimension,
                     pattern_a, pattern_b):
        """E7 = OBSERVABLE SEMANTIC DISAGREEMENT.

        Afirma SOLO que dos observaciones presentan
        comportamientos semanticos incompatibles sobre la
        misma dimension. JAMAS afirma 'EDGE != CACHE'.
        """
        if ch_a.channel_type == "SEMANTIC_CONTRACT" \
                or ch_b.channel_type == "SEMANTIC_CONTRACT":
            # contrato vs observacion: desacuerdo observable
            # pero el contrato no es canal independiente
            return {"e7": True, "independent": False,
                    "channels": [ch_a.channel_id,
                                 ch_b.channel_id],
                    "dimension": dimension,
                    "pattern_a": pattern_a,
                    "pattern_b": pattern_b,
                    "nota": ("observacion incompatible con la "
                             "regla de referencia; la regla no "
                             "es canal independiente")}
        ind = [c.independence_status for c in (ch_a, ch_b)]
        # mecanismos de observacion distintos -> el par es
        # independiente EN MECANISMO. El dispositivo sigue
        # sin poder verificarse (PARTIAL como maximo).
        # correlation=STRONG no se deriva solo de esto: el
        # juez exige reproducibilidad y estructura.
        independent = (ch_a.channel_type
                       != ch_b.channel_type)
        return {"e7": True,
                "independent": independent,
                "channels": [ch_a.channel_id, ch_b.channel_id],
                "independence": ind,
                "dimension": dimension,
                "pattern_a": pattern_a,
                "pattern_b": pattern_b,
                "nota": ("desacuerdo entre observaciones; "
                         "atribucion a capas: hipotesis "
                         "(CANDIDATE), no hecho")}

    def to_dicts(self):
        return [c.to_dict() for c in self.channels]


class TrackedClient:
    """Fetch con genealogia y presupuesto.

    Cada request abre su propia conexion (F.fetch), por lo
    que connection_id distingue conexiones TCP reales. El
    dispositivo que responde no es verificable: la
    independencia queda PARTIAL como maximo.
    """

    def __init__(self, url, timeout, budget, registry):
        self.url = url
        self.timeout = timeout
        self.budget = budget
        self.registry = registry
        self.genealogy = []
        self._conn = [0]

    def probe(self, fase, dimension, variant, path, headers,
              parent, expected, channel_type="RESPONSE_DIRECT"):
        self.budget.spend(fase)
        self._conn[0] += 1
        fp, _raw, err = F.fetch(self.url, path, headers,
                                self.timeout)
        pid = _next_id("probe")
        observed = ("respuesta obtenida" if fp and
                    fp.get("valid") else
                    "sin respuesta (%s)"
                    % (err or "fetch invalido"))
        ch = None
        if fp and fp.get("valid"):
            ch = self.registry.observe(
                channel_type,
                {"path": path,
                 "status": fp["signals"]["status_code"].get(
                     "value"),
                 "body_hash": fp["signals"]["body_hash"].get(
                     "value"),
                 "etag": fp["signals"]["etag"].get("value"),
                 "cache_status": fp["signals"][
                     "cache_status"].get("value"),
                 "age": fp["signals"]["age"].get("value"),
                 "content_type": fp["signals"][
                     "content_type"].get("value")},
                self._conn[0])
        g = ProbeGenealogy(
            probe_id=pid, parent_observation=parent,
            semantic_dimension=dimension, variant=variant,
            expected_effect=expected, observed_effect=observed,
            channel_ids=[ch.channel_id] if ch else [])
        gd = g.to_dict()
        self.genealogy.append(gd)
        time.sleep(F.COOLDOWN)
        return fp, gd, ch


def _selftest():
    from core.semantic_models import Budget
    r = ChannelRegistry()
    a = r.observe("RESPONSE_DIRECT", {"x": 1}, 1)
    b = r.observe("STATE_PERSISTENCE", {"x": 2}, 2)
    c = r.observe("RESPONSE_DIRECT", {"x": 3}, 3)
    d = r.observe("SEMANTIC_CONTRACT", {"regla": "RFC"}, 0)
    assert a.independence_status == "UNKNOWN"
    assert b.independence_status == "PARTIAL"
    assert c.independence_status == "UNKNOWN"
    assert d.independence_status == "UNKNOWN"
    dis = r.disagreement(a, b, "case",
                         ["MISS", "HIT"], ["MISS", "MISS"])
    assert dis["e7"] and dis["independent"]
    dis2 = r.disagreement(a, d, "case", "obs", "regla")
    assert dis2["e7"] and not dis2["independent"]
    print("semantic_channels selftest OK")


if __name__ == "__main__":
    _selftest()
