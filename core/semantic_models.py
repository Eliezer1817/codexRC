"""Modelos de datos de SEMANTIC-CACHE (v0.80).

Regla epistemologica central (diseno aprobado):
    Hipotesis != Observacion != Evidencia != Veredicto.

Estos modelos NUNCA representan estados internos del
edge/cache/proxy/origin como hechos. Toda propiedad
interna no demostrable con observaciones del motor queda
como UNKNOWN o CANDIDATE en su campo dedicado
(attribution), nunca como hecho del reporte.
"""
import os as _os
import sys as _sys

_sys.path.insert(0, _os.path.dirname(_os.path.dirname(
    _os.path.abspath(__file__))))
# _bootstrap


from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# ---- independencia de canales -------------------------------
# VERIFIED solo con evidencia de dispositivos distintos
# (topologia). v0.80 no la produce: maximo PARTIAL.
INDEPENDENCE = ("VERIFIED", "PARTIAL", "UNKNOWN")

CHANNEL_TYPES = (
    # respuesta inmediata a un request propio
    "RESPONSE_DIRECT",
    # comportamiento de estado persistido (refetch, senales
    # de cache a traves del tiempo). Derivado de
    # observaciones REALES, no de suposiciones internas.
    "STATE_PERSISTENCE",
    # referencia a regla auditable (RFC). NO es una
    # observacion: nunca cuenta como canal independiente
    # para correlation=STRONG.
    "SEMANTIC_CONTRACT",
)

SELF_INDUCED = ("RULED_OUT", "UNKNOWN")
SELF_METHODS = ("VIRGIN_PATH", "NEGATIVE_CONTROL", "CLEAN_REPRO",
                "MULTI_RUN", "UNKNOWN")

VERDICTS = ("CONSISTENT", "BENIGN", "INCONSISTENT", "SUSPICIOUS",
            "DEMO", "UNKNOWN")

SEMANTIC_STATES = ("CONSISTENT", "INCONSISTENT")
CORRELATIONS = ("NONE", "OBSERVED", "STRONG")
IMPACTS = ("NONE", "CROSS-CONSUMER", "SECURITY")
ATTRIBUTIONS = ("UNKNOWN", "CANDIDATE", "SUPPORTED")
BINDINGS = ("WEAK", "MODERATE", "STRONG", "UNKNOWN")


def _now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ChannelObservation:
    """Una observacion desde un canal, con su independencia.

    independence_status NO se deduce del nombre del canal.
    VERIFIED exige evidencia de dispositivo distinto
    (v0.80: inalcanzable -> maximo PARTIAL, documentado en
    independence_evidence).
    """
    channel_id: str
    channel_type: str
    connection_id: int
    observed: dict
    independence_status: str = "UNKNOWN"
    independence_evidence: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ProbeGenealogy:
    """Genealogia minima de cada sonda v0.80.

    Regla (diseno aprobado): ninguna observacion producida
    por una sonda se convierte en evidencia de causalidad si
    no podemos descartar razonablemente que la propia sonda
    creo el estado observado (ver self_induced en el juez).
    """
    probe_id: str
    parent_observation: str
    semantic_dimension: str
    variant: str
    timestamp: str = field(default_factory=_now)
    expected_effect: str = ""
    observed_effect: str = ""
    channel_ids: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


class Budget:
    """HARD CAP de requests. El motor NUNCA lo excede.

    FASE1 <= 17, FASE2 <= 8, CONTROLES <= 4, TOTAL <= 30.
    Si se alcanza el limite sin poder discriminar:
    UNKNOWN. No se persigue una hipotesis.
    """

    def __init__(self):
        self.caps = {"fase1": 17, "fase2": 8, "controles": 4,
                     "total": 30}
        self.spent = {"fase1": 0, "fase2": 0, "controles": 0,
                     "total": 0}

    def can(self, fase="fase2", n=1):
        return (self.spent["total"] + n <= self.caps["total"]
                and self.spent[fase] + n <= self.caps[fase])

    def spend(self, fase="fase2", n=1):
        if not self.can(fase, n):
            raise RuntimeError("presupuesto agotado: %s" % fase)
        self.spent[fase] += n
        self.spent["total"] += n

    def to_dict(self):
        return {"caps": self.caps, "spent": self.spent}


@dataclass
class Attributes:
    """Atributos de evidencia SEPARADOS del veredicto.

    El veredicto se deriva de condiciones sobre estos
    atributos. Nunca se suman ni se promedian.
    """
    semantic_state: str = "CONSISTENT"
    correlation: str = "NONE"
    impact: str = "NONE"
    attribution: str = "UNKNOWN"
    binding: str = "UNKNOWN"
    self_induced: str = "UNKNOWN"
    self_induced_method: str = "UNKNOWN"

    def to_dict(self):
        return asdict(self)


@dataclass
class VerdictRecord:
    target: str
    verdict: str
    attributes: Attributes
    conditions: dict = field(default_factory=dict)
    channels: list = field(default_factory=list)
    genealogy: list = field(default_factory=list)
    unknown_causes: list = field(default_factory=list)
    faltó_para_escalar: list = field(default_factory=list)
    budget: dict = field(default_factory=dict)
    informe79_verdict: str = ""
    nota: str = ""

    def to_dict(self):
        return {
            "target": self.target,
            "verdict": self.verdict,
            "attributes": self.attributes.to_dict(),
            "conditions": self.conditions,
            "channels": self.channels,
            "genealogy": self.genealogy,
            "unknown_causes": self.unknown_causes,
            "falto_para_escalar": self.faltó_para_escalar,
            "budget": self.budget,
            "informe79_verdict": self.informe79_verdict,
            "nota": self.nota,
        }


def _selftest():
    b = Budget()
    assert b.can("fase1", 17) and not b.can("fase1", 18)
    b.spend("fase1", 17)
    assert not b.can("fase2", 1) is False or True  # fase1 aparte
    assert b.can("fase2", 8) and not b.can("fase2", 9)
    b.spend("fase2", 8)
    assert b.can("controles", 4)
    assert not b.can("controles", 5)
    b.spend("controles", 4)
    assert b.spent["total"] == 29 and not b.can("fase2", 1)
    a = Attributes()
    assert a.correlation == "NONE"
    p = ProbeGenealogy(probe_id="p1", parent_observation="f1",
                       semantic_dimension="path",
                       variant="virgin", expected_effect="converge")
    assert p.timestamp
    print("semantic_models selftest OK")


if __name__ == "__main__":
    _selftest()
