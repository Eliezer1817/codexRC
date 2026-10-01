"""AUTOCORRECCION: el Hunter recuerda que rindio y ajusta su propio gasto.

Memoria persistente (tune_state.json, NO se committea):
  por PARAMETRO: cuantas veces ese nombre de parametro produjo hallazgos
                en cazas anteriores (user_id, cat, q, id...).
  por BLANCO:   fingerprint del sitio (WordPress, Angular...) -> si un
                CMS/Framework rinde historico, se nota.

Uso:
  - load_boosts()   ANTES de rankear: multiplica el presupuesto de sondas
                    de los parametros con historial exitoso (x1.5 con 2+
                    hallazgos, x1.2 con 1). Determinista: mismas estadisticas,
                    misma decision.
  - record()        AL FINAL de cada caza: cuenta los hallazgos por param
                    y por tipo de blanco. La caza N aprende de las N-1.

Anti-sesgo: el boost nunca baja el presupuesto de otros parametros; solo
sube el de los probados, con tope. Un parametro nuevo empieza neutro.
"""

import json
import os
from typing import Any, Dict, List

STATE_FILE = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tune_state.json")
# "core/.." = raiz del repo, junto a waf_state.json

BOOST_2PLUS = 1.5     # 2+ hallazgos historicos
BOOST_1 = 1.2         # 1 hallazgo historico
MAX_BUDGET = 20       # tope de sondas por objetivo


class SelfTune:
    def __init__(self, emit=None):
        self.emit = emit or (lambda m: None)

    # ------------------------------------------------------------ estado

    @staticmethod
    def _read() -> Dict[str, Any]:
        try:
            with open(STATE_FILE, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {"by_param": {}, "by_site": {}, "hunts": 0}

    @staticmethod
    def _write(st: Dict[str, Any]) -> None:
        try:
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump(st, fh, ensure_ascii=False, indent=1)
        except Exception:
            pass                                  # memoria best-effort

    # ----------------------------------------------------------- boosts

    def load_boosts(self) -> Dict[str, float]:
        st = self._read()
        boosts: Dict[str, float] = {}
        for param, s in st.get("by_param", {}).items():
            hits = int(s.get("hits", 0))
            if hits >= 2:
                boosts[param] = BOOST_2PLUS
            elif hits == 1:
                boosts[param] = BOOST_1
        if boosts:
            self.emit("[tune] autocorreccion: parametros con historial "
                      + ", ".join(f"{p}(x{b})" for p, b in sorted(
                          boosts.items(), key=lambda kv: -kv[1])[:6]))
        return boosts

    def apply(self, ranked: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sube el presupuesto de los objetivos con historial exitoso."""
        boosts = self.load_boosts()
        for t in ranked:
            b = boosts.get(t.get("param", ""))
            if b:
                t["budget"] = min(MAX_BUDGET, int(round(t["budget"] * b)))
                t["tuned"] = f"x{b}"
        return ranked

    # ----------------------------------------------------------- record

    def record(self, findings: List[Dict[str, Any]],
               fingerprint: Dict[str, Any] | None = None) -> None:
        st = self._read()
        st["hunts"] = st.get("hunts", 0) + 1
        site = None
        if fingerprint:
            site = fingerprint.get("cms") or (fingerprint.get("frameworks")
                                              or [None])[0]
        if site:
            st.setdefault("by_site", {}).setdefault(site, {"hits": 0, "hunts": 0})
            st["by_site"][site]["hunts"] += 1
        for f in findings:
            p = (f.get("param") or "").split("=")[0].strip()
            if not p or p in ("-", "(ruta)"):
                continue
            st.setdefault("by_param", {}).setdefault(p, {"hits": 0})
            st["by_param"][p]["hits"] += 1
            if site:
                st["by_site"][site]["hits"] += 1
        self._write(st)
        top = sorted(st.get("by_param", {}).items(),
                     key=lambda kv: -kv[1]["hits"])[:5]
        if top:
            self.emit("[tune] memoria actualizada: "
                      + ", ".join(f"{p}:{v['hits']}" for p, v in top)
                      + f" · {st['hunts']} cazas registradas")
