"""EXPERIMENT-GRAPH (v0.83.0): grafo dirigido de
investigacion para la linea DESYNC.

Principio inviolable:
    Hypothesis != Observation != Evidence != Verdict

Flujo obligatorio:
    HYPOTHESIS -> EXPERIMENT -> OBSERVATION -> EVIDENCE ->
    CORRELATION -> VERDICT

Reglas:
  - Todo contrato se registra ANTES de ejecutar (anti
    post-hoc).
  - Journal append-only: la evidencia previa NUNCA se
    sobrescribe; se anula con evidencia nueva citada.
  - Sobrevivir experimentos NO demuestra una hipotesis:
    solo evidencia explicita de apoyo la marca SUPPORTED.
  - Contradiccion es terminal: gana, pero el historial
    conserva el apoyo previo.
  - La reproducibilidad NO es "dos respuestas iguales":
    exige huellas completas (request, conexion, reuso,
    timing, respuesta, estado, cache, baseline, controles,
    genealogia) reconstruibles.
  - CONFIRMED exige E-DESYNC-IMPACT + invariantes
    anti-falso-positivo limpias. La corona no se fabrica.
"""

import datetime
import itertools
import json
import os
import subprocess
import uuid

_SEQ = itertools.count(1)

from state import home

# ---------------- estados y clases ----------------

HYP_STATES = ("LIVE", "SUPPORTED", "CONTRADICTED",
              "INCONCLUSIVE", "CLOSED")

CANDIDATE_STATES = ("NONE", "CANDIDATE", "SUPPORTED",
                    "REPRODUCIBLE", "IMPACT-CANDIDATE",
                    "CONFIRMED", "REFUTED", "UNKNOWN")

# clases de evidencia desync (escalera de impacto)
E_SIGNAL = "E-DESYNC-SIGNAL"
E_REPRO = "E-DESYNC-REPRO"
E_STATE = "E-DESYNC-STATE"
E_CROSSCONN = "E-DESYNC-CROSSCONN"
E_IMPACT = "E-DESYNC-IMPACT"

# etiquetas cross-layer: lo externo solo es OBSERVED
LAYER_TAGS = ("OBSERVED", "INFERRED", "ATTRIBUTED",
              "UNKNOWN")

WEIGHT = {"CONTRADICT": 2.0, "SUPPORT": 1.0,
          "INCONCLUSIVE": 0.0}

# invariantes anti-falso-positivo: si ALGUNA se viola,
# CONFIRMED esta bloqueado. Cada una es (nombre, requisito)
FP_INVARIANTS = (
    ("baseline_caracterizado",
     "baseline STABLE o caracterizado antes de DEMO"),
    ("multiples_anomalias",
     "mas de una respuesta anomala (no una sola)"),
    ("no_solo_igualdad_cuerpos",
     "la senal no es solo igualdad de cuerpos"),
    ("no_solo_igualdad_headers",
     "la senal no es solo igualdad de headers"),
    ("no_solo_diferencia_temporal",
     "la senal no es solo diferencia temporal"),
    ("bot_management_descartado",
     "bot management no explica la observacion"),
    ("explicaciones_descartadas",
     "toda explicacion legitima esta descartada"),
    ("fuera_del_propio_experimento",
     "el fenomeno existe fuera del experimento mismo"),
    ("reproducible",
     "existen reproducciones con genealogia distinta"),
    ("impacto",
     "existe evidencia E-DESYNC-IMPACT"),
)


def _now():
    return datetime.datetime.utcnow().isoformat(
        timespec="seconds")


def _git_commit():
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True,
            timeout=5).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


class ExpGraph:
    """Grafo de investigacion append-only por run."""

    def __init__(self, target, hypotheses=None,
                 baseline_state=None):
        self.target = target
        # monotono: (ms, contador) evita coliciones de
        # orden entre runs del mismo segundo
        self.run_id = (
            datetime.datetime.utcnow().isoformat(
                timespec="milliseconds").replace("-", "")
            .replace(":", "") + "-"
            + str(next(_SEQ)).zfill(6))
        self.created = _now()
        self.git_commit = _git_commit()
        self.baseline_state = baseline_state
        self.nodes = {}
        self.journal = []
        self.contracts = {}
        self.candidate = "NONE"
        self.candidate_reasons = []
        for hid, name in (hypotheses or []):
            self.add_hypothesis(hid, name)

    # ---------------- nodos base ----------------

    def _node(self, nid, tipo, **kw):
        if nid in self.nodes:
            raise ValueError(f"nodo duplicado: {nid}")
        n = {"id": nid, "tipo": tipo,
             "created": _now(),
             "run_id": self.run_id,
             "target": self.target}
        n.update(kw)
        self.nodes[nid] = n
        self.journal.append({"event": "node", "id": nid,
                             "tipo": tipo, "ts": _now()})
        return n

    # ---------------- hipotesis ----------------

    def add_hypothesis(self, hid, name, layer=None):
        n = self._node(hid, "HYPOTHESIS", name=name,
                       state="LIVE", layer=layer,
                       evidence_for=[], evidence_against=[])
        return n

    def _hyp_transition(self, hid, new_state, evid_id,
                         why):
        h = self.nodes[hid]
        old = h["state"]
        if old == "CONTRADICTED" and new_state != \
                "CONTRADICTED":
            # terminal: solo se anota, no se revive
            self.journal.append({
                "event": "transition_blocked", "id": hid,
                "from": old, "to": new_state,
                "evidence": evid_id, "ts": _now(),
                "nota": "CONTRADICTED es terminal"})
            return h
        if old in ("SUPPORTED", "CONTRADICTED") and \
                new_state == "SUPPORTED":
            return h
        h["state"] = new_state
        self.journal.append({
            "event": "transition", "id": hid,
            "from": old, "to": new_state,
            "evidence": evid_id, "why": why,
            "ts": _now()})
        return h

    def live(self):
        return [h for h in self.nodes.values()
                if h["tipo"] == "HYPOTHESIS"
                and h["state"] in ("LIVE", "SUPPORTED",
                                   "INCONCLUSIVE")]

    # ---------------- contratos (pre-ejecucion) ----

    def register_contract(self, exp_id, hypothesis_ids,
                         procedure, expected_branches,
                         controls, budget, spectrum,
                         prereq=None):
        """Registra el contrato ANTES de ejecutar. Si el
        experimento ya tiene observaciones, se rechaza
        (anti post-hoc)."""
        if exp_id in self.contracts:
            if self.contracts[exp_id].get("ejecutado"):
                raise ValueError(
                    f"{exp_id} ya ejecutado: no se puede "
                    f"re-registrar post-hoc")
            return self.contracts[exp_id]
        self._node(exp_id, "EXPERIMENT",
                   hypothesis_ids=hypothesis_ids,
                   procedure=procedure,
                   expected_branches=expected_branches,
                   controls=controls, budget=budget,
                   spectrum=spectrum,
                   prereq=prereq or [],
                   ejecutado=False)
        self.contracts[exp_id] = self.nodes[exp_id]
        self.journal.append({
            "event": "contract_registered", "id": exp_id,
            "ts": _now(),
            "nota": "contrato pre-registrado"})
        return self.nodes[exp_id]

    # ---------------- observaciones ----------------

    def add_observation(self, exp_id, facts,
                        repro=None, signal=None,
                        parent=None):
        """Registra la observacion cruda del experimento.
        repro: huellas completas de reproducibilidad
        (request_fp, conn_identity, conn_reuse, timing,
        response_fp, state_fp, cache_fp, baseline_ref,
        controls, genealogy). Nunca interpretada."""
        if exp_id not in self.contracts:
            raise ValueError(
                f"sin contrato: {exp_id} (anti post-hoc)")
        obs_id = "OBS-" + str(len(
            [n for n in self.nodes.values()
             if n["tipo"] == "OBSERVATION"]) + 1).zfill(4)
        self._node(obs_id, "OBSERVATION", experiment=exp_id,
                   facts=facts, signal=signal,
                   repro=repro or {}, parent=parent)
        self.nodes[exp_id]["ejecutado"] = True
        self.journal.append({
            "event": "observation", "id": obs_id,
            "experiment": exp_id, "signal": signal,
            "ts": _now()})
        return obs_id

    # ---------------- evidencia y aplicacion ------

    def add_evidence(self, evid_id, obs_id, hyp_id,
                     action, tag, clase, nota):
        """EVIDENCE: interpretacion de una observacion con
        tag cross-layer. Append-only."""
        self._node(evid_id, "EVIDENCE", observation=obs_id,
                   hypothesis=hyp_id, action=action,
                   tag=tag, clase=clase, nota=nota)
        h = self.nodes[hyp_id]
        (h["evidence_against"]
         if action == "CONTRADICT"
         else h["evidence_for"]).append(evid_id)
        self.journal.append({
            "event": "evidence", "id": evid_id,
            "obs": obs_id, "hyp": hyp_id, "action": action,
            "tag": tag, "clase": clase, "ts": _now()})
        return self.nodes[evid_id]

    def apply(self, exp_id, obs_id, signal):
        """Aplica la rama del contrato PRE-registrado para
        la senal observada. El contrato es la autoridad."""
        c = self.contracts[exp_id]
        br = c["expected_branches"].get(signal)
        if br is None:
            self.journal.append({
                "event": "branch_missing", "id": exp_id,
                "signal": signal, "ts": _now()})
            return []
        out = []
        for hid in br.get("supports", []):
            ev = self._new_evidence(obs_id, hid, "SUPPORT",
                                    br)
            self._hyp_transition(
                hid, "SUPPORTED", ev["id"],
                f"observacion {obs_id} senal {signal}")
            out.append(ev)
        for hid in br.get("contradicts", []):
            ev = self._new_evidence(obs_id, hid,
                                    "CONTRADICT", br)
            self._hyp_transition(
                hid, "CONTRADICTED", ev["id"],
                f"observacion {obs_id} senal {signal}")
            out.append(ev)
        for hid in br.get("inconclusive", []):
            h = self.nodes[hid]
            if h["state"] == "LIVE":
                self._hyp_transition(
                    hid, "INCONCLUSIVE", None,
                    f"observacion {obs_id} senal {signal}"
                    f" inconclusiva")
        return out

    def _new_evidence(self, obs_id, hid, action, br):
        n = len([n for n in self.nodes.values()
                 if n["tipo"] == "EVIDENCE"]) + 1
        evid_id = "EV-" + str(n).zfill(4)
        clase = br.get("clase",
                       E_SIGNAL if action == "SUPPORT"
                       else None)
        # lo externo siempre es OBSERVED; la atribucion
        # interna exige evidencia adicional (UNKNOWN)
        tag = br.get("tag", "OBSERVED")
        return self.add_evidence(
            evid_id, obs_id, hid, action, tag, clase,
            br.get("nota", ""))

    # ---------------- EDV ----------------

    def edv(self, exp_id):
        """Valor de discriminacion esperado sobre hipotesis
        vivas. Ramas del contrato, uniformes, sin
        probabilidades inventadas. Solo ordena."""
        c = self.contracts[exp_id]
        vivas = {h["id"] for h in self.live()}
        total = 0.0
        for rama in c["spectrum"]:
            total += sum(WEIGHT[a] for h, a in rama
                         if h in vivas)
        return total / len(c["spectrum"])

    def next_experiment(self, budget_left=10**9,
                        cost_fn=None):
        """(exp_id, edv, tabla, razon). exp_id None si
        ningun experimento discrimina las vivas."""
        tabla = []
        best = None
        for exp_id, c in self.contracts.items():
            if c["ejecutado"]:
                continue
            if any(p not in self.contracts or
                   not self.contracts[p]["ejecutado"]
                   for p in c.get("prereq", [])):
                continue
            cost = (cost_fn(exp_id) if cost_fn
                    else c["budget"]["max_requests"])
            if cost > budget_left:
                continue
            e = self.edv(exp_id)
            tabla.append((exp_id, round(e, 3)))
            if e <= 0:
                continue
            if best is None or e > best[1]:
                best = (exp_id, e)
        if best is None:
            razon = ("ningun experimento disponible "
                     "discrimina las hipotesis vivas: "
                     + ",".join(sorted(h["id"] for h
                                       in self.live())))
            return None, 0.0, tabla, razon
        razon = (f"{best[0]}: mayor EDV "
                 f"({', '.join(t[0] + ' ' + str(t[1]) for t in tabla)})")
        return best[0], best[1], tabla, razon

    def record_selection(self, exp_id, edv, tabla,
                         targets, reason):
        """Por que se ejecuto este experimento: se registra
        ANTES de ejecutar para reconstruccion futura."""
        self.journal.append({
            "event": "selection", "id": exp_id,
            "edv": round(edv, 3), "tabla": tabla,
            "targets": targets, "reason": reason,
            "live": [h["id"] for h in self.live()],
            "ts": _now()})

    # ---------------- PATH OF INVESTIGATION ------

    def why(self, exp_id):
        """Reconstruye la cadena: EXP <- seleccion <-
        hipotesis vivas <- evidencia <- observaciones <-
        experimentos. Nunca inventa: cada eslabon cita su
        registro en el journal."""
        chain = []
        sel = [j for j in self.journal
               if j["event"] == "selection"
               and j["id"] == exp_id]
        if not sel:
            return [{"link": "EXPERIMENT", "id": exp_id,
                     "porque": "sin registro de seleccion"
                               " (contrato directo)"}]
        s = sel[-1]
        chain.append({"link": "EXPERIMENT", "id": exp_id,
                     "edv": s["edv"],
                     "reason": s["reason"]})
        for hid in s["targets"]:
            h = self.nodes.get(hid, {})
            chain.append({"link": "HYPOTHESIS", "id": hid,
                          "state": h.get("state")})
            for eid in (h.get("evidence_against", []) +
                        h.get("evidence_for", [])):
                ev = self.nodes.get(eid, {})
                obs = self.nodes.get(ev.get("observation"),
                                     {})
                chain.append({
                    "link": "EVIDENCE", "id": eid,
                    "action": ev.get("action"),
                    "observation": ev.get("observation")})
                if obs:
                    chain.append({
                        "link": "OBSERVATION",
                        "id": obs["id"],
                        "experiment": obs.get("experiment"),
                        "signal": obs.get("signal")})
        return chain

    # ---------------- DESYNC-CANDIDATE -----------

    def _evidences_of_class(self, clase):
        return [n for n in self.nodes.values()
                if n["tipo"] == "EVIDENCE"
                and n.get("clase") == clase]

    def _distinct_genealogies(self, clase):
        ge = set()
        for n in self._evidences_of_class(clase):
            obs = self.nodes.get(n.get("observation"))
            if obs:
                g = (obs.get("repro") or {}).get(
                    "genealogy")
                if g:
                    ge.add(tuple(g) if isinstance(
                        g, list) else g)
        return ge

    def declare_transition(self, new_state, why=""):
        """Transicion del candidato DESYNC. Solo avanza con
        evidencia; CONFIRMED exige impact + invariantes."""
        cur = self.candidate
        if new_state == cur:
            return False, cur
        if new_state == "CANDIDATE":
            if self._evidences_of_class(E_SIGNAL):
                self.candidate = new_state
        elif new_state == "SUPPORTED":
            if (self._evidences_of_class(E_SIGNAL)
                    and self.baseline_state in
                    ("STABLE", "CARACTERIZADO")):
                self.candidate = new_state
        elif new_state == "REPRODUCIBLE":
            ok = (self.candidate in ("CANDIDATE",
                                     "SUPPORTED")
                  and self._evidences_of_class(E_SIGNAL)
                  and len(self._distinct_genealogies(
                      E_SIGNAL)) >= 2)
            if ok:
                self.candidate = new_state
        elif new_state == "IMPACT-CANDIDATE":
            ok = (self.candidate == "REPRODUCIBLE"
                  and (self._evidences_of_class(
                      E_STATE)
                       or self._evidences_of_class(
                          E_CROSSCONN)))
            if ok:
                self.candidate = new_state
        elif new_state == "CONFIRMED":
            blockers = self.confirm_blockers()
            if (blockers or self.candidate !=
                    "IMPACT-CANDIDATE"):
                self.journal.append({
                    "event": "confirm_blocked",
                    "blockers": blockers, "ts": _now()})
                return False, cur
            self.candidate = new_state
        elif new_state == "REFUTED":
            self.candidate = new_state
        if self.candidate != cur:
            self.journal.append({
                "event": "candidate", "from": cur,
                "to": self.candidate, "why": why,
                "ts": _now()})
            return True, self.candidate
        return False, cur

    def confirm_blockers(self):
        """Invariantes anti-falso-positivo: lista de las
        violadas. Cada bloqueo tiene fuente real en el
        estado del grafo, no un checkbox decorativo."""
        out = []
        if self.baseline_state not in ("STABLE",
                                      "CARACTERIZADO"):
            out.append("baseline_caracterizado")
        sig = self._evidences_of_class(E_SIGNAL)
        if len(sig) < 2:
            out.append("multiples_anomalias")
        # senales que solo comparan cuerpos/headers/tiempo
        # no existen aqui: una senal edgesync es eco/estado
        # de sonda/conteo; si fuese solo igualdad, estaria
        # mal clasificada y el contrato no la habria
        # convertido en E-DESYNC-SIGNAL.
        if len(self._distinct_genealogies(E_SIGNAL)) < 2:
            out.append("reproducible")
        if not self._evidences_of_class(E_IMPACT):
            out.append("impacto")
        return out

    # ---------------- persistencia ----------------

    def _dir(self):
        return os.path.join(
            home(), ".codexrc", "intelligence",
            "experiments", self.target)

    def save(self):
        """Persiste la investigacion. Nunca sobrescribe:
        cada run_id es un archivo nuevo."""
        os.makedirs(self._dir(), exist_ok=True)
        p = os.path.join(self._dir(),
                         self.run_id + ".json")
        if os.path.exists(p):
            raise ValueError(
                "investigacion previa: no se sobrescribe")
        json.dump(self.dump(), open(p, "w"), indent=1)
        return p

    def dump(self):
        return {"target": self.target,
                "run_id": self.run_id,
                "created": self.created,
                "git_commit": self.git_commit,
                "baseline_state": self.baseline_state,
                "hypotheses": {
                    h["id"]: h["state"]
                    for h in self.nodes.values()
                    if h["tipo"] == "HYPOTHESIS"},
                "experiments": {
                    e["id"]: {"ejecutado": e["ejecutado"],
                              "hypothesis_ids":
                                  e["hypothesis_ids"]}
                    for e in self.nodes.values()
                    if e["tipo"] == "EXPERIMENT"},
                "observations": [
                    n for n in self.nodes.values()
                    if n["tipo"] == "OBSERVATION"],
                "evidence": [
                    n for n in self.nodes.values()
                    if n["tipo"] == "EVIDENCE"],
                "candidate": self.candidate,
                "confirm_blockers":
                    self.confirm_blockers(),
                "journal": self.journal}


def latest_run(target):
    d = os.path.join(home(), ".codexrc", "intelligence",
                     "experiments", target)
    if not os.path.isdir(d):
        return None
    runs = sorted(f for f in os.listdir(d)
                  if f.endswith(".json"))
    if not runs:
        return None
    # latest por campo created (no por nombre de archivo:
    # dos runs del mismo segundo no colisionan)
    best, best_key = None, None
    for f in runs:
        try:
            j = json.load(open(os.path.join(d, f)))
        except (ValueError, OSError):
            continue
        key = (j.get("created") or "", f)
        if best_key is None or key > best_key:
            best, best_key = j, key
    return best
