"""HYPOTHESIS-GRAPH (v0.81.0): hipotesis explicativas de una
observacion AMBIGUA, con reglas de actualizacion deterministas.

Reglas:
  - SUPPORT exige evidencia positiva explicita (contrato).
  - CONTRADICT exige observacion discriminante (el mecanismo
    predice algo que NO ocurrio en su dimension).
  - La contradiccion es terminal: un soporte posterior no
    revive una hipotesis (se registra como conflicto).
  - Todo lo demas queda UNKNOWN. Hipotesis != observacion !=
    evidencia != veredicto.
"""

HYPOTHESES = {
    "H1": "load_balancing",
    "H2": "personalization",
    "H3": "cache_variation",
    "H4": "bot_management",
    "H5": "origin_dynamics",
}


def seed(trigger):
    """Grafico inicial para un disparador dado. Cada disparador
    nombra sus hipotesis explicativas candidatas."""
    if trigger == "baseline_ambiguous":
        ids = ["H1", "H2", "H3", "H4", "H5"]
    else:
        ids = []
    return {
        "trigger": trigger,
        "nodes": [
            {"id": h, "name": HYPOTHESES[h], "status": "UNKNOWN",
             "evidence": [], "contradictions": [], "conflicts": []}
            for h in ids
        ],
    }


def apply(graph, actions):
    """actions: lista de (hyp_id, 'SUPPORT'|'CONTRADICT', nota).
    Determinista: la contradiccion gana; soporte sobre
    contradicha se registra como conflicto, no revive."""
    for hyp_id, action, note in actions:
        node = _node(graph, hyp_id)
        if node is None:
            continue
        if action == "SUPPORT":
            if node["status"] == "CONTRADICTED":
                node["conflicts"].append(note)
            else:
                node["status"] = "SUPPORTED"
                node["evidence"].append(note)
        elif action == "CONTRADICT":
            if node["status"] != "CONTRADICTED":
                node["status"] = "CONTRADICTED"
            node["contradictions"].append(note)


def _node(graph, hyp_id):
    for n in graph["nodes"]:
        if n["id"] == hyp_id:
            return n
    return None


def live(graph):
    """Hipotesis vivas: UNKNOWN o SUPPORTED (no contradichas)."""
    return [n for n in graph["nodes"]
            if n["status"] in ("UNKNOWN", "SUPPORTED")]


def contradicted(graph):
    return [n for n in graph["nodes"]
            if n["status"] == "CONTRADICTED"]


def summary(graph):
    return [{"id": n["id"], "name": n["name"],
             "status": n["status"],
             "evidence": n["evidence"],
             "contradictions": n["contradictions"],
             "prior": n.get("prior")}
            for n in graph["nodes"]]


def render(graph):
    out = []
    for n in graph["nodes"]:
        marca = {"SUPPORTED": "[+] ", "CONTRADICTED": "[-] ",
                 "UNKNOWN": "[?] "}.get(n["status"], "[?] ")
        out.append(f"{marca}{n['id']} {n['name']} "
                   f"({n['status']})")
        for e in n["evidence"]:
            out.append(f"      soporte: {e}")
        for c in n["contradictions"]:
            out.append(f"      contradice: {c}")
    return "\n".join(out)
