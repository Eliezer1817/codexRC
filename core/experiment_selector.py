"""SELECTOR DE EXPERIMENTOS (v0.82): grafo de experimentos.

Responde UNA pregunta: dadas las hipotesis vivas y el
presupuesto, ¿cual es la siguiente prueba que mas
informacion me puede dar?

EDV (Valor de Discriminacion Esperado) por experimento:
  para cada RAMA POSIBLE de su contrato (union estatica
  pre-registrada, parte del contrato, no una prediccion):
    valor_rama = suma de pesos sobre hipotesis VIVAS
      CONTRADICT = 2.0 (contradiccion es terminal: reduce
                      el conjunto vivo de forma determinista)
      SUPPORT    = 1.0 (apoyo solo prepara convergencia)
  EDV = media de valores de rama.

Sin probabilidades inventadas: las ramas se ponderan uniforme
porque NO se conoce su probabilidad; EDV es una heuristica
de ORDENAMIENTO, no de veredicto. Ningun resultado afecta
que hipotesis es apoyada o refutada: eso lo decide el
contrato.

DAG DE DEPENDENCIAS (del propio catalogo):
  INTRA-CONN -> CROSS-CONN -> VIRGIN
  INTRA-CONN -> TIME-OFFSET
  Un experimento no es elegible si falta un prerequisito.

DESEMPATES (deterministas, en orden):
  1. mayor EDV
  2. epsilon: discriminante en la ventana previa de memoria
     (eficiencia, nunca evidencia)
  3. orden de dependencia del catalogo

PARADA HONESTA: si ningun experimento restante puede
tocar una hipotesis viva (EDV == 0 en todos), el loop se
detiene y declara que NINGUN experimento disponible
discrimina las hipotesis vivas. El UNKNOWN conserva esa
razon, no un silencio.
"""

import hypothesis_graph as hg

WEIGHT = {"CONTRADICT": 2.0, "SUPPORT": 1.0}

# Espectro estatico: ramas posibles de cada contrato.
SPECTRUM = {
    "INTRA-CONN": [
        [("H1", "CONTRADICT"), ("H3", "CONTRADICT")],
        [],
    ],
    "CROSS-CONN": [
        [("H1", "SUPPORT"), ("H3", "SUPPORT")],
        [("H1", "CONTRADICT"), ("H3", "CONTRADICT")],
        [],
    ],
    "SESSION": [
        [("H2", "CONTRADICT"), ("H4", "CONTRADICT")],
        [("H2", "SUPPORT"), ("H4", "SUPPORT")],
        [],
    ],
    "VIRGIN": [
        [("H3", "CONTRADICT"), ("H1", "SUPPORT")],
        [("H1", "CONTRADICT"), ("H3", "CONTRADICT")],
        [("H1", "CONTRADICT"), ("H3", "SUPPORT")],
        [],
    ],
    "TIME-OFFSET": [
        [("H5", "SUPPORT")],
        [("H5", "CONTRADICT")],
        [],
    ],
}

PREREQ = {
    "CROSS-CONN": ["INTRA-CONN"],
    "VIRGIN": ["CROSS-CONN"],
    "TIME-OFFSET": ["INTRA-CONN"],
}

_ORDER = {e: i for i, e in enumerate(
    ["INTRA-CONN", "CROSS-CONN", "SESSION",
     "VIRGIN", "TIME-OFFSET"])}


def edv(exp_id, graph):
    """EDV puro: media de valor de rama sobre hipotesis
    vivas. Sin desempates ni epsilon."""
    live = {n["id"] for n in hg.live(graph)}
    total = 0.0
    for rama in SPECTRUM[exp_id]:
        total += sum(WEIGHT[a]
                     for h, a in rama if h in live)
    return total / len(SPECTRUM[exp_id])


def select(graph, ejecutados, budget_left,
           costs, prev_hints=None):
    """Devuelve (eleccion, tabla, razon).

    eleccion = (exp_id, edv_efectivo) o None si ningun
    experimento disponible discrimina las hipotesis vivas.
    tabla = [(exp_id, edv_efectivo)] de TODOS los elegibles
    (para visibilidad y para el gap ledger).
    """
    live = {n["id"] for n in hg.live(graph)}
    tabla = []
    best = None
    for exp_id in SPECTRUM:
        if exp_id in ejecutados:
            continue
        if any(p not in ejecutados
               for p in PREREQ.get(exp_id, [])):
            continue
        cost = costs.get(exp_id, 0)
        if cost > budget_left:
            continue
        e = edv(exp_id, graph)
        eps = 0.001 if (prev_hints
                        and exp_id in prev_hints) else 0.0
        tabla.append((exp_id, round(e + eps, 4)))
        if e <= 0:
            continue
        cand = (exp_id, e + eps)
        if best is None or _mejor(cand, best):
            best = cand
    if best is None:
        razon = ("ningun experimento disponible discrimina "
                 "las hipotesis vivas: "
                 + ",".join(sorted(live)))
        return None, tabla, razon
    razon = (f"{best[0]}: EDV {best[1]:.2f} "
             f"(vivas: {','.join(sorted(live))})")
    return best, tabla, razon


def _mejor(a, b):
    """a es mejor que b: EDV estricto, luego epsilon ya
    incluido, luego orden de dependencia."""
    if a[1] != b[1]:
        return a[1] > b[1]
    return _ORDER[a[0]] < _ORDER[b[0]]
