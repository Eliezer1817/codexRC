"""GRAPHQL: bateria dedicada contra endpoints GraphQL ocultos.

Las SPA modernas esconden toda la logica en /graphql. Esta bateria:

  1. DESCUBRE el endpoint (rutas comunes + soporte GET ?query=)
  2. INTROSPECCION: si esta habilitada, lista los tipos del esquema:
     el mapa completo de la API = mapa de donde buscar IDORs/BAC
  3. FIELD SUGGESTIONS: con introspeccion CERRADA, los errores tipo
     "Did you mean 'user'?" siguen filtrando el esquema campo por campo
  4. BATCHING: detecta si acepta arrays de queries en un solo request
     (bypass de rate limits) — se envia UN lote de 2 consultas inertes,
     jamas un bombardeo (DoS fuera de reglas)

Todo lectura: introspeccion y sugerencias son metadatos publicos.
"""

import json
from typing import Any, Dict, List
from urllib.parse import urlparse

PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
         "/api/graphql/v1", "/query", "/api/query", "/gql"]

INTROSPECTION_Q = "{__schema{queryType{name}mutationType{name}" \
                  "types{name kind}}}"
SUGGESTION_Q = "{n0t4r34lf13ldx9}"     # campo inventado: fuerza sugerencias
BATCH_Q = [{"query": "{__typename}"}, {"query": "{__typename}"}]


class GraphqlBait:
    def __init__(self, session, emit, delay: float = 0.0):
        self.session = session
        self.emit = emit or (lambda m: None)

    def _post(self, url: str, body: Any):
        try:
            r = self.session.post(url, json=body, timeout=12,
                                  headers={"Content-Type": "application/json"})
            return r
        except Exception:
            return None

    def _get(self, url: str, params: Dict[str, str]):
        try:
            return self.session.get(url, params=params, timeout=12)
        except Exception:
            return None

    # -------------------------------------------------------------- run

    def run(self, url: str) -> List[Dict[str, Any]]:
        self.emit("[graphql] === GRAPHQL: descubrimiento + esquema ===")
        root = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        findings: List[Dict[str, Any]] = []
        endpoint = None

        for path in PATHS:
            r = self._post(root + path, {"query": "{__typename}"})
            if r is not None and r.status_code == 200 and "__typename" in (
                    r.text or ""):
                endpoint = root + path
                break
            r = self._get(root + path, {"query": "{__typename}"})
            if r is not None and r.status_code == 200 and "__typename" in (
                    r.text or ""):
                endpoint = root + path
                break

        if not endpoint:
            self.emit("[graphql] sin endpoint GraphQL visible")
            return findings

        findings.append({
            "type": "Endpoint GraphQL", "severity": "info",
            "target": endpoint, "param": "-",
            "evidence": "endpoint GraphQL activo (POST/GET)",
            "verdict": "mapeado",
        })

        # 1) introspeccion
        r = self._post(endpoint, {"query": INTROSPECTION_Q})
        if r is not None and r.status_code == 200 and "__schema" in (r.text or ""):
            types: List[str] = []
            try:
                data = json.loads(r.text)
                for t in (data.get("data", {}).get("__schema", {})
                          .get("types", [])):
                    n = t.get("name", "")
                    if n and not n.startswith("__"):
                        types.append(n)
            except Exception:
                types = []
            findings.append({
                "type": "GraphQL introspeccion abierta", "severity": "media",
                "target": endpoint, "param": "introspection",
                "evidence": "esquema legible: mapa de la API = mapa de "
                            f"IDORs. Tipos visibles ({len(types)}): "
                            + ", ".join(types[:40]),
                "verdict": "confirmado por introspeccion",
            })
            self.emit(f"[graphql] 💥 introspeccion abierta: {len(types)} tipos "
                      "del esquema legibles")
        else:
            # 2) field suggestions (esquema cerrado pero parlanchin)
            r2 = self._post(endpoint, {"query": SUGGESTION_Q})
            if r2 is not None and "did you mean" in (r2.text or "").lower():
                findings.append({
                    "type": "GraphQL field suggestions", "severity": "media",
                    "target": endpoint, "param": "suggestions",
                    "evidence": "con introspeccion cerrada, los errores "
                                "revelan campos del esquema ('Did you mean')",
                    "verdict": "confirmado por sugerencias",
                })
                self.emit("[graphql] 💥 field suggestions activas: el esquema "
                          "se filtra por los errores")

        # 3) batching (deteccion, lote de 2 consultas inertes)
        r = self._post(endpoint, BATCH_Q)
        if r is not None and r.status_code == 200:
            try:
                is_batch = isinstance(json.loads(r.text), list)
            except Exception:
                is_batch = False
            if is_batch:
                findings.append({
                    "type": "GraphQL batching aceptado", "severity": "baja",
                    "target": endpoint, "param": "batching",
                    "evidence": "acepta arrays de queries en un request "
                                "(bypass potencial de rate limits)",
                    "verdict": "detectado con lote inerte de 2",
                })

        n = len([f for f in findings if f["severity"] != "info"])
        self.emit(f"[graphql] === GRAPHQL: {n} hallazgo(s) ===")
        return findings
