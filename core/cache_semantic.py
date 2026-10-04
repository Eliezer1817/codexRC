#!/usr/bin/env python3
"""CACHE-SEMANTIC (v0.79.0): relacion entre Request A y Request B.

Regla fundamental del operador: NO asumir ni afirmar que
conocemos la cache key interna. cache_key(A) == cache_key(B)
es solo HIPOTESIS de correlacion; lo observable son huellas
externas. La escalera: hipotesis != observacion != evidencia
!= veredicto.

Conjunto CERRADO y pequeno de transformaciones cuya
neutralidad es demostrable por regla RFC. Si una diferencia no
pertenece al conjunto: UNKNOWN. No se fuerza EQUIVALENT.
"""
import json

TRANSFORMACIONES = {
    "T-IDENT": {
        "doc": "bytes identicos: misma representacion",
        "http": "identidad",
        "cache": "por-definicion",
    },
    "T-HEADER-CASE": {
        "doc": ("RFC 7230 3.2: los NOMBRES de header son "
                "case-insensitive; cualquier capa (cache, edge, "
                "origin) que distinga por el CASO del nombre es "
                "defectuosa"),
        "http": "rfc7230-3.2",
        "cache": "por-regla",
    },
}


def relate(a, b):
    """a, b: {"path": str, "headers": {nombre: valor}}.
    Devuelve ficha auditable de la relacion A<->B."""
    ficha = {
        "pair_id": None,
        "request_a": a,
        "request_b": b,
        "relation": "UNKNOWN",
        "justification": "",
        "transformations": [],
        "http_equivalence": None,
        "cache_equivalence": None,
        "origin_equivalence": None,
    }
    if a.get("path") != b.get("path"):
        ficha.update({
            "relation": "DISTINCT",
            "justification": ("request-target difiere; sin "
                              "evidencia de reescritura o "
                              "equivalencia semantica"),
            "transformations": [],
            "http_equivalence": "no",
            "cache_equivalence": None,
            "origin_equivalence": None})
        return ficha

    na = {k.lower(): v for k, v in (a.get("headers") or {}).items()}
    nb = {k.lower(): v for k, v in (b.get("headers") or {}).items()}
    if na == nb:
        if (a.get("headers") or {}) == (b.get("headers") or {}):
            ficha.update({
                "relation": "EQUIVALENT",
                "justification": "bytes identicos",
                "transformations": ["T-IDENT"],
                "http_equivalence": "identidad",
                "cache_equivalence": "por-definicion",
                "origin_equivalence": "heredada"})
        else:
            ficha.update({
                "relation": "EQUIVALENT",
                "justification": ("mismo path y mismos pares "
                                 "nombre=valor; solo el CASE del "
                                 "nombre de un header (RFC 7230 "
                                 "3.2)"),
                "transformations": ["T-HEADER-CASE"],
                "http_equivalence": "rfc7230-3.2",
                "cache_equivalence": "por-regla",
                "origin_equivalence": "heredada"})
        return ficha

    ficha["justification"] = (
        "mismo path pero headers con valores distintos; la "
        "diferencia no pertenece al conjunto cerrado de "
        "transformaciones neutrales demostrables")
    return ficha


def _selftest():
    assert relate({"path": "/a", "headers": {}},
                  {"path": "/a", "headers": {}}
                  )["relation"] == "EQUIVALENT"
    assert relate({"path": "/a", "headers":
                   {"X-Cache-Probe": "v1"}},
                  {"path": "/a", "headers":
                   {"x-cache-probe": "v1"}}
                  )["relation"] == "EQUIVALENT"
    assert relate({"path": "/a", "headers": {}},
                  {"path": "/b", "headers": {}}
                  )["relation"] == "DISTINCT"
    assert relate({"path": "/a", "headers": {}},
                  {"path": "/a", "headers":
                   {"Cookie": "x=1"}})["relation"] == "UNKNOWN"
    print("cache_semantic selftest OK")


if __name__ == "__main__":
    _selftest()
