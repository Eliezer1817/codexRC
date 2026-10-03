#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SEMANTIC CORE (v0.58.0) — Nivel 0: identidad canonica de recursos.

Fundamento del nivel semantico del motor. Un hallazgo solo puede
alcanzar DEMOSTRADO-ESTATICO si la evidencia proviene del archivo
correcto, verificado por hash de contenido.

Identidad canonica de un archivo (FileId):
    root canonico (absoluto, normalizado)
    + ruta relativa normalizada (separador '/', sin '..')

El basename NO es identidad. Si la resolucion solo puede hacerse por
basename, el resultado es AMBIGUO y bloquea el veredicto alto.

Cadena de integridad:
    Finding -> FileId -> ContentHash -> contenido analizado
    Si el hash del contenido analizado != hash esperado:
    INTEGRITY FAILURE -> el finding no puede pasar a DEMOSTRADO-ESTATICO.

Python puro, Termux/armv7l OK.
"""
from __future__ import annotations

import hashlib
import os
from typing import Dict, Optional, Tuple

INTEGRITY_OK = "OK"
INTEGRITY_AMBIGUOUS = "AMBIGUO"        # resuelto solo por basename
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"  # hash no coincide con testigo


def _norm_rel(path: str) -> str:
    """Normaliza una ruta relativa a forma canonica."""
    return os.path.normpath(path.replace("\\", "/")).replace(os.sep, "/")


def content_hash(path: str) -> Optional[str]:
    """SHA-256 corto (16 hex) del contenido del archivo."""
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()[:16]
    except OSError:
        return None


def file_id(root: str, relpath: str) -> str:
    """FileId canonico: root + relativa normalizada (sin el root absoluto
    fisico, para que sea portable entre maquinas)."""
    return _norm_rel(relpath)


def build_index(root: str) -> Dict[str, Dict[str, str]]:
    """Indice del arbol bajo root: ruta relativa normalizada ->
    {path: abs, hash: sha256-16}."""
    idx: Dict[str, Dict[str, str]] = {}
    for d, _sd, fs in os.walk(root):
        for f in fs:
            full = os.path.join(d, f)
            rel = os.path.relpath(full, root).replace("\\", "/")
            h = content_hash(full)
            if h is not None:
                idx[rel] = {"path": full, "hash": h}
    return idx


# cache simple de indices por root (los lotes resuelven cientos de
# findings sobre el mismo arbol: sin cache seria O(n x arbol))
_INDEX_CACHE: Dict[str, Dict[str, Dict[str, str]]] = {}


def cached_index(root: str,
                 refresh: bool = False) -> Dict[str, Dict[str, str]]:
    key = os.path.abspath(root)
    if refresh or key not in _INDEX_CACHE:
        # limite de memoria: conservamos los ultimos 8 roots
        if len(_INDEX_CACHE) >= 8:
            _INDEX_CACHE.pop(next(iter(_INDEX_CACHE)))
        _INDEX_CACHE[key] = build_index(root)
    return _INDEX_CACHE[key]


def resolve(root: str, relpath: str,
            index: Optional[Dict[str, Dict[str, str]]] = None
            ) -> Dict[str, str]:
    """Resuelve un archivo por identidad canonica.

    Retorna: {file_id, path, hash, integrity}
      - integrity OK: match por ruta relativa exacta, hash verificado
      - integrity AMBIGUO: solo hubo match por basename (ambiguedad
        real; el basename NO es identidad)
      - integrity FAILURE: no existe
    """
    rel = _norm_rel(relpath)
    idx = index if index is not None else cached_index(root)
    out = {"file_id": rel, "path": "", "hash": "", "integrity": INTEGRITY_FAILURE}
    if rel in idx:
        out.update(path=idx[rel]["path"], hash=idx[rel]["hash"],
                   integrity=INTEGRITY_OK)
        return out
    # fallback por basename: NO es identidad; se marca ambiguo para que
    # el veredicto alto quede bloqueado (nunca otra vez "el ultimo del
    # os.walk": se listan TODAS las coincidencias y se exige unicidad)
    base = rel.rsplit("/", 1)[-1]
    matches = [k for k in idx if k.rsplit("/", 1)[-1] == base]
    if len(matches) == 1:
        k = matches[0]
        out.update(file_id=k, path=idx[k]["path"], hash=idx[k]["hash"],
                   integrity=INTEGRITY_AMBIGUOUS)
    return out


def verify(path: str, expected_hash: Optional[str]) -> str:
    """Verifica que el contenido actual coincida con el testigo.

    Retorna INTEGRITY_OK / INTEGRITY_FAILURE. Sin testigo esperado no
    hay nada que verificar (retorna OK con hash actual: es el caso de
    primera observacion, donde el testigo se ESTABLECE).
    """
    h = content_hash(path)
    if h is None:
        return INTEGRITY_FAILURE
    if expected_hash is None or expected_hash == h:
        return INTEGRITY_OK
    return INTEGRITY_FAILURE


def blocks_demostrado(integrity: str) -> bool:
    """Regla de integridad para el JUEZ: un finding cuya resolucion no
    es OK no puede alcanzar DEMOSTRADO-ESTATICO."""
    return integrity != INTEGRITY_OK


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 3:
        print("uso: semantic_core.py <root> <relpath>")
        sys.exit(1)
    print(json.dumps(resolve(sys.argv[1], sys.argv[2]), indent=1))
