"""Estado individual por operador/IA.

Un solo repositorio de codigo (compartido via git) puede ser usado por
varias IAs u operadores en paralelo sin pisarse: todo archivo de
ESTADO (avance de caza, ya-auditados, resultados) vive en el
workspace del operador. Por defecto es el propio repo (compatibilidad
total con lo existente); exportando CODEXRC_HOME cada IA tiene el
suyo:

    export CODEXRC_HOME=~/.codexrc_hermes     # cada IA, distinto

    python3 core/hunt_wide.py --shard 0/2    # ademas: repartir corpus
    python3 core/hunt_wide.py --shard 1/2

Regla: el repo guarda CODIGO y datos publicos (data/:
vdp_mapa.json, wide_corpus.json); CODEXRC_HOME guarda HECHOS
propios (hechos/,
resultados). Dos IAs con distintos CODEXRC_HOME no comparten la
cola de "ya auditados" ni se duplican hallazgos.
"""
import os

__all__ = ["home", "hechos", "path", "workdir"]


def home() -> str:
    """Raiz del workspace de ESTADO: $CODEXRC_HOME o el repo mismo."""
    env = os.environ.get("CODEXRC_HOME", "").strip()
    if env:
        os.makedirs(env, exist_ok=True)
        return os.path.abspath(env)
    # default: el repo (parent de core/) -> comportamiento historico
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def hechos(*parts) -> str:
    """Ruta de un archivo de estado dentro de <home>/hechos/."""
    d = os.path.join(home(), "hechos")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, *parts) if parts else d


def path(*parts) -> str:
    """Ruta arbitraria dentro del workspace de estado."""
    return os.path.join(home(), *parts) if parts else home()


def workdir(*parts) -> str:
    """Scratch dir para descargas/descompresion (NUNCA /tmp del SO:
    en varios Termux/Android /tmp es read-only o ni existe). Vive
    bajo <home>/hechos/_work/ -- el mismo arbol donde ya se escriben
    hechos/, asi que si ESO anda, esto tambien anda."""
    d = os.path.join(home(), "hechos", "_work", *parts) if parts \
        else os.path.join(home(), "hechos", "_work")
    os.makedirs(d, exist_ok=True)
    return d
