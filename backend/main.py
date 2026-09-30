"""Compatibilidad para instalaciones antiguas.

El backend oficial es Flask y vive en :mod:`backend.app`. Este módulo evita
mantener una segunda implementación incompatible con Termux.
"""

from .app import app

__all__ = ["app"]
