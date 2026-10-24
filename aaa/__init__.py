"""Autenticación, autorización y registro de auditoría."""

from .auth import autenticar
from .authz import autorizar

__all__ = ["autenticar", "autorizar"]