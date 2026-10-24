"""Autorización basada en roles y una matriz explícita de permisos."""

from __future__ import annotations

import json
from pathlib import Path

from .logger import registrar_evento

_USUARIOS = Path(__file__).with_name("usuarios.json")
PERMISOS: dict[str, dict[str, set[str]]] = {
    "admin": {
        "usuarios": {"consultar", "crear", "modificar", "eliminar"},
        "reportes": {"consultar", "crear"},
        "configuracion": {"leer", "escribir"},
    },
    "empleado": {
        "usuarios": {"consultar"},
        "reportes": {"consultar", "crear"},
    },
    "invitado": {
        "reportes": {"consultar"},
    },
}


def _rol_de(usuario: str) -> str | None:
    with _USUARIOS.open(encoding="utf-8") as archivo:
        usuarios = json.load(archivo)
    registro = usuarios.get(usuario)
    return None if registro is None else registro.get("rol")


def autorizar(
    usuario: str,
    recurso: str,
    accion: str,
    ip_origen: str = "desconocida",
) -> bool:
    """Decide si el rol de ``usuario`` puede ejecutar una acción."""
    rol = _rol_de(usuario)
    permitido = accion in PERMISOS.get(rol or "", {}).get(recurso, set())
    registrar_evento(
        usuario,
        ip_origen,
        "AUTORIZAR",
        recurso,
        "PERMITIDO" if permitido else "RECHAZADO",
    )
    return permitido
