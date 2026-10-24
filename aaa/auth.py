"""Autenticación de usuarios mediante hashes salados scrypt."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .logger import registrar_evento

_USUARIOS = Path(__file__).with_name("usuarios.json")
_HASH_SIMULADO = b"\0" * 64


def _cargar_usuarios() -> dict[str, dict[str, Any]]:
    with _USUARIOS.open(encoding="utf-8") as archivo:
        datos = json.load(archivo)
    return datos


def autenticar(
    usuario: str,
    contraseña: str,
    ip_origen: str = "desconocida",
) -> bool:
    """Valida credenciales; devuelve ``True`` solo cuando son correctas.

    Esta función solo autentica identidad. Las decisiones sobre recursos y
    acciones pertenecen a :func:`aaa.authz.autorizar`.
    """
    usuarios = _cargar_usuarios()
    registro = usuarios.get(usuario)
    if registro is None:
        esperado = _HASH_SIMULADO
        salt = b"\0" * 16
        parametros = {"n": 16384, "r": 8, "p": 1}
    else:
        esperado = base64.b64decode(registro["hash"])
        salt = base64.b64decode(registro["salt"])
        parametros = registro

    calculado = hashlib.scrypt(
        contraseña.encode("utf-8"),
        salt=salt,
        n=parametros["n"],
        r=parametros["r"],
        p=parametros["p"],
        dklen=len(esperado),
    )
    valido = registro is not None and hmac.compare_digest(calculado, esperado)
    registrar_evento(
        usuario,
        ip_origen,
        "AUTENTICAR",
        "credenciales",
        "PERMITIDO" if valido else "RECHAZADO",
    )
    return valido
