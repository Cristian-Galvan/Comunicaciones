"""Registro estructurado de eventos de autenticación y autorización."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_NOMBRE_LOGGER = "aaa.auditoria"
_logger = logging.getLogger(_NOMBRE_LOGGER)
_logger.setLevel(logging.INFO)
_logger.propagate = False
_configuracion: tuple[Path, bool] | None = None


def configurar_logger(ruta: str | Path = "logs/aaa.log", consola: bool = True) -> None:
    """Configura el archivo de auditoría y, opcionalmente, la salida de consola."""
    global _configuracion
    ruta_log = Path(ruta)
    configuracion = (ruta_log.resolve(), consola)
    if _configuracion == configuracion:
        return

    for handler in _logger.handlers[:]:
        handler.close()
        _logger.removeHandler(handler)
    ruta_log.parent.mkdir(parents=True, exist_ok=True)
    archivo = logging.FileHandler(ruta_log, encoding="utf-8")
    archivo.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(archivo)
    if consola:
        consola_handler = logging.StreamHandler(sys.stdout)
        consola_handler.setFormatter(logging.Formatter("%(message)s"))
        _logger.addHandler(consola_handler)
    _configuracion = configuracion


def registrar_evento(
    usuario: str,
    ip_origen: str,
    accion: str,
    recurso: str,
    resultado: str,
) -> None:
    """Registra un evento con los campos de auditoría establecidos por el proyecto."""
    if not _logger.handlers:
        configurar_logger()
    evento: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "usuario": usuario,
        "ip_origen": ip_origen,
        "accion": accion,
        "recurso": recurso,
        "resultado": resultado,
    }
    _logger.info(json.dumps(evento, ensure_ascii=True))
