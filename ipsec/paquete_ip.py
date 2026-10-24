"""Modelo mínimo de un paquete IP para la simulación didáctica."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass


@dataclass(frozen=True)
class PaqueteIP:
    """Representa solo los campos necesarios para observar IPsec."""

    ip_origen: str
    ip_destino: str
    protocolo: str
    payload: bytes

    def serializar(self) -> bytes:
        """Serializa el paquete de forma independiente del sistema."""
        documento = {
            "ip_origen": self.ip_origen,
            "ip_destino": self.ip_destino,
            "protocolo": self.protocolo,
            "payload": base64.b64encode(self.payload).decode("ascii"),
        }
        return json.dumps(
            documento, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def deserializar(cls, datos: bytes) -> "PaqueteIP":
        """Reconstruye un paquete IP simulado serializado."""
        documento = json.loads(datos.decode("utf-8"))
        return cls(
            ip_origen=str(documento["ip_origen"]),
            ip_destino=str(documento["ip_destino"]),
            protocolo=str(documento["protocolo"]),
            payload=base64.b64decode(documento["payload"], validate=True),
        )

    to_bytes = serializar
    from_bytes = deserializar
