"""Modo transporte: protege el payload y conserva el encabezado IP."""

from __future__ import annotations

from .antireplay import VentanaAntiReplay
from .esp import PaqueteESP
from .paquete_ip import PaqueteIP


def proteger(
    paquete: PaqueteIP, clave: bytes, spi: int, numero_secuencia: int
) -> PaqueteIP:
    esp = PaqueteESP.cifrar(
        paquete.payload, clave, spi, numero_secuencia
    )
    return PaqueteIP(
        paquete.ip_origen, paquete.ip_destino, paquete.protocolo, esp.serializar()
    )


def desproteger(
    paquete: PaqueteIP, clave: bytes, ventana: VentanaAntiReplay | None = None
) -> PaqueteIP:
    esp = PaqueteESP.deserializar(paquete.payload)
    payload = esp.descifrar(clave)
    if ventana is not None and not ventana.aceptar(esp.numero_secuencia):
        raise ValueError("Paquete ESP rechazado por anti-replay")
    return PaqueteIP(paquete.ip_origen, paquete.ip_destino, paquete.protocolo, payload)


encapsular = proteger
desencapsular = desproteger
