"""Modo túnel: cifra el paquete IP completo entre gateways."""

from __future__ import annotations

from .antireplay import VentanaAntiReplay
from .esp import PaqueteESP
from .paquete_ip import PaqueteIP


def encapsular(
    paquete: PaqueteIP,
    clave: bytes,
    spi: int,
    numero_secuencia: int,
    ip_gateway_origen: str,
    ip_gateway_destino: str,
) -> PaqueteIP:
    esp = PaqueteESP.cifrar(
        paquete.serializar(), clave, spi, numero_secuencia
    )
    return PaqueteIP(ip_gateway_origen, ip_gateway_destino, "ESP", esp.serializar())


def desencapsular(
    paquete: PaqueteIP, clave: bytes, ventana: VentanaAntiReplay | None = None
) -> PaqueteIP:
    esp = PaqueteESP.deserializar(paquete.payload)
    contenido = esp.descifrar(clave)
    if ventana is not None and not ventana.aceptar(esp.numero_secuencia):
        raise ValueError("Paquete ESP rechazado por anti-replay")
    return PaqueteIP.deserializar(contenido)


proteger = encapsular
desproteger = desencapsular
