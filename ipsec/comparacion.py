"""Salida didáctica de la diferencia entre transporte y túnel."""

from __future__ import annotations

from .modo_transporte import proteger as proteger_transporte
from .modo_tunel import encapsular as encapsular_tunel
from .paquete_ip import PaqueteIP


def mostrar_comparacion() -> None:
    """Imprime lado a lado los campos visibles para un observador."""
    clave = b"0123456789abcdef0123456789abcdef"
    original = PaqueteIP("10.0.0.10", "10.0.0.20", "TCP", b"mensaje secreto")
    transporte = proteger_transporte(original, clave, 7, 1)
    tunel = encapsular_tunel(original, clave, 7, 1, "198.51.100.1", "198.51.100.2")
    print("OBSERVADOR             TRANSPORTE                 TÚNEL")
    print(f"IP origen              {transporte.ip_origen:<27} {tunel.ip_origen}")
    print(f"IP destino             {transporte.ip_destino:<27} {tunel.ip_destino}")
    print(f"Cabecera visible       original                  gateways")
    print(f"Payload visible        ESP cifrado               ESP cifrado (IP completo)")
