"""Simulación didáctica de ESP en modo transporte y modo túnel."""

from .esp import PaqueteESP
from .paquete_ip import PaqueteIP
from .comparacion import mostrar_comparacion

__all__ = ["PaqueteESP", "PaqueteIP", "mostrar_comparacion"]