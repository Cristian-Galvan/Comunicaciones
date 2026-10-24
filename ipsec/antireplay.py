"""Ventana deslizante anti-replay de 64 números de secuencia."""

from __future__ import annotations

from aaa import logger as aaa_logger


class VentanaAntiReplay:
    """Acepta secuencias nuevas y registra cada descarte."""

    TAMAÑO = 64

    def __init__(self, ip_origen: str = "desconocida") -> None:
        self.ip_origen = ip_origen
        self._maximo = 0
        self._bitmap = 0

    @property
    def maximo_recibido(self) -> int:
        return self._maximo

    def aceptar(self, numero_secuencia: int) -> bool:
        """Devuelve si la secuencia puede procesarse una sola vez."""
        if numero_secuencia <= 0:
            self._rechazar(numero_secuencia, "secuencia no positiva")
            return False
        if self._maximo == 0:
            self._maximo, self._bitmap = numero_secuencia, 1
            return True
        if numero_secuencia > self._maximo:
            desplazamiento = numero_secuencia - self._maximo
            self._bitmap = (
                1 if desplazamiento >= self.TAMAÑO else
                ((self._bitmap << desplazamiento) | 1) & ((1 << self.TAMAÑO) - 1)
            )
            self._maximo = numero_secuencia
            return True
        desplazamiento = self._maximo - numero_secuencia
        if desplazamiento >= self.TAMAÑO:
            self._rechazar(numero_secuencia, "fuera de la ventana")
            return False
        mascara = 1 << desplazamiento
        if self._bitmap & mascara:
            self._rechazar(numero_secuencia, "duplicado")
            return False
        self._bitmap |= mascara
        return True

    def _rechazar(self, secuencia: int, motivo: str) -> None:
        aaa_logger.registrar_evento(
            usuario="ipsec",
            ip_origen=self.ip_origen,
            accion="ANTIREPLAY",
            recurso=f"secuencia:{secuencia} ({motivo})",
            resultado="RECHAZADO",
        )
