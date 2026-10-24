"""Demostración legible de aceptación y rechazo anti-replay."""

from aaa import logger as aaa_logger

from .antireplay import VentanaAntiReplay


def main() -> None:
    aaa_logger.configurar_logger("logs/aaa.log", consola=False)
    ventana = VentanaAntiReplay("demo-ipsec")
    print("IPSec / ventana anti-replay (64 secuencias)")
    for secuencia in (10, 12, 11, 12, 0, 1):
        resultado = ventana.aceptar(secuencia)
        estado = "ACEPTADA" if resultado else "RECHAZADA"
        print(f"  secuencia {secuencia:>2}: {estado}")


if __name__ == "__main__":
    main()
