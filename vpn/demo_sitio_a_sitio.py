"""Demostración de túnel sitio a sitio y sus rechazos."""

from ipsec.paquete_ip import PaqueteIP

from .sitio_a_sitio import GatewaySitio, crear_tunel


def main() -> None:
    gateway_a = GatewaySitio("A", "10.1.0.0/24", "198.51.100.1", "clave-demo")
    gateway_b = GatewaySitio("B", "10.2.0.0/24", "198.51.100.2", "clave-demo")
    crear_tunel(gateway_a, gateway_b)
    interno = PaqueteIP("10.1.0.10", "10.2.0.20", "TCP", b"datos A-B")
    externo = PaqueteIP("10.1.0.10", "203.0.113.20", "TCP", b"fuera")
    encapsulado = gateway_a.enrutar(interno)
    print("VPN sitio a sitio")
    print(f"  A -> B por túnel: {gateway_b.recibir(encapsulado) if encapsulado else 'RECHAZADO'}")
    print(f"  tráfico externo fuera: {'RECHAZADO' if gateway_a.enrutar(externo) is None else 'ACEPTADO'}")
    try:
        crear_tunel(
            GatewaySitio("A2", "10.3.0.0/24", "198.51.100.3", "clave-errónea"),
            GatewaySitio("B2", "10.4.0.0/24", "198.51.100.4", "clave-demo"),
        )
    except PermissionError as exc:
        print(f"  PSK errónea: RECHAZADO ({exc})")


if __name__ == "__main__":
    main()
