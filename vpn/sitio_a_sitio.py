"""Simulación de una VPN IPsec permanente entre dos redes internas."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from ipsec.modo_tunel import desencapsular, encapsular
from ipsec.paquete_ip import PaqueteIP


def _clave_aes(clave: bytes | str) -> bytes:
    valor = clave.encode("utf-8") if isinstance(clave, str) else clave
    return valor if len(valor) in (16, 24, 32) else hashlib.sha256(valor).digest()


@dataclass
class GatewaySitio:
    """Gateway de una red que no requiere autenticación por equipo."""

    nombre: str
    red_local: str
    ip_gateway: str
    clave_precompartida: bytes | str

    def __post_init__(self) -> None:
        self.red = IPv4Network(self.red_local)
        self.clave = _clave_aes(self.clave_precompartida)
        self.peer: GatewaySitio | None = None
        self.tunel_permanente = False
        self._secuencia = 0

    def establecer_tunel(self, peer: "GatewaySitio") -> None:
        """Levanta una SA permanente si ambos gateways comparten la clave."""
        if self.red.overlaps(peer.red):
            raise ValueError("Las redes del túnel no pueden solaparse")
        if not hmac.compare_digest(self.clave, peer.clave):
            raise PermissionError("Clave precompartida incorrecta")
        self.peer = peer
        peer.peer = self
        self.tunel_permanente = peer.tunel_permanente = True

    def enrutar(self, paquete: PaqueteIP) -> PaqueteIP | None:
        """Encapsula solo paquetes entre la red local y la red del peer."""
        if not self.tunel_permanente or self.peer is None:
            return None
        if (
            IPv4Address(paquete.ip_origen) not in self.red
            or IPv4Address(paquete.ip_destino) not in self.peer.red
        ):
            return None
        self._secuencia += 1
        return encapsular(
            paquete,
            self.clave,
            spi=200,
            numero_secuencia=self._secuencia,
            ip_gateway_origen=self.ip_gateway,
            ip_gateway_destino=self.peer.ip_gateway,
        )

    def recibir(self, paquete: PaqueteIP) -> PaqueteIP:
        """Desencapsula un paquete recibido desde el gateway enlazado."""
        if not self.tunel_permanente or self.peer is None:
            raise ConnectionError("El túnel no está establecido")
        if (
            paquete.ip_origen != self.peer.ip_gateway
            or paquete.ip_destino != self.ip_gateway
        ):
            raise ValueError("Paquete fuera del túnel sitio a sitio")
        resultado = desencapsular(paquete, self.clave)
        if (
            IPv4Address(resultado.ip_origen) not in self.peer.red
            or IPv4Address(resultado.ip_destino) not in self.red
        ):
            raise ValueError("Paquete fuera de las redes del túnel")
        return resultado

    transmitir = enrutar


def crear_tunel(
    gateway_a: GatewaySitio, gateway_b: GatewaySitio
) -> None:
    """Configura el túnel permanente en ambos extremos."""
    gateway_a.establecer_tunel(gateway_b)


GatewayVPNsitio = GatewaySitio
