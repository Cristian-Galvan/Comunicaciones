"""Simulación de una VPN de acceso remoto con AAA e IPsec."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

from aaa import auth
from aaa import logger as aaa_logger
from ipsec.modo_transporte import proteger
from ipsec.paquete_ip import PaqueteIP

_POLITICAS = Path(__file__).with_name("politicas.json")


@dataclass(frozen=True)
class SesionVPN:
    """Identidad y direccion virtual asignadas a una conexión."""

    usuario: str
    rol: str
    token: str
    ip_virtual: str
    expira: datetime

    @property
    def activa(self) -> bool:
        """Indica si la sesión todavía no ha expirado."""
        return datetime.now(timezone.utc) < self.expira


class GatewayAccesoRemoto:
    """Gateway que autentica usuarios y aplica una política por solicitud."""

    def __init__(
        self,
        *,
        red_virtual: str = "10.250.0.0/24",
        duracion: timedelta = timedelta(hours=8),
        clave: bytes = b"0123456789abcdef0123456789abcdef",
        spi: int = 100,
        politicas: str | Path = _POLITICAS,
    ) -> None:
        self.red_virtual = IPv4Network(red_virtual)
        self.duracion = duracion
        self.clave = clave
        self.spi = spi
        self._politica = self._cargar_politica(politicas)
        self._sesiones: dict[str, SesionVPN] = {}
        self._asignadas: set[IPv4Address] = set()
        self._secuencia = 0

    @staticmethod
    def _cargar_politica(ruta: str | Path) -> dict[str, Any]:
        with Path(ruta).open(encoding="utf-8") as archivo:
            politica = json.load(archivo)
        if not isinstance(politica.get("roles"), dict):
            raise ValueError("La política VPN debe definir roles")
        return politica

    def conectar(self, usuario: str, contraseña: str, ip_origen: str) -> SesionVPN:
        """Autentica y crea una sesión con token, expiración e IP virtual."""
        if not auth.autenticar(usuario, contraseña, ip_origen):
            raise PermissionError("Credenciales rechazadas")
        rol = self._rol_de_usuario(usuario)
        ip_virtual = self._asignar_ip()
        sesion = SesionVPN(
            usuario,
            rol,
            secrets.token_urlsafe(32),
            str(ip_virtual),
            datetime.now(timezone.utc) + self.duracion,
        )
        self._sesiones[sesion.token] = sesion
        aaa_logger.registrar_evento(
            usuario, ip_origen, "CONECTAR_VPN", "vpn", "PERMITIDO"
        )
        return sesion

    def desconectar(self, token: str) -> None:
        """Invalida una sesión y devuelve su IP virtual al pool."""
        sesion = self._sesiones.pop(token, None)
        if sesion is not None:
            self._asignadas.discard(IPv4Address(sesion.ip_virtual))

    def autorizar(self, token: str, recurso: str, ip_origen: str) -> bool:
        """Autoriza una solicitud aun cuando la sesión ya esté conectada."""
        sesion = self._sesion_activa(token, ip_origen)
        recursos = self._politica["roles"].get(sesion.rol, [])
        permitido = "*" in recursos or recurso in recursos
        aaa_logger.registrar_evento(
            sesion.usuario,
            ip_origen,
            "AUTORIZAR_VPN",
            recurso,
            "PERMITIDO" if permitido else "RECHAZADO",
        )
        return permitido

    def solicitar(
        self, token: str, recurso: str, ip_origen: str
    ) -> bool:
        """Alias expresivo para autorizar una solicitud posterior a conectar."""
        return self.autorizar(token, recurso, ip_origen)

    def proteger_trafico(
        self,
        token: str,
        recurso: str,
        paquete: PaqueteIP,
        ip_origen: str,
    ) -> PaqueteIP:
        """Autoriza y protege el paquete cliente en modo transporte."""
        if not self.autorizar(token, recurso, ip_origen):
            raise PermissionError("Recurso VPN no permitido para el rol")
        self._sesion_activa(token, ip_origen)
        self._secuencia += 1
        return proteger(paquete, self.clave, self.spi, self._secuencia)

    def _sesion_activa(self, token: str, ip_origen: str) -> SesionVPN:
        sesion = self._sesiones.get(token)
        if sesion is None or not sesion.activa:
            if sesion is not None:
                self.desconectar(token)
            aaa_logger.registrar_evento(
                "desconocido", ip_origen, "AUTORIZAR_VPN", "vpn", "RECHAZADO"
            )
            raise PermissionError("Sesión VPN inexistente o expirada")
        return sesion

    @staticmethod
    def _rol_de_usuario(usuario: str) -> str:
        ruta = Path(auth.__file__).with_name("usuarios.json")
        with ruta.open(encoding="utf-8") as archivo:
            registro = json.load(archivo).get(usuario)
        if not registro or not registro.get("rol"):
            raise PermissionError("Usuario sin rol VPN")
        return str(registro["rol"])

    def _asignar_ip(self) -> IPv4Address:
        for ip in self.red_virtual.hosts():
            if ip not in self._asignadas:
                self._asignadas.add(ip)
                return ip
        raise RuntimeError("No hay IP virtuales disponibles")


GatewayVPN = GatewayAccesoRemoto
