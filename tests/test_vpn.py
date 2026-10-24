"""Pruebas de las simulaciones VPN."""

import json

import pytest

from aaa import logger as logger_module
from ipsec.paquete_ip import PaqueteIP
from vpn.acceso_remoto import GatewayAccesoRemoto
from vpn.sitio_a_sitio import GatewaySitio, crear_tunel


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    ruta = tmp_path / "aaa.log"
    monkeypatch.setattr(logger_module, "_configuracion", None)
    logger_module._logger.handlers.clear()
    logger_module.configurar_logger(ruta, consola=False)
    return ruta


def eventos(ruta):
    return [json.loads(linea) for linea in ruta.read_text().splitlines()]


def test_acceso_remoto_autentica_asigna_ip_y_aplica_rol(log_path):
    gateway = GatewayAccesoRemoto(red_virtual="10.250.0.0/30")
    sesion = gateway.conectar("empleado", "Empleado123!", "192.0.2.10")

    assert sesion.ip_virtual == "10.250.0.1"
    assert gateway.autorizar(sesion.token, "base_datos_consulta", "10.250.0.1")
    assert not gateway.autorizar(sesion.token, "intranet_publica", "10.250.0.1")
    assert eventos(log_path)[-1]["resultado"] == "RECHAZADO"


def test_acceso_remoto_login_incorrecto(log_path):
    gateway = GatewayAccesoRemoto()

    with pytest.raises(PermissionError, match="Credenciales"):
        gateway.conectar("empleado", "incorrecta", "192.0.2.11")

    assert eventos(log_path)[-1]["accion"] == "AUTENTICAR"
    assert eventos(log_path)[-1]["resultado"] == "RECHAZADO"


def test_acceso_remoto_protege_trafico_autorizado():
    gateway = GatewayAccesoRemoto()
    sesion = gateway.conectar("empleado", "Empleado123!", "192.0.2.12")
    paquete = PaqueteIP(sesion.ip_virtual, "10.20.0.5", "TCP", b"consulta")

    protegido = gateway.proteger_trafico(
        sesion.token, "base_datos_consulta", paquete, sesion.ip_virtual
    )
    assert protegido.payload != paquete.payload


def test_sitio_a_sitio_solo_enruta_redes_del_tunel():
    gateway_a = GatewaySitio("A", "10.1.0.0/24", "198.51.100.1", "clave-demo")
    gateway_b = GatewaySitio("B", "10.2.0.0/24", "198.51.100.2", "clave-demo")
    crear_tunel(gateway_a, gateway_b)
    entre_redes = PaqueteIP("10.1.0.10", "10.2.0.20", "TCP", b"datos")
    fuera_de_redes = PaqueteIP("10.1.0.10", "203.0.113.20", "TCP", b"datos")

    encapsulado = gateway_a.enrutar(entre_redes)

    assert encapsulado is not None
    assert gateway_b.recibir(encapsulado) == entre_redes
    assert gateway_a.enrutar(fuera_de_redes) is None


def test_sitio_a_sitio_rechaza_clave_incorrecta():
    gateway_a = GatewaySitio("A", "10.1.0.0/24", "198.51.100.1", "clave-a")
    gateway_b = GatewaySitio("B", "10.2.0.0/24", "198.51.100.2", "clave-b")

    with pytest.raises(PermissionError):
        crear_tunel(gateway_a, gateway_b)
