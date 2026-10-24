"""Pruebas de la simulación didáctica de ESP."""

import json

import pytest

from aaa import logger as logger_module
from ipsec.antireplay import VentanaAntiReplay
from ipsec.comparacion import mostrar_comparacion
from ipsec.modo_transporte import desproteger, proteger
from ipsec.modo_tunel import desencapsular, encapsular
from ipsec.paquete_ip import PaqueteIP


CLAVE = b"0123456789abcdef0123456789abcdef"


@pytest.fixture
def paquete():
    return PaqueteIP("10.0.0.10", "10.0.0.20", "TCP", b"datos privados")


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    ruta = tmp_path / "aaa.log"
    monkeypatch.setattr(logger_module, "_configuracion", None)
    logger_module._logger.handlers.clear()
    logger_module.configurar_logger(ruta, consola=False)
    return ruta


def test_ida_y_vuelta_en_transporte(paquete):
    protegido = proteger(paquete, CLAVE, 10, 1)
    assert protegido.ip_origen == paquete.ip_origen
    assert protegido.ip_destino == paquete.ip_destino
    assert protegido.protocolo == paquete.protocolo
    assert desproteger(protegido, CLAVE) == paquete


def test_ida_y_vuelta_en_tunel(paquete):
    protegido = encapsular(paquete, CLAVE, 10, 1, "198.51.100.1", "198.51.100.2")
    assert (protegido.ip_origen, protegido.ip_destino) == (
        "198.51.100.1",
        "198.51.100.2",
    )
    assert desencapsular(protegido, CLAVE) == paquete


def test_paquete_manipulado_rechazado(paquete):
    protegido = proteger(paquete, CLAVE, 10, 1)
    manipulado = PaqueteIP(
        protegido.ip_origen,
        protegido.ip_destino,
        protegido.protocolo,
        protegido.payload[:-1] + bytes([protegido.payload[-1] ^ 1]),
    )
    with pytest.raises(ValueError, match="etiqueta"):
        desproteger(manipulado, CLAVE)


def test_antireplay_duplicado_y_antiguo_registra_rechazos(log_path):
    ventana = VentanaAntiReplay("10.0.0.10")
    assert ventana.aceptar(100)
    assert not ventana.aceptar(100)
    assert not ventana.aceptar(36)
    eventos = [json.loads(linea) for linea in log_path.read_text().splitlines()]
    assert len(eventos) == 2
    assert all(evento["resultado"] == "RECHAZADO" for evento in eventos)


def test_antireplay_fuera_de_orden_en_ventana():
    ventana = VentanaAntiReplay()
    assert ventana.aceptar(10)
    assert ventana.aceptar(12)
    assert ventana.aceptar(11)


def test_comparacion_es_legible(capsys):
    mostrar_comparacion()
    salida = capsys.readouterr().out
    assert "TRANSPORTE" in salida
    assert "TÚNEL" in salida
    assert "gateways" in salida
