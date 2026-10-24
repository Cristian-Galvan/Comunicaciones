"""Pruebas del módulo AAA."""

import json

import pytest

from aaa import auth, authz
from aaa import logger as logger_module


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    ruta = tmp_path / "aaa.log"
    monkeypatch.setattr(logger_module, "_configuracion", None)
    logger_module._logger.handlers.clear()
    logger_module.configurar_logger(ruta, consola=False)
    return ruta


def eventos(ruta):
    return [json.loads(linea) for linea in ruta.read_text(encoding="utf-8").splitlines()]


def test_login_correcto_y_evento_en_log(log_path):
    assert auth.autenticar("admin", "Admin123!", "192.0.2.1")
    evento = eventos(log_path)[-1]
    assert evento["resultado"] == "PERMITIDO"
    assert evento["accion"] == "AUTENTICAR"


@pytest.mark.parametrize(
    ("usuario", "contraseña"),
    [("admin", "incorrecta"), ("no-existe", "cualquier cosa")],
)
def test_login_rechazado_y_evento_en_log(log_path, usuario, contraseña):
    assert not auth.autenticar(usuario, contraseña, "192.0.2.2")
    assert eventos(log_path)[-1]["resultado"] == "RECHAZADO"


def test_rol_sin_permiso_y_evento_en_log(log_path):
    assert not authz.autorizar("invitado", "configuracion", "escribir", "192.0.2.3")
    evento = eventos(log_path)[-1]
    assert evento["accion"] == "AUTORIZAR"
    assert evento["resultado"] == "RECHAZADO"


def test_rol_con_permiso_y_evento_en_log(log_path):
    assert authz.autorizar("empleado", "reportes", "consultar", "192.0.2.4")
    assert eventos(log_path)[-1]["resultado"] == "PERMITIDO"
