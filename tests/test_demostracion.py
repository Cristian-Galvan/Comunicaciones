"""Suite de los nueve puntos de demostración del proyecto."""

from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ipsec.antireplay import VentanaAntiReplay
from ipsec.modo_transporte import desproteger, proteger
from ipsec.modo_tunel import desencapsular, encapsular
from ipsec.paquete_ip import PaqueteIP
from vpn.acceso_remoto import GatewayAccesoRemoto

CLAVE = b"0123456789abcdef0123456789abcdef"
ROOT = Path(__file__).parents[1]


def _crear_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA de prueba")])
    certificado = (
        x509.CertificateBuilder()
        .subject_name(nombre)
        .issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(clave.public_key()), critical=False)
        .sign(clave, hashes.SHA256())
    )
    return clave, certificado


def _crear_certificado(
    clave_ca: rsa.RSAPrivateKey,
    ca: x509.Certificate,
    *,
    hostname: str,
    firmado_por_ca: bool = True,
    expirado: bool = False,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sujeto = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    if firmado_por_ca:
        emisor, clave_firma = ca.subject, clave_ca
    else:
        emisor, clave_firma = sujeto, clave
    ahora = datetime.now(timezone.utc)
    inicio = ahora - timedelta(days=2) if expirado else ahora - timedelta(minutes=1)
    fin = ahora - timedelta(days=1) if expirado else ahora + timedelta(days=1)
    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeto)
        .issuer_name(emisor)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(inicio)
        .not_valid_after(fin)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca.public_key() if firmado_por_ca else clave.public_key()
            ),
            critical=False,
        )
        .sign(clave_firma, hashes.SHA256())
    )
    return clave, certificado


def _guardar_certificado(
    ruta: Path, clave: rsa.RSAPrivateKey, certificado: x509.Certificate
) -> None:
    ruta.with_suffix(".key.pem").write_bytes(
        clave.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ruta.write_bytes(certificado.public_bytes(serialization.Encoding.PEM))


def _handshake_tls(
    ca: Path, certificado: Path, clave: Path, hostname: str
) -> BaseException | None:
    servidor = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    servidor.load_cert_chain(certificado, clave)
    cliente = ssl.create_default_context(cafile=ca)
    izquierdo, derecho = socket.socketpair()
    error_servidor: list[BaseException] = []

    def aceptar() -> None:
        try:
            with servidor.wrap_socket(derecho, server_side=True) as conexion:
                conexion.do_handshake()
        except BaseException as error:  # El cliente recibe el error relevante.
            error_servidor.append(error)

    hilo = threading.Thread(target=aceptar, daemon=True)
    hilo.start()
    error_cliente: BaseException | None = None
    try:
        with cliente.wrap_socket(izquierdo, server_hostname=hostname) as conexion:
            conexion.do_handshake()
    except BaseException as error:
        error_cliente = error
    hilo.join(timeout=5)
    assert not hilo.is_alive(), "el handshake TLS no terminó"
    return error_cliente


@pytest.fixture
def certificados_tls(tmp_path: Path) -> dict[str, Path]:
    clave_ca, ca = _crear_ca()
    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    clave_valida, valida = _crear_certificado(
        clave_ca, ca, hostname="servidor.demo.test"
    )
    valida_path = tmp_path / "valida.crt"
    _guardar_certificado(valida_path, clave_valida, valida)

    clave_expirada, expirada = _crear_certificado(
        clave_ca, ca, hostname="servidor.demo.test", expirado=True
    )
    expirada_path = tmp_path / "expirada.crt"
    _guardar_certificado(expirada_path, clave_expirada, expirada)

    otra_clave_ca, otra_ca = _crear_ca()
    clave_otra, otra = _crear_certificado(
        otra_clave_ca, otra_ca, hostname="servidor.demo.test"
    )
    otra_path = tmp_path / "otra.crt"
    _guardar_certificado(otra_path, clave_otra, otra)

    clave_hostname, hostname = _crear_certificado(
        clave_ca, ca, hostname="nombre.incorrecto"
    )
    hostname_path = tmp_path / "hostname.crt"
    _guardar_certificado(hostname_path, clave_hostname, hostname)
    return {
        "ca": ca_path,
        "valida": valida_path,
        "valida_key": valida_path.with_suffix(".key.pem"),
        "expirada": expirada_path,
        "expirada_key": expirada_path.with_suffix(".key.pem"),
        "otra": otra_path,
        "otra_key": otra_path.with_suffix(".key.pem"),
        "hostname": hostname_path,
        "hostname_key": hostname_path.with_suffix(".key.pem"),
    }


def test_01_tls_valido(certificados_tls: dict[str, Path]) -> None:
    assert _handshake_tls(
        certificados_tls["ca"],
        certificados_tls["valida"],
        certificados_tls["valida_key"],
        "servidor.demo.test",
    ) is None


@pytest.mark.parametrize("cert", ["expirada", "hostname"])
def test_02_rechazo_de_certificados_invalidos(
    certificados_tls: dict[str, Path], cert: str
) -> None:
    assert isinstance(
        _handshake_tls(
            certificados_tls["ca"],
            certificados_tls[cert],
            certificados_tls[f"{cert}_key"],
            "servidor.demo.test",
        ),
        ssl.SSLError,
    )


def test_03_cadena_de_confianza(certificados_tls: dict[str, Path]) -> None:
    assert isinstance(
        _handshake_tls(
            certificados_tls["ca"],
            certificados_tls["otra"],
            certificados_tls["otra_key"],
            "servidor.demo.test",
        ),
        ssl.SSLError,
    )


def test_04_ssh_autorizado_y_no_autorizado() -> None:
    configuracion = (ROOT / "ssh" / "sshd_config.ejemplo").read_text(encoding="utf-8")
    directivas = dict(
        linea.split(maxsplit=1)
        for linea in configuracion.splitlines()
        if linea and not linea.startswith("#") and len(linea.split(maxsplit=1)) == 2
    )
    assert directivas["AllowUsers"] == "sshadmin"
    assert "sshintruso" not in directivas["AllowUsers"]
    assert directivas["PubkeyAuthentication"] == "yes"


def test_05_ipsec_transporte() -> None:
    paquete = PaqueteIP("10.0.0.10", "10.0.0.20", "TCP", b"datos privados")
    protegido = proteger(paquete, CLAVE, 10, 1)
    assert (protegido.ip_origen, protegido.ip_destino) == (
        paquete.ip_origen,
        paquete.ip_destino,
    )
    assert desproteger(protegido, CLAVE) == paquete


def test_06_ipsec_tunel() -> None:
    paquete = PaqueteIP("10.0.0.10", "10.0.0.20", "TCP", b"datos privados")
    protegido = encapsular(paquete, CLAVE, 10, 1, "198.51.100.1", "198.51.100.2")
    assert (protegido.ip_origen, protegido.ip_destino) == (
        "198.51.100.1",
        "198.51.100.2",
    )
    assert desencapsular(protegido, CLAVE) == paquete


def test_07_replay_detectado() -> None:
    ventana = VentanaAntiReplay()
    assert ventana.aceptar(7)
    assert not ventana.aceptar(7)


def test_08_vpn_acceso_remoto() -> None:
    gateway = GatewayAccesoRemoto(red_virtual="10.250.0.0/30")
    sesion = gateway.conectar("empleado", "Empleado123!", "192.0.2.10")
    assert sesion.ip_virtual == "10.250.0.1"
    assert gateway.autorizar(sesion.token, "base_datos_consulta", sesion.ip_virtual)


def test_09_restriccion_posterior_a_la_conexion() -> None:
    gateway = GatewayAccesoRemoto()
    sesion = gateway.conectar("empleado", "Empleado123!", "192.0.2.11")
    assert not gateway.autorizar(sesion.token, "intranet_publica", sesion.ip_virtual)
