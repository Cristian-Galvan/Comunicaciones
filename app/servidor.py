"""Servidor TCP multihilo para la demostración de comunicaciones seguras."""

from __future__ import annotations

import argparse
import shlex
import socket
import socketserver
import ssl
import sys
from pathlib import Path

from aaa import auth, authz
from aaa.logger import configurar_logger, registrar_evento

_MAX_LINEA = 64 * 1024


def crear_contexto_tls(certificado: Path, llave: Path) -> ssl.SSLContext:
    """Crea el contexto TLS del servidor, permitiendo únicamente TLS 1.2 o superior."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.load_cert_chain(certfile=str(certificado), keyfile=str(llave))
    return contexto


def procesar_comando(
    linea: str,
    usuario: str | None,
    ip_origen: str,
) -> tuple[str, str | None, bool]:
    """Procesa una línea y devuelve respuesta, usuario actualizado y continuidad."""
    texto = linea.rstrip("\r\n")
    if not texto:
        return "ERR comando_vacio\n", usuario, True

    try:
        partes = shlex.split(texto)
    except ValueError:
        return "ERR sintaxis_invalida\n", usuario, True

    comando = partes[0].upper()
    if comando == "LOGIN":
        if len(partes) != 3:
            return "ERR uso_LOGIN\n", usuario, True
        usuario_login, contraseña = partes[1:]
        if auth.autenticar(usuario_login, contraseña, ip_origen):
            return "OK LOGIN\n", usuario_login, True
        return "ERR LOGIN credenciales_invalidas\n", None, True

    if comando == "GET":
        if len(partes) != 2:
            return "ERR uso_GET\n", usuario, True
        if usuario is None:
            return "ERR AUTENTICACION requerida\n", usuario, True
        recurso = partes[1]
        if authz.autorizar(usuario, recurso, "consultar", ip_origen):
            return f"OK GET {recurso}\n", usuario, True
        return "ERR AUTORIZACION denegada\n", usuario, True

    if comando == "ECHO":
        mensaje = texto[len(texto.split(maxsplit=1)[0]) :].lstrip()
        registrar_evento(usuario or "anonimo", ip_origen, "ECHO", "echo", "PERMITIDO")
        return f"OK ECHO {mensaje}\n", usuario, True

    if comando == "QUIT":
        return "OK BYE\n", usuario, False

    return "ERR comando_desconocido\n", usuario, True


class _Servidor(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """TCPServer con una configuración TLS opcional compartida por sus hilos."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        direccion: tuple[str, int],
        contexto_tls: ssl.SSLContext | None,
    ) -> None:
        self.contexto_tls = contexto_tls
        super().__init__(direccion, _Manejador)


class _Manejador(socketserver.BaseRequestHandler):
    """Atiende comandos de un cliente hasta ``QUIT`` o el cierre del socket."""

    def handle(self) -> None:
        conexion: socket.socket = self.request
        if self.server.contexto_tls is not None:
            try:
                conexion = self.server.contexto_tls.wrap_socket(
                    conexion, server_side=True
                )
            except ssl.SSLError as exc:
                print(f"Handshake TLS rechazado desde {self.client_address[0]}: {exc}")
                return

        usuario: str | None = None
        ip_origen = self.client_address[0]
        try:
            archivo_entrada = conexion.makefile("r", encoding="utf-8", newline="\n")
            while True:
                linea = archivo_entrada.readline(_MAX_LINEA)
                if not linea:
                    break
                if len(linea) >= _MAX_LINEA and not linea.endswith("\n"):
                    conexion.sendall(b"ERR linea_demasiado_larga\n")
                    break
                respuesta, usuario, continuar = procesar_comando(
                    linea, usuario, ip_origen
                )
                conexion.sendall(respuesta.encode("utf-8"))
                if not continuar:
                    break
        finally:
            if conexion is not self.request:
                conexion.close()


def crear_parser() -> argparse.ArgumentParser:
    """Construye el parser de línea de comandos del servidor."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modo", choices=("plano", "tls"), required=True)
    parser.add_argument(
        "--host",
        "--ip",
        dest="host",
        default="0.0.0.0",
        help="IP de escucha",
    )
    parser.add_argument("--puerto", type=int, required=True)
    parser.add_argument("--cert", type=Path, default=Path("pki/out/servidor.crt"))
    parser.add_argument("--key", type=Path, default=Path("pki/out/servidor.key.pem"))
    parser.add_argument("--log", type=Path, default=Path("logs/aaa.log"))
    return parser


def main(argv: list[str] | None = None) -> int:
    """Inicia el servidor y permanece atendiendo conexiones."""
    args = crear_parser().parse_args(argv)
    configurar_logger(args.log)
    contexto = (
        crear_contexto_tls(args.cert, args.key) if args.modo == "tls" else None
    )
    with _Servidor((args.host, args.puerto), contexto) as servidor:
        print(f"Servidor {args.modo} escuchando en {args.host}:{args.puerto}")
        try:
            servidor.serve_forever()
        except KeyboardInterrupt:
            print("\nServidor detenido.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
