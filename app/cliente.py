"""Cliente TCP para probar los modos plano y TLS del servidor."""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
from pathlib import Path

_MAX_LINEA = 64 * 1024


def crear_contexto_tls(ca: Path) -> ssl.SSLContext:
    """Crea un cliente TLS confiando exclusivamente en ``ca``."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.verify_mode = ssl.CERT_REQUIRED
    contexto.check_hostname = True
    contexto.load_verify_locations(cafile=str(ca))
    return contexto


def _texto_campo(certificado: dict, campo: str) -> str:
    valores = certificado.get(campo, ())
    return ", ".join(f"{clave}={valor}" for entrada in valores for clave, valor in entrada)


def mostrar_detalles_tls(conexion: ssl.SSLSocket) -> None:
    """Imprime información verificable del canal y del certificado remoto."""
    certificado = conexion.getpeercert()
    print(f"TLS: {conexion.version()}")
    print(f"Cipher suite: {conexion.cipher()[0]}")
    print(f"Emisor: {_texto_campo(certificado, 'issuer')}")
    print(f"Sujeto: {_texto_campo(certificado, 'subject')}")
    print(f"Válido desde: {certificado.get('notBefore', 'desconocido')}")
    print(f"Válido hasta: {certificado.get('notAfter', 'desconocido')}")


def _motivo_rechazo(exc: ssl.SSLCertVerificationError) -> str:
    """Obtiene el mensaje exacto que proporciona OpenSSL para el rechazo."""
    return getattr(exc, "verify_message", None) or str(exc)


def enviar_comandos(
    host: str,
    puerto: int,
    modo: str,
    comandos: list[str],
    ca: Path,
    server_hostname: str | None,
    verbose: bool,
) -> int:
    """Conecta al servidor, envía comandos y muestra las respuestas."""
    contexto: ssl.SSLContext | None = crear_contexto_tls(ca) if modo == "tls" else None
    try:
        with socket.create_connection((host, puerto)) as socket_tcp:
            if contexto is not None:
                conexion: socket.socket = contexto.wrap_socket(
                    socket_tcp, server_hostname=server_hostname or host
                )
                if verbose:
                    mostrar_detalles_tls(conexion)
            else:
                conexion = socket_tcp

            with conexion:
                archivo = conexion.makefile("r", encoding="utf-8", newline="\n")
                for comando in comandos:
                    conexion.sendall((comando.rstrip("\r\n") + "\n").encode("utf-8"))
                    respuesta = archivo.readline(_MAX_LINEA)
                    if not respuesta:
                        break
                    print(respuesta.rstrip("\r\n"))
    except ssl.SSLCertVerificationError as exc:
        print(f"TLS rechazado: {_motivo_rechazo(exc)}", file=sys.stderr)
        return 1
    except ssl.SSLError as exc:
        print(f"TLS rechazado: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error de conexión: {exc}", file=sys.stderr)
        return 1
    return 0


def crear_parser() -> argparse.ArgumentParser:
    """Construye el parser de línea de comandos del cliente."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--modo", choices=("plano", "tls"), required=True)
    parser.add_argument(
        "--host",
        "--ip",
        dest="host",
        required=True,
        help="IP o DNS del servidor",
    )
    parser.add_argument("--puerto", type=int, required=True)
    parser.add_argument("--ca", type=Path, default=Path("pki/out/ca.crt"))
    parser.add_argument(
        "--server-hostname",
        help="nombre usado para validar el certificado; por defecto es --host",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--comando",
        action="append",
        default=[],
        help="comando a enviar; se puede repetir (sin él, se lee stdin)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Ejecuta el cliente en modo interactivo o con comandos proporcionados."""
    args = crear_parser().parse_args(argv)
    comandos = args.comando or [linea.rstrip("\r\n") for linea in sys.stdin if linea.strip()]
    if not comandos:
        print("No se proporcionaron comandos.", file=sys.stderr)
        return 2
    return enviar_comandos(
        args.host,
        args.puerto,
        args.modo,
        comandos,
        args.ca,
        args.server_hostname,
        args.verbose,
    )


if __name__ == "__main__":
    raise SystemExit(main())
