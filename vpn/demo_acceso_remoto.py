"""Demostración de matriz usuario x recurso y login fallido."""

from aaa import logger as aaa_logger

from .acceso_remoto import GatewayAccesoRemoto


def main() -> None:
    aaa_logger.configurar_logger("logs/aaa.log", consola=False)
    gateway = GatewayAccesoRemoto()
    credenciales = {
        "admin": "Admin123!",
        "empleado": "Empleado123!",
        "invitado": "Invitado123!",
    }
    recursos = ("base_datos_consulta", "intranet_publica", "administracion_red")
    print("VPN acceso remoto / matriz usuario x recurso")
    for usuario, contraseña in credenciales.items():
        sesion = gateway.conectar(usuario, contraseña, "192.0.2.50")
        decisiones = [
            "OK" if gateway.autorizar(sesion.token, recurso, sesion.ip_virtual) else "DENEGADO"
            for recurso in recursos
        ]
        print(f"  {usuario:>8}: " + " | ".join(
            f"{recurso}={decision}" for recurso, decision in zip(recursos, decisiones)
        ))
    try:
        gateway.conectar("invitado", "contraseña-incorrecta", "192.0.2.50")
    except PermissionError as exc:
        print(f"  login fallido (invitado): RECHAZADO ({exc})")


if __name__ == "__main__":
    main()
