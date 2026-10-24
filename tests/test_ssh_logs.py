"""Pruebas del analizador de registros de OpenSSH."""

from ssh.analizar_logs import extraer_eventos


def test_formato_clasico_sshd_con_pid() -> None:
    """Reconoce las líneas ``sshd[pid]:`` de auth.log tradicional."""
    contenido = (
        "Oct 23 10:00:01 servidor sshd[1234]: Accepted publickey for sshadmin "
        "from 10.0.0.5 port 50000 ssh2: ED25519 SHA256:abc\n"
        "Oct 23 10:00:05 servidor sshd[1235]: Failed password for sshadmin "
        "from 10.0.0.5 port 50001 ssh2\n"
    )
    eventos = extraer_eventos(contenido)
    resumen = [(evento.resultado, evento.usuario, evento.ip) for evento in eventos]
    assert resumen == [
        ("PERMITIDO", "sshadmin", "10.0.0.5"),
        ("RECHAZADO", "sshadmin", "10.0.0.5"),
    ]


def test_formato_sshd_session_con_timestamp_iso() -> None:
    """Reconoce ``sshd-session[pid]:`` de OpenSSH reciente e ignora preauth."""
    contenido = (
        "2026-10-23T10:00:01.123456-06:00 kali sshd-session[2001]: Accepted "
        "publickey for sshadmin from 192.168.56.1 port 51000 ssh2: ED25519 "
        "SHA256:abc\n"
        "2026-10-23T10:00:05.000000-06:00 kali sshd-session[2002]: Failed "
        "password for invalid user sshintruso from 192.168.56.1 port 51001 ssh2\n"
        "2026-10-23T10:00:09.000000-06:00 kali sshd-session[2003]: User root "
        "from 192.168.56.1 not allowed because not listed in AllowUsers\n"
        "2026-10-23T10:00:10.000000-06:00 kali sshd-session[2003]: Connection "
        "reset by invalid user root 192.168.56.1 port 51002 [preauth]\n"
    )
    eventos = extraer_eventos(contenido)
    resumen: list[tuple[str, str]] = [
        (evento.resultado, evento.usuario) for evento in eventos
    ]
    assert resumen == [
        ("PERMITIDO", "sshadmin"),
        ("RECHAZADO", "sshintruso"),
        ("RECHAZADO", "root"),
    ]
    assert all(evento.ip == "192.168.56.1" for evento in eventos)
