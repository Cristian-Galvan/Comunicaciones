"""Resume eventos de autenticación de OpenSSH y los registra en AAA."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# Permite ejecutar ``python3 ssh/analizar_logs.py`` desde la raíz del proyecto.
_RAIZ_PROYECTO = Path(__file__).resolve().parents[1]
if str(_RAIZ_PROYECTO) not in sys.path:
    sys.path.insert(0, str(_RAIZ_PROYECTO))

from aaa.logger import configurar_logger, registrar_evento

_PATRONES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PERMITIDO", re.compile(
        r"sshd(?:\[\d+\])?: Accepted \S+ for (?P<usuario>\S+) from "
        r"(?P<ip>\S+)"
    )),
    ("RECHAZADO", re.compile(
        r"sshd(?:\[\d+\])?: Failed \S+ for (?:invalid user )?"
        r"(?P<usuario>\S+) from (?P<ip>\S+)"
    )),
    ("RECHAZADO", re.compile(
        r"sshd(?:\[\d+\])?: User (?P<usuario>\S+) from (?P<ip>\S+) "
        r"not allowed because not listed in AllowUsers"
    )),
)


@dataclass(frozen=True)
class EventoSSH:
    """Intento SSH normalizado para el informe de auditoría."""

    usuario: str
    ip: str
    resultado: str


def extraer_eventos(contenido: str) -> list[EventoSSH]:
    """Extrae éxitos y fallos de las variantes habituales de auth.log."""
    eventos: list[EventoSSH] = []
    for linea in contenido.splitlines():
        for resultado, patron in _PATRONES:
            coincidencia = patron.search(linea)
            if coincidencia:
                eventos.append(EventoSSH(
                    coincidencia["usuario"],
                    coincidencia["ip"],
                    resultado,
                ))
                break
    return eventos


def analizar(ruta: Path) -> list[EventoSSH]:
    """Lee ``ruta``, registra cada evento en el logger de AAA y lo devuelve."""
    eventos = extraer_eventos(ruta.read_text(encoding="utf-8", errors="replace"))
    for evento in eventos:
        registrar_evento(
            evento.usuario,
            evento.ip,
            "ANALIZAR_SSH",
            "sshd",
            evento.resultado,
        )
    return eventos


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path, default=Path("/var/log/auth.log"))
    parser.add_argument("--salida-aaa", type=Path, default=Path("logs/aaa.log"))
    argumentos = parser.parse_args()
    configurar_logger(argumentos.salida_aaa, consola=True)
    eventos = analizar(argumentos.log)
    conteo = Counter((evento.resultado, evento.usuario, evento.ip) for evento in eventos)
    print(f"Eventos SSH analizados: {len(eventos)}")
    for (resultado, usuario, ip), cantidad in sorted(conteo.items()):
        print(f"{resultado}: usuario={usuario} ip={ip} intentos={cantidad}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
