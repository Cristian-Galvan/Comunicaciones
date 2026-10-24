"""Encapsulación ESP simulada con AES-GCM.

No se simulan IKE, la negociación de asociaciones de seguridad ni el rekey.
La clave se entrega directamente a las funciones para mantener el ejemplo
pequeño y didáctico.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_FORMATO_ENCABEZADO = "!IQ12s"
_TAMAÑO_ENCABEZADO = struct.calcsize(_FORMATO_ENCABEZADO)
_TAMAÑO_ETIQUETA = 16
_TAMAÑO_NONCE = 12


@dataclass(frozen=True)
class PaqueteESP:
    """Paquete ESP con encabezado, ciphertext y etiqueta GCM."""

    spi: int
    numero_secuencia: int
    nonce: bytes
    payload_cifrado: bytes
    etiqueta_integridad: bytes

    @property
    def secuencia(self) -> int:
        """Alias corto para el número de secuencia ESP."""
        return self.numero_secuencia

    @classmethod
    def cifrar(
        cls,
        payload: bytes,
        clave: bytes,
        spi: int,
        numero_secuencia: int,
        nonce: bytes | None = None,
    ) -> "PaqueteESP":
        """Cifra ``payload`` y autentica el encabezado ESP como AAD."""
        nonce_real = urandom(_TAMAÑO_NONCE) if nonce is None else nonce
        if len(nonce_real) != _TAMAÑO_NONCE:
            raise ValueError("El nonce AES-GCM debe tener 12 bytes")
        encabezado = struct.pack(_FORMATO_ENCABEZADO, spi, numero_secuencia, nonce_real)
        resultado = AESGCM(clave).encrypt(nonce_real, payload, encabezado)
        return cls(
            spi=spi,
            numero_secuencia=numero_secuencia,
            nonce=nonce_real,
            payload_cifrado=resultado[:-_TAMAÑO_ETIQUETA],
            etiqueta_integridad=resultado[-_TAMAÑO_ETIQUETA:],
        )

    def descifrar(self, clave: bytes) -> bytes:
        """Verifica la etiqueta y devuelve el payload original."""
        encabezado = self._encabezado()
        try:
            return AESGCM(clave).decrypt(
                self.nonce,
                self.payload_cifrado + self.etiqueta_integridad,
                encabezado,
            )
        except InvalidTag as exc:
            raise ValueError("Paquete ESP rechazado: etiqueta inválida") from exc

    def _encabezado(self) -> bytes:
        return struct.pack(
            _FORMATO_ENCABEZADO, self.spi, self.numero_secuencia, self.nonce
        )

    def serializar(self) -> bytes:
        """Serializa encabezado, ciphertext y etiqueta en bytes."""
        if len(self.nonce) != _TAMAÑO_NONCE:
            raise ValueError("El nonce AES-GCM debe tener 12 bytes")
        if len(self.etiqueta_integridad) != _TAMAÑO_ETIQUETA:
            raise ValueError("La etiqueta AES-GCM debe tener 16 bytes")
        return self._encabezado() + self.payload_cifrado + self.etiqueta_integridad

    @classmethod
    def deserializar(cls, datos: bytes) -> "PaqueteESP":
        """Deserializa un paquete ESP y valida su estructura."""
        if len(datos) < _TAMAÑO_ENCABEZADO + _TAMAÑO_ETIQUETA:
            raise ValueError("Paquete ESP truncado")
        spi, secuencia, nonce = struct.unpack(
            _FORMATO_ENCABEZADO, datos[:_TAMAÑO_ENCABEZADO]
        )
        final = len(datos) - _TAMAÑO_ETIQUETA
        return cls(
            spi=spi,
            numero_secuencia=secuencia,
            nonce=nonce,
            payload_cifrado=datos[_TAMAÑO_ENCABEZADO:final],
            etiqueta_integridad=datos[final:],
        )

    to_bytes = serializar
    from_bytes = deserializar
