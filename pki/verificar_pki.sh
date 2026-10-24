#!/usr/bin/env bash
set -euo pipefail

unset OPENSSL_CONF 2>/dev/null || true
export MSYS2_ARG_CONV_EXCL='-subj'

if [[ "$#" -ne 2 ]]; then
    echo "Uso: $0 <dns-servidor> <ip-servidor>" >&2
    exit 64
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
INVALID_DIR="${OUT_DIR}/invalidos"
CA_CERT="${OUT_DIR}/ca.crt"
SERVER_CERT="${OUT_DIR}/servidor.crt"

"${SCRIPT_DIR}/01_crear_ca.sh"
"${SCRIPT_DIR}/02_crear_cert_servidor.sh" "$1" "$2"
"${SCRIPT_DIR}/03_crear_certs_invalidos.sh" "$1" "$2"

echo "Verificando certificado válido:"
openssl verify -CAfile "${CA_CERT}" "${SERVER_CERT}"

for cert in \
    "${INVALID_DIR}/invalido_autofirmado.crt" \
    "${INVALID_DIR}/invalido_otra_ca.crt" \
    "${INVALID_DIR}/invalido_expirado.crt"; do
    echo "Verificando inválido (se espera FAIL): $(basename "${cert}")"
    if openssl verify -CAfile "${CA_CERT}" "${cert}" >/dev/null 2>&1; then
        echo "ERROR: se aceptó un certificado inválido: ${cert}" >&2
        exit 1
    fi
done

hostname_cert="${INVALID_DIR}/invalido_hostname.crt"
echo "Verificando inválido por hostname (se espera FAIL): $(basename "${hostname_cert}")"
if openssl verify -CAfile "${CA_CERT}" -verify_hostname "$1" \
    "${hostname_cert}" >/dev/null 2>&1; then
    echo "ERROR: se aceptó un certificado con hostname incorrecto." >&2
    exit 1
fi

echo "OK: el certificado válido se verifica y los cuatro inválidos fallan."
