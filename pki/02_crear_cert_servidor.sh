#!/usr/bin/env bash
set -euo pipefail

unset OPENSSL_CONF 2>/dev/null || true
export MSYS2_ARG_CONV_EXCL='-subj'

if [[ "$#" -ne 2 ]]; then
    echo "Uso: $0 <dns-servidor> <ip-servidor>" >&2
    exit 64
fi

DNS_NAME="$1"
IP_ADDRESS="$2"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
CA_KEY="${OUT_DIR}/ca.key.pem"
CA_CERT="${OUT_DIR}/ca.crt"
SERVER_KEY="${OUT_DIR}/servidor.key.pem"
SERVER_CSR="${OUT_DIR}/servidor.csr.pem"
SERVER_CERT="${OUT_DIR}/servidor.crt"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
    echo "Error: primero ejecuta 01_crear_ca.sh." >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"
if [[ -e "${SERVER_KEY}" || -e "${SERVER_CSR}" || -e "${SERVER_CERT}" ]]; then
    if [[ -f "${SERVER_KEY}" && -f "${SERVER_CSR}" && -f "${SERVER_CERT}" ]]; then
        echo "El certificado del servidor ya existe; no se regenerará: ${SERVER_CERT}"
        exit 0
    fi
    echo "Error: existe un conjunto parcial del servidor en ${OUT_DIR}" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
cat > "${TMP_DIR}/servidor.cnf" <<EOF
[req]
distinguished_name = servidor_dn
prompt = no

[servidor_dn]
C = MX
O = Comunicaciones Academicas
CN = ${DNS_NAME}
EOF
cat > "${TMP_DIR}/servidor.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${DNS_NAME},IP:${IP_ADDRESS}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "${SERVER_KEY}"
chmod 600 "${SERVER_KEY}"

openssl req \
    -new \
    -sha256 \
    -key "${SERVER_KEY}" \
    -out "${SERVER_CSR}" \
    -config "${TMP_DIR}/servidor.cnf"

openssl x509 \
    -req \
    -sha256 \
    -in "${SERVER_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -CAserial "${TMP_DIR}/ca-cert.srl" \
    -out "${SERVER_CERT}" \
    -days 365 \
    -extfile "${TMP_DIR}/servidor.ext"

echo "Certificado del servidor creado: ${SERVER_CERT}"
