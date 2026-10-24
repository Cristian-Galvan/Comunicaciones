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
INVALID_DIR="${OUT_DIR}/invalidos"
CA_KEY="${OUT_DIR}/ca.key.pem"
CA_CERT="${OUT_DIR}/ca.crt"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
    echo "Error: primero ejecuta 01_crear_ca.sh." >&2
    exit 1
fi

mkdir -p "${OUT_DIR}" "${INVALID_DIR}"
INVALID_FILES=(
    "${INVALID_DIR}/invalido_autofirmado.crt"
    "${INVALID_DIR}/invalido_otra_ca.crt"
    "${INVALID_DIR}/invalido_expirado.crt"
    "${INVALID_DIR}/invalido_hostname.crt"
)
existing_count=0
for file in "${INVALID_FILES[@]}"; do
    if [[ -e "${file}" ]]; then
        ((existing_count += 1))
    fi
done
if [[ "${existing_count}" -eq "${#INVALID_FILES[@]}" ]]; then
    echo "Los certificados inválidos ya existen; no se regenerarán."
    exit 0
elif [[ "${existing_count}" -ne 0 ]]; then
    echo "Error: existe un conjunto parcial de certificados inválidos." >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat > "${TMP_DIR}/invalid.cnf" <<EOF
[req]
distinguished_name = invalid_dn
prompt = no

[invalid_dn]
C = MX
O = Pruebas
CN = ${DNS_NAME}
EOF
cat > "${TMP_DIR}/other-ca.cnf" <<'EOF'
[req]
distinguished_name = other_ca_dn
prompt = no

[other_ca_dn]
C = MX
O = Pruebas
CN = Otra CA
EOF

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${TMP_DIR}/invalid.key.pem"
openssl req -new -sha256 -key "${TMP_DIR}/invalid.key.pem" \
    -out "${TMP_DIR}/invalid.csr.pem" \
    -config "${TMP_DIR}/invalid.cnf"
cat > "${TMP_DIR}/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${DNS_NAME},IP:${IP_ADDRESS}
EOF

# 1. Certificado autofirmado.
openssl x509 -req -sha256 -in "${TMP_DIR}/invalid.csr.pem" \
    -signkey "${TMP_DIR}/invalid.key.pem" -out "${INVALID_FILES[0]}" \
    -days 365 -extfile "${TMP_DIR}/server.ext"
cp -- "${TMP_DIR}/invalid.key.pem" "${INVALID_FILES[0]%.crt}.key.pem"

# 2. Certificado firmado por una CA que no es la CA confiable.
openssl req -x509 -new -sha256 -key "${TMP_DIR}/invalid.key.pem" \
    -out "${TMP_DIR}/other-ca.crt" -days 365 \
    -config "${TMP_DIR}/other-ca.cnf" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl x509 -req -sha256 -in "${TMP_DIR}/invalid.csr.pem" \
    -CA "${TMP_DIR}/other-ca.crt" -CAkey "${TMP_DIR}/invalid.key.pem" \
    -CAcreateserial -CAserial "${TMP_DIR}/other-ca.srl" \
    -out "${INVALID_FILES[1]}" -days 365 -extfile "${TMP_DIR}/server.ext"
cp -- "${TMP_DIR}/invalid.key.pem" "${INVALID_FILES[1]%.crt}.key.pem"

# 3. Certificado firmado por la CA confiable, pero ya expirado.
openssl x509 -req -sha256 -in "${TMP_DIR}/invalid.csr.pem" \
    -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
    -CAcreateserial -CAserial "${TMP_DIR}/expired.srl" \
    -out "${INVALID_FILES[2]}" -days 0 -extfile "${TMP_DIR}/server.ext"
cp -- "${TMP_DIR}/invalid.key.pem" "${INVALID_FILES[2]%.crt}.key.pem"

# 4. Certificado firmado por la CA confiable con un SAN DNS incorrecto.
sed "s/subjectAltName=.*/subjectAltName=DNS:incorrecto.invalid,IP:${IP_ADDRESS}/" \
    "${TMP_DIR}/server.ext" > "${TMP_DIR}/wrong-host.ext"
openssl x509 -req -sha256 -in "${TMP_DIR}/invalid.csr.pem" \
    -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
    -CAcreateserial -CAserial "${TMP_DIR}/wrong-host.srl" \
    -out "${INVALID_FILES[3]}" -days 365 -extfile "${TMP_DIR}/wrong-host.ext"
cp -- "${TMP_DIR}/invalid.key.pem" "${INVALID_FILES[3]%.crt}.key.pem"

echo "Certificados y llaves inválidos (solo pruebas) creados en ${INVALID_DIR}"
