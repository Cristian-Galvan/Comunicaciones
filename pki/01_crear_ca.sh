#!/usr/bin/env bash
set -euo pipefail

# Evita que una configuración global inexistente de otro programa interfiera.
unset OPENSSL_CONF 2>/dev/null || true
export MSYS2_ARG_CONV_EXCL='-subj'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/out"
CA_KEY="${OUT_DIR}/ca.key.pem"
CA_CERT="${OUT_DIR}/ca.crt"

mkdir -p "${OUT_DIR}"

if [[ -e "${CA_KEY}" || -e "${CA_CERT}" ]]; then
    if [[ -f "${CA_KEY}" && -f "${CA_CERT}" ]]; then
        echo "La CA ya existe; no se regenerará: ${CA_CERT}"
        exit 0
    fi
    echo "Error: existe un artefacto parcial de la CA en ${OUT_DIR}" >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
cat > "${TMP_DIR}/ca.cnf" <<'EOF'
[req]
distinguished_name = ca_dn
prompt = no

[ca_dn]
C = MX
O = Comunicaciones Academicas
CN = Comunicaciones Root CA
EOF

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -out "${CA_KEY}"
chmod 600 "${CA_KEY}"

openssl req \
    -x509 \
    -new \
    -sha256 \
    -key "${CA_KEY}" \
    -out "${CA_CERT}" \
    -days 3650 \
    -config "${TMP_DIR}/ca.cnf" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

echo "CA creada: ${CA_CERT}"
