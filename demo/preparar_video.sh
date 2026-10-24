#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "Uso: $0 <dns-servidor> <ip-servidor>" >&2
    exit 64
fi

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ -n "${PYTHON:-}" ]]; then
    read -r -a python_cmd <<< "${PYTHON}"
elif [[ -x ".venv/Scripts/python.exe" ]]; then
    python_cmd=(".venv/Scripts/python.exe")
elif command -v python3 >/dev/null 2>&1; then
    python_cmd=(python3)
elif command -v python >/dev/null 2>&1; then
    python_cmd=(python)
else
    python_cmd=(py -3)
fi

mkdir -p logs
./pki/01_crear_ca.sh
./pki/02_crear_cert_servidor.sh "$1" "$2"
./pki/03_crear_certs_invalidos.sh "$1" "$2"
./pki/verificar_pki.sh "$1" "$2"
"${python_cmd[@]}" -m pytest -q

echo
echo "Preparación local terminada."
echo "Copiar únicamente pki/out/ca.crt al CLIENTE."
echo "Aviso: después de regenerar la PKI hay que volver a copiar ca.crt al CLIENTE."
echo "No copiar pki/out/ca.key.pem ni pki/out/servidor.key.pem."
