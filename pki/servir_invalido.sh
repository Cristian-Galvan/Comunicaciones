#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 1 ]]; then
    echo "Uso: $0 <autofirmado|otra_ca|expirado|hostname>" >&2
    exit 64
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
case "$1" in
    autofirmado) tipo="autofirmado" ;;
    otra_ca) tipo="otra_ca" ;;
    expirado) tipo="expirado" ;;
    hostname) tipo="hostname" ;;
    *) echo "Tipo inválido: $1" >&2; exit 64 ;;
esac

cert="${SCRIPT_DIR}/out/invalidos/invalido_${tipo}.crt"
key="${SCRIPT_DIR}/out/invalidos/invalido_${tipo}.key.pem"
[[ -r "${cert}" && -r "${key}" ]] || {
    echo "Faltan los artefactos; ejecuta 03_crear_certs_invalidos.sh primero." >&2
    exit 1
}

if [[ -n "${PYTHON:-}" ]]; then
    read -r -a python_cmd <<< "${PYTHON}"
elif [[ -x "${ROOT}/.venv/Scripts/python.exe" ]]; then
    python_cmd=("${ROOT}/.venv/Scripts/python.exe")
else
    python_cmd=(python3)
fi

exec "${python_cmd[@]}" -m app.servidor --modo tls \
    --host "${HOST:-0.0.0.0}" --puerto "${PORT:-8443}" \
    --cert "${cert}" --key "${key}"
