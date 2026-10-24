#!/usr/bin/env bash
set -Eeuo pipefail

readonly HOST="${SSH_HOST:-127.0.0.1}"
readonly PORT="${SSH_PORT:-22}"
readonly USUARIO_AUTORIZADO="${SSH_USER:-sshadmin}"
readonly USUARIO_NO_AUTORIZADO="${SSH_DENIED_USER:-sshintruso}"
readonly LLAVE="${SSH_KEY:?Defina SSH_KEY con la llave privada de sshadmin}"
readonly OPCIONES=(-p "${PORT}" -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)

comprobar_herramienta() {
    command -v "$1" >/dev/null || { echo "Falta la herramienta: $1" >&2; exit 1; }
}

comprobar_herramienta ssh
comprobar_herramienta sshpass

ssh "${OPCIONES[@]}" -i "${LLAVE}" "${USUARIO_AUTORIZADO}@${HOST}" true
echo "OK: acceso autorizado"

if ssh "${OPCIONES[@]}" -i "${LLAVE}" "${USUARIO_NO_AUTORIZADO}@${HOST}" true \
    >/dev/null 2>&1; then
    echo "ERROR: el usuario no autorizado pudo acceder" >&2
    exit 1
fi
echo "OK: usuario no autorizado rechazado"

if SSHPASS="contraseña-incorrecta-solo-prueba" sshpass -e \
    ssh "${OPCIONES[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password \
    "${USUARIO_AUTORIZADO}@${HOST}" true >/dev/null 2>&1; then
    echo "ERROR: una contraseña incorrecta fue aceptada" >&2
    exit 1
fi
echo "OK: contraseña incorrecta rechazada"
