#!/usr/bin/env bash
set -Eeuo pipefail

readonly DIRECTORIO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PLANTILLA="${DIRECTORIO}/sshd_config.ejemplo"
readonly DROP_IN="/etc/ssh/sshd_config.d/99-comunicaciones.conf"
readonly COPIA_SEGURIDAD="/etc/ssh/sshd_config.d/99-comunicaciones.conf.bak"

usuario_autorizado="sshadmin"
usuario_no_autorizado="sshintruso"
llave_publica=""
password_authentication="no"

uso() {
    cat <<'EOF'
Uso: configurar_ssh.sh [-k archivo.pub] [-p yes|no] [-u usuario_autorizado]
                        [-n usuario_no_autorizado]

Instala el fragmento de sshd, crea dos usuarios de prueba y autoriza la
llave pública indicada para el usuario autorizado.
EOF
}

while getopts ":k:p:u:n:h" opcion; do
    case "${opcion}" in
        k) llave_publica="${OPTARG}" ;;
        p) password_authentication="${OPTARG}" ;;
        u) usuario_autorizado="${OPTARG}" ;;
        n) usuario_no_autorizado="${OPTARG}" ;;
        h) uso; exit 0 ;;
        :) echo "Falta un argumento para -${OPTARG}" >&2; uso >&2; exit 2 ;;
        \?) echo "Opción no válida: -${OPTARG}" >&2; uso >&2; exit 2 ;;
    esac
done

[[ "${EUID}" -eq 0 ]] || { echo "Ejecute este script como root." >&2; exit 1; }
[[ -r "${PLANTILLA}" ]] || { echo "No se encuentra ${PLANTILLA}." >&2; exit 1; }
[[ "${password_authentication}" == "yes" || "${password_authentication}" == "no" ]] ||
    { echo "-p debe ser yes o no." >&2; exit 2; }
[[ "${usuario_autorizado}" =~ ^[a-z_][a-z0-9_-]*$ &&
   "${usuario_no_autorizado}" =~ ^[a-z_][a-z0-9_-]*$ ]] ||
    { echo "Los nombres de usuario no son válidos." >&2; exit 2; }
[[ "${usuario_autorizado}" != "${usuario_no_autorizado}" ]] ||
    { echo "Los usuarios de prueba deben ser distintos." >&2; exit 2; }

if [[ -n "${llave_publica}" && ! -r "${llave_publica}" ]]; then
    echo "No se puede leer la llave pública: ${llave_publica}" >&2
    exit 1
fi

crear_usuario() {
    local usuario="$1"
    if ! id --user "${usuario}" &>/dev/null; then
        useradd --create-home --shell /bin/bash "${usuario}"
    fi
    passwd --lock "${usuario}" >/dev/null
}

crear_usuario "${usuario_autorizado}"
crear_usuario "${usuario_no_autorizado}"

install --directory --mode 0700 -o "${usuario_autorizado}" -g "${usuario_autorizado}" \
    "/home/${usuario_autorizado}/.ssh"
if [[ -n "${llave_publica}" ]]; then
    install --mode 0600 -o "${usuario_autorizado}" -g "${usuario_autorizado}" \
        "${llave_publica}" "/home/${usuario_autorizado}/.ssh/authorized_keys"
else
    echo "Aviso: no se instaló authorized_keys; proporcione -k archivo.pub." >&2
fi

install --mode 0644 "${PLANTILLA}" "${DROP_IN}.new"
sed --in-place \
    -e "s/^AllowUsers .*/AllowUsers ${usuario_autorizado}/" \
    -e "s/^PasswordAuthentication .*/PasswordAuthentication ${password_authentication}/" \
    "${DROP_IN}.new"
if [[ -f "${DROP_IN}" ]]; then
    install --mode 0600 "${DROP_IN}" "${COPIA_SEGURIDAD}"
fi
install --mode 0644 "${DROP_IN}.new" "${DROP_IN}"
rm -- "${DROP_IN}.new"

sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd
echo "SSH configurado. AllowUsers=${usuario_autorizado}; PasswordAuthentication=${password_authentication}"
