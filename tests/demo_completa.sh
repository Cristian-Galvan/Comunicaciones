#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
if [[ -n "${PYTHON:-}" ]]; then
    read -r -a python_cmd <<< "${PYTHON}"
elif [[ -x ".venv/Scripts/python.exe" ]]; then
    python_cmd=(".venv/Scripts/python.exe")
elif command -v python >/dev/null 2>&1; then
    python_cmd=(python)
else
    python_cmd=(py -3)
fi

tests=(
    "test_01_tls_valido"
    "test_02_rechazo_de_certificados_invalidos"
    "test_03_cadena_de_confianza"
    "test_04_ssh_autorizado_y_no_autorizado"
    "test_05_ipsec_transporte"
    "test_06_ipsec_tunel"
    "test_07_replay_detectado"
    "test_08_vpn_acceso_remoto"
    "test_09_restriccion_posterior_a_la_conexion"
)
labels=(
    "TLS válido"
    "Rechazo de certs inválidos"
    "Cadena de confianza"
    "SSH autorizado y no autorizado"
    "IPSec transporte"
    "IPSec túnel"
    "Replay detectado"
    "VPN acceso remoto"
    "Restricción posterior a la conexión"
)

mkdir -p docs
fecha="$(date '+%Y-%m-%d %H:%M:%S %z')"
{
    echo "# Resultados de la demostración"
    echo
    echo "Fecha de ejecución: ${fecha}"
    echo
    echo "| # | Prueba | Resultado |"
    echo "|---:|---|---|"
} > docs/resultados.md

fallos=0
for i in "${!tests[@]}"; do
    if "${python_cmd[@]}" -m pytest -q \
        "tests/test_demostracion.py::${tests[$i]}" >/dev/null 2>&1; then
        resultado="PASS"
    else
        resultado="FAIL"
        fallos=$((fallos + 1))
    fi
    printf '%s: %s\n' "${labels[$i]}" "${resultado}"
    printf '| %d | %s | **%s** |\n' "$((i + 1))" "${labels[$i]}" "${resultado}" \
        >> docs/resultados.md
done

if [[ "${fallos}" -eq 0 ]]; then
    echo
    echo "Demostración completa: PASS"
else
    echo
    echo "Demostración completa: FAIL (${fallos} prueba(s))"
fi
exit "${fallos}"
