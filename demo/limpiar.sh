#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
make clean
mkdir -p logs
echo "Entorno limpiado; logs/ quedó creado y vacío."
