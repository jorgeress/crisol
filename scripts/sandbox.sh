#!/usr/bin/env bash
# Ejecuta un comando de yardstick dentro de un sandbox de bubblewrap.
#
# Por qué: el análisis es ESTÁTICO (nunca se ejecuta la muestra), así que el
# riesgo no es la muestra corriendo: es que un fichero deliberadamente
# malformado reviente el parser (pefile, oletools, libyara) y consiga
# ejecución dentro de NUESTRO proceso. Este wrapper hace que, si eso pasa, el
# atacante caiga en un sitio inútil: sin red, sin $HOME, sin poder escribir en
# el repo y sin poder ganar privilegios.
#
# No necesita root: usa user namespaces sin privilegios.
#
#   scripts/sandbox.sh make bench
#   scripts/sandbox.sh .venv/bin/python -m yardstick.cli scan corpus/malware/<sha>
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v bwrap >/dev/null; then
    echo "falta bubblewrap:  sudo pacman -S bubblewrap" >&2
    exit 1
fi
if [ $# -eq 0 ]; then
    echo "uso: scripts/sandbox.sh <comando...>   (p.ej. scripts/sandbox.sh make bench)" >&2
    exit 2
fi

mkdir -p "$REPO/reports"

# Techo de tamaño de fichero: un parser en bucle no llena el disco.
ulimit -f 1048576   # 1 GiB en bloques de 1K

# La clave de la API no pinta nada en el análisis: se tapa si existe.
MASK_KEY=()
if [ -f "$REPO/.mb_api_key" ]; then
    MASK_KEY=(--ro-bind /dev/null "$REPO/.mb_api_key")
fi

exec bwrap \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --symlink usr/bin /bin \
    --symlink usr/sbin /sbin \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --ro-bind "$REPO" "$REPO" \
    --bind "$REPO/reports" "$REPO/reports" \
    "${MASK_KEY[@]}" \
    --chdir "$REPO" \
    --unshare-all \
    --new-session \
    --die-with-parent \
    --setenv PYTHONDONTWRITEBYTECODE 1 \
    --setenv HOME /tmp \
    -- "$@"
