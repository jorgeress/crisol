#!/usr/bin/env bash
# Añade binarios de Go para Windows al corpus de goodware.
#
# Por qué esto existe: el corpus de goodware eran 52 binarios de Linux y de
# Wine, ni uno solo compilado con Go. Eso hacía invisible una clase entera de
# falsos positivos, porque la tabla de imports de un binario de Go es
# constante (solo kernel32.dll, ~40-48 funciones) y es exactamente la misma
# en un stealer y en `fmt.Println("hola")`. Cualquier regla que mire esa forma
# marcaría todo el ecosistema Go —docker, kubectl, terraform, hugo— y contra
# un corpus sin Go daría 0% de FP, mintiendo.
#
# No se versionan los binarios (pesan MB y el repo no guarda corpus): se
# reconstruyen aquí, que además es más honesto — cualquiera reproduce el
# mismo experimento con su propio toolchain.
#
#   bench/make_goodware_go.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/corpus/goodware"

if ! command -v go >/dev/null; then
    echo "falta el toolchain de Go:  sudo pacman -S go" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Programas deliberadamente triviales y deliberadamente legítimos: si una
# regla dispara aquí, es un falso positivo y no hay discusión posible.
cat > hello.go <<'GO'
package main

import "fmt"

func main() { fmt.Println("hola") }
GO

mkdir -p cli
cat > cli/main.go <<'GO'
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Cliente HTTP de juguete: añade net/http y crypto/tls a la imagen, que es
// lo que engorda a un binario de Go real (y a un stealer, de ahí la gracia).
func main() {
	url := flag.String("url", "https://example.com", "endpoint")
	flag.Parse()
	c := &http.Client{Timeout: 5 * time.Second}
	r, err := c.Get(*url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer r.Body.Close()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]int{"status": r.StatusCode})
}
GO

export GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache" GOFLAGS=-mod=mod
go mod init goodware >/dev/null 2>&1

build() {  # build <nombre> <goos-goarch> <paquete> [ldflags]
    local name=$1 arch=$2 pkg=$3 ld=${4:-}
    rm -f "$OUT/$name"               # los anteriores quedan 0444: se rehace, no se sobrescribe
    GOOS=windows GOARCH=$arch go build ${ld:+-ldflags="$ld"} -o "$OUT/$name" "$pkg"
    chmod 0444 "$OUT/$name"          # goodware tampoco necesita bit de ejecución
    echo "  $name"
}

mkdir -p "$OUT"
echo "goodware de Go -> $OUT"
build go-hello-amd64.exe    amd64 ./hello.go
build go-hello-386.exe      386   ./hello.go
build go-httpcli-amd64.exe  amd64 ./cli
build go-httpcli-stripped.exe amd64 ./cli "-s -w"

# --- control con forma de instalador auto-extraíble --------------------------
# La regla de overlay que mide el "inflado de tamaño" tiene un enemigo natural:
# un instalador legítimo (NSIS, Inno, 7z SFX) es un PE pequeño con un archivo
# comprimido gigante pegado detrás — estructuralmente idéntico al relleno de
# evasión. El corpus de goodware no tenía ni uno, así que aquí se construye:
# binario legítimo + ZIP real detrás, que es literalmente lo que es un SFX.
# Si la regla dispara aquí, es un falso positivo sobre software legítimo.
sfx() {
    local name=$1 mb=$2
    python3 - "$WORK/payload.zip" "$mb" <<'PYZ'
import os, sys, zipfile
out, mb = sys.argv[1], int(sys.argv[2])
# ZIP_STORED sobre datos aleatorios: entropía ~8, igual que un payload comprimido
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
    for i in range(mb):
        z.writestr(f"data/blob{i}.bin", os.urandom(1024 * 1024))
PYZ
    rm -f "$OUT/$name"
    cat "$OUT/go-hello-amd64.exe" "$WORK/payload.zip" > "$OUT/$name"
    chmod 0444 "$OUT/$name"
    rm -f "$WORK/payload.zip"
    echo "  $name (overlay ZIP de ~${mb} MB)"
}

sfx control-sfx-zip-amd64.exe 20

# Segundo control, para el escaneo recursivo (--recursive): un auto-extraíble
# que lleva dentro EJECUTABLES legítimos, sin comprimir, o sea tallables. El
# anterior solo llevaba datos, así que no decía nada sobre lo que pasa cuando
# el motor abre un contenedor y escanea lo de dentro. Un instalador de verdad
# tiene exactamente esta forma: stub + ejecutables reales detrás.
bundle() {
    local name=$1
    python3 - "$WORK/bundle.zip" "$OUT" <<'PYZ'
import sys, zipfile
from pathlib import Path
out, good = sys.argv[1], Path(sys.argv[2])
# ZIP_STORED a propósito: comprimidos no se pueden tallar, y lo que se quiere
# medir aquí es justo el caso en que sí se pueden.
with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
    for exe in sorted(good.glob("go-*.exe")):
        z.write(exe, f"bin/{exe.name}")
PYZ
    rm -f "$OUT/$name"
    cat "$OUT/go-hello-amd64.exe" "$WORK/bundle.zip" > "$OUT/$name"
    chmod 0444 "$OUT/$name"
    rm -f "$WORK/bundle.zip"
    echo "  $name (lleva dentro los PE legítimos, sin comprimir)"
}

bundle control-bundle-pe-amd64.exe

echo "[ok] $(go version)"
