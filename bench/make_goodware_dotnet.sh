#!/usr/bin/env bash
# Añade assemblies .NET legítimas al corpus de goodware.
#
# Por qué esto existe: el corpus de goodware no tenía ni un solo binario .NET,
# y eso bloqueaba dos cosas (docs/ronda-2-reglas.md, docs/escaneo-recursivo.md):
#
#   1. Cualquier regla .NET daba 0% de FP sin medir nada, igual que pasó con
#      el runtime de Go en la ronda 2.
#   2. Las +6 detecciones del escaneo recursivo salen de high_entropy_section
#      disparando sobre assemblies .NET embebidas. Sin assemblies legítimas
#      no se puede saber si esa regla marca también software normal.
#
# Cada binario de aquí representa una clase de software .NET real que una
# regla mal afinada marcaría. Los cuatro primeros bloques son programas
# triviales; el quinto es el runtime real de Windows que acompaña a una app de
# escritorio. Todos son legítimos: si una regla dispara aquí, es un falso
# positivo.
#
# Igual que con Go, no se versionan los binarios: se reconstruyen.
# Lo que se midió con ellos está en docs/ronda-3-dotnet.md y
# docs/ronda-4-loader-dotnet.md.
#
#   bench/make_goodware_dotnet.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/corpus/goodware"

if ! command -v dotnet >/dev/null; then
    echo "falta el toolchain de .NET:  sudo pacman -S dotnet-sdk" >&2
    exit 1
fi

export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# El SDK instalado decide la versión de .NET moderno (net8.0, net10.0...).
NET="net$(dotnet --version | cut -d. -f1-2)"

# proyecto <dir> <TargetFramework> <OutputType> [xml extra dentro del PropertyGroup/ItemGroup]
proyecto() {
    local dir=$1 tfm=$2 kind=$3 props=${4:-} items=${5:-}
    mkdir -p "$WORK/$dir"
    cat > "$WORK/$dir/app.csproj" <<XML
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>$tfm</TargetFramework>
    <OutputType>$kind</OutputType>
    <Nullable>disable</Nullable>
    <AssemblyName>$dir</AssemblyName>
    <EnableWindowsTargeting>true</EnableWindowsTargeting>
    $props
  </PropertyGroup>
  <ItemGroup>
    $items
  </ItemGroup>
</Project>
XML
}

# compila <build|publish> <args...>: silencioso, salvo si falla, que enseña el log
compila() {
    if ! dotnet "$@" >"$WORK/dotnet.log" 2>&1; then
        cat "$WORK/dotnet.log" >&2
        exit 1
    fi
}

# copia <origen> <nombre en el corpus>
copia() {
    rm -f "$OUT/$2"               # los anteriores quedan 0444: se rehace, no se sobrescribe
    cp "$1" "$OUT/$2"
    chmod 0444 "$OUT/$2"          # goodware tampoco necesita bit de ejecución
    echo "  $2"
}

mkdir -p "$OUT"
echo "goodware de .NET ($NET) -> $OUT"

# --- 1. consola moderna, dependiente del framework ----------------------------
# Lo más común que hay: un apphost nativo (el .exe) que carga la assembly
# gestionada (el .dll). Son dos PE muy distintos y los dos van al corpus.
proyecto hola "$NET" Exe
cat > "$WORK/hola/Program.cs" <<'CS'
System.Console.WriteLine("hola");
CS
compila publish "$WORK/hola" -c Release -r win-x64 --self-contained false \
    -o "$WORK/hola/out"
copia "$WORK/hola/out/hola.exe" dotnet-hola-apphost.exe
copia "$WORK/hola/out/hola.dll" dotnet-hola.dll

# --- 2. WinForms de .NET Framework 4.8 ----------------------------------------
# La forma clásica de un ejecutable .NET: un solo import, mscoree!_CorExeMain.
# Es exactamente lo que tienen 12 de las 13 muestras .NET del corpus de
# malware (njrat, MassLogger...), así que es el control que más importa para
# la hipótesis 3. Las referencias de .NET Framework llegan por NuGet, lo que
# permite compilarlo en Linux sin Windows.
FW_ITEMS='<PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies" Version="1.0.3" PrivateAssets="all" />
    <Reference Include="System.Windows.Forms" />
    <Reference Include="System.Drawing" />'
proyecto formulario net48 WinExe "" "$FW_ITEMS"
cat > "$WORK/formulario/Program.cs" <<'CS'
using System;
using System.Windows.Forms;

static class Program {
    [STAThread]
    static void Main() {
        var f = new Form { Text = "Formulario", Width = 320, Height = 160 };
        var b = new Button { Text = "Aceptar", Dock = DockStyle.Fill };
        b.Click += (s, e) => f.Close();
        f.Controls.Add(b);
        Application.EnableVisualStyles();
        Application.Run(f);
    }
}
CS
compila build "$WORK/formulario" -c Release -o "$WORK/formulario/out"
copia "$WORK/formulario/out/formulario.exe" dotnet-winforms-net48.exe

# --- 3. app con recursos grandes y de alta entropía ---------------------------
# El caso de "un instalador de WPF con imágenes embebidas". En una assembly
# .NET los recursos gestionados viven DENTRO de .text, que es ejecutable, así
# que 3 MB de datos comprimidos (aquí aleatorios, que tienen la misma
# entropía que un PNG o un ZIP) convierten .text en una sección ejecutable de
# entropía ~8. Si high_entropy_section dispara aquí, dispara sobre media
# industria. Se genera en .NET Framework y en .NET moderno.
python3 -c 'import os,sys; open(sys.argv[1],"wb").write(os.urandom(3*1024*1024))' \
    "$WORK/recursos.bin"
RES_ITEMS='<EmbeddedResource Include="../recursos.bin" LogicalName="imagenes.bin" />'
RES_CS='using System;
using System.IO;
using System.Reflection;

static class Program {
    static void Main() {
        using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("imagenes.bin"))
            Console.WriteLine("recursos: " + s.Length + " bytes");
    }
}'
proyecto recursos-fw net48 Exe "" "$FW_ITEMS
    $RES_ITEMS"
echo "$RES_CS" > "$WORK/recursos-fw/Program.cs"
compila build "$WORK/recursos-fw" -c Release -o "$WORK/recursos-fw/out"
copia "$WORK/recursos-fw/out/recursos-fw.exe" dotnet-recursos-net48.exe

proyecto recursos "$NET" Exe "" "$RES_ITEMS"
echo "$RES_CS" > "$WORK/recursos/Program.cs"
compila publish "$WORK/recursos" -c Release -r win-x64 --self-contained false \
    -o "$WORK/recursos/out"
copia "$WORK/recursos/out/recursos.dll" dotnet-recursos.dll

# --- 4. single-file autocontenido ---------------------------------------------
# `PublishSingleFile` mete el runtime y las assemblies dentro del .exe, SIN
# comprimir: es un contenedor lleno de PE tallables. Es el control que le
# faltaba al escaneo recursivo: un ejecutable con assemblies .NET dentro, como
# los instaladores de ConnectWise que producían las +6. Se recorta
# (PublishTrimmed) para que no pese 70 MB; lo que queda dentro sigue siendo
# runtime .NET real.
proyecto unico "$NET" Exe \
    '<PublishSingleFile>true</PublishSingleFile>
    <SelfContained>true</SelfContained>
    <PublishTrimmed>true</PublishTrimmed>' \
    "$RES_ITEMS"
echo "$RES_CS" > "$WORK/unico/Program.cs"
compila publish "$WORK/unico" -c Release -r win-x64 -o "$WORK/unico/out"
copia "$WORK/unico/out/unico.exe" dotnet-singlefile.exe

# --- 5. una app de escritorio tal y como se distribuye ------------------------
# Los programas de arriba son de juguete: no usan Bitmap, GetPixel ni
# reflexión, así que una regla que mire esas APIs daría 0% de FP contra ellos
# sin medir nada. Aquí se publica una app WinForms + WPF autocontenida, que es
# como un fabricante entrega software .NET: la carpeta lleva la implementación
# real de WinForms, WPF y System.Drawing, y las DLL nativas del runtime. Son
# binarios de Microsoft de producción, cientos, y son justo la clase de
# software que usa legítimamente las mismas APIs que un loader.
# Solo se copian los PE del nivel superior: las subcarpetas son traducciones
# (*.resources.dll) que repiten lo mismo en quince idiomas.
proyecto escritorio "$NET-windows" WinExe \
    '<UseWindowsForms>true</UseWindowsForms>
    <UseWPF>true</UseWPF>
    <SelfContained>true</SelfContained>'
cat > "$WORK/escritorio/Program.cs" <<'CS'
using System;
using System.Windows.Forms;

static class Program {
    [STAThread]
    static void Main() => Application.Run(new Form { Text = "escritorio" });
}
CS
compila publish "$WORK/escritorio" -c Release -r win-x64 -o "$WORK/escritorio/out"
rm -rf "$OUT/dotnet-escritorio"
mkdir -p "$OUT/dotnet-escritorio"
find "$WORK/escritorio/out" -maxdepth 1 -type f \( -name '*.dll' -o -name '*.exe' \) \
    -exec cp -t "$OUT/dotnet-escritorio" {} +
chmod 0444 "$OUT"/dotnet-escritorio/*
echo "  dotnet-escritorio/ ($(ls "$OUT/dotnet-escritorio" | wc -l) binarios del runtime de Windows)"

# --- 6. controles con la forma de un loader esteganográfico -------------------
# Ocho muestras del corpus (njrat, MassLogger, RemcosRAT, Formbook) son el
# mismo crypter: una app WinForms de tapadera con una imagen enorme en
# Properties.Resources, leída con ResourceManager.GetObject, de cuyos píxeles
# (Bitmap.GetPixel) se reconstruye el payload, que luego se ejecuta por
# reflexión. Ver docs/ronda-4-loader-dotnet.md
#
# Cada pieza por separado es de lo más normal, así que estos dos controles son
# apps legítimas con esa misma forma. Si la regla del loader dispara aquí,
# es un falso positivo:
#   visor   imagen grande en los recursos + GetObject + GetPixel (un cuentagotas)
#   plugins lo mismo, y además carga plugins con Activator.CreateInstance
python3 - "$WORK/fondo.png" <<'PY'
# PNG de verdad, 1024x768 con ruido: pesa y tiene la entropía de una foto
import os, struct, sys, zlib
w, h = 1024, 768
raw = b"".join(b"\x00" + os.urandom(w * 3) for _ in range(h))
chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
open(sys.argv[1], "wb").write(png)
PY
# el .resx es lo que Visual Studio genera al arrastrar una imagen a Resources
RESX='<?xml version="1.0" encoding="utf-8"?>
<root>
  <resheader name="resmimetype"><value>text/microsoft-resx</value></resheader>
  <resheader name="version"><value>2.0</value></resheader>
  <resheader name="reader"><value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value></resheader>
  <resheader name="writer"><value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value></resheader>
  <data name="Fondo" type="System.Resources.ResXFileRef, System.Windows.Forms">
    <value>../fondo.png;System.Byte[], mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>
  </data>
</root>'
VISOR_CS='using System;
using System.Drawing;
using System.IO;
using System.Resources;
using System.Windows.Forms;

static class Program {
    [STAThread]
    static void Main() {
        var rm = new ResourceManager("Visor.Properties.Resources", typeof(Program).Assembly);
        var fondo = new Bitmap(new MemoryStream((byte[])rm.GetObject("Fondo")));
        var f = new Form { Text = "Cuentagotas", BackgroundImage = fondo };
        f.MouseClick += (s, e) => f.Text = fondo.GetPixel(e.X, e.Y).ToString();
        PLUGINS
        Application.Run(f);
    }
}'
control_loader() {  # control_loader <nombre> <código extra en Main>
    local name=$1 extra=$2
    proyecto "$name" net48 WinExe '<RootNamespace>Visor</RootNamespace>' "$FW_ITEMS"
    mkdir -p "$WORK/$name/Properties"
    cp "$WORK/fondo.png" "$WORK/$name/"
    echo "$RESX" > "$WORK/$name/Properties/Resources.resx"
    echo "${VISOR_CS/PLUGINS/$extra}" > "$WORK/$name/Program.cs"
    compila build "$WORK/$name" -c Release -o "$WORK/$name/out"
    copia "$WORK/$name/out/$name.exe" "dotnet-$name.exe"
}
control_loader visor ""
control_loader plugins 'foreach (var dll in Directory.GetFiles("plugins", "*.dll"))
            foreach (var t in System.Reflection.Assembly.LoadFrom(dll).GetExportedTypes())
                if (typeof(IDisposable).IsAssignableFrom(t)) Activator.CreateInstance(t);'

echo "[ok] .NET SDK $(dotnet --version)"
