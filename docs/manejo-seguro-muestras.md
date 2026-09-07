# Manejo seguro de muestras

Este documento explica **cómo se manejan las muestras reales de malware** en
crisol y, sobre todo, *por qué* cada control está donde está. Es la parte
que un laboratorio de verdad da por supuesta y que casi ningún proyecto de
portfolio documenta.

## El punto de partida: análisis estático

crisol **nunca ejecuta la muestra**. Extrae features (cabeceras PE/ELF,
IAT, entropía, strings) y corre reglas YARA sobre los bytes. Eso cambia el
modelo de amenaza por completo respecto a un laboratorio dinámico: no hace
falta una VM desechable con red aislada, porque no hay proceso malicioso
corriendo del que defenderse.

Lo que sí queda es un riesgo más sutil, y es el que se ataca aquí.

## Modelo de amenaza

| # | Riesgo | Probabilidad | Impacto | Control |
|---|--------|--------------|---------|---------|
| 1 | **Ejecución accidental**: un `chmod +x`, un glob en un script, un doble clic | Alta | Compromiso del host | Muestras `0400` sin extensión; el nombre es el sha256; nunca se toca el bit de ejecución |
| 2 | **Fuga al repo público**: `git add -f`, un rename, un `.gitignore` mal editado | Media | Distribuir malware; incumplir el ToS de abuse.ch | `.gitignore` + hook `pre-commit` que inspecciona el *index*, no las reglas de ignore |
| 3 | **Exploit del parser**: un fichero malformado a propósito revienta `pefile`, `oletools` o `libyara` | Baja | Ejecución en el proceso analizador | `scripts/sandbox.sh`: bubblewrap sin red, sin `$HOME`, repo de solo lectura, `NoNewPrivs` |
| 4 | **Propagación lateral**: la muestra acaba en un backup, un sync a la nube o la escanea un Windows de la red | Media | Alertas de EDR ajenas; borrado del corpus | Corpus fuera de rutas sincronizadas; directorio `0700`; excluido de backups |
| 5 | **Corpus mal etiquetado**: se guarda algo distinto de lo que el manifiesto afirma | Media | **Métricas mentirosas** | sha256 recalculado en la descarga; si no cuadra, se descarta |

El riesgo 5 no es de seguridad sino de integridad, pero es el más caro para
este proyecto en concreto: todo el valor de crisol está en que sus números
sean creíbles.

## Controles implementados

### 1. Almacenamiento sin filo cortante
`bench/fetch_malwarebazaar.py` guarda cada muestra:

- con el **sha256 como nombre y sin extensión**: no hay `.exe` que invite a un
  doble clic, ni extensión que dispare un handler del escritorio;
- con permisos **`0400`** (solo lectura, ni ejecución ni escritura), en un
  directorio `0700`;
- **verificando el sha256** contra el que anuncia MalwareBazaar antes de
  escribir nada.

### 2. Aislamiento del analizador
```bash
scripts/sandbox.sh make bench          # o: make sandbox-bench
scripts/sandbox.sh .venv/bin/python -m crisol.cli scan corpus/malware/<sha>
```

`scripts/sandbox.sh` envuelve el comando en [bubblewrap](https://github.com/containers/bubblewrap)
usando **user namespaces sin privilegios** (no pide root, no hay demonio, no
hay imagen que construir):

| Propiedad | Cómo |
|---|---|
| Sin red | `--unshare-all` (incluye el namespace de red) |
| Sin `$HOME` real | solo se monta el repo; `HOME` apunta a un tmpfs |
| Repo de solo lectura | `--ro-bind`; única excepción de escritura: `reports/` |
| Sin escalada de privilegios | `NoNewPrivs=1` |
| Sin robo de terminal | `--new-session` (bloquea `TIOCSTI`) |
| Muere con el padre | `--die-with-parent` |
| Clave de API tapada | `.mb_api_key` se enmascara con `/dev/null` |

Estas propiedades están **verificadas por tests** (`tests/test_sandbox.py`),
no solo documentadas: si alguien añade un `--bind` de más, el test falla.

### 3. El corpus no sale del disco
```bash
make hooks   # instala scripts/pre-commit
```
El hook bloquea cualquier commit que meta ficheros bajo `corpus/` o cualquier
binario `MZ`/`ELF`/`OLE` en el index, venga de donde venga. Mira el index
directamente, así que un `git add -f` no lo esquiva.

### 4. Endurecimiento opcional del host
Un montaje `noexec` sobre el corpus hace imposible ejecutar una muestra aunque
alguien le ponga `+x`. Requiere root una sola vez:

```bash
sudo mount --bind -o noexec,nosuid,nodev corpus/malware corpus/malware
```

Y, para que sobreviva a un reinicio, la línea equivalente en `/etc/fstab`.
Recomendado también: excluir `corpus/` de cualquier backup o carpeta
sincronizada (Dropbox, Drive, Syncthing), porque un backup automático es la vía más
silenciosa de propagar una muestra a otra máquina.

## Lo que deliberadamente NO se hace

- **No hay análisis dinámico.** Ejecutar malware exige una VM con snapshots y
  red controlada; queda fuera del alcance del proyecto y por eso el sandbox de
  bubblewrap es suficiente. Bubblewrap **no** es una frontera de seguridad
  pensada para contener código hostil ejecutándose a propósito: aquí contiene
  las consecuencias de un accidente en un proceso propio, que es otra cosa.
- **No se redistribuyen muestras.** El ToS de abuse.ch lo prohíbe. Los
  sha256 y las familias sí se pueden publicar: con eso cualquiera reconstruye
  el mismo corpus y reproduce las métricas.
- **No se desactiva el antivirus del host.** Si un EDR pone en cuarentena una
  muestra, es el sistema funcionando bien; la respuesta correcta es una
  exclusión acotada al directorio del corpus, no apagar la protección.

## Checklist operativo

Antes de descargar:
- [ ] `make hooks`: el hook anti-fugas está instalado
- [ ] `corpus/` no está dentro de una carpeta sincronizada ni de un backup

Al analizar:
- [ ] `make sandbox-bench` en vez de `make bench` cuando haya muestras reales
- [ ] nunca `chmod +x` sobre nada de `corpus/malware/`

Al publicar:
- [ ] solo hashes, familias y métricas, jamás bytes de una muestra
