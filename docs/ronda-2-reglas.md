# Segunda ronda: qué sobrevive al banco

_7 de septiembre de 2026 · 69 muestras de malware · 57 de goodware_

La [primera medición](hallazgos-deteccion.md) dejó tres hipótesis con su
ganancia esperada. Este documento las pasa por el banco. **Una se refuta, una
se publica y una se queda bloqueada**, y el motivo del bloqueo es más
interesante que las otras dos juntas.

## Resultado

| Métrica | Antes | Después |
|---|:---:|:---:|
| Detección (69 muestras) | 21.74% (15) | **28.99%** (20) |
| Falsos positivos (57 goodware) | 0.0% | **0.0%** |

Métricas crudas en [`bench/metrics-2026-09-07.json`](../bench/metrics-2026-09-07.json).

> **El 36.84% de la ronda 1 no se compara con esto.** Aquel número salía de 19
> muestras dominadas por familias empaquetadas; este corpus se amplió *a
> propósito* hacia las familias ciegas (ValleyRAT 3→13, RemusStealer 2→12,
> njrat 1→11, RustyStealer 1→11, ConnectWise 1→11). Al meter 50 muestras
> elegidas por ser las difíciles, la tasa global baja aunque las reglas
> mejoren. La única comparación honesta es la de la tabla: mismo corpus,
> mismas muestras, antes y después.

### Por familia

| Familia | Antes | Después | Total |
|---|:---:|:---:|:---:|
| njrat | 6 | 6 | 11 |
| RemusStealer | 0 | **2** | 12 |
| RustyStealer | 1 | **2** | 11 |
| ConnectWise | 0 | **1** | 11 |
| ValleyRAT | 1 | 1 | 13 |
| unknown | 1 | **2** | 3 |
| Vidar | 1 | 1 | 3 |
| ACRStealer, CoinMiner, Formbook, MassLogger, RemcosRAT | 1 | 1 | 1 c/u |

Las dos peores siguen siendo **ConnectWise (1/11)** y **ValleyRAT (1/13)**, y
ninguna de las dos cae por empaquetado, que es lo único que este motor sabe
hacer bien.

## Hipótesis 1 — REFUTADA: no era un crypter, era el runtime de Go

La ronda 1 encontró cuatro muestras con `imphash f0ea7b78...` y exactamente 40
imports, repartidas entre Vidar, RemusStealer y `unknown`, y concluyó que era
"el mismo crypter con etiquetas distintas". Era la pieza de mayor rendimiento
esperado: +3 detecciones.

Con el corpus ampliado el cluster crece a 6 muestras, y aparece un grupo mayor:
**15 muestras con 39-47 imports que importan solo `kernel32.dll`** (10
RemusStealer, 3 Vidar, 2 `unknown`) y que comparten **35 funciones idénticas**.
Entre ellas `CreateIoCompletionPort`, `GetQueuedCompletionStatusEx`,
`SwitchToThread`, `SetProcessPriorityBoost`, `SetWaitableTimer`... que no es la
firma de ningún crypter: **es la tabla de imports del runtime de Go**.

El grep lo confirma sin margen: las muestras que llevan dentro la cadena
`Go build ID` son **exactamente esas 15**, ni una más ni una menos.

La prueba definitiva es de tres líneas:

```go
package main

import "fmt"

func main() { fmt.Println("hola") }
```

Compilado con `GOOS=windows go build`, ese programa tiene **47 imports, solo
kernel32**, y una IAT indistinguible de la de los stealers del corpus.

Así que se escribió la regla que pedía la hipótesis —la *forma* de la IAT, no
el hash literal— y se midió contra un goodware que ahora incluye binarios de Go
para Windows generados con [`bench/make_goodware_go.sh`](../bench/make_goodware_go.sh):

| Versión de la regla | TP | FP | Veredicto |
|---|:---:|:---:|---|
| `imphash` literal + 40 imports | 6 | 0 | Es un **IOC**, no una regla: solo reconoce esas compilaciones exactas. Cero generalización. |
| Forma de la IAT (lo que pedía la hipótesis) | 6 | **5 de 5** | Marca **el 100% del goodware de Go del corpus**. FP global 8.77%. |

Cinco de cinco. La regla no detecta un crypter: detecta que un programa está
escrito en Go, y eso incluye docker, kubectl, terraform y hugo.

**Y aquí está lo importante**: esta regla habría dado 0% de falsos positivos
contra el corpus de la ronda 1, porque aquel goodware eran 52 binarios de Linux
y de Wine, ni uno compilado con Go. Es *exactamente* el mismo error del
hallazgo 2 de la ronda anterior —afinar contra un corpus que no contiene la
clase que te va a doler— pero cazado antes de publicar la regla en vez de
después. El arreglo no fue tocar la regla: fue **arreglar el corpus**, y por eso
`make_goodware_go.sh` es el entregable real de esta hipótesis.

## Hipótesis 2 — PUBLICADA: overlay que se come el fichero

El overlay son los bytes que van detrás de la última sección. Medido sobre los
dos corpus:

| | overlay máximo | ratio máximo |
|---|:---:|:---:|
| Goodware (57) | **0.72 MB** | 61.9% (de un fichero de 0.16 MB) |
| Malware (69) | **88.09 MB** | 99.6% |

Ningún binario legítimo del corpus pasa de un mega. Nueve muestras van de 8.4 a
88.1 MB de overlay, dominando entre el 61.1% y el 99.6% del fichero. Eso es relleno
para pasarse del umbral de tamaño por encima del cual muchos AV y sandboxes
descartan un fichero sin mirarlo.

Se publican dos reglas en [`rules/malware/overlay_inflation.yar`](../rules/malware/overlay_inflation.yar):

| Regla | Condición | TP | FP |
|---|---|:---:|:---:|
| `overlay_bulk_inflation` | overlay >4 MB, >60% del fichero, sin firma de contenedor conocido | **7** | 0 |
| `overlay_null_padding` | overlay >1 MB, >50%, entropía <1.0 | **2** | 0 |

Ganancia neta: **+5 detecciones** sobre falsos negativos (RemusStealer 0→2,
ConnectWise 0→1, RustyStealer 1→2, `unknown` 1→2); las otras dos ya caían por
otra regla.

### La renuncia deliberada

Un instalador legítimo —NSIS, Inno Setup, un 7z auto-extraíble— es un PE
pequeño con un archivo comprimido gigante pegado detrás. Estructuralmente es
**idéntico** al relleno de evasión. Por eso la regla no dispara si el overlay
empieza por la firma de un contenedor conocido (ZIP, CAB, 7z, RAR, XZ, gzip,
OLE/MSI, Inno).

Eso cuesta detecciones reales y medibles: dos ValleyRAT del corpus tienen
overlays de 16 y 29 MB que empiezan por `7a 6c 62 1a`, o sea `zlb\x1a`, la
firma de Inno Setup. Son instaladores maliciosos, y la regla los deja pasar a
sabiendas. La alternativa era marcar como malicioso todo instalador del mundo;
distinguirlos exige abrir el contenedor, que es la siguiente **herramienta**, no
la siguiente regla.

Para que esa renuncia esté medida y no solo argumentada, el goodware incluye
ahora un control con forma de auto-extraíble: un binario legítimo de Go con 21
MB de ZIP detrás (89% del fichero). Si alguien relaja la regla, ese control se
enciende y el gate de CI falla.

**Punto ciego que queda anotado**: un auto-extraíble legítimo con un contenedor
*propietario* (sin firma reconocible) sí sería un falso positivo. No hay ninguno
en el corpus, así que hoy es una hipótesis sin medir, no un hecho.

## Hipótesis 3 — BLOQUEADA: no hay goodware .NET con el que falsarla

Trece muestras del corpus son .NET (10 njrat, MassLogger, Formbook, RemcosRAT),
doce de ellas con un único import: `mscoree.dll!_CorExeMain`. Cinco njrat siguen
sin detectarse.

La hipótesis proponía combinar ese pivote .NET con strings de RAT. Al buscarlas,
lo que aparece en las trece muestras es WinForms genérico —`STAThreadAttribute`,
`ResumeLayout`, `ResourceManager`, el manifiesto de `requestedPrivileges`— y no
un solo indicador específico de familia: no son njRAT desnudo, son *droppers*
.NET con el payload dentro de los recursos. Los indicadores de comportamiento
que sí discriminarían (`InvokeMember`, `GetManifestResourceStream`,
`RegistryKey`) aparecen también en el goodware del corpus.

Se podría escribir igualmente una regla del tipo "assembly .NET con un recurso
enorme y de alta entropía" y saldría un 0% de FP. **Sería mentira**, por la
misma razón que la hipótesis 1: en el corpus de goodware no hay ni un solo
binario .NET, así que ese 0% no mediría nada. Un instalador de WPF con imágenes
embebidas tiene exactamente esa forma.

La regla no se publica. El bloqueo no es de detección, es de corpus, y tiene
arreglo concreto: hace falta un toolchain .NET (`dotnet` no está en esta
máquina) para generar goodware .NET igual que se hizo con Go. Hasta entonces,
cualquier regla .NET de este repo sería una regla sin banco.

## Qué se lleva uno de aquí

Las tres hipótesis venían con una ganancia esperada. La suma prometida era ~+7
detecciones; la entregada es +5, y de una sola de las tres. Las otras dos no
fallaron por escribir mal la regla:

- La **1** fallaba porque el corpus de goodware no contenía la clase de software
  que la regla iba a marcar.
- La **3** falla por lo mismo, y por eso no se publica.

El patrón se repite: **el banco de pruebas vale lo que valga el corpus de
goodware**. Escribir la regla es la parte fácil; construir el corpus que puede
demostrar que está mal es el trabajo.

## Cómo seguir

1. **Goodware .NET** (`dotnet build`, análogo a `make_goodware_go.sh`) — sin eso
   la hipótesis 3 no se puede ni intentar.
2. **Goodware de instaladores reales** (NSIS, Inno, 7z SFX legítimos) para
   medir de verdad el punto ciego de `overlay_bulk_inflation`, hoy cubierto solo
   por un control sintético.
3. **Abrir contenedores**: extraer el payload de un Inno/NSIS y escanearlo
   recursivamente. Ahí están las dos ValleyRAT que hoy se dejan pasar a
   sabiendas, y es lo que convierte el motor en algo más que un mirador de
   cabeceras.
4. **Familias todavía ciegas**: ConnectWise 1/11 y ValleyRAT 1/13 son las peores
   del banco, y ninguna cae por empaquetado.
