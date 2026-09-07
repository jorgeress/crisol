# Primera medición de detección sobre malware real

_3 de septiembre de 2026 · 19 muestras · 12 familias_

Hasta aquí crisol solo medía **falsos positivos** (0% sobre 52 binarios
legítimos). Eso es media historia: unas reglas que no disparan nunca también
tienen 0% de FP. Este documento es la otra mitad: qué detectan de verdad, qué
se les escapa y **por qué**.

## Resultado

| Métrica | Valor |
|---|---|
| Falsos positivos (52 goodware) | **0.0%** |
| Detección (19 muestras reales) | **36.84%** (7/19) |

Métricas crudas en [`bench/metrics-2026-09-03.json`](../bench/metrics-2026-09-03.json).

### Por regla

| Regla | TP | FP |
|---|---|---|
| `high_entropy_section` | 5 | 0 |
| `packer_signature_strings` | 1 | 0 |
| `anti_debug_stacked` | 1 | 0 |
| `process_injection_apis` | **0** | 0 |
| `dynamic_api_resolution_small_iat` | **0** | 0 |
| reglas VBA (`vba_*`) | 0 | 0 |

### Por familia

| Familia | Detectadas | Total |
|---|---|---|
| ACRStealer, CoinMiner, Formbook, MassLogger, RemcosRAT | 1 | 1 |
| Vidar | 1 | 3 |
| unknown | 1 | 3 |
| **ValleyRAT** | **0** | 3 |
| **RemusStealer** | **0** | 2 |
| **ConnectWise, RustyStealer, njrat** | **0** | 1 |

## Metodología

- **Corpus**: MalwareBazaar vía `--recent` (rodaja temporal de lo que circulaba
  ese día) filtrado a `exe,dll`, con tope de 3 por familia para que una campaña
  activa no domine la muestra.
- **Integridad**: sha256 recalculado antes de guardar. Un corpus mal etiquetado
  produce métricas mentirosas, que es el fallo más caro de este proyecto.
- **Aislamiento**: todo el análisis corrió dentro de `scripts/sandbox.sh`
  (ver [manejo seguro de muestras](manejo-seguro-muestras.md)).
- **Reproducibilidad**: [`bench/corpus_manifest.json`](../bench/corpus_manifest.json)
  publica los sha256 y las familias. Con eso cualquiera reconstruye el mismo
  corpus y contrasta estos números. Las muestras no se redistribuyen.

## Hallazgos

### 1. El motor es, hoy, un detector de entropía
Cinco de las siete detecciones vienen de `high_entropy_section`, una de strings
de packer y una de anti-debug. **Ninguna de comportamiento.** Todo lo que
crisol caza, lo caza porque está empaquetado; contra una muestra sin
empaquetar es ciego.

### 2. La hipótesis del "IAT diminuta" queda refutada
`dynamic_api_resolution_small_iat` exige `pe.number_of_imported_functions < 30`.
Ese umbral salió de afinar **contra goodware**, y funcionó: bajó los FP. Contra
malware real da **0 verdaderos positivos**, porque los stealers de este corpus
tienen IAT de 39 a 658 funciones:

| Muestra | Familia | Imports |
|---|---|---|
| `2faf35c8` | ValleyRAT | 658 |
| `ffb3eacf` | RustyStealer | 303 |
| `52e889aa` | ValleyRAT | 146 |
| `32431111` | ConnectWise | 76 |
| `0b00260f` | RemusStealer | 39 |

Es sobreajuste de libro: se optimizó una métrica (FP) hasta vaciar la regla de
valor en la otra (detección). Documentarlo vale más que la regla que sí
funcionaba, porque es la trampa en la que cae cualquiera que afine reglas
mirando un solo lado del banco.

### 3. Un cluster de imphash agrupa 4 muestras (3 sin detectar)
Cuatro muestras comparten `imphash f0ea7b7844bbc5bfa9bb32efdcea957c` con
exactamente 40 funciones importadas: dos etiquetadas Vidar y dos `unknown`. Es
el mismo crypter con etiquetas distintas. Solo una cae (por strings de packer).

Una regla sobre esa forma de IAT convierte 3 falsos negativos en detecciones.
**Es la pieza suelta de mayor rendimiento del corpus.**

### 4. Un imphash que parece regla y es solo un pivote
Otro cluster, `f34d5f2d4577ed6d9ceec516c1f5a744` con 1 import, es
`mscoree.dll!_CorExeMain`: la firma de **cualquier ejecutable .NET**
(MassLogger, Formbook, njrat aquí). Como regla suelta devolvería el FP rate a
dos dígitos el día que el goodware tenga un binario .NET. Sirve como
**pivote** (condición de entrada que se combina con otra evidencia), nunca
como detección por sí sola.

### 5. Inflado de tamaño como evasión
Dos muestras rondan los 90 MB con ~87 MB de **overlay** (datos tras la última
sección). Es relleno deliberado: muchos AV y sandboxes saltan ficheros por
encima de un umbral de tamaño. La estructura es muy característica (overlay
enorme y de baja entropía) y el goodware casi nunca la tiene, así que promete
detección con FP bajo.

### 6. Lo pequeño y sin empaquetar es invisible
`njrat` ocupa 0.0 MB, es .NET y tiene entropía 5.57. No hay nada que empaquetar
ni sección de alta entropía que ver. Contra este perfil las reglas actuales no
pueden hacer nada por construcción: hace falta otra familia de reglas basada en
strings y estructura .NET.

## Limitaciones (leer antes de citar los porcentajes)

- **n = 19.** Cada muestra vale 5.3 puntos de detección. Los intervalos de
  confianza son anchísimos; estos números orientan el trabajo, no certifican
  nada.
- **Las familias con 1 muestra no tienen tasa**, tienen un sí o un no.
- **`--recent` es una rodaja temporal**, no una muestra representativa del
  malware en general: sobrerrepresenta las campañas activas ese día.
- **El goodware son 52 binarios de Linux/Wine**, así que el 0% de FP no dice
  nada sobre software Windows firmado, que es donde más duele un falso positivo.

## Cómo seguir

Las tres reglas siguientes, en orden de rendimiento esperado, cada una con su
hipótesis falsable:

1. **Cluster de crypter por forma de IAT** (hallazgo 3). *Hipótesis*: la
   combinación de imphash y conteo de imports identifica al crypter con
   independencia de la familia. *Ganancia esperada*: +3 detecciones (→ ~52%).
2. **Overlay desproporcionado** (hallazgo 5). *Hipótesis*: un overlay que es
   >80% del fichero y supera decenas de MB es relleno de evasión, no datos
   legítimos. *Ganancia esperada*: +1, y generaliza a campañas futuras.
3. **Malware .NET sin empaquetar** (hallazgo 6). *Hipótesis*: el pivote .NET
   del hallazgo 4 más strings de RAT (`mscoree` + patrones de configuración
   embebida) discrimina sin tocar el goodware .NET.

**Criterio de aceptación innegociable: el FP rate se queda en 0%.** Una regla
que suba la detección rompiendo eso es una regla que se descarta. Y después de
escribirlas hay que **volver a medir con el corpus ampliado**, no con este:
afinar contra las mismas 19 muestras es repetir el error del hallazgo 2 en la
otra dirección.

Antes de escribir nada conviene subir el corpus a 50-60 muestras con
`--signature` sobre las familias ciegas (ValleyRAT, RemusStealer, njrat), para
que cada muestra deje de valer 5 puntos.

---

> **Continuación (7 sep 2026)**: hecho, y con sorpresa. El corpus está en 69
> muestras y las tres hipótesis ya pasaron por el banco: la 2 se publica, la 3 se
> queda bloqueada y **la 1, la de mayor rendimiento esperado, queda refutada: el
> "cluster de crypter" de este documento es el runtime de Go**. Está todo en
> **[la ronda 2](ronda-2-reglas.md)**.
