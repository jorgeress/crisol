# Tercera ronda: goodware .NET, y una regla que no detectaba lo que parecía

_23 de septiembre de 2026 · 69 muestras de malware · 64 de goodware_

Las dos rondas anteriores dejaron el mismo bloqueo apuntado dos veces: en el
corpus de goodware no había ni un solo binario .NET. Eso impedía intentar la
[hipótesis 3](ronda-2-reglas.md) (una regla para los droppers .NET) y validar
las [+6 detecciones del escaneo recursivo](escaneo-recursivo.md), que salían de
`high_entropy_section` disparando sobre assemblies .NET embebidas.

Esta ronda construye ese goodware. **La detección baja del 28.99% al 17.39%**, y
es el resultado correcto: ocho de los aciertos que el banco daba por buenos no
detectaban malware, detectaban una característica que cualquier app .NET con
imágenes tiene.

## Resultado

| Métrica | Antes | Después |
|---|:---:|:---:|
| Falsos positivos (64 goodware, 6 de ellos .NET) | 3.12% (2) | **0.0%** |
| Detección directa (69 muestras) | 28.99% (20) | **17.39%** (12) |
| Detecciones extra al abrir contenedores | +6 | **+0** |

La columna "antes" es la regla antigua medida contra el corpus nuevo. Contra el
corpus viejo daba 0% de FP, y ese 0% era exactamente el que no se podía creer.

Métricas crudas en [`bench/metrics-2026-09-23-ronda3.json`](../bench/metrics-2026-09-23-ronda3.json).

## Qué se ha construido

[`bench/make_goodware_dotnet.sh`](../bench/make_goodware_dotnet.sh), análogo al
generador de Go de la ronda 2. Compila seis binarios .NET triviales y
legítimos. Cada uno representa una clase de software real que una regla mal
afinada marcaría:

| Fichero | Qué representa |
|---|---|
| `dotnet-hola-apphost.exe` + `dotnet-hola.dll` | Una app de consola moderna: el lanzador nativo y la assembly gestionada. Lo más común que existe. |
| `dotnet-winforms-net48.exe` | Un formulario de .NET Framework 4.8. Tiene **un solo import, `mscoree!_CorExeMain`**, igual que 12 de las 13 muestras .NET del malware. |
| `dotnet-recursos-net48.exe`, `dotnet-recursos.dll` | Una app con 3 MB de recursos de alta entropía, que es la forma de cualquier app WPF con imágenes. |
| `dotnet-singlefile.exe` | Un ejecutable single-file autocontenido: un contenedor con el runtime y las assemblies dentro sin comprimir, o sea tallables. Como los instaladores de ConnectWise del corpus, lleva assemblies .NET dentro. |

Se genera con `make goodware` (necesita `dotnet-sdk`) y la CI lo reconstruye en
cada push.

## El hallazgo

Con el goodware nuevo, `high_entropy_section` marca las dos apps con recursos.
Eso ya se esperaba. Lo que no se esperaba sale al mirar **sus aciertos en el
malware**:

| Muestra | Tipo | Entropía de `.text` | Sin los recursos gestionados |
|---|---|:---:|:---:|
| 5 njrat, MassLogger, RemcosRAT, Formbook | .NET, 0.7 a 1.4 MB de recursos | 7.69 a 7.87 | **5.18 a 6.16** |
| CoinMiner, `unknown` | PE nativo, sección ejecutable cifrada | 7.98 | (no aplica) |
| Las dos apps legítimas | .NET, 3.15 MB de recursos | 8.00 | **5.02 a 5.05** |

De los 10 aciertos de la regla, **8 son assemblies .NET**. En los ocho, la alta
entropía viene **solo de los recursos**: quitándolos, el código tiene la
entropía de un programa normal. Las dos apps legítimas disparan por el mismo
motivo exacto.

Así que la regla nunca detectó un dropper .NET. Detectaba "assembly .NET con
recursos comprimidos grandes", y eso incluye media industria.

### Por qué pasa

En un PE nativo, una sección ejecutable con entropía cercana a 8 es código
cifrado o comprimido: la firma de un empaquetador, que es lo que la regla
quería cazar. En una assembly .NET los recursos gestionados (imágenes, iconos,
ficheros de datos) se guardan **dentro de `.text`**, y `.text` está marcada como
ejecutable. La regla mira la entropía de la sección entera y no puede saber que
casi todos esos bytes no son código.

## El arreglo

`high_entropy_section` deja de aplicarse a las assemblies .NET: si el PE tiene
cabecera CLR, la regla no mira la entropía de sus secciones.

```yara
pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address == 0
```

Cuesta **8 detecciones** (njrat 6 → 1, MassLogger, RemcosRAT y Formbook 1 → 0),
y ninguna de las 8 era una detección real. Un empaquetador de .NET que cifre
el código en sí (y no solo los recursos) queda fuera de esta regla, y eso se
acepta: necesita una regla propia, que mire .NET por dentro.

Queda vigilado por dos tests con PE generados en memoria
(`tests/test_rules.py`): la regla tiene que seguir disparando en un PE nativo
cifrado y tiene que callarse con los mismos bytes en una assembly .NET. El
segundo falla con la regla antigua, que es la forma de saber que vigila algo.

### El +6 del escaneo recursivo, cerrado

Las seis detecciones de ConnectWise que el escaneo recursivo añadía
desaparecen con el arreglo, porque venían del mismo mecanismo.
[`escaneo-recursivo.md`](escaneo-recursivo.md) ya se negaba a firmarlas sin
este corpus; ahora está medido que eran falsos positivos.

## Qué se lleva uno de aquí

Es la tercera vez que se repite la lección de este proyecto: **el banco vale lo
que valga el corpus de goodware.**

- Ronda 1: `dynamic_api_resolution_small_iat` se afinó mirando solo goodware y
  resultó tener 0 aciertos reales.
- Ronda 2: el "cluster de crypter" era el runtime de Go.
- Ronda 3: `high_entropy_section` llevaba desde el principio en el repo, con 0%
  de FP, y el 40% de la detección total del motor salía de una
  característica que tiene cualquier app .NET con imágenes.

Esta vez no era una regla nueva que se descartó antes de publicarla: era una
regla publicada, con buenos números, y los números eran falsos. Nada en las
métricas lo delataba. Lo delató el corpus.

## Cómo seguir

> **Actualización:** el punto 1 está hecho en la
> [ronda 4](ronda-4-loader-dotnet.md).

1. **Hipótesis 3, ya desbloqueada.** Los droppers .NET (5 njrat ahora ciegos,
   MassLogger, RemcosRAT, Formbook) vuelven a no tener regla, pero ahora hay
   goodware con el que medir una. Lo que ya se sabe que **no** sirve: la
   entropía de los recursos (la tienen las apps legítimas) ni las strings
   genéricas de WinForms (ronda 2). Hay que mirar algo que una app normal no
   haga, como un recurso que se carga y se convierte en código
   (`Assembly.Load` sobre un stream de recursos).
2. **Descomprimir instaladores** (Inno, NSIS), para llegar a las dos ValleyRAT
   que se dejan pasar a sabiendas.
3. **Goodware de instaladores reales**, para medir el punto ciego de
   `overlay_bulk_inflation`, hoy cubierto solo por controles sintéticos.
