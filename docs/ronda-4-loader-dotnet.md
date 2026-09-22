# Cuarta ronda: el crypter de las cuatro familias

_23 de septiembre de 2026 · 69 muestras de malware · 315 de goodware_

La [ronda 3](ronda-3-dotnet.md) dejó ciegas a 8 muestras .NET: `high_entropy_section`
las detectaba por una razón equivocada, y al corregirla se quedaron sin regla.
Esta ronda les busca una regla de verdad. Lo que sale es mejor de lo esperado:
cuatro "familias" distintas resultan ser **el mismo crypter**.

## Resultado

| Métrica | Antes | Después |
|---|:---:|:---:|
| Falsos positivos | 0.0% (64 goodware) | **0.0%** (315 goodware) |
| Detección (69 muestras) | 17.39% (12) | **33.33%** (23) |
| njrat | 1/11 | **9/11** |
| MassLogger, RemcosRAT, Formbook | 0/1 cada una | **1/1** cada una |

Supera el 28.99% de la ronda 2, y esta vez sin ningún acierto por la razón
equivocada que se sepa. Métricas crudas en
[`bench/metrics-2026-09-23-ronda4.json`](../bench/metrics-2026-09-23-ronda4.json).

## Primero, un corpus que pueda decir que no

Los seis binarios .NET de la ronda 3 son programas de juguete: no dibujan
imágenes ni usan reflexión. Una regla que mire esas APIs daría 0% de FP contra
ellos sin haber probado nada, que es la trampa de la que va este proyecto.

Así que `make_goodware_dotnet.sh` hace ahora dos cosas más:

1. **Publica una app WinForms + WPF autocontenida**, como la distribuiría un
   fabricante. La carpeta resultante son 249 binarios: la propia app y
   **247 binarios reales de Microsoft**: la implementación de WinForms, WPF,
   System.Drawing y el runtime, con sus DLL nativas. Es software de producción
   que usa legítimamente todas las APIs que usa un loader.
2. **Construye dos controles con la forma exacta del loader** (se explican
   abajo, porque salen del análisis).

El goodware pasa de 64 a 315 binarios, 234 de ellos .NET.

## Una regla que ya estaba mal: `anti_debug_stacked`

Antes de escribir nada nuevo, las reglas existentes contra el corpus ampliado.
`anti_debug_stacked` marca **`mscordbi.dll`, el depurador de .NET**.

La regla clasificaba `DebugActiveProcess` como técnica *fuerte*, rara en
software legítimo. Y lo es, salvo en depuradores: es literalmente la API con la
que un depurador se engancha a un proceso. Lo mismo vale para profilers y
reportadores de errores. El corpus no tenía ninguno.

Se degrada a *ubicua*. **No cuesta ningún acierto**: las cuatro muestras que
disparan la regla tienen además `NtQueryInformationProcess`. Un test nuevo
(`test_anti_debug_does_not_fire_on_a_debugger`) reproduce las APIs de
`mscordbi.dll` y falla con la regla antigua.

## El hallazgo: un crypter, cuatro familias

Las 13 muestras .NET del corpus se separan en dos grupos sin mirar ninguna
etiqueta:

**Grupo A, njRAT a pelo** (4 muestras de 20 a 60 KB). La configuración va en
claro: host, puerto, el separador de protocolo `|'|'|`, los comandos
(`netsh firewall`, `cmd.exe /c ping 0 -n 2 & del`) y los mensajes de error del
builder (`Execute ERROR`, `Download ERROR`).

**Grupo B, loader esteganográfico** (8 muestras: 5 njrat, MassLogger, RemcosRAT
y Formbook). Todas son una app WinForms de tapadera con nombres de proyecto
inventados (`VineyardFrost`, `CollieryWinder`, `PonsFuniculus`, `RegenGarten`),
con una imagen de 0.7 a 1.4 MB en `Properties.Resources` que ocupa **entre el
83% y el 96% del fichero**, y las mismas APIs: `Bitmap`, `GetPixel`,
`InvokeMember`. El payload va escondido en los píxeles de la imagen, se
reconstruye leyéndolos uno a uno y se ejecuta por reflexión.

MassLogger y RemcosRAT comparten incluso la tapadera (`VineyardFrost`, con
textos en finés). Lo que MalwareBazaar etiqueta como cuatro familias es **el
mismo empaquetador** con cuatro payloads distintos. Para una regla eso es una
buena noticia: se caza el envoltorio, y el envoltorio es común.

## Qué combinación sobrevive

Cada pieza del grupo B por separado es de lo más normal. Esto es lo que da cada
candidata contra el corpus final (234 assemblies .NET legítimas):

| Condición | TP | FP | Quién la tumba |
|---|:---:|:---:|---|
| `GetPixel` | 6 | 4 | `System.Windows.Forms.dll` y los dos controles |
| `InvokeMember` | 7 | 5 | `PresentationCore.dll`, `System.Xaml.dll`... |
| Recurso > 50% del fichero (la hipótesis 3 original) | 8 | **8** | 4 DLL de Microsoft (temas de WPF como `PresentationFramework.Luna.dll`, y `System.Text.Encoding.CodePages.dll`) y 4 controles |
| Recurso > 50% + `GetObject` | 8 | 0 → **2** | los dos controles |
| Recurso > 50% + (`InvokeMember` o `Activator`) | 8 | 0 → **1** | el control `plugins` |
| **Recurso > 50% + `Bitmap` + `InvokeMember`** | **7** | **0** | nadie |

La hipótesis 3 de la ronda 2 ("recurso enorme y de alta entropía") queda
refutada con datos: **cuatro DLL reales de Microsoft** tienen esa forma, sin
contar los controles sintéticos.

### Los dos controles, y por qué hacían falta

Las filas con la flecha (`0 → 2`, `0 → 1`) daban **8 TP y 0 FP** contra los 247
binarios de Microsoft. Parecían las ganadoras. Pero todos esos binarios son
**librerías**, y lo que el loader imita es una **aplicación**: una app WinForms
que lee su imagen de fondo con `ResourceManager.GetObject` hace exactamente lo
mismo que el dropper, y el corpus no tenía ninguna.

Así que se construyeron dos, compilados para .NET Framework 4.8 igual que las
muestras:

- **`dotnet-visor.exe`**: un cuentagotas. Imagen PNG de 1024x768 en
  `Properties.Resources`, leída con `GetObject`, y `GetPixel` para mostrar el
  color donde se hace clic.
- **`dotnet-plugins.exe`**: el mismo visor, que además carga plugins por
  reflexión con `Activator.CreateInstance`.

Tumbaron las dos candidatas. Sin ellos se habría publicado una regla que marca
cualquier app con una imagen de fondo grande.

### La regla publicada

[`rules/malware/dotnet_loaders.yar`](../rules/malware/dotnet_loaders.yar):

```yara
dotnet.is_dotnet and $bitmap and $invoke and
for any i in (0..dotnet.number_of_resources - 1): (
    dotnet.resources[i].length > filesize \ 2
)
```

`$bitmap` y `$invoke` buscan los nombres en el heap de metadatos delimitados por
bytes nulos, para no casar con `BitmapData` o `InvokeMemberBinder`.

**Punto ciego anotado**: una app legítima con una imagen que ocupe más de medio
fichero y que automatice COM (Excel, Word) con `InvokeMember` dispararía. No hay
ninguna en el corpus, así que es una hipótesis sin medir, no un hecho.

## La regla de njRAT

`njrat_config_markers` pide 4 de 8 marcadores del grupo A (separador, comandos y
mensajes de error), en UTF-16 porque .NET guarda así sus strings. 4 TP, 0 FP.

Es una **firma de familia**, no de comportamiento, y conviene decirlo: caza el
builder 0.7d de njRAT y nada más. Se deja fuera `0.7d` (demasiado corto) y la
clave `Run` del registro (la usa cualquier programa que arranque con Windows).

## Lo que sigue sin detectarse

Dos njrat:

- **`a9665d49`**: es del grupo B (imagen del 95%, tapadera `RegenGarten`), pero
  usa `Activator.CreateInstance` en vez de `InvokeMember`. Cazarla exige aceptar
  `Activator`, y el control `plugins` demuestra que eso marca apps legítimas.
  Se deja pasar a sabiendas.
- **`6f201afc`**: ofuscada (espacios de nombres como `Ⴍ`), sin recurso grande ni
  strings en claro. Necesita otra herramienta, no otra regla.

## Qué se lleva uno de aquí

Esta ronda sube la detección en vez de bajarla, pero la lección es la misma de
siempre, y esta vez se ve en la tabla: **dos de las candidatas daban 8 TP y 0 FP
hasta que se construyó el goodware capaz de tumbarlas.** Contra 247 binarios de
Microsoft ya parecían sólidas. Lo que faltaba no era volumen, era la clase de
software correcta: una aplicación con la misma forma que el malware.

## Cómo seguir

1. **Descomprimir instaladores** (Inno, NSIS): las dos ValleyRAT que se dejan
   pasar a sabiendas desde la ronda 2.
2. **Goodware de instaladores reales**, para medir el punto ciego de
   `overlay_bulk_inflation`.
3. **Familias ciegas**: ConnectWise 1/11 y ValleyRAT 1/13 siguen siendo las
   peores, y ya no queda nada fácil en ellas.
