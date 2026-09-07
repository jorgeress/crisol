# Abrir el contenedor: escaneo recursivo

_7 de septiembre de 2026 · 69 muestras de malware · 58 de goodware_

`overlay_bulk_inflation` renuncia a propósito a los instaladores: un NSIS
malicioso y uno legítimo tienen la misma forma, y separarlos exige mirar
dentro. Esto es mirar dentro. **Y el resultado principal no es la detección que
suma, sino por qué no puedo firmarla.**

## Qué se ha construido

`src/yardstick/carve.py` extrae payloads de una muestra y
`RuleSet.scan_recursive()` los escanea:

- **PE embebidos sin comprimir**, tallados leyendo la tabla de secciones a mano
  (no con pefile: sobre un offset arbitrario de un fichero hostil es mucha
  superficie de ataque para solo querer un tamaño).
- **Miembros de ZIP**, que cubre los auto-extraíbles con esa forma.

Con topes en todo (64 payloads, 64 MB cada uno) porque cada offset que entra
ahí lo eligió el fichero analizado, no yo.

Disponible en `bench/harness.py --recursive` y en `yardstick scan --recursive`.

## Los dos números van separados

*"Este fichero dispara una regla"* y *"este fichero contiene algo que la
dispara"* son afirmaciones distintas. Sumarlas infla la detección sin decirlo,
así que el harness las cuenta aparte y el CLI no deja que un payload embebido
cambie el veredicto de la muestra.

| Métrica | Valor |
|---|---|
| Detección directa | 20/69 = **28.99%** |
| Solo al abrirlos | +6 → 26/69 = **37.68%** |
| FP directos (58 goodware) | 0.0% |
| FP solo por lo de dentro | **0/58** |

## Por qué ese +6 no me lo creo

Las seis detecciones nuevas son **todas ConnectWise**, y todas vienen de la
misma regla: `high_entropy_section` disparando sobre una assembly .NET de 3 MB
embebida en el instalador.

ConnectWise ScreenConnect es **software legítimo de acceso remoto**, abusado
por actores que lo despliegan configurado contra su propio servidor. Las
muestras del corpus llevan dentro las URLs de code signing de DigiCert: son
instaladores firmados de verdad. Lo malicioso es la **configuración** —en una de
ellas, el IOC `192.162.199.231`— no la estructura del binario.

O sea: un instalador legítimo de ScreenConnect dispararía exactamente igual.

### El mecanismo, que es lo generalizable

En una assembly .NET los recursos gestionados embebidos viven **dentro de
`.text`**, que está marcada como ejecutable. `high_entropy_section` exige
precisamente una sección ejecutable con entropía ≥7.4. Conclusión: **cualquier
assembly .NET con recursos comprimidos grandes dispara esa regla**, y eso
describe a media industria — apps WPF, instaladores, ClickOnce.

Sobre el fichero de arriba eso casi nunca se ve, porque una assembly .NET
suelta no suele traer 3 MB de recursos. Al escanear recursivamente, en cambio,
se abre todo instalador y se mira todo lo que lleva dentro, que es justo donde
viven esas assemblies. **El escaneo recursivo no añade poder de detección: le
multiplica el alcance a las reglas que ya tienes, puntos ciegos incluidos.**

### Y no puedo falsarlo

Para medirlo haría falta goodware .NET. En esta máquina hay **cero** assemblies
.NET (rebuscado en `/usr/lib/wine`, `/opt`, `/usr/lib/mono`, `/usr/share/dotnet`)
y no hay toolchain `dotnet` con el que generarlas. Es la misma pared que
bloqueó la [hipótesis 3 de la ronda 2](ronda-2-reglas.md#hipótesis-3--bloqueada-no-hay-goodware-net-con-el-que-falsarla),
y ahora bloquea dos cosas en vez de una.

Por eso el 37.68% no sube al README como tasa de detección, y `--recursive` es
opcional y va apagado por defecto.

## Lo que sí queda medido

El goodware tenía un problema silencioso: **ni un solo fichero con PEs
embebidos**. Escanear recursivamente contra él habría dado 0% de FP sin
comprobar nada, que es la trampa de este proyecto entero.

`make_goodware_go.sh` genera ahora un segundo control,
`control-bundle-pe-amd64.exe`: un stub legítimo con los binarios de Go dentro,
en ZIP **sin comprimir** para que sean tallables. El motor extrae los cuatro y
no dispara sobre ninguno. Ese 0 sí significa algo.

## Un límite que también es una defensa

El tallado solo encuentra payloads **sin comprimir**. Un instalador que
deflatea su contenido es invisible aquí — eso recorta lo que se detecta, pero
recorta exactamente igual lo que se puede marcar por error: lo que sale del
tallador son ejecutables tal cual, no blobs descomprimidos que se parezcan a
cualquier cosa.

Las dos ValleyRAT de Inno Setup que la ronda 2 dejaba pasar **siguen pasando**:
su payload va comprimido. Para esas hace falta `innoextract` o equivalente, y
eso es una dependencia externa, no una regla.

## Un gate que no podía fallar

`--max-fp-rate` miraba solo la tasa de matches directos. En modo recursivo, un
goodware que se enciende **solo** por lo que lleva dentro no incrementaba esa
tasa: el umbral pasaba sin haber comprobado nada. Arreglado con
`false_positive_rate_recursive`, que es la que mira el gate cuando `--recursive`
está activo, y con un test de regresión (`tests/test_harness_gate.py`) que
construye el caso —contenedor limpio, payload sucio— y comprueba que el gate
falla. Un gate que no puede fallar no es un gate.

## Cómo seguir

1. **Goodware .NET.** Bloquea la hipótesis 3 y bloquea validar este +6. Es, con
   diferencia, lo siguiente que más vale.
2. **Revisar `high_entropy_section`** a la luz de esto: probablemente deba
   excluir assemblies .NET, o exigir que la sección de alta entropía no sea la
   `.text` de un binario gestionado. No se toca sin corpus con el que medirlo.
3. **Descompresión de instaladores** (Inno, NSIS) para llegar a los payloads
   comprimidos, asumiendo la dependencia externa.
