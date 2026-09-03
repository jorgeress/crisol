# yardstick — motor de triaje estático de malware + banco de reglas YARA

> Analiza binarios (PE / ELF / documentos ofimáticos) **sin ejecutarlos**, los
> puntúa con heurísticas explicables y coincidencias YARA propias, y —lo más
> importante— **mide la calidad de esas reglas** contra corpus de goodware y
> malware. Detection engineering, no una caja negra.

![python](https://img.shields.io/badge/python-3.11+-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![ci](https://img.shields.io/badge/ci-github_actions-lightgrey)

## Por qué este proyecto

Cualquiera puede correr `yara reglas.yar muestra.exe`. Lo que distingue a un
analista es saber **cuánto vale una regla**: ¿cuántos falsos positivos genera
contra software legítimo? ¿qué tasa de detección real tiene? Este proyecto
convierte esa pregunta en un número reproducible.

Ejemplo real del baseline de este repo — un binario **legítimo y firmado de
Microsoft** clasificado como malicioso por reglas demasiado laxas:

```
$ yardstick scan winhttp-proxy-shim.exe
  veredicto malicious-likely  (score 75/100)      <-- FALSO POSITIVO
  YARA: dynamic_api_resolution_and_alloc, anti_debug_checks
```

### Afinado guiado por métricas (antes → después)

El harness midió la tasa de falsos positivos sobre 52 binarios legítimos y
guió el rediseño de cada regla. Cada cambio está justificado con datos:

| Regla | FP antes | FP después | Qué cambió (y por qué) |
|-------|:-------:|:---------:|------------------------|
| `anti_debug_checks` → `anti_debug_stacked` | **12.2%** | **0%** | Una sola API (`IsDebuggerPresent` del CRT) es ubicua. Se estratifican las APIs en *fuertes* (nivel NT, raras en goodware) vs *ubicuas*, y se exigen 2 fuertes o 1 fuerte + 2 ubicuas. |
| `dynamic_api_resolution_and_alloc` → `..._small_iat` | **4.5%** | **0%** | `LoadLibrary`+`GetProcAddress` es normal en software grande (IAT de 100-258 fns). Los loaders reales tienen IAT **diminuta**; se añade `number_of_imported_functions < 30`. |
| `vba_powershell_invocation` | **0.6%** | **0%** | Disparaba sobre PEs donde `"powershell"` aparece legítimamente. Ahora excluye binarios PE/ELF nativos. |
| **Global** | **12.18%** | **0.0%** | 52 muestras de goodware, 0 marcadas. |

### Y el otro lado del banco: detección real (3 sep 2026)

Unas reglas que no disparan nunca también tienen 0% de FP, así que el número
anterior por sí solo no dice nada. Contra **19 muestras reales de
MalwareBazaar** (12 familias):

| Métrica | Valor |
|---|---|
| Falsos positivos (52 goodware) | **0.0%** |
| Detección (19 muestras reales) | **36.84%** |

Y ahí aparece lo interesante: **`dynamic_api_resolution_small_iat`, la regla que
mejor bajó los FP en la tabla de arriba, tiene 0 verdaderos positivos.** El
umbral `IAT < 30` se ajustó mirando solo goodware; el malware real de este
corpus importa entre 39 y 658 funciones. Es sobreajuste de manual, medido y
documentado.

La autopsia completa —qué detecta cada regla, qué familias quedan ciegas, un
cluster de imphash que agrupa 4 muestras, evasión por inflado de tamaño, y las
limitaciones de un corpus de n=19— está en
**[docs/hallazgos-deteccion.md](docs/hallazgos-deteccion.md)**.

Métricas crudas versionadas en [`bench/metrics-2026-09-03.json`](bench/metrics-2026-09-03.json);
el corpus es reconstruible desde [`bench/corpus_manifest.json`](bench/corpus_manifest.json)
(sha256 y familia; las muestras no se redistribuyen).

## Arquitectura

```
muestra ──► features.py ──► señales estáticas (entropía, imports, secciones,
              (sin ejecutar)   macros VBA, IOCs, overlay, imphash…)
        │
        └──► scanner.py ────► reglas YARA propias (rules/)  ──┐
                                                              ├─► report.py
              scoring heurístico explicable  ─────────────────┘   (JSON / HTML / CLI)

bench/harness.py ──► corre las reglas sobre corpus etiquetados
                     ► FP rate (goodware) · detección (malware) · por-regla
```

| Módulo | Qué hace |
|--------|----------|
| `src/yardstick/features.py` | Extracción estática: hashes, entropía global/por-sección, imports (con lista curada de APIs abusadas), imphash, overlay, secciones RWX, macros VBA (oletools), IOCs (URLs/IPs/dominios/registro). |
| `src/yardstick/scanner.py`  | Compila todo `rules/**/*.yar` en un ruleset y ejecuta el match. |
| `src/yardstick/report.py`   | Scoring ponderado **explicable** (cada punto tiene su razón) + salida JSON y HTML. |
| `src/yardstick/cli.py`      | `scan`, `features`, `rules`. Exit code 0/1/2 = limpio/sospechoso/malicioso (útil en pipelines). |
| `bench/harness.py`          | El banco de pruebas: métricas de FP/detección por regla, con umbral para CI. |
| `rules/`                    | Reglas YARA propias, con `author`/`date`/`severity`/`mitre`/`reference`. |

## Uso

```bash
make install                          # crea .venv e instala dependencias
make rules                            # compila y valida el ruleset
make scan SAMPLE=/ruta/muestra.exe    # triaje de una muestra
make bench                            # métricas de FP/detección
make test

# salidas alternativas
yardstick scan muestra.exe --json > report.json
yardstick scan muestra.exe --html reports/muestra.html
```

## El corpus (importante)

- **Goodware**: binarios legítimos del sistema (`/usr/bin`, DLLs de Windows/Wine).
  Cualquier match aquí es un falso positivo.
- **Malware**: se descarga de [MalwareBazaar](https://bazaar.abuse.ch) con
  `bench/fetch_malwarebazaar.py` (ZIP con contraseña `infected`). **Nunca se
  ejecutan** y **nunca se suben al repo**.

> **Cómo se manejan las muestras sin pegarse un tiro en el pie:**
> guardadas `0400` con el sha256 verificado, análisis aislado en bubblewrap
> (sin red, sin `$HOME`, repo de solo lectura) y un hook `pre-commit` que
> impide subirlas. El modelo de amenaza completo, con lo que se hace y lo que
> deliberadamente no, está en **[docs/manejo-seguro-muestras.md](docs/manejo-seguro-muestras.md)**.

```bash
make hooks           # hook anti-fugas (hazlo ANTES de descargar nada)
make sandbox-bench   # el bench, con el analizador aislado
```

```bash
export MB_API_KEY=...                  # gratis en bazaar.abuse.ch
# o bien:  echo '<clave>' > .mb_api_key   (gitignored)

make corpus                            # TAG=exe LIMIT=30 MAXFAM=3 por defecto
python bench/fetch_malwarebazaar.py --tag exe --limit 30 --max-per-family 3 --dry-run
```

El fetcher tope por familia (`--max-per-family`) para que el corpus no sea
monotemático, salta lo ya descargado y escribe `bench/corpus_manifest.json`
(sha256 → familia, tipo, tags). Con ese manifiesto el harness desglosa la
**detección por familia** y lista los **falsos negativos**, que son la lista de
tareas de la siguiente ronda de reglas.

## Roadmap

- [x] Extracción de features PE/ELF/OLE + scoring explicable
- [x] Ruleset YARA propio con metadatos y módulo `pe`/`math`
- [x] Harness de FP/detección por regla + gate en CI
- [x] **Afinado de reglas guiado por métricas** (FP rate 12.18% → 0%, documentado en la tabla de arriba)
- [x] **Medición de detección sobre malware real** (36.84% con 0% de FP,
      [autopsia documentada](docs/hallazgos-deteccion.md))
- [x] **Manejo seguro de muestras**: almacenamiento sin bit de ejecución, sandbox
      de bubblewrap con aislamiento verificado por tests, y hook anti-fugas
      ([documentado](docs/manejo-seguro-muestras.md))
- [ ] **Subir la detección sin romper el 0% de FP** — tres reglas con hipótesis
      falsable, en orden de rendimiento esperado: cluster de crypter por forma de
      IAT, overlay desproporcionado, y .NET sin empaquetar
      ([detalle y criterio de aceptación](docs/hallazgos-deteccion.md#cómo-seguir))
- [ ] **Módulo de evasión controlada**: empaquetar/ofuscar muestras benignas para
      mostrar cómo rompen la detección, y endurecer las reglas en consecuencia
      (el ciclo rojo↔azul es el gancho de entrevista)
- [ ] Export de IOCs a **STIX 2.1 / MISP**
- [ ] Desensamblado con capstone: detección de patrones de shellcode
- [ ] Comparativa de detección frente a ClamAV
- [ ] Dockerfile + informe HTML con capturas

## Ética y alcance

Herramienta **defensiva y educativa** de análisis estático. No ejecuta muestras.
El corpus de malware se maneja en local, cifrado en su ZIP de origen, y jamás se
versiona. El módulo de evasión opera sobre binarios benignos de prueba para
estudiar los límites de la detección, no para producir malware funcional.

## Licencia

MIT — Jorge García, 2026.
