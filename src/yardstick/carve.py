"""Extracción de payloads embebidos, para escanear lo que hay *dentro*.

Muchas muestras no son maliciosas por sí mismas: son un contenedor con el
payload dentro. `overlay_bulk_inflation` renuncia a propósito a los
instaladores porque un NSIS malicioso y uno legítimo tienen la misma forma;
la respuesta a eso no es una regla más laxa, es abrir el contenedor y escanear
lo de dentro, que es lo que hace este módulo.

Alcance deliberado — esto NO es un desempaquetador:

  - Talla PE embebidos que estén **sin comprimir**. Un payload deflateado
    dentro de un instalador es invisible aquí, y eso limita tanto lo que se
    detecta como lo que se puede marcar por error: lo que se talla son
    ejecutables tal cual, no blobs descomprimidos.
  - Abre ZIP (y por tanto los auto-extraíbles con esa forma) con la librería
    estándar, con topes de tamaño y de número de miembros.

Todo lo que entra aquí es hostil por definición: cada offset viene del
fichero analizado. Por eso hay topes en todo y ninguna excepción se propaga.
"""
from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import dataclass

MAX_PAYLOADS = 64           # un contenedor con 500 PEs es un DoS, no una muestra
MAX_PAYLOAD_SIZE = 64 << 20  # 64 MB por payload extraído
MIN_PAYLOAD_SIZE = 1024      # por debajo de esto no hay PE que valga


@dataclass
class Payload:
    """Un trozo extraído de la muestra, con de dónde salió."""
    origin: str          # "pe@0x1a2b", "zip:setup/app.exe"
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


def _pe_extent(data: bytes, off: int) -> int:
    """Tamaño del PE que empieza en `off`: fin de su última sección.

    Se lee la tabla de secciones a mano en vez de con pefile porque aquí solo
    hace falta el tamaño, y pefile sobre un offset arbitrario de un fichero
    hostil es mucha superficie de ataque para tan poco.
    """
    try:
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
        if not (0 < e_lfanew < 0x1000):
            return 0
        pe = off + e_lfanew
        if data[pe:pe + 4] != b"PE\x00\x00":
            return 0
        n_sections = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        if not (0 < n_sections <= 96):
            return 0
        table = pe + 24 + opt_size
        end = 0
        for i in range(n_sections):
            s = table + i * 40
            raw_size, raw_ptr = struct.unpack_from("<II", data, s + 16)
            if raw_size > MAX_PAYLOAD_SIZE:
                return 0
            end = max(end, raw_ptr + raw_size)
        return end
    except (struct.error, IndexError):
        return 0


def carve_pes(data: bytes) -> list[Payload]:
    """PE embebidos y sin comprimir. Se salta el offset 0: ese es la muestra."""
    out: list[Payload] = []
    off = data.find(b"MZ", 1)
    while off != -1 and len(out) < MAX_PAYLOADS:
        size = _pe_extent(data, off)
        if MIN_PAYLOAD_SIZE <= size <= MAX_PAYLOAD_SIZE and off + size <= len(data):
            out.append(Payload(f"pe@0x{off:x}", data[off:off + size]))
            off = data.find(b"MZ", off + size)   # no volver a tallar lo mismo
        else:
            off = data.find(b"MZ", off + 1)
    return out


def unzip(data: bytes) -> list[Payload]:
    """Miembros de un ZIP embebido (el caso del auto-extraíble)."""
    start = data.find(b"PK\x03\x04")
    if start == -1:
        return []
    out: list[Payload] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data[start:])) as z:
            for info in z.infolist()[:MAX_PAYLOADS]:
                if info.is_dir() or not (MIN_PAYLOAD_SIZE <= info.file_size <= MAX_PAYLOAD_SIZE):
                    continue
                try:
                    out.append(Payload(f"zip:{info.filename}", z.read(info)))
                except Exception:  # noqa: BLE001  (miembro cifrado o corrupto)
                    continue
    except Exception:  # noqa: BLE001  (no era un ZIP válido)
        return []
    return out


def extract_payloads(data: bytes) -> list[Payload]:
    """Todo lo extraíble de una muestra, sin duplicados y con tope global."""
    payloads = carve_pes(data) + unzip(data)
    seen: set[bytes] = set()
    out: list[Payload] = []
    for p in payloads:
        key = p.data[:4096]
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= MAX_PAYLOADS:
            break
    return out
