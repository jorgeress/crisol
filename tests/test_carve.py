"""Tests del tallado de payloads embebidos.

Todo con PE mínimos generados en memoria (tests/minipe.py): lo que se prueba
es el extractor, y para eso no hace falta (ni conviene) una muestra real.
"""
import io
import os
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from minipe import build_pe
from crisol.carve import MAX_PAYLOADS, MIN_PAYLOAD_SIZE, carve_pes, extract_payloads, unzip


def test_carves_embedded_pe_intact():
    inner = build_pe(section_data=b"\x90" * 2048)
    host = build_pe(overlay=b"\x00" * 4096 + inner + b"\x00" * 4096)
    payloads = carve_pes(host)
    assert len(payloads) == 1
    assert payloads[0].data.startswith(b"MZ")
    assert payloads[0].data[:len(inner)] == inner


def test_does_not_carve_the_sample_itself():
    # el offset 0 es la muestra: tallarla sería escanearla dos veces
    assert carve_pes(build_pe()) == []


def test_ignores_bare_mz_without_pe_header():
    # "MZ" aparece por casualidad en cualquier blob binario
    host = build_pe(overlay=b"MZ" + os.urandom(8192))
    assert carve_pes(host) == []


def test_carves_several_and_respects_the_cap():
    inner = build_pe(section_data=b"\x41" * 2048)
    host = build_pe(overlay=inner * 3)
    assert len(carve_pes(host)) == 3
    assert len(carve_pes(build_pe(overlay=inner * (MAX_PAYLOADS + 10)))) <= MAX_PAYLOADS


def test_unzip_reads_members_and_skips_tiny_ones():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bin/app.exe", b"A" * (MIN_PAYLOAD_SIZE * 2))
        z.writestr("leeme.txt", b"corto")          # por debajo del mínimo
    host = build_pe(overlay=buf.getvalue())
    origins = {p.origin for p in unzip(host)}
    assert origins == {"zip:bin/app.exe"}


def test_corrupt_container_does_not_raise():
    # un ZIP truncado a propósito: el extractor devuelve vacío, no revienta
    assert unzip(build_pe(overlay=b"PK\x03\x04" + os.urandom(512))) == []


def test_extract_payloads_deduplicates():
    inner = build_pe(section_data=b"\x42" * 2048)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("copia.exe", inner)
    # el mismo PE, alcanzable tallándolo y abriendo el ZIP: debe salir una vez
    host = build_pe(overlay=buf.getvalue())
    assert len(extract_payloads(host)) == 1
