"""Tests de las reglas YARA en AMBAS direcciones:
  - positivos: un buffer con el patrón malicioso DEBE disparar
  - negativos: goodware real NO debe disparar (complementa bench/harness.py)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import os

import pytest
from minipe import build_pe
from crisol.scanner import RuleSet

RULES = RuleSet(str(Path(__file__).resolve().parents[1] / "rules")).compile()


def _rules_hit(data: bytes) -> set[str]:
    return {m.rule for m in RULES.scan_bytes(data)}


# --- POSITIVOS: el patrón malicioso debe detectarse ------------------------

def test_anti_debug_stacked_fires_on_two_strong():
    # MZ + 2 técnicas anti-debug FUERTES -> debe disparar
    buf = b"MZ" + b"\x00" * 64
    buf += b"NtQueryInformationProcess\x00CheckRemoteDebuggerPresent\x00"
    assert "anti_debug_stacked" in _rules_hit(buf)


def test_anti_debug_one_strong_two_weak_fires():
    buf = b"MZ" + b"\x00" * 64
    buf += b"NtSetInformationThread\x00IsDebuggerPresent\x00OutputDebugString\x00"
    assert "anti_debug_stacked" in _rules_hit(buf)


def test_anti_debug_does_not_fire_on_single_weak():
    # solo IsDebuggerPresent (caso ubicuo del CRT) -> NO debe disparar
    buf = b"MZ" + b"\x00" * 64 + b"IsDebuggerPresent\x00OutputDebugString\x00"
    assert "anti_debug_stacked" not in _rules_hit(buf)


def test_anti_debug_does_not_fire_on_a_debugger():
    # las APIs de mscordbi.dll, el depurador de .NET: engancharse a un proceso
    # (DebugActiveProcess) es lo que hace un depurador, no una evasión. Ronda 4.
    buf = b"MZ" + b"\x00" * 64
    buf += b"DebugActiveProcess\x00IsDebuggerPresent\x00GetThreadContext\x00"
    assert "anti_debug_stacked" not in _rules_hit(buf)


def test_vba_downloader_fires_on_maldoc_pattern():
    doc = (b"\xd0\xcf\x11\xe0"  # cabecera OLE (no PE)
           b"...AutoOpen...MSXML2.XMLHTTP...CreateObject...Shell...")
    assert "vba_autoopen_download_exec" in _rules_hit(doc)


def test_vba_powershell_fires_on_doc_not_pe():
    doc = b"PK\x03\x04" + b"powershell -nop -enc SQBFAFgA FromBase64String"
    assert "vba_powershell_invocation" in _rules_hit(doc)


# --- NEGATIVOS: goodware real no dispara -----------------------------------

def test_no_fp_on_powershell_string_inside_pe():
    # 'powershell' dentro de un PE NO debe disparar la regla de maldoc
    pe = b"MZ" + b"\x00" * 64 + b"powershell -enc -nop FromBase64String"
    assert "vba_powershell_invocation" not in _rules_hit(pe)


@pytest.mark.skipif(not Path("/usr/bin/ls").exists(), reason="sin /usr/bin/ls")
def test_no_fp_on_system_elf():
    assert _rules_hit(Path("/usr/bin/ls").read_bytes()) == set()


# --- overlay: inflado de tamaño -------------------------------------------
# Se prueban con PE mínimos generados en memoria (tests/minipe.py): las reglas
# usan el módulo `pe` de YARA, que necesita una cabecera real, no un buffer.

MB = 1024 * 1024


def test_overlay_bulk_fires_on_dominant_overlay():
    assert "overlay_bulk_inflation" in _rules_hit(build_pe(overlay=os.urandom(6 * MB)))


def test_overlay_null_padding_fires_on_zero_fill():
    hits = _rules_hit(build_pe(overlay=b"\x00" * 6 * MB))
    assert "overlay_null_padding" in hits


def test_overlay_ignores_known_installer_containers():
    # ZIP e Inno Setup: un instalador legítimo tiene esta misma forma, así que
    # la regla se calla a propósito (ver la nota del fichero de reglas).
    for magic in (b"PK\x03\x04", b"zlb\x1a", b"MSCF", b"7z\xbc\xaf\x27\x1c"):
        pe = build_pe(overlay=magic + os.urandom(6 * MB))
        assert "overlay_bulk_inflation" not in _rules_hit(pe), magic


def test_overlay_does_not_fire_below_thresholds():
    # 1 MB de overlay: por debajo del suelo de 4 MB
    assert "overlay_bulk_inflation" not in _rules_hit(build_pe(overlay=os.urandom(MB)))
    # overlay minoritario dentro de un fichero grande: 6 MB sobre 26 MB
    big = build_pe(section_data=os.urandom(20 * MB), overlay=os.urandom(6 * MB))
    assert "overlay_bulk_inflation" not in _rules_hit(big)


def test_high_entropy_section_fires_on_native_pe():
    # sección ejecutable cifrada en un PE nativo: el caso del empaquetador
    assert "high_entropy_section" in _rules_hit(build_pe(section_data=os.urandom(64 * 1024)))


def test_high_entropy_section_ignores_dotnet_assembly():
    # los mismos bytes en una assembly .NET son recursos gestionados dentro de
    # .text (imágenes, datos comprimidos), no código cifrado. Ver ronda 3.
    pe = build_pe(section_data=os.urandom(64 * 1024), dotnet=True)
    assert "high_entropy_section" not in _rules_hit(pe)


def test_clean_minimal_pe_is_not_flagged():
    assert _rules_hit(build_pe()) == set()
