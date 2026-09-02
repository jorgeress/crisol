"""Tests de las reglas YARA en AMBAS direcciones:
  - positivos: un buffer con el patrón malicioso DEBE disparar
  - negativos: goodware real NO debe disparar (complementa bench/harness.py)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from yardstick.scanner import RuleSet

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
