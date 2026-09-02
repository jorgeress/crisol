import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from yardstick.features import shannon_entropy, extract_strings, _detect_filetype


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) == 0.0          # uniforme
    assert shannon_entropy(bytes(range(256)) * 8) > 7.9    # casi aleatorio


def test_detect_filetype():
    assert _detect_filetype(b"MZ\x90\x00") == "pe"
    assert _detect_filetype(b"\x7fELF") == "elf"
    assert _detect_filetype(b"PK\x03\x04") == "ooxml/zip"
    assert _detect_filetype(b"%PDF-1.7") == "pdf"
    assert _detect_filetype(b"random") == "unknown"


def test_extract_strings():
    ascii_s, wide_s = extract_strings(b"hello\x00\x01world!!", min_len=5)
    assert "hello" in ascii_s
    assert "world" in ascii_s[0] or any("world" in s for s in ascii_s)


def test_extract_on_self():
    # extrae features de un binario real del sistema sin petar
    from yardstick.features import extract
    f = extract("/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable)
    assert f.sha256 and f.size > 0
    assert f.filetype in ("elf", "pe")
