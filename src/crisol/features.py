"""Extracción de features estáticas de una muestra.

Diseñado para triaje: nada de ejecución, todo lectura de bytes. Soporta PE,
ELF y documentos OLE/OOXML (macros VBA). Cada extractor es defensivo: una
muestra corrupta no debe tumbar el motor, así que capturamos y anotamos.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# --- APIs de Windows habitualmente abusadas por malware (subset curado) ------
SUSPICIOUS_IMPORTS = {
    # inyección / manipulación de procesos
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookExA",
    "SetWindowsHookExW",
    # resolución dinámica de APIs (evasión de análisis de imports)
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    # persistencia / servicios
    "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
    # anti-análisis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount",
    # red / descarga
    "InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "WinHttpOpen",
    "WSAStartup", "connect", "send", "recv",
    # cripto (ransomware / packers)
    "CryptEncrypt", "CryptGenKey", "CryptAcquireContextA",
}

RE_URL = re.compile(rb"https?://[\w\-./%?=&:@+~#]{4,}")
RE_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_REGKEY = re.compile(rb"(?:HKEY_|SOFTWARE\\|SYSTEM\\)[\w\\ .-]{4,}")
RE_DOMAIN = re.compile(rb"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,10}\b")


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon en bits/byte (0=uniforme, 8=aleatorio/comprimido)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def extract_strings(data: bytes, min_len: int = 5) -> tuple[list[str], list[str]]:
    """Devuelve (ascii, wide/utf-16le): imitación ligera de `strings`."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    wide_re = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    ascii_s = [m.decode("ascii", "ignore") for m in ascii_re.findall(data)]
    wide_s = [m.decode("utf-16le", "ignore") for m in wide_re.findall(data)]
    return ascii_s, wide_s


def _iocs_from_bytes(data: bytes) -> dict[str, list[str]]:
    def uniq(matches):
        return sorted({m.decode("ascii", "ignore") for m in matches})
    return {
        "urls": uniq(RE_URL.findall(data)),
        "ipv4": [ip for ip in uniq(RE_IPV4.findall(data))
                 if all(0 <= int(o) <= 255 for o in ip.split("."))],
        "registry": uniq(RE_REGKEY.findall(data))[:50],
        "domains": [d for d in uniq(RE_DOMAIN.findall(data))
                    if not d.replace(".", "").isdigit()][:50],
    }


@dataclass
class Features:
    path: str
    size: int
    md5: str
    sha256: str
    filetype: str
    entropy: float
    errors: list[str] = field(default_factory=list)
    pe: dict[str, Any] | None = None
    ole: dict[str, Any] | None = None
    iocs: dict[str, list[str]] = field(default_factory=dict)
    interesting_strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _detect_filetype(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] == b"PK\x03\x04":
        return "ooxml/zip"  # docx/xlsm/apk/jar...
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"  # doc/xls legacy
    if data[:4] == b"%PDF":
        return "pdf"
    return "unknown"


def _analyze_pe(data: bytes, feats: Features) -> None:
    import pefile
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except Exception as e:  # noqa: BLE001
        feats.errors.append(f"pe_parse: {e}")
        return

    sections = []
    for s in pe.sections:
        raw = s.get_data()
        name = s.Name.rstrip(b"\x00").decode("latin-1", "ignore")
        sections.append({
            "name": name,
            "vsize": s.Misc_VirtualSize,
            "rawsize": s.SizeOfRawData,
            "entropy": shannon_entropy(raw),
            "writable_executable": bool(
                (s.Characteristics & 0x80000000) and (s.Characteristics & 0x20000000)
            ),
        })

    imports, suspicious = [], []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "ignore") if entry.dll else "?"
        for imp in entry.imports:
            fname = imp.name.decode("latin-1", "ignore") if imp.name else f"ord{imp.ordinal}"
            imports.append(f"{dll}!{fname}")
            if fname in SUSPICIOUS_IMPORTS:
                suspicious.append(fname)

    # Overlay: datos tras la última sección (packers, droppers lo usan mucho)
    overlay_off = pe.get_overlay_data_start_offset()
    overlay_size = len(data) - overlay_off if overlay_off else 0

    feats.pe = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "is_dotnet": bool(getattr(pe, "OPTIONAL_HEADER", None)
                          and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress),
        "n_sections": len(sections),
        "sections": sections,
        "n_imports": len(imports),
        "suspicious_imports": sorted(set(suspicious)),
        "imphash": pe.get_imphash(),
        "overlay_size": overlay_size,
        "max_section_entropy": max((s["entropy"] for s in sections), default=0.0),
        "has_rwx_section": any(s["writable_executable"] for s in sections),
    }
    pe.close()


def _analyze_ole(path: Path, feats: Features) -> None:
    try:
        from oletools.olevba import VBA_Parser
    except Exception as e:  # noqa: BLE001
        feats.errors.append(f"olevba_import: {e}")
        return
    try:
        vp = VBA_Parser(str(path))
        macros, keywords, autoexec = [], [], []
        if vp.detect_vba_macros():
            for _, _, name, code in vp.extract_macros():
                macros.append(name)
            results = vp.analyze_macros()
            for kw_type, keyword, desc in results:
                keywords.append({"type": kw_type, "keyword": keyword, "desc": desc})
                if kw_type == "AutoExec":
                    autoexec.append(keyword)
        feats.ole = {
            "has_macros": bool(macros),
            "macro_modules": macros,
            "autoexec_triggers": autoexec,
            "suspicious_keywords": [k for k in keywords if k["type"] == "Suspicious"][:30],
        }
        vp.close()
    except Exception as e:  # noqa: BLE001
        feats.errors.append(f"olevba: {e}")


def extract(path: str | Path) -> Features:
    path = Path(path)
    data = path.read_bytes()
    ftype = _detect_filetype(data)
    ascii_s, wide_s = extract_strings(data)

    feats = Features(
        path=str(path),
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        filetype=ftype,
        entropy=shannon_entropy(data),
        iocs=_iocs_from_bytes(data),
    )

    # strings "interesantes": nombres de API sospechosos + IOCs de red
    interesting = {s for s in ascii_s + wide_s if s in SUSPICIOUS_IMPORTS}
    feats.interesting_strings = sorted(interesting)

    if ftype == "pe":
        _analyze_pe(data, feats)
    elif ftype in ("ole", "ooxml/zip"):
        _analyze_ole(path, feats)

    return feats
