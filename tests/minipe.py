"""Constructor de PE mínimos y válidos, para probar reglas sin muestras reales.

Las reglas que usan el módulo `pe` de YARA (overlay, imports, secciones) no se
pueden probar con un buffer falso: hace falta una cabecera que el parser
acepte. Estos PE se generan en memoria, son inertes (no hay código, el punto
de entrada no apunta a nada ejecutable) y viajan en el repo como código, no
como binario, que es la única forma de versionar "muestras" sin subir malware.
"""
from __future__ import annotations

import struct

DOS_STUB = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64

IMAGE_FILE_MACHINE_AMD64 = 0x8664
SECTION_CNT_CODE = 0x00000020
SECTION_MEM_EXECUTE = 0x20000000
SECTION_MEM_READ = 0x40000000


def build_pe(section_data: bytes = b"\x90" * 512,
             overlay: bytes = b"",
             section_name: bytes = b".text") -> bytes:
    """PE64 de una sección, con el overlay que se le pida detrás."""
    file_align = 0x200
    sect_raw = section_data.ljust(
        (len(section_data) + file_align - 1) // file_align * file_align, b"\x00")

    opt_header_size = 240  # PE32+ con 16 data directories
    coff = struct.pack("<HHIIIHH",
                       IMAGE_FILE_MACHINE_AMD64,
                       1,                 # NumberOfSections
                       0x68000000,        # TimeDateStamp
                       0, 0,              # tabla de símbolos (ninguna)
                       opt_header_size,
                       0x0022)            # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    headers_size = 0x400   # DOS + PE + secciones, alineado
    opt = struct.pack(
        "<HBBIIIIII",
        0x020B,            # PE32+
        14, 0,             # linker version
        len(sect_raw), 0, 0,
        0x1000,            # AddressOfEntryPoint
        0x1000,            # BaseOfCode
        0,                 # (relleno: ImageBase va en Q justo debajo)
    )[:24] + struct.pack("<Q", 0x140000000)         # ImageBase
    opt += struct.pack("<II", 0x1000, file_align)   # Section/FileAlignment
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)  # versiones de OS/imagen/subsistema
    opt += struct.pack("<I", 0)                      # Win32VersionValue
    opt += struct.pack("<II", 0x2000 + len(sect_raw), headers_size)
    opt += struct.pack("<IHH", 0, 3, 0x8140)         # CheckSum, Subsystem=CUI, DllCharacteristics
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)  # stack/heap
    opt += struct.pack("<II", 0, 16)                 # LoaderFlags, NumberOfRvaAndSizes
    opt += b"\x00" * (16 * 8)                        # los 16 data directories, vacíos
    assert len(opt) == opt_header_size, len(opt)

    section = struct.pack("<8sIIIIIIHHI",
                          section_name.ljust(8, b"\x00"),
                          len(section_data),   # VirtualSize
                          0x1000,              # VirtualAddress
                          len(sect_raw),       # SizeOfRawData
                          headers_size,        # PointerToRawData
                          0, 0, 0, 0,
                          SECTION_CNT_CODE | SECTION_MEM_EXECUTE | SECTION_MEM_READ)

    head = DOS_STUB + b"PE\x00\x00" + coff + opt + section
    return head.ljust(headers_size, b"\x00") + sect_raw + overlay
