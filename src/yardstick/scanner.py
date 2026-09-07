"""Compilación y ejecución de reglas YARA sobre una muestra."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara


@dataclass
class Match:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[str] = field(default_factory=list)


class RuleSet:
    """Carga todos los .yar/.yara bajo un directorio y los compila una vez."""

    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        self._compiled: yara.Rules | None = None
        self.sources: dict[str, str] = {}

    def compile(self) -> "RuleSet":
        files = sorted(self.rules_dir.rglob("*.yar")) + sorted(
            self.rules_dir.rglob("*.yara")
        )
        if not files:
            raise FileNotFoundError(f"no hay reglas en {self.rules_dir}")
        # namespace = ruta relativa, para saber de qué archivo vino cada match
        self.sources = {
            str(f.relative_to(self.rules_dir)): f.read_text(encoding="utf-8")
            for f in files
        }
        self._compiled = yara.compile(sources=self.sources)
        return self

    @property
    def rule_count(self) -> int:
        return len(list(self._compiled)) if self._compiled else 0

    def scan_bytes(self, data: bytes, timeout: int = 30) -> list[Match]:
        if self._compiled is None:
            self.compile()
        results = self._compiled.match(data=data, timeout=timeout)
        out = []
        for m in results:
            strings = []
            for s in getattr(m, "strings", []) or []:
                # yara-python >=4.3 usa StringMatch con .instances
                for inst in getattr(s, "instances", []):
                    val = inst.matched_data
                    strings.append(
                        f"{s.identifier} @0x{inst.offset:x}: "
                        + val[:40].hex()
                    )
            out.append(Match(
                rule=m.rule,
                namespace=m.namespace,
                tags=list(m.tags),
                meta=dict(m.meta),
                strings=strings[:20],
            ))
        return out

    def scan_file(self, path: str | Path, timeout: int = 30) -> list[Match]:
        return self.scan_bytes(Path(path).read_bytes(), timeout=timeout)

    def scan_recursive(self, data: bytes, timeout: int = 30
                       ) -> tuple[list[Match], list[tuple[str, list[Match]]]]:
        """Escanea la muestra y, aparte, cada payload que lleve dentro.

        Devuelve (matches del fichero, [(origen, matches) por payload]). Van
        separados a propósito: "este fichero dispara una regla" y "este
        fichero *contiene* algo que la dispara" son afirmaciones distintas y
        mezclarlas infla la detección sin decirlo.
        """
        from .carve import extract_payloads

        top = self.scan_bytes(data, timeout=timeout)
        nested: list[tuple[str, list[Match]]] = []
        for payload in extract_payloads(data):
            hits = self.scan_bytes(payload.data, timeout=timeout)
            if hits:
                nested.append((payload.origin, hits))
        return top, nested
