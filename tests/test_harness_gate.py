"""El gate de CI en modo recursivo tiene que vigilar los payloads embebidos.

Regresión de un fallo real: --max-fp-rate solo miraba la tasa de matches
directos, así que un goodware que se enciende *solo* por lo que lleva dentro
pasaba el umbral sin que nadie mirase. Un gate que no puede fallar no es un
gate.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench.harness import run
from minipe import build_pe

RULES = str(Path(__file__).resolve().parents[1] / "rules")


def _corpus(tmp_path):
    """Un goodware que no dispara nada, pero lleva dentro algo que sí."""
    good = tmp_path / "good"
    good.mkdir()
    # sección aleatoria -> high_entropy_section dispara sobre ESTE PE
    inner = build_pe(section_data=os.urandom(100 * 1024))
    # el contenedor: sección plana y el payload detrás. Se queda por debajo de
    # los umbrales de las reglas de overlay, así que por sí mismo es limpio.
    (good / "contenedor.exe").write_bytes(build_pe(overlay=inner))
    empty = tmp_path / "mal"
    empty.mkdir()
    return str(good), str(empty)


def test_container_is_clean_but_its_payload_is_not(tmp_path):
    good, mal = _corpus(tmp_path)
    directo = run(RULES, good, mal, manifest_path=None, recursive=False)
    assert directo["false_positive_rate"] == 0.0

    rec = run(RULES, good, mal, manifest_path=None, recursive=True)
    assert rec["false_positive_rate"] == 0.0          # sigue limpio "por fuera"
    assert rec["goodware_flagged_via_embedded"] == 1  # pero no por dentro
    assert rec["false_positive_rate_recursive"] == 1.0


def test_gate_fails_on_embedded_only_false_positive(tmp_path):
    good, mal = _corpus(tmp_path)
    from bench.harness import main
    argv = ["--rules", RULES, "--goodware", good, "--malware", mal,
            "--manifest", "", "--max-fp-rate", "0.0"]
    assert main(argv) == 0, "sin --recursive el contenedor es limpio"
    assert main(argv + ["--recursive"]) == 1, "con --recursive el gate debe fallar"
