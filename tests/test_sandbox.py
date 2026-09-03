"""El sandbox de análisis debe cumplir lo que promete.

Si estas propiedades se rompen (alguien añade un --bind de más, por ejemplo),
el análisis deja de estar aislado sin que nadie se entere. Por eso son tests
y no una nota en el README.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SANDBOX = REPO / "scripts" / "sandbox.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bwrap") is None, reason="bubblewrap no instalado"
)


def _in_sandbox(code: str) -> subprocess.CompletedProcess:
    """Corre un snippet de Python dentro del sandbox y devuelve el resultado."""
    return subprocess.run(
        [str(SANDBOX), sys.executable, "-c", code],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )


def test_sandbox_sin_red():
    r = _in_sandbox(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
        "    print('HAY_RED')\n"
        "except OSError:\n"
        "    print('SIN_RED')\n"
    )
    assert "SIN_RED" in r.stdout, r.stdout + r.stderr


def test_sandbox_sin_home_del_usuario():
    r = _in_sandbox("import os; print(os.path.exists(os.path.expanduser('~/.ssh')))")
    assert r.stdout.strip() == "False", r.stdout + r.stderr


def test_sandbox_repo_de_solo_lectura():
    r = _in_sandbox(
        "import pathlib\n"
        "try:\n"
        "    pathlib.Path('rules/_probe.yar').write_text('x')\n"
        "    print('ESCRIBIBLE')\n"
        "except OSError:\n"
        "    print('SOLO_LECTURA')\n"
    )
    assert "SOLO_LECTURA" in r.stdout, r.stdout + r.stderr
    assert not (REPO / "rules" / "_probe.yar").exists()


def test_sandbox_no_permite_ganar_privilegios():
    r = _in_sandbox(
        "print([l.split()[1] for l in open('/proc/self/status') "
        "if l.startswith('NoNewPrivs')][0])"
    )
    assert r.stdout.strip() == "1", r.stdout + r.stderr


def test_sandbox_deja_escribir_informes():
    # reports/ es la única ruta con escritura: si se rompe, los informes HTML fallan
    r = _in_sandbox(
        "import pathlib\n"
        "p = pathlib.Path('reports/.probe'); p.write_text('x'); p.unlink()\n"
        "print('OK')\n"
    )
    assert "OK" in r.stdout, r.stdout + r.stderr
