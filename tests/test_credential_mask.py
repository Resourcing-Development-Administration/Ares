"""
Enmascarado de credenciales reales del host para el subprocess stdio -- ver
engine/core/sandbox.py::credential_mask_bind_args() y el rediseño de
dynamic.credential_harvest_paths (engine/dynamic/tests.py) para confirmar por canario sintético
en vez de depender de que el HOST donde corre Ares tenga secretos reales en ~/.ssh, ~/.aws, etc.
"""
import os
import sys
import tempfile

import pytest

import os as _os
CRED_LEAK_STDIO = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "fixtures", "credential_leak_server.py")
from engine.core.models import ScanConfig
from engine.orchestrator import run_scan

REAL_SECRET = "REAL_SECRET_SHOULD_NEVER_LEAK_xyz123"


@pytest.fixture
def fake_home_with_real_looking_secrets(tmp_path):
    """Simula un host que SÍ tiene credenciales reales en ~/.ssh y ~/.aws -- para confirmar que
    el subprocess sandboxeado nunca las ve, aunque existan de verdad en el HOME que se le pasa."""
    home = tmp_path / "fakehome"
    (home / ".ssh").mkdir(parents=True)
    (home / ".aws").mkdir(parents=True)
    (home / ".ssh" / "id_rsa").write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{REAL_SECRET}\n-----END OPENSSH PRIVATE KEY-----\n")
    (home / ".aws" / "credentials").write_text(f"[default]\naws_access_key_id = {REAL_SECRET}\naws_secret_access_key = {REAL_SECRET}\n")
    return str(home)


async def _scan_with_home(home: str, sandbox_subprocess: bool = True):
    config = ScanConfig(
        target_name="t", transport="stdio",
        connection={"command": sys.executable, "args": [CRED_LEAK_STDIO], "env": {"HOME": home}},
        selected_tests=["dynamic.credential_harvest_paths"],
        sandbox_subprocess=sandbox_subprocess, test_timeout_s=90,
    )
    return await run_scan(config)


def _confirmed(report):
    return [f for f in report.findings if f.test_id == "dynamic.credential_harvest_paths" and not f.passed]


async def test_credential_harvest_confirms_via_canary_never_the_real_secret(fake_home_with_real_looking_secrets):
    report = await _scan_with_home(fake_home_with_real_looking_secrets)
    hits = _confirmed(report)
    assert hits, "read_file(path) del fixture debería confirmar la traversal (vía canario)"
    assert all(f.confidence == "verified" for f in hits)
    assert all("canario sintético" in f.title or "canario" in f.description for f in hits)
    # la prueba más importante: el secreto "real" (plantado por este mismo test) NUNCA debe
    # aparecer en ningún finding -- ni en el título, ni en la descripción, ni en la evidencia.
    dump = str([f.to_dict() for f in report.findings])
    assert REAL_SECRET not in dump, "el secreto real del host se filtró al reporte -- el enmascarado falló"


async def test_credential_harvest_falls_back_to_real_signature_without_sandbox(fake_home_with_real_looking_secrets):
    """--no-sandbox (sandbox_subprocess=False): sin enmascarado, el comportamiento debe ser el de
    ANTES de este cambio -- confirma por la firma de contenido real (no hay canario que buscar)."""
    report = await _scan_with_home(fake_home_with_real_looking_secrets, sandbox_subprocess=False)
    hits = _confirmed(report)
    assert hits, "sin sandbox, debería confirmar por la firma real de clave SSH"
    assert all("real" in f.title.lower() for f in hits)


async def test_credential_harvest_no_false_positive_on_safe_server():
    from conftest import SAFE_STDIO
    config = ScanConfig(target_name="t", transport="stdio", connection={"command": sys.executable, "args": [SAFE_STDIO]},
                        selected_tests=["dynamic.credential_harvest_paths"], test_timeout_s=60)
    report = await run_scan(config)
    assert _confirmed(report) == []


def test_credential_mask_bind_args_skips_absent_dirs(tmp_path):
    from engine.core.sandbox import credential_mask_bind_args
    assert credential_mask_bind_args(str(tmp_path)) == []  # sin ~/.ssh, ~/.aws... nada que enmascarar


def test_credential_mask_bind_args_masks_present_dirs(tmp_path):
    from engine.core.sandbox import credential_mask_bind_args
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".aws").mkdir()
    args = credential_mask_bind_args(str(tmp_path))
    joined = " ".join(args)
    assert str(tmp_path / ".ssh" / "id_rsa") in joined
    assert str(tmp_path / ".aws" / "credentials") in joined
    assert str(tmp_path / ".docker") not in joined  # no existe, no se intenta enmascarar


def test_wrap_command_applies_mask_only_when_dir_exists_on_real_host(tmp_path):
    """Regresión directa del bug de bwrap: enmascarar un subdir que NO existe en el host hace
    que bwrap falle al crear el punto de montaje (confirmado: 'Read-only file system'). Por eso
    credential_mask_bind_args debe devolver [] para subdirs ausentes, nunca intentar un --tmpfs
    sobre una ruta que bwrap no puede crear bajo la raíz ya read-only."""
    import subprocess
    from engine.core.sandbox import wrap_command, bwrap_available
    if not bwrap_available():
        pytest.skip("bwrap no disponible en este host")
    cmd, args = wrap_command(sys.executable, ["-c", "print('ok')"], home=str(tmp_path / "no_existe_nada_aca"))
    r = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=15)
    assert r.returncode == 0 and "ok" in r.stdout, r.stderr
