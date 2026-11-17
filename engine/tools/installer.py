"""
Descarga y verifica binarios de seguridad usados por el módulo netrecon de Ares.
Versiones pinneadas con verificación de checksum SHA-256, igual que el Dockerfile
de ARTEX -- ningún binario se instala sin verificación previa.

Herramientas soportadas:
  nuclei, httpx, subfinder, katana   → ProjectDiscovery (releases en GitHub)
  ffuf                               → ffuf/ffuf
  dalfox                             → hahwul/dalfox
  sqlmap                             → sqlmapproject/sqlmap (Python, wrapper script)
  bbot                               → blacklanternsec/bbot (pip, venv aislado)

Uso desde CLI: ares install-tools [--tools nuclei,httpx,...] [--force]
Uso programático: install_all(progress=print)
"""
from __future__ import annotations
import hashlib
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

from engine.tools.paths import tool_path, tools_dir

# ── versiones pinneadas (mismas que ARTEX Dockerfile) ───────────────────────
TOOL_VERSIONS: dict[str, str] = {
    "nuclei":    "3.11.1",
    "httpx":     "1.12.0",
    "subfinder": "2.17.0",
    "katana":    "1.8.0",
    "ffuf":      "2.3.0",
    "dalfox":    "3.2.4",
    "sqlmap":    "1.9.9",
    "bbot":      "3.0.2",
}

ALL_TOOLS = list(TOOL_VERSIONS.keys())


# ── utilidades internas ──────────────────────────────────────────────────────

def _arch() -> tuple[str, str, str]:
    """(pd_arch, ffuf_arch, dalfox_arch) para la plataforma actual."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64", "amd64", "x86_64"
    if machine in ("aarch64", "arm64"):
        return "arm64", "arm64", "aarch64"
    raise RuntimeError(f"Arquitectura no soportada: {machine}")


def _os_name() -> str:
    s = platform.system().lower()
    if s == "linux":   return "linux"
    if s == "darwin":  return "macos"
    if s == "windows": return "windows"
    raise RuntimeError(f"OS no soportado: {s}")


def _fetch(url: str, dest: pathlib.Path, progress=None) -> None:
    if progress:
        progress(f"  → descargando {url.split('/')[-1]} …")
    urllib.request.urlretrieve(url, dest)


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_pd_checksum(archive_path: pathlib.Path, checksums_path: pathlib.Path, asset_name: str) -> None:
    """Verifica el checksum SHA-256 de archive_path contra el archivo de checksums
    de ProjectDiscovery (formato: 'HASH  filename' o 'HASH *filename')."""
    asset_base = pathlib.Path(asset_name).name
    with open(checksums_path) as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            want_hash, fname = parts
            fname = fname.lstrip("*").strip()
            if fname == asset_base:
                got = _sha256(archive_path)
                if got != want_hash:
                    raise RuntimeError(
                        f"Checksum incorrecto para {asset_base}:\n"
                        f"  esperado: {want_hash}\n"
                        f"  obtenido: {got}"
                    )
                return
    raise RuntimeError(f"No se encontró entrada de checksum para '{asset_base}' en el archivo de sumas.")


def _extract_binary(archive_path: pathlib.Path, binary_name: str, dest: pathlib.Path) -> None:
    """Extrae binary_name del archivo comprimido y lo coloca en dest con permisos 0o755."""
    if str(archive_path).endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            for name in zf.namelist():
                if pathlib.Path(name).name == binary_name:
                    with zf.open(name) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
                    dest.chmod(0o755)
                    return
    else:  # .tar.gz
        with tarfile.open(archive_path) as tf:
            for member in tf.getmembers():
                if pathlib.Path(member.name).name == binary_name:
                    fobj = tf.extractfile(member)
                    if fobj:
                        with open(dest, "wb") as dst:
                            dst.write(fobj.read())
                        dest.chmod(0o755)
                        return
    raise RuntimeError(f"Binario '{binary_name}' no encontrado dentro del archivo {archive_path.name}")


# ── instaladores por herramienta ─────────────────────────────────────────────

def install_pd_tool(name: str, version: str, force: bool = False, progress=None) -> None:
    """Instala una herramienta de ProjectDiscovery (nuclei/httpx/subfinder/katana)."""
    pd_arch, _, _ = _arch()
    os_name = _os_name()
    binary_name = f"{name}.exe" if os_name == "windows" else name
    dest = tool_path(binary_name)

    if dest.exists() and not force:
        if progress:
            progress(f"  ✓ {name} ya instalado en {dest} (--force para reinstalar)")
        return

    ver = version
    asset     = f"{name}_{ver}_{os_name}_{pd_arch}.zip"
    checksums = f"{name}_{ver}_checksums.txt"
    base_url  = f"https://github.com/projectdiscovery/{name}/releases/download/v{ver}"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        archive  = tmp_path / asset
        chk_file = tmp_path / checksums

        _fetch(f"{base_url}/{asset}", archive, progress)
        _fetch(f"{base_url}/{checksums}", chk_file, progress)
        _verify_pd_checksum(archive, chk_file, asset)
        _extract_binary(archive, binary_name, dest)

    if progress:
        progress(f"  ✓ {name} v{ver} → {dest}")


def install_ffuf(version: str, force: bool = False, progress=None) -> None:
    """Instala ffuf."""
    _, ffuf_arch, _ = _arch()
    os_name    = _os_name()
    binary_name = "ffuf.exe" if os_name == "windows" else "ffuf"
    dest = tool_path(binary_name)

    if dest.exists() and not force:
        if progress:
            progress(f"  ✓ ffuf ya instalado en {dest} (--force para reinstalar)")
        return

    ver = version
    ext   = ".zip" if os_name == "windows" else ".tar.gz"
    asset = f"ffuf_{ver}_{os_name}_{ffuf_arch}{ext}"
    checksums = f"ffuf_{ver}_checksums.txt"
    base_url  = f"https://github.com/ffuf/ffuf/releases/download/v{ver}"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        archive  = tmp_path / asset
        chk_file = tmp_path / checksums

        _fetch(f"{base_url}/{asset}", archive, progress)
        _fetch(f"{base_url}/{checksums}", chk_file, progress)
        _verify_pd_checksum(archive, chk_file, asset)
        _extract_binary(archive, binary_name, dest)

    if progress:
        progress(f"  ✓ ffuf v{ver} → {dest}")


def install_dalfox(version: str, force: bool = False, progress=None) -> None:
    """Instala dalfox (XSS scanner de hahwul)."""
    _, _, dalfox_arch = _arch()
    os_name     = _os_name()
    binary_name = "dalfox.exe" if os_name == "windows" else "dalfox"
    dest = tool_path(binary_name)

    if dest.exists() and not force:
        if progress:
            progress(f"  ✓ dalfox ya instalado en {dest} (--force para reinstalar)")
        return

    ver   = version
    asset = f"dalfox-{ver}-{os_name}-{dalfox_arch}-musl.tar.gz"
    base_url = f"https://github.com/hahwul/dalfox/releases/download/v{ver}"
    chk_url  = f"{base_url}/{asset}.sha256"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = pathlib.Path(tmp)
        archive  = tmp_path / asset
        chk_file = tmp_path / f"{asset}.sha256"

        _fetch(f"{base_url}/{asset}", archive, progress)
        _fetch(chk_url, chk_file, progress)

        # dalfox: formato "HASH  filename" o solo "HASH"
        with open(chk_file) as f:
            first_token = f.read().strip().split()[0]
        got = _sha256(archive)
        if got != first_token:
            raise RuntimeError(
                f"Checksum incorrecto para dalfox:\n"
                f"  esperado: {first_token}\n"
                f"  obtenido: {got}"
            )
        _extract_binary(archive, binary_name, dest)

    if progress:
        progress(f"  ✓ dalfox v{ver} → {dest}")


def install_sqlmap(version: str, force: bool = False, progress=None) -> None:
    """Instala sqlmap descargando el tarball de GitHub y creando un wrapper script.

    sqlmap es un proyecto Python sin binario compilado; se instala en
    ~/.ares/lib/sqlmap/ y se expone via un wrapper shell en ~/.ares/bin/sqlmap.
    No se verifican checksums (GitHub no publica .sha256 para los archives de código
    fuente) -- se confía en HTTPS hacia github.com.
    """
    lib_dir = tools_dir().parent / "lib" / "sqlmap"
    wrapper  = tool_path("sqlmap")

    if wrapper.exists() and lib_dir.exists() and not force:
        if progress:
            progress(f"  ✓ sqlmap ya instalado en {lib_dir} (--force para reinstalar)")
        return

    ver = version
    url = f"https://github.com/sqlmapproject/sqlmap/archive/refs/tags/{ver}.tar.gz"
    asset = f"sqlmap-{ver}.tar.gz"

    with tempfile.TemporaryDirectory() as tmp:
        archive = pathlib.Path(tmp) / asset
        _fetch(url, archive, progress)

        lib_dir.parent.mkdir(parents=True, exist_ok=True)
        if lib_dir.exists():
            shutil.rmtree(lib_dir)

        with tarfile.open(archive) as tf:
            # el tarball contiene sqlmap-X.Y.Z/; lo extraemos a lib_dir
            members = tf.getmembers()
            prefix = members[0].name.split("/")[0] + "/"
            for member in members:
                member.name = member.name[len(prefix):]
                if member.name:
                    tf.extract(member, lib_dir)

    # wrapper script: llama a python3 con la ruta absoluta del sqlmap.py
    sqlmap_py = lib_dir / "sqlmap.py"
    if not sqlmap_py.exists():
        raise RuntimeError(f"sqlmap.py no encontrado en {lib_dir} después de extraer el tarball")

    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        f"#!/bin/sh\nexec {sys.executable} {sqlmap_py} \"$@\"\n"
    )
    wrapper.chmod(0o755)

    if progress:
        progress(f"  ✓ sqlmap v{ver} → {wrapper} (Python wrapper → {sqlmap_py})")


def install_bbot(version: str, force: bool = False, progress=None) -> None:
    """Instala bbot en un virtualenv aislado en ~/.ares/bbot_venv/ y crea un wrapper.

    bbot es un paquete PyPI; se instala en un venv propio para no contaminar el
    entorno principal de Ares. El wrapper en ~/.ares/bin/bbot delega al binario
    del venv.
    """
    venv_dir = tools_dir().parent / "bbot_venv"
    wrapper  = tool_path("bbot")

    if wrapper.exists() and venv_dir.exists() and not force:
        if progress:
            progress(f"  ✓ bbot ya instalado en {venv_dir} (--force para reinstalar)")
        return

    if progress:
        progress(f"  → creando virtualenv en {venv_dir} …")

    if venv_dir.exists() and force:
        shutil.rmtree(venv_dir)

    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
    )

    pip = venv_dir / "bin" / "pip"
    if not pip.exists():
        pip = venv_dir / "Scripts" / "pip.exe"  # Windows

    ver = version
    if progress:
        progress(f"  → pip install bbot=={ver} en venv aislado …")

    subprocess.run(
        [str(pip), "install", f"bbot=={ver}"],
        check=True,
        capture_output=True,
    )

    bbot_bin = venv_dir / "bin" / "bbot"
    if not bbot_bin.exists():
        bbot_bin = venv_dir / "Scripts" / "bbot.exe"  # Windows

    if not bbot_bin.exists():
        raise RuntimeError(f"bbot binario no encontrado en {venv_dir} después de pip install")

    # wrapper shell que llama al binario del venv
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text(
        f"#!/bin/sh\nexec {bbot_bin} \"$@\"\n"
    )
    wrapper.chmod(0o755)

    if progress:
        progress(f"  ✓ bbot v{ver} → {wrapper} (venv → {bbot_bin})")


# ── punto de entrada público ─────────────────────────────────────────────────

def install_all(
    tools: list[str] | None = None,
    force: bool = False,
    progress=None,
) -> dict[str, str]:
    """Instala todas (o las indicadas) las herramientas con verificación de checksum.
    Devuelve un dict {nombre: mensaje_de_error} para las que fallaron (vacío = éxito total)."""
    if tools is None:
        tools = ALL_TOOLS
    errors: dict[str, str] = {}

    for name in tools:
        if name not in TOOL_VERSIONS:
            errors[name] = f"herramienta desconocida: '{name}'"
            continue
        ver = TOOL_VERSIONS[name]
        try:
            if progress:
                progress(f"\n[{name}] v{ver}")
            if name in ("nuclei", "httpx", "subfinder", "katana"):
                install_pd_tool(name, ver, force=force, progress=progress)
            elif name == "ffuf":
                install_ffuf(ver, force=force, progress=progress)
            elif name == "dalfox":
                install_dalfox(ver, force=force, progress=progress)
            elif name == "sqlmap":
                install_sqlmap(ver, force=force, progress=progress)
            elif name == "bbot":
                install_bbot(ver, force=force, progress=progress)
        except Exception as exc:
            errors[name] = str(exc)
            if progress:
                progress(f"  ✗ Error: {exc}")

    return errors
