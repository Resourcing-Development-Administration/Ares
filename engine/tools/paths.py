"""
Rutas para los binarios de herramientas de seguridad que gestiona Ares.
Los binarios se guardan en ~/.ares/bin/ (o ARES_TOOLS_DIR) y tienen prioridad
sobre los que haya en PATH -- así la versión pinneada de Ares siempre gana.
"""
from __future__ import annotations
import os
import shutil
import pathlib


def tools_dir() -> pathlib.Path:
    """Directorio donde Ares almacena sus binarios. ~/.ares/bin por defecto,
    sobreescribible con la variable de entorno ARES_TOOLS_DIR."""
    d = pathlib.Path(
        os.environ.get("ARES_TOOLS_DIR", pathlib.Path.home() / ".ares" / "bin")
    )
    d.mkdir(parents=True, exist_ok=True)
    return d


def tool_path(name: str) -> pathlib.Path:
    """Ruta del binario 'name' dentro del directorio gestionado por Ares."""
    return tools_dir() / name


def find_tool(name: str) -> str | None:
    """Devuelve el path absoluto al binario. Prioridad:
    1. Directorio gestionado por Ares (~/.ares/bin/)
    2. PATH del sistema (shutil.which)
    Devuelve None si no se encuentra en ninguno."""
    p = tool_path(name)
    if p.exists() and os.access(p, os.X_OK):
        return str(p)
    return shutil.which(name)


def tool_available(name: str) -> bool:
    """True si el binario está disponible (en el dir de Ares o en PATH)."""
    return find_tool(name) is not None


def tools_status() -> dict[str, dict]:
    """Estado de cada herramienta conocida: disponible, path, fuente."""
    from engine.tools.installer import TOOL_VERSIONS, ALL_TOOLS
    result = {}
    for name in ALL_TOOLS:
        p = tool_path(name)
        in_tools_dir = p.exists() and os.access(p, os.X_OK)
        in_path = shutil.which(name)
        result[name] = {
            "available":       in_tools_dir or bool(in_path),
            "pinned_version":  TOOL_VERSIONS.get(name, "?"),
            "path":            str(p) if in_tools_dir else (in_path or None),
            "source":          "ares_tools_dir" if in_tools_dir
                               else ("path" if in_path else "not_found"),
        }
    return result
