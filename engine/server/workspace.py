"""
Workspace — browse, view, and manage files in the shared work directory.
Port of ARTEX server/workspace.go.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

MAX_READ = 2 * 1024 * 1024    # 2 MiB — inline view/edit limit
MAX_UPLOAD = 512 * 1024 * 1024  # 512 MiB per upload


@dataclass
class WsEntry:
    name: str
    path: str    # workspace-relative path (forward slashes)
    is_dir: bool
    size: int
    mtime: int   # unix milliseconds


class Workspace:
    """
    Confined filesystem view over a base directory.
    All paths are validated to stay within the base directory.
    """

    def __init__(self, base_dir: str):
        self._base = Path(base_dir).resolve()
        self._base.mkdir(parents=True, exist_ok=True)

    def _resolve(self, rel: str) -> tuple[Path, bool]:
        """Resolve a user-supplied relative path. Returns (abs_path, ok)."""
        rel = rel.lstrip("/").strip()
        clean = Path(os.path.normpath("/" + rel))  # collapse .. sequences
        abs_path = (self._base / str(clean).lstrip("/")).resolve()
        ok = abs_path == self._base or str(abs_path).startswith(str(self._base) + os.sep)
        return abs_path, ok

    def _rel(self, abs_path: Path) -> str:
        try:
            return str(abs_path.relative_to(self._base)).replace(os.sep, "/")
        except ValueError:
            return ""

    def list(self, rel: str = "") -> list[WsEntry]:
        """List contents of a directory."""
        abs_path, ok = self._resolve(rel)
        if not ok or not abs_path.is_dir():
            return []
        entries: list[WsEntry] = []
        try:
            for child in sorted(abs_path.iterdir()):
                st = child.stat()
                entries.append(WsEntry(
                    name=child.name,
                    path=self._rel(child),
                    is_dir=child.is_dir(),
                    size=st.st_size if child.is_file() else 0,
                    mtime=int(st.st_mtime * 1000),
                ))
        except PermissionError:
            pass
        return entries

    def read(self, rel: str) -> tuple[bytes | None, str]:
        """Read a file. Returns (content, error_msg)."""
        abs_path, ok = self._resolve(rel)
        if not ok:
            return None, "path outside workspace"
        if not abs_path.is_file():
            return None, "not a file"
        size = abs_path.stat().st_size
        if size > MAX_READ:
            return None, f"file too large for inline view ({size} bytes > {MAX_READ})"
        try:
            return abs_path.read_bytes(), ""
        except OSError as exc:
            return None, str(exc)

    def write(self, rel: str, content: bytes) -> str:
        """Write bytes to a file. Returns error string or ''."""
        abs_path, ok = self._resolve(rel)
        if not ok:
            return "path outside workspace"
        abs_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            abs_path.write_bytes(content)
            return ""
        except OSError as exc:
            return str(exc)

    def delete(self, rel: str) -> str:
        """Delete a file or empty directory. Returns error string or ''."""
        abs_path, ok = self._resolve(rel)
        if not ok:
            return "path outside workspace"
        if not abs_path.exists():
            return "not found"
        try:
            if abs_path.is_dir():
                abs_path.rmdir()
            else:
                abs_path.unlink()
            return ""
        except OSError as exc:
            return str(exc)

    def mkdir(self, rel: str) -> str:
        abs_path, ok = self._resolve(rel)
        if not ok:
            return "path outside workspace"
        try:
            abs_path.mkdir(parents=True, exist_ok=True)
            return ""
        except OSError as exc:
            return str(exc)

    def move(self, src_rel: str, dst_rel: str) -> str:
        src, ok1 = self._resolve(src_rel)
        dst, ok2 = self._resolve(dst_rel)
        if not ok1 or not ok2:
            return "path outside workspace"
        try:
            shutil.move(str(src), str(dst))
            return ""
        except OSError as exc:
            return str(exc)

    def stat(self, rel: str) -> dict | None:
        abs_path, ok = self._resolve(rel)
        if not ok or not abs_path.exists():
            return None
        st = abs_path.stat()
        return {
            "path": self._rel(abs_path),
            "name": abs_path.name,
            "is_dir": abs_path.is_dir(),
            "size": st.st_size,
            "mtime": int(st.st_mtime * 1000),
        }

    @property
    def base_dir(self) -> str:
        return str(self._base)
