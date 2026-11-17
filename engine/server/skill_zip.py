"""
skill_zip — ZIP decompressor supporting bzip2 and Zstd beyond Python's built-in deflate.
Port of ARTEX server/skill_zip.go.
"""
from __future__ import annotations

import bz2
import io
import zipfile
from pathlib import Path
from typing import Generator

# ZIP compression method constants
METHOD_STORED = 0
METHOD_DEFLATE = 8
METHOD_BZIP2 = 12
METHOD_LZMA = 14
METHOD_ZSTD_93 = 93    # Zstd (official PKWARE extension)
METHOD_ZSTD_20 = 20    # Zstd (Info-ZIP extension)
METHOD_DEFLATE64 = 9
METHOD_AES = 99


def _decompress_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """
    Decompress a ZIP member, adding bzip2 and Zstd support beyond Python's built-in.
    Raises ValueError for unsupported methods with helpful error messages.
    """
    method = info.compress_type

    if method in (METHOD_STORED, METHOD_DEFLATE):
        return zf.read(info)

    if method == METHOD_BZIP2:
        with zf.open(info) as fh:
            return bz2.decompress(fh.read())

    if method in (METHOD_ZSTD_93, METHOD_ZSTD_20):
        try:
            import zstandard as zstd
        except ImportError:
            raise ValueError(
                f"Zstd-compressed entry {info.filename!r} requires the 'zstandard' package. "
                "Install it with: pip install zstandard"
            )
        with zf.open(info) as fh:
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(fh.read())

    if method == METHOD_LZMA:
        raise ValueError(
            f"LZMA-compressed entry {info.filename!r} is not supported. "
            "Re-compress the archive with Deflate, bzip2, or Zstd."
        )

    if method == METHOD_DEFLATE64:
        raise ValueError(
            f"Deflate64-compressed entry {info.filename!r} is not supported. "
            "Re-compress the archive with standard Deflate."
        )

    if method == METHOD_AES:
        raise ValueError(
            f"AES-encrypted entry {info.filename!r} is not supported. "
            "Remove encryption before uploading skill archives."
        )

    raise ValueError(
        f"Unknown ZIP compression method {method} for entry {info.filename!r}."
    )


def extract_skill_zip(data: bytes, dest_dir: str) -> list[str]:
    """
    Extract a skill ZIP archive to dest_dir.
    Returns list of extracted relative paths.
    Supports Store/Deflate (built-in), bzip2, and Zstd.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            # Prevent path traversal
            safe_name = info.filename.lstrip("/").replace("..", "_")
            out_path = (dest / safe_name).resolve()
            try:
                out_path.relative_to(dest.resolve())
            except ValueError:
                continue

            out_path.parent.mkdir(parents=True, exist_ok=True)
            content = _decompress_member(zf, info)
            out_path.write_bytes(content)
            extracted.append(safe_name)

    return extracted


def list_zip_members(data: bytes) -> list[dict]:
    """Return metadata for all members in a ZIP archive."""
    members: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            members.append({
                "name": info.filename,
                "size": info.file_size,
                "compress_size": info.compress_size,
                "method": info.compress_type,
                "is_dir": info.is_dir(),
            })
    return members
