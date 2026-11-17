"""
chatupload — Handle file uploads attached to chat messages.
Port of ARTEX server/chatupload.go.
"""
from __future__ import annotations

import hashlib
import mimetypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB per file
MAX_FILES_PER_MESSAGE = 10

_ALLOWED_MIME_PREFIXES = (
    "text/",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/pdf",
    "image/",
)


@dataclass
class UploadedFile:
    name: str
    content_type: str
    size: int
    sha256: str
    path: str       # relative path under upload_dir


def _allowed_mime(content_type: str) -> bool:
    ct = content_type.split(";")[0].strip().lower()
    return any(ct.startswith(p) for p in _ALLOWED_MIME_PREFIXES)


def store_upload(
    name: str,
    data: bytes,
    upload_dir: str,
    content_type: str = "",
) -> UploadedFile:
    """
    Validate and store an uploaded file. Returns UploadedFile metadata.
    Raises ValueError for oversized or disallowed files.
    """
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"File {name!r} exceeds maximum upload size "
            f"({len(data) // 1024}KB > {MAX_UPLOAD_BYTES // 1024}KB)"
        )

    if not content_type:
        guessed, _ = mimetypes.guess_type(name)
        content_type = guessed or "application/octet-stream"

    if not _allowed_mime(content_type):
        raise ValueError(
            f"File type {content_type!r} is not allowed for upload. "
            "Allowed: text, JSON, XML, JS, PDF, images."
        )

    sha = hashlib.sha256(data).hexdigest()
    safe_name = "".join(c for c in Path(name).name if c.isalnum() or c in "-_.")
    if not safe_name:
        safe_name = sha[:16]

    dest = Path(upload_dir) / sha[:2] / f"{sha[2:16]}_{safe_name}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

    return UploadedFile(
        name=name,
        content_type=content_type,
        size=len(data),
        sha256=sha,
        path=str(dest.relative_to(upload_dir)),
    )


def file_to_text_block(uf: UploadedFile, upload_dir: str) -> str:
    """Read a stored upload and return a safe text block for the agent prompt."""
    full_path = Path(upload_dir) / uf.path
    if not full_path.exists():
        return f"[uploaded file {uf.name!r} not found]"
    try:
        text = full_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return f"[uploaded file {uf.name!r}: binary, {uf.size} bytes]"
    if len(text) > 65536:
        text = text[:65536] + "\n[... truncated]"
    return f"<uploaded_file name={uf.name!r} type={uf.content_type!r}>\n{text}\n</uploaded_file>"
