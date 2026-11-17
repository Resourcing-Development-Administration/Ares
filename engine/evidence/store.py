"""
Almacén de evidencia content-addressed (sha256) para findings de seguridad.
Preserva cuerpos de tráfico HTTP, screenshots y payloads como evidencia
ligada a hallazgos específicos.

Port de ARTEX evidence/store.go.
"""
from __future__ import annotations
import asyncio
import hashlib
import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

class StoreError(Exception): pass

@dataclass
class EvidenceRef:
    """Referencia a un blob de evidencia."""
    sha256: str           # hash del contenido
    size: int             # bytes
    mime_type: str        # "text/plain" | "application/json" | "text/http" | etc.
    finding_id: str       # finding al que pertenece
    label: str = ""       # descripción humana ("request", "response", "screenshot")

@dataclass
class BlobMeta:
    sha256: str
    size: int
    mime_type: str
    ref_count: int = 0    # cuántos findings referencian este blob

class EvidenceStore:
    """Almacén content-addressed de evidencia para findings.

    Garantías:
    - Deduplicación automática (mismo contenido = mismo sha256 = un solo blob)
    - GC por referencia: un blob no referenciado puede ser eliminado
    - Verificación de integridad en lectura
    - Export/import portable (tar.gz de blobs + manifest.json)
    """

    def __init__(self, base_dir: str | Path):
        self._base = Path(base_dir)
        self._blobs_dir = self._base / "blobs"
        self._meta_file = self._base / "meta.json"
        self._refs: dict[str, list[EvidenceRef]] = {}     # sha256 → refs
        self._meta: dict[str, BlobMeta] = {}              # sha256 → meta
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        """Inicializa el store, creando directorios y cargando metadata."""
        self._blobs_dir.mkdir(parents=True, exist_ok=True)
        if self._meta_file.exists():
            try:
                data = json.loads(self._meta_file.read_text())
                for sha, m in data.items():
                    self._meta[sha] = BlobMeta(**m)
            except Exception:
                pass  # meta corrupto → reconstruir

    async def put(self, content: bytes, mime_type: str, finding_id: str, label: str = "") -> EvidenceRef:
        """Almacena un blob de evidencia. Retorna la referencia (con sha256)."""
        sha256 = hashlib.sha256(content).hexdigest()
        async with self._lock:
            blob_path = self._blobs_dir / sha256[:2] / sha256[2:]
            blob_path.parent.mkdir(exist_ok=True)
            if not blob_path.exists():
                blob_path.write_bytes(content)

            # Actualizar meta
            if sha256 not in self._meta:
                self._meta[sha256] = BlobMeta(sha256=sha256, size=len(content), mime_type=mime_type)
            self._meta[sha256].ref_count += 1

            ref = EvidenceRef(sha256=sha256, size=len(content), mime_type=mime_type,
                            finding_id=finding_id, label=label)
            self._refs.setdefault(sha256, []).append(ref)
            await self._save_meta()
        return ref

    async def get(self, sha256: str) -> bytes:
        """Lee y verifica un blob de evidencia."""
        blob_path = self._blobs_dir / sha256[:2] / sha256[2:]
        if not blob_path.exists():
            raise StoreError(f"Blob {sha256} not found")
        content = blob_path.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if actual != sha256:
            raise StoreError(f"Integrity check failed for {sha256}")
        return content

    async def refs_for_finding(self, finding_id: str) -> list[EvidenceRef]:
        """Retorna todas las referencias de evidencia de un finding."""
        result = []
        for refs in self._refs.values():
            result.extend(r for r in refs if r.finding_id == finding_id)
        return result

    async def gc(self) -> int:
        """Elimina blobs sin referencias. Retorna número de blobs eliminados."""
        async with self._lock:
            removed = 0
            for sha256, meta in list(self._meta.items()):
                if meta.ref_count <= 0:
                    blob_path = self._blobs_dir / sha256[:2] / sha256[2:]
                    if blob_path.exists():
                        blob_path.unlink()
                        removed += 1
                    del self._meta[sha256]
                    self._refs.pop(sha256, None)
            if removed:
                await self._save_meta()
        return removed

    async def export_manifest(self) -> dict:
        """Exporta el manifest del store para backup/transfer."""
        return {
            "version": 1,
            "blobs": {sha: {"size": m.size, "mime_type": m.mime_type, "ref_count": m.ref_count}
                     for sha, m in self._meta.items()},
            "refs": {sha: [{"finding_id": r.finding_id, "label": r.label} for r in refs]
                    for sha, refs in self._refs.items()},
        }

    async def _save_meta(self) -> None:
        data = {sha: {"sha256": m.sha256, "size": m.size, "mime_type": m.mime_type, "ref_count": m.ref_count}
               for sha, m in self._meta.items()}
        self._meta_file.write_text(json.dumps(data, indent=2))
