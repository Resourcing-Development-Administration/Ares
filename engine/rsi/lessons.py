"""
RSI Lesson Library — puerto de ARTEX db/lessons.go.
Una lección captura qué HACER (action) cuando se observa un patrón (cue),
respaldado por evidencia concreta (evidence). La library persiste en JSON.
"""
from __future__ import annotations
import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class LessonKind(str, Enum):
    # Exploitation: qué tests correr para confirmar una vuln encontrada
    EXPLOITATION = "exploitation"
    # Enumeration: cómo descubrir más superficie de ataque
    ENUMERATION = "enumeration"
    # False positive: pattern que genera mucho ruido sin valor
    FALSE_POSITIVE = "false_positive"
    # Efficiency: qué tests se pueden saltar dado cierto contexto
    EFFICIENCY = "efficiency"
    # Chaining: secuencia de tests que producen mejor cobertura
    CHAINING = "chaining"


class RSIMode(str, Enum):
    """Controla cuándo se activa la extracción RSI."""
    SHADOW = "shadow"      # extrae lecciones pero no las aplica (default)
    ACTIVE = "active"      # extrae Y aplica lecciones al plan
    DISABLED = "disabled"  # no extrae nada


@dataclass
class Lesson:
    id: str
    kind: LessonKind
    cue: str          # patrón/condición que activa la lección
    action: str       # qué hacer cuando se detecta el cue
    evidence: str     # qué scan / hallazgo soporta esta lección
    confidence: float = 0.5   # 0.0–1.0
    hits: int = 0             # cuántas veces se aplicó con éxito
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_applied: Optional[str] = None
    source_scan_id: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "cue": self.cue,
            "action": self.action,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "hits": self.hits,
            "created_at": self.created_at,
            "last_applied": self.last_applied,
            "source_scan_id": self.source_scan_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Lesson":
        return cls(
            id=d.get("id", uuid.uuid4().hex[:12]),
            kind=LessonKind(d.get("kind", "efficiency")),
            cue=d.get("cue", ""),
            action=d.get("action", ""),
            evidence=d.get("evidence", ""),
            confidence=float(d.get("confidence", 0.5)),
            hits=int(d.get("hits", 0)),
            created_at=d.get("created_at", datetime.now(timezone.utc).isoformat()),
            last_applied=d.get("last_applied"),
            source_scan_id=d.get("source_scan_id", ""),
        )


class LessonLibrary:
    """Thread-safe lesson store with JSON persistence.

    Default path: ~/.ares/rsi_lessons.json (overridable via ARES_RSI_PATH env var).
    """

    _DEFAULT_PATH = os.path.expanduser("~/.ares/rsi_lessons.json")

    def __init__(self, path: str | None = None) -> None:
        self._path = path or os.environ.get("ARES_RSI_PATH") or self._DEFAULT_PATH
        self._lessons: dict[str, Lesson] = {}
        self._lock = threading.Lock()
        self._load()

    # -----------------------------------------------------------------
    # Persistence
    # -----------------------------------------------------------------

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as f:
                data = json.load(f)
            for d in data.get("lessons", []):
                lesson = Lesson.from_dict(d)
                self._lessons[lesson.id] = lesson
        except Exception:
            pass

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(
                    {"lessons": [l.to_dict() for l in self._lessons.values()]},
                    f, indent=2, ensure_ascii=False,
                )
            os.replace(tmp, self._path)
        except Exception:
            pass

    # -----------------------------------------------------------------
    # CRUD
    # -----------------------------------------------------------------

    def add(self, lesson: Lesson) -> Lesson:
        """Add a lesson; raises if cue/action/evidence are empty (ARTEX constraint)."""
        if not lesson.cue.strip():
            raise ValueError("lesson.cue must not be empty")
        if not lesson.action.strip():
            raise ValueError("lesson.action must not be empty")
        if not lesson.evidence.strip():
            raise ValueError("lesson.evidence must not be empty")

        with self._lock:
            if not lesson.id:
                lesson.id = uuid.uuid4().hex[:12]
            self._lessons[lesson.id] = lesson
            self._save()
        return lesson

    def get(self, lesson_id: str) -> Optional[Lesson]:
        with self._lock:
            return self._lessons.get(lesson_id)

    def all(self) -> list[Lesson]:
        with self._lock:
            return list(self._lessons.values())

    def by_kind(self, kind: LessonKind) -> list[Lesson]:
        with self._lock:
            return [l for l in self._lessons.values() if l.kind == kind]

    def relevant_for(self, context: str, limit: int = 5) -> list[Lesson]:
        """Simple keyword relevance: sort by cue overlap with context."""
        context_lower = context.lower()
        with self._lock:
            scored = []
            for lesson in self._lessons.values():
                cue_words = set(lesson.cue.lower().split())
                ctx_words = set(context_lower.split())
                overlap = len(cue_words & ctx_words)
                if overlap > 0:
                    scored.append((overlap * lesson.confidence + lesson.hits * 0.1, lesson))
            scored.sort(key=lambda x: x[0], reverse=True)
            return [l for _, l in scored[:limit]]

    def record_hit(self, lesson_id: str) -> None:
        with self._lock:
            lesson = self._lessons.get(lesson_id)
            if lesson:
                lesson.hits += 1
                lesson.last_applied = datetime.now(timezone.utc).isoformat()
                self._save()

    def clear(self) -> int:
        with self._lock:
            count = len(self._lessons)
            self._lessons.clear()
            self._save()
        return count

    def remove(self, lesson_id: str) -> bool:
        with self._lock:
            if lesson_id in self._lessons:
                del self._lessons[lesson_id]
                self._save()
                return True
        return False

    def __len__(self) -> int:
        with self._lock:
            return len(self._lessons)
