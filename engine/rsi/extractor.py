"""
RSI Extractor — extrae lecciones de un ScanReport completado.
Puerto de ARTEX db/lessons.go heuristics: busca patrones en findings,
notas del analista y tests ejecutados para generar lecciones accionables.
"""
from __future__ import annotations
import uuid
from typing import Optional

from engine.core.models import ScanReport
from engine.rsi.lessons import Lesson, LessonKind, LessonLibrary


# -----------------------------------------------------------------
# Severity thresholds
# -----------------------------------------------------------------
_HIGH_SEVERITIES = {"critical", "high"}
_MEDIUM_SEVERITIES = {"medium"}


def extract_lessons_from_report(
    report: ScanReport,
    library: LessonLibrary,
    rsi_mode: str = "shadow",
) -> list[Lesson]:
    """Extract lessons from a completed scan and persist them.

    Returns the list of new lessons added (may be empty).
    In 'shadow' mode, lessons are saved but not surfaced to the agent.
    In 'active' mode, lessons would additionally be passed to the planner.
    In 'disabled' mode, nothing is done.
    """
    if rsi_mode == "disabled":
        return []

    new_lessons: list[Lesson] = []

    findings = report.findings
    notes = report.analyst_notes or []
    scan_id = report.scan_id

    # -------------------------------------------------------------------
    # Heuristic 1: high/critical findings → exploitation lesson
    # -------------------------------------------------------------------
    high_findings = [f for f in findings if f.severity.value in _HIGH_SEVERITIES]
    if high_findings:
        # Group by test_id to identify which test produced critical value
        tests_with_highs: dict[str, int] = {}
        for f in high_findings:
            tid = getattr(f, "test_id", "") or "unknown"
            tests_with_highs[tid] = tests_with_highs.get(tid, 0) + 1

        for test_id, count in tests_with_highs.items():
            if count >= 1:
                severity_list = ", ".join(
                    sorted({f.severity.value for f in high_findings if (getattr(f, "test_id", "") or "unknown") == test_id})
                )
                cue = f"Test '{test_id}' encontró hallazgos de severidad {severity_list} en target similar"
                action = (
                    f"Correr '{test_id}' temprano en el scan. "
                    f"Encontró {count} hallazgo(s) crítico(s)/alto(s)."
                )
                evidence = (
                    f"Scan {scan_id}: {count} hallazgo(s) {severity_list} "
                    f"de test '{test_id}'. Titles: "
                    + "; ".join(f.title for f in high_findings[:3] if (getattr(f, "test_id", "") or "unknown") == test_id)
                )
                lesson = Lesson(
                    id=uuid.uuid4().hex[:12],
                    kind=LessonKind.EXPLOITATION,
                    cue=cue.strip(),
                    action=action.strip(),
                    evidence=evidence.strip()[:500],
                    confidence=min(0.5 + count * 0.1, 0.95),
                    source_scan_id=scan_id,
                )
                try:
                    library.add(lesson)
                    new_lessons.append(lesson)
                except ValueError:
                    pass

    # -------------------------------------------------------------------
    # Heuristic 2: tests that produced zero findings → efficiency lesson
    # -------------------------------------------------------------------
    # Identify all tests that ran but produced no findings
    tests_run = set()
    tests_with_findings = set()
    for f in findings:
        tid = getattr(f, "test_id", "")
        if tid:
            tests_with_findings.add(tid)

    # Try to get tests_run from analyst notes keywords
    for note in notes:
        content = note.get("content", "")
        # Basic heuristic: look for patterns like "net.xxx" in note content
        import re
        ids_in_note = re.findall(r'\bnet\.[a-z_]+\b', content)
        tests_run.update(ids_in_note)

    barren_tests = tests_run - tests_with_findings
    for test_id in list(barren_tests)[:3]:  # limit to 3 efficiency lessons per scan
        cue = f"Target con perfil similar: test '{test_id}' corrió sin producir hallazgos"
        action = f"Considerar saltear o deprioritizar '{test_id}' en targets con perfil similar"
        evidence = f"Scan {scan_id}: '{test_id}' no produjo hallazgos. Total findings: {len(findings)}."
        lesson = Lesson(
            id=uuid.uuid4().hex[:12],
            kind=LessonKind.EFFICIENCY,
            cue=cue.strip(),
            action=action.strip(),
            evidence=evidence.strip(),
            confidence=0.4,
            source_scan_id=scan_id,
        )
        try:
            library.add(lesson)
            new_lessons.append(lesson)
        except ValueError:
            pass

    # -------------------------------------------------------------------
    # Heuristic 3: analyst notes with "chain" / "secuencia" → chaining
    # -------------------------------------------------------------------
    for note in notes:
        content = note.get("content", "").lower()
        title = note.get("title", "").lower()
        if any(kw in content or kw in title for kw in ["chain", "secuencia", "después de", "seguido de", "entonces"]):
            cue = f"Hallazgo que sugiere encadenamiento: {note.get('title', '')[:80]}"
            action = f"Revisar nota del analista para secuencia de tests: {note.get('title', '')[:80]}"
            evidence = f"Scan {scan_id} nota: {note.get('content', '')[:200]}"
            lesson = Lesson(
                id=uuid.uuid4().hex[:12],
                kind=LessonKind.CHAINING,
                cue=cue.strip(),
                action=action.strip(),
                evidence=evidence.strip(),
                confidence=0.5,
                source_scan_id=scan_id,
            )
            try:
                library.add(lesson)
                new_lessons.append(lesson)
            except ValueError:
                pass

    # -------------------------------------------------------------------
    # Heuristic 4: extra_assets discovered → enumeration lesson
    # -------------------------------------------------------------------
    extra = getattr(report, "extra_assets", [])
    if len(extra) >= 3:
        cue = f"Target {report.target_name} con subdominios/activos descubiertos por scanner ingest"
        action = "Correr enumeración de subdominios al inicio; este target tiene surface amplia"
        evidence = f"Scan {scan_id}: {len(extra)} activos extra descubiertos ({', '.join(extra[:5])})"
        lesson = Lesson(
            id=uuid.uuid4().hex[:12],
            kind=LessonKind.ENUMERATION,
            cue=cue.strip(),
            action=action.strip(),
            evidence=evidence.strip()[:500],
            confidence=0.6,
            source_scan_id=scan_id,
        )
        try:
            library.add(lesson)
            new_lessons.append(lesson)
        except ValueError:
            pass

    return new_lessons
