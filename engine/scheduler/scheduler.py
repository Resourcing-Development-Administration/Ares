"""
Scheduled / continuous scans — cron-style scan automation.
Implementa un scheduler in-process con persistencia JSON.

No requiere dependencias externas (no APScheduler). Usa asyncio.
La configuración de schedules se persiste en reports/schedules.json.

Uso:
    scheduler = ScanScheduler(reports_dir)
    scheduler.add(ScheduleEntry(
        id="daily-example",
        cron="0 2 * * *",        # cada día a las 02:00
        scan_type="netrecon",
        params={"target_url": "https://example.com", "scope": ["example.com"]},
    ))
    asyncio.create_task(scheduler.run_forever())
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Literal


ScanType = Literal["scan", "api-scan", "netrecon", "agent-scan"]


@dataclass
class ScheduleEntry:
    id: str
    cron: str                      # "minute hour dom month dow" (5 campos)
    scan_type: ScanType
    params: dict                   # parámetros pasados al runner correspondiente
    enabled: bool = True
    last_run: str | None = None
    next_run: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    run_count: int = 0
    error_count: int = 0
    last_error: str | None = None
    notify_on_regression: bool = True
    notify_webhook: str | None = None  # override por-schedule


def _cron_matches(cron: str, dt: datetime) -> bool:
    """Evalúa si un cron expression (5 campos) matchea un datetime dado."""
    parts = cron.strip().split()
    if len(parts) != 5:
        return False
    minute, hour, dom, month, dow = parts

    def _match_field(value: int, expr: str) -> bool:
        if expr == "*":
            return True
        if re.match(r"^\*/(\d+)$", expr):
            step = int(re.match(r"^\*/(\d+)$", expr).group(1))
            return value % step == 0
        if "-" in expr and not expr.startswith("-"):
            lo, hi = expr.split("-", 1)
            return int(lo) <= value <= int(hi)
        try:
            return int(expr) == value
        except ValueError:
            return False

    return all([
        _match_field(dt.minute, minute),
        _match_field(dt.hour, hour),
        _match_field(dt.day, dom),
        _match_field(dt.month, month),
        _match_field(dt.weekday(), dow),
    ])


def _next_run_after(cron: str, after: datetime) -> datetime:
    """Calcula el próximo disparo del cron después de `after` (resolución: 1 minuto)."""
    dt = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(60 * 24 * 8):  # max 8 días de búsqueda
        if _cron_matches(cron, dt):
            return dt
        dt += timedelta(minutes=1)
    return dt


class ScanScheduler:
    """Scheduler async in-process con persistencia JSON."""

    SCHEDULES_FILE = "schedules.json"

    def __init__(
        self,
        reports_dir: str,
        run_callback: Callable[[ScheduleEntry], None] | None = None,
    ) -> None:
        self._dir = reports_dir
        self._path = os.path.join(reports_dir, self.SCHEDULES_FILE)
        self._schedules: dict[str, ScheduleEntry] = {}
        self._run_callback = run_callback  # llamado cuando un schedule dispara
        self._load()

    # ─── CRUD ────────────────────────────────────────────────────────────────

    def add(self, entry: ScheduleEntry) -> ScheduleEntry:
        now = datetime.now(timezone.utc)
        entry.next_run = _next_run_after(entry.cron, now).isoformat()
        self._schedules[entry.id] = entry
        self._save()
        return entry

    def update(self, id: str, **kwargs) -> ScheduleEntry | None:
        e = self._schedules.get(id)
        if not e:
            return None
        for k, v in kwargs.items():
            if hasattr(e, k):
                setattr(e, k, v)
        self._save()
        return e

    def delete(self, id: str) -> bool:
        if id not in self._schedules:
            return False
        del self._schedules[id]
        self._save()
        return True

    def list_all(self) -> list[ScheduleEntry]:
        return list(self._schedules.values())

    def get(self, id: str) -> ScheduleEntry | None:
        return self._schedules.get(id)

    # ─── runner loop ─────────────────────────────────────────────────────────

    async def run_forever(self) -> None:
        """Loop principal: cada minuto evalúa qué schedules deben disparar."""
        while True:
            now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
            for entry in list(self._schedules.values()):
                if not entry.enabled:
                    continue
                if _cron_matches(entry.cron, now):
                    asyncio.create_task(self._fire(entry, now))
            await asyncio.sleep(60 - datetime.now(timezone.utc).second)

    async def _fire(self, entry: ScheduleEntry, fired_at: datetime) -> None:
        """Dispara un schedule en background."""
        entry.last_run = fired_at.isoformat()
        entry.run_count += 1
        next_dt = _next_run_after(entry.cron, fired_at)
        entry.next_run = next_dt.isoformat()
        self._save()

        if self._run_callback:
            try:
                self._run_callback(entry)
            except Exception as e:
                entry.error_count += 1
                entry.last_error = str(e)
                self._save()
            return

        # runner por defecto — ejecuta según scan_type
        try:
            await self._default_run(entry)
        except Exception as e:
            entry.error_count += 1
            entry.last_error = str(e)
            self._save()

    async def _default_run(self, entry: ScheduleEntry) -> None:
        """Ejecuta el scan según entry.scan_type y compara con el run anterior."""
        p = entry.params
        target_url = p.get("target_url", "")
        report = None

        if entry.scan_type == "netrecon":
            from engine.netrecon.runner import run_netrecon_scan
            report = await run_netrecon_scan(
                target_url=target_url,
                scope=p.get("scope"),
                nuclei_severity=p.get("nuclei_severity", ["critical", "high", "medium"]),
                timeout_s=p.get("timeout_s", 180),
                rate_limit=p.get("rate_limit", 150),
                min_confidence=p.get("min_confidence", "heuristic"),
                environment=p.get("environment", "production"),
                allowlist_path=p.get("allowlist_path"),
            )
        elif entry.scan_type == "agent-scan":
            from engine.agent.orchestrator import run_agent_scan
            report = await run_agent_scan(
                target_url=target_url,
                scope=p.get("scope"),
                goal=p.get("goal"),
                provider=p.get("provider", "auto"),
                model=p.get("model"),
                max_rounds=p.get("max_rounds", 8),
                timeout_s=p.get("timeout_s", 180),
                rate_limit=p.get("rate_limit", 150),
                min_confidence=p.get("min_confidence", "heuristic"),
                environment=p.get("environment", "production"),
                allow_level3=p.get("allow_level3", False),
                denylist=p.get("denylist"),
                allowlist_path=p.get("allowlist_path"),
            )
        # scan / api-scan se pueden agregar análogamente

        if report is not None:
            await self._post_run(entry, report, target_url)

    async def _post_run(self, entry: ScheduleEntry, report: Any, target_url: str) -> None:
        """Persiste el reporte, compara con el anterior y notifica regresiones."""
        import os, json as _json

        reports_dir = self._dir
        scan_id = report.scan_id or uuid.uuid4().hex[:8]
        scan_dir = os.path.join(reports_dir, scan_id)
        os.makedirs(scan_dir, exist_ok=True)

        # guardar JSON
        try:
            from engine.reporting.html_report import save_html_report
            from engine.reporting.sarif import save_sarif_report
            save_html_report(report, os.path.join(scan_dir, "report.html"))
            with open(os.path.join(scan_dir, "report.json"), "w", encoding="utf-8") as fh:
                _json.dump(report.to_dict(), fh, indent=2, ensure_ascii=False, default=str)
            save_sarif_report(report, os.path.join(scan_dir, "report.sarif"))
        except Exception:
            pass

        # retesting: cargar el report anterior del mismo target
        previous_findings: list = []
        try:
            index_path = os.path.join(reports_dir, "index.json")
            if os.path.exists(index_path):
                with open(index_path, encoding="utf-8") as fh:
                    index = _json.load(fh)
                prev_entries = [
                    e for e in index
                    if e.get("target_name") == target_url
                    and e.get("scan_id") != scan_id
                ]
                if prev_entries:
                    prev_entries.sort(key=lambda x: x.get("started_at", ""), reverse=True)
                    prev_scan_id = prev_entries[0]["scan_id"]
                    prev_json = os.path.join(reports_dir, prev_scan_id, "report.json")
                    if os.path.exists(prev_json):
                        with open(prev_json, encoding="utf-8") as fh:
                            prev_data = _json.load(fh)
                        # reconstruir findings mínimos para comparar
                        from engine.core.models import Finding, Severity, Category
                        for f_dict in (prev_data.get("findings") or []):
                            try:
                                previous_findings.append(Finding(
                                    test_id=f_dict.get("test_id", ""),
                                    title=f_dict.get("title", ""),
                                    severity=Severity(f_dict.get("severity", "info")),
                                    category=Category(f_dict.get("category", "network")),
                                    target=f_dict.get("target", target_url),
                                    passed=f_dict.get("passed", False),
                                ))
                            except Exception:
                                pass
        except Exception:
            pass

        # comparar
        if previous_findings:
            try:
                from engine.reporting.dedup import compare_findings, retest_summary
                results = compare_findings(previous_findings, report.findings)
                summary = retest_summary(results)
                entry.last_error = None
                if summary["regression"] and entry.notify_on_regression:
                    await self._send_regression_notification(entry, report, summary)
            except Exception:
                pass

        # persistir en Postgres si está disponible
        try:
            from engine.persistence.store import PersistenceStore
            store = await PersistenceStore.connect()
            if store.available:
                await store.save_report(report, mode=entry.scan_type)
                await store.close()
        except Exception:
            pass

    async def _send_regression_notification(
        self, entry: ScheduleEntry, report: Any, retest_summary: dict,
    ) -> None:
        try:
            from engine.notify.notifier import Notifier, NotifierConfig
            cfg = NotifierConfig.from_env()
            if entry.notify_webhook:
                cfg.webhook_url = entry.notify_webhook
            notifier = Notifier(cfg)
            if not notifier._cfg.any_configured:
                return
            # construir findings nuevos como objetos simples
            new_f = []
            for f_dict in retest_summary.get("new_findings", []):
                class _F:
                    test_id = f_dict.get("test_id", "")
                    title = f_dict.get("title", "")
                    class severity:
                        value = f_dict.get("severity", "info")
                new_f.append(_F())
            await notifier.notify_regression(report, new_f)  # type: ignore
        except Exception:
            pass

    # ─── persistence ─────────────────────────────────────────────────────────

    def _save(self) -> None:
        os.makedirs(self._dir, exist_ok=True)
        data = [asdict(e) for e in self._schedules.values()]
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            for item in data:
                e = ScheduleEntry(**{k: v for k, v in item.items()
                                     if k in ScheduleEntry.__dataclass_fields__})
                self._schedules[e.id] = e
        except Exception:
            pass
