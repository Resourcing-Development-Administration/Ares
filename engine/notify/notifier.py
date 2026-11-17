"""
Notificaciones extendidas — webhook genérico, Feishu, Slack.
Inspirado en ARTEX notify/.

Configuración por env vars o por dict de config:
    ARES_NOTIFY_WEBHOOK_URL       — webhook genérico (POST JSON)
    ARES_NOTIFY_SLACK_URL         — Slack Incoming Webhook URL
    ARES_NOTIFY_FEISHU_URL        — Feishu/Lark Bot Webhook URL
    ARES_NOTIFY_ON_REGRESSION     — "1" para notificar solo en regresiones
    ARES_NOTIFY_ON_COMPLETION     — "1" para notificar al finalizar todo scan

Uso:
    notifier = Notifier.from_env()
    await notifier.notify_scan_complete(report, baseline_diff=diff)
    await notifier.notify_regression(report, new_findings)
"""
from __future__ import annotations
import os
import re
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from engine.core.models import ScanReport, Finding

_log = logging.getLogger(__name__)

# SSRF guard: IPs privadas/internas bloqueadas en URLs de webhook
_BLOCKED_NETS = [
    re.compile(r'^https?://localhost'),
    re.compile(r'^https?://127\.'),
    re.compile(r'^https?://10\.'),
    re.compile(r'^https?://172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^https?://192\.168\.'),
    re.compile(r'^https?://169\.254\.'),  # link-local/metadata
    re.compile(r'^https?://\[?::1'),       # IPv6 loopback
]


def _ssrf_check(url: str) -> None:
    """Lanza ValueError si la URL apunta a una red interna."""
    for pattern in _BLOCKED_NETS:
        if pattern.match(url):
            raise ValueError(f"URL de webhook bloqueada (red interna): {url}")


def _escape_markdown(text: str, platform: str = "generic") -> str:
    """Escapa caracteres especiales para evitar inyección de Markdown."""
    if platform == "slack":
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    elif platform in ("feishu", "markdown"):
        for c in r"\`*_{}[]()#+-.!|":
            text = text.replace(c, "\\" + c)
    return text


def _cap_message(text: str, max_chars: int = 3800) -> str:
    """Trunca un mensaje al límite de la plataforma."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[mensaje truncado]"


@dataclass
class NotifierConfig:
    webhook_url: str | None = None
    slack_url: str | None = None
    feishu_url: str | None = None
    on_regression: bool = True
    on_completion: bool = False
    timeout_s: int = 10
    # Nuevos canales
    dingtalk_url: str | None = None
    dingtalk_secret: str | None = None   # para firma HMAC
    wecom_url: str | None = None
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None
    email_smtp_host: str | None = None
    email_smtp_port: int = 587
    email_smtp_user: str | None = None
    email_smtp_password: str | None = None  # se redacta en logs
    email_from: str | None = None
    email_to: list[str] = field(default_factory=list)
    # Filtros
    min_severity: str = "low"           # "low" | "medium" | "high" | "critical"
    filter_regression_only: bool = False  # solo notificar regresiones

    @classmethod
    def from_env(cls) -> "NotifierConfig":
        return cls(
            webhook_url=os.environ.get("ARES_NOTIFY_WEBHOOK_URL"),
            slack_url=os.environ.get("ARES_NOTIFY_SLACK_URL"),
            feishu_url=os.environ.get("ARES_NOTIFY_FEISHU_URL"),
            on_regression=os.environ.get("ARES_NOTIFY_ON_REGRESSION", "1") == "1",
            on_completion=os.environ.get("ARES_NOTIFY_ON_COMPLETION", "0") == "1",
            dingtalk_url=os.environ.get("ARES_NOTIFY_DINGTALK_URL"),
            dingtalk_secret=os.environ.get("ARES_NOTIFY_DINGTALK_SECRET"),
            wecom_url=os.environ.get("ARES_NOTIFY_WECOM_URL"),
            telegram_bot_token=os.environ.get("ARES_NOTIFY_TELEGRAM_TOKEN"),
            telegram_chat_id=os.environ.get("ARES_NOTIFY_TELEGRAM_CHAT_ID"),
            email_smtp_host=os.environ.get("ARES_NOTIFY_EMAIL_SMTP_HOST"),
            email_smtp_user=os.environ.get("ARES_NOTIFY_EMAIL_SMTP_USER"),
            email_smtp_password=os.environ.get("ARES_NOTIFY_EMAIL_SMTP_PASSWORD"),
            email_from=os.environ.get("ARES_NOTIFY_EMAIL_FROM"),
            email_to=[x.strip() for x in os.environ.get("ARES_NOTIFY_EMAIL_TO", "").split(",") if x.strip()],
            min_severity=os.environ.get("ARES_NOTIFY_MIN_SEVERITY", "low"),
        )

    @property
    def any_configured(self) -> bool:
        return bool(
            self.webhook_url or self.slack_url or self.feishu_url
            or self.dingtalk_url or self.wecom_url
            or (self.telegram_bot_token and self.telegram_chat_id)
            or (self.email_smtp_host and self.email_to)
        )


class Notifier:
    def __init__(self, config: NotifierConfig) -> None:
        self._cfg = config

    @classmethod
    def from_env(cls) -> "Notifier":
        return cls(NotifierConfig.from_env())

    # ─── public API ──────────────────────────────────────────────────────────

    async def notify_scan_complete(
        self,
        report: "ScanReport",
        baseline_diff: dict | None = None,
        scan_url: str | None = None,
    ) -> list[str]:
        """Envía notificación de scan completado. Returns lista de errores."""
        if not self._cfg.any_configured:
            return []
        if not self._cfg.on_completion and baseline_diff is None:
            return []

        confirmed = sum(1 for f in report.findings if not f.passed)
        score = report.score
        grade = score.get("grade", "?") if isinstance(score, dict) else "?"
        policy = report.policy_verdict
        overall = policy.get("overall", "?") if isinstance(policy, dict) else str(policy)

        summary = {
            "scan_id": report.scan_id,
            "target": report.target_name,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "confirmed_findings": confirmed,
            "grade": grade,
            "policy": overall,
            "scan_url": scan_url,
            "baseline_diff": baseline_diff,
        }
        return await self._dispatch_all(
            summary,
            slack_text=self._scan_complete_slack_text(summary),
            feishu_text=self._scan_complete_feishu_text(summary),
        )

    async def notify_regression(
        self,
        report: "ScanReport",
        new_findings: list["Finding"],
        scan_url: str | None = None,
    ) -> list[str]:
        """Envía notificación de regresión (findings nuevos vs baseline)."""
        if not self._cfg.any_configured or not self._cfg.on_regression:
            return []
        summary = {
            "scan_id": report.scan_id,
            "target": report.target_name,
            "new_findings_count": len(new_findings),
            "new_findings": [
                {"test_id": f.test_id, "title": f.title,
                 "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity)}
                for f in new_findings[:10]
            ],
            "scan_url": scan_url,
        }
        return await self._dispatch_all(
            summary,
            slack_text=self._regression_slack_text(summary),
            feishu_text=self._regression_feishu_text(summary),
        )

    async def notify_agent_error(self, target: str, error: str) -> list[str]:
        """Notifica errores críticos del agente."""
        if not self._cfg.any_configured:
            return []
        payload = {"event": "agent_error", "target": target, "error": error}
        return await self._dispatch_all(
            payload,
            slack_text=f":red_circle: *Ares agent error* en `{target}`: {error[:300]}",
            feishu_text=f"Ares agent error en {target}: {error[:300]}",
        )

    # ─── filtering ───────────────────────────────────────────────────────────

    def _should_notify_finding(self, finding: object) -> bool:
        """Aplica filtros de severidad y regresión."""
        sev = getattr(finding, 'severity', 'low')
        sev_str = sev.value if hasattr(sev, 'value') else str(sev)
        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_sev = sev_order.get(self._cfg.min_severity.lower(), 0)
        if sev_order.get(sev_str.lower(), 0) < min_sev:
            return False
        return True

    # ─── dispatch ────────────────────────────────────────────────────────────

    async def _dispatch_all(
        self,
        payload: dict,
        slack_text: str,
        feishu_text: str,
    ) -> list[str]:
        # Derivar title/body para canales nuevos desde feishu_text (plain text)
        title = feishu_text.split("\n")[0][:80] if feishu_text else "Ares Notificación"
        body = feishu_text

        errors: list[str] = []
        tasks = []
        if self._cfg.webhook_url:
            tasks.append(self._post_webhook(self._cfg.webhook_url, payload))
        if self._cfg.slack_url:
            tasks.append(self._post_slack(self._cfg.slack_url, slack_text))
        if self._cfg.feishu_url:
            tasks.append(self._post_feishu(self._cfg.feishu_url, feishu_text))
        if self._cfg.dingtalk_url:
            tasks.append(self._send_dingtalk(title, body))
        if self._cfg.wecom_url:
            tasks.append(self._send_wecom(title, body))
        if self._cfg.telegram_bot_token and self._cfg.telegram_chat_id:
            tasks.append(self._send_telegram(title, body))
        if self._cfg.email_smtp_host and self._cfg.email_to:
            tasks.append(self._send_email(title, body))

        import asyncio
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                errors.append(str(r))
        return errors

    async def _post_webhook(self, url: str, payload: dict) -> None:
        _ssrf_check(url)
        async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
            resp = await client.post(url, json=payload,
                                     headers={"User-Agent": "Ares-Notifier/1.0"})
            resp.raise_for_status()

    async def _post_slack(self, url: str, text: str) -> None:
        _ssrf_check(url)
        async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
            resp = await client.post(url, json={"text": text})
            resp.raise_for_status()

    async def _post_feishu(self, url: str, text: str) -> None:
        _ssrf_check(url)
        # Feishu Bot Webhook espera {"msg_type": "text", "content": {"text": "..."}}
        async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
            resp = await client.post(url, json={
                "msg_type": "text",
                "content": {"text": text},
            })
            resp.raise_for_status()

    async def _send_dingtalk(self, title: str, body: str) -> None:
        """DingTalk robot webhook con firma HMAC opcional."""
        if not self._cfg.dingtalk_url:
            return
        _ssrf_check(self._cfg.dingtalk_url)

        url = self._cfg.dingtalk_url
        # Firma HMAC si hay secret
        if self._cfg.dingtalk_secret:
            import hmac as _hmac
            import hashlib
            import base64
            import urllib.parse
            ts = str(int(time.time() * 1000))
            sign_str = f"{ts}\n{self._cfg.dingtalk_secret}"
            sig = base64.b64encode(
                _hmac.new(
                    self._cfg.dingtalk_secret.encode(),
                    sign_str.encode(),
                    digestmod=hashlib.sha256,
                ).digest()
            ).decode()
            url = f"{url}&timestamp={ts}&sign={urllib.parse.quote_plus(sig)}"

        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": _escape_markdown(title[:50], "markdown"),
                "text": _cap_message(_escape_markdown(body, "markdown")),
            },
        }
        async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()

    async def _send_wecom(self, title: str, body: str) -> None:
        """WeCom (企业微信) robot webhook."""
        if not self._cfg.wecom_url:
            return
        _ssrf_check(self._cfg.wecom_url)
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": _cap_message(
                    f"**{_escape_markdown(title)}**\n\n{_escape_markdown(body)}"
                ),
            },
        }
        async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
            resp = await client.post(self._cfg.wecom_url, json=payload)
            resp.raise_for_status()

    async def _send_telegram(self, title: str, body: str) -> None:
        """Telegram Bot API."""
        if not self._cfg.telegram_bot_token or not self._cfg.telegram_chat_id:
            return
        text = _cap_message(
            f"*{_escape_markdown(title, 'telegram')}*\n\n{_escape_markdown(body, 'telegram')}",
            max_chars=4000,
        )
        url = f"https://api.telegram.org/bot{self._cfg.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self._cfg.telegram_chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
        }
        async with httpx.AsyncClient(timeout=self._cfg.timeout_s) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()

    async def _send_email(self, subject: str, body: str) -> None:
        """Email vía SMTP (aiosmtplib)."""
        if not self._cfg.email_smtp_host or not self._cfg.email_to:
            return
        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject[:200]
            msg["From"] = self._cfg.email_from or self._cfg.email_smtp_user or "ares@localhost"
            msg["To"] = ", ".join(self._cfg.email_to)
            await aiosmtplib.send(
                msg,
                hostname=self._cfg.email_smtp_host,
                port=self._cfg.email_smtp_port,
                username=self._cfg.email_smtp_user,
                password=self._cfg.email_smtp_password,
                start_tls=True,
            )
        except ImportError:
            _log.warning("aiosmtplib no instalado. pip install aiosmtplib para email.")
        except Exception as e:
            _log.error("Error enviando email: %s", e)

    # ─── message formatters ──────────────────────────────────────────────────

    def _scan_complete_slack_text(self, s: dict) -> str:
        emoji = ":white_check_mark:" if s["policy"] == "pass" else ":x:"
        link = f" <{s['scan_url']}|Ver reporte>" if s.get("scan_url") else ""
        return (
            f"{emoji} *Ares scan completo* — `{s['target']}`\n"
            f"Grade: *{s['grade']}* · Policy: *{s['policy']}* · "
            f"Findings: *{s['confirmed_findings']}*{link}"
        )

    def _regression_slack_text(self, s: dict) -> str:
        link = f" <{s['scan_url']}|Ver reporte>" if s.get("scan_url") else ""
        lines = [f":warning: *Ares regresión detectada* — `{s['target']}`",
                 f"{s['new_findings_count']} findings nuevos vs baseline{link}"]
        for f in s.get("new_findings", [])[:5]:
            lines.append(f"  • [{f['severity'].upper()}] {f['title']} ({f['test_id']})")
        return "\n".join(lines)

    def _scan_complete_feishu_text(self, s: dict) -> str:
        status = "✓ PASS" if s["policy"] == "pass" else "✗ FAIL"
        return (
            f"[Ares] Scan completo {status}\n"
            f"Target: {s['target']}\n"
            f"Grade: {s['grade']} | Findings: {s['confirmed_findings']}\n"
            + (f"Reporte: {s['scan_url']}" if s.get("scan_url") else "")
        )

    def _regression_feishu_text(self, s: dict) -> str:
        lines = [f"[Ares] REGRESIÓN en {s['target']}",
                 f"{s['new_findings_count']} findings nuevos:"]
        for f in s.get("new_findings", [])[:5]:
            lines.append(f"  - [{f['severity'].upper()}] {f['title']}")
        return "\n".join(lines)
