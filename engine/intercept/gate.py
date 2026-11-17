"""
Gate de intercepción pre-ejecución para tests de red.
Puerto de ARTEX's intercept/target_gate.go — scope, denylist, IPs privadas,
pinned dialer (anti-rebinding) y approval callback para decisiones borderline.
"""
from __future__ import annotations
import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Literal
from urllib.parse import urlparse


@dataclass
class GateDecision:
    action: Literal["allow", "deny", "pending"]
    reason: str
    resolved_ip: str = ""   # IP resuelta por el dialer (vacío si no se resolvió)


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
]


def _is_private(ip_str: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip_str) in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _resolve_host(host: str) -> str:
    """Resolución DNS síncrona — retorna la primera IP o cadena vacía."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return infos[0][4][0] if infos else ""
    except OSError:
        return ""


# Tipo del callback de aprobación: recibe (host, test_id, reason) → bool
ApprovalCallback = Callable[[str, str, str], Awaitable[bool]]


class InterceptGate:
    """Gate de intercepción con pinned dialer y approval callback opcional.

    Checks (en orden):
    1. Explicit denylist      — deny si el host matchea cualquier entrada
    2. Pinned dialer          — resuelve DNS y verifica que la IP no sea privada
                                (anti DNS-rebinding); bloquea si cambia entre checks
    3. Private IP protection  — deny a menos que allow_private=True
    4. Level-3 gate           — deny si level >= 3 sin allow_level3=True
    5. Scope check            — deny si scope declarado y host fuera de él
    6. Approval callback      — si está configurado, consulta para decisiones borderline
    """

    def __init__(
        self,
        scope: list[str] | None = None,
        denylist: list[str] | None = None,
        allow_level3: bool = False,
        allow_private: bool = False,
        pin_dialer: bool = True,
        approval_cb: ApprovalCallback | None = None,
    ):
        self.scope = scope or []
        self.denylist = set(denylist or [])
        self.allow_level3 = allow_level3
        self.allow_private = allow_private
        self.pin_dialer = pin_dialer
        self.approval_cb = approval_cb
        # Cache de IPs resueltas para detectar rebinding: host → ip
        self._pinned: dict[str, str] = {}

    def _host_from_url(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        return parsed.hostname or target_url.split("/")[0].split(":")[0]

    def check(self, target_url: str, test_id: str, test_level: int) -> GateDecision:
        """Check síncrono — no hace DNS, usa IP pinned si ya fue resuelta."""
        host = self._host_from_url(target_url)
        resolved_ip = self._pinned.get(host, "")
        return self._evaluate(host, resolved_ip, test_id, test_level)

    async def check_async(
        self, target_url: str, test_id: str, test_level: int
    ) -> GateDecision:
        """Check asíncrono — resuelve DNS y pinna la IP contra rebinding."""
        host = self._host_from_url(target_url)

        # Pinned dialer: resolver y verificar consistencia
        resolved_ip = ""
        if self.pin_dialer:
            resolved_ip = await asyncio.get_event_loop().run_in_executor(
                None, _resolve_host, host
            )
            if resolved_ip:
                prev = self._pinned.get(host)
                if prev and prev != resolved_ip:
                    return GateDecision(
                        "deny",
                        f"DNS rebinding detectado para '{host}': "
                        f"era {prev}, ahora {resolved_ip}",
                        resolved_ip=resolved_ip,
                    )
                self._pinned[host] = resolved_ip

        decision = self._evaluate(host, resolved_ip, test_id, test_level)

        # Approval callback para decisiones borderline (allow_private en test interno, etc.)
        if decision.action == "pending" and self.approval_cb:
            approved = await self.approval_cb(host, test_id, decision.reason)
            if approved:
                return GateDecision("allow", f"aprobado manualmente: {decision.reason}", resolved_ip=resolved_ip)
            return GateDecision("deny", f"rechazado manualmente: {decision.reason}", resolved_ip=resolved_ip)

        return decision

    def _evaluate(
        self, host: str, resolved_ip: str, test_id: str, test_level: int
    ) -> GateDecision:
        # 1. Explicit denylist (host y IP resuelta)
        for denied in self.denylist:
            clean = denied.lstrip("*.")
            if clean and (host == clean or host.endswith("." + clean)):
                return GateDecision("deny", f"host '{host}' en denylist")
            if resolved_ip and resolved_ip == denied:
                return GateDecision("deny", f"IP '{resolved_ip}' en denylist")

        # 2. Private IP check (sobre IP resuelta si disponible, sino sobre el host literal)
        check_target = resolved_ip or host
        is_loopback = check_target in ("localhost", "::1") or check_target.startswith("127.")
        is_priv = is_loopback or _is_private(check_target)
        if is_priv and not self.allow_private:
            return GateDecision(
                "deny",
                f"'{check_target}' es IP privada/loopback — allow_private=True para permitir",
            )

        # 3. Level-3 gate
        if test_level >= 3 and not self.allow_level3:
            return GateDecision(
                "deny",
                f"{test_id} es nivel {test_level} — requiere allow_level3=True",
            )

        # 4. Scope check
        if self.scope:
            in_scope = any(
                host == s
                or host.endswith("." + s)
                or (s.startswith("*.") and host.endswith(s[1:]))
                for s in self.scope
            )
            if not in_scope:
                return GateDecision(
                    "deny",
                    f"'{host}' fuera del scope: {', '.join(self.scope)}",
                )

        return GateDecision("allow", "OK", resolved_ip=resolved_ip)

    def add_to_denylist(self, entry: str) -> None:
        self.denylist.add(entry)

    def pin_ip(self, host: str, ip: str) -> None:
        """Pinna manualmente un host a una IP (para tests con IP conocida)."""
        self._pinned[host] = ip

    def pinned_ips(self) -> dict[str, str]:
        return dict(self._pinned)
