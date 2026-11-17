"""
Rate limiter por IP para el endpoint de login.
Escala progresiva: 0-4 fallos → libre; 5-9 → 60s; 10-19 → 300s; 20+ → 1800s.
"""
from __future__ import annotations

import time
from collections import defaultdict


class LoginLimiter:
    """Rate limiter por IP con escala de cooldown progresiva."""

    _THRESHOLDS = [
        (20, 1800),  # 20+ intentos → 30 min
        (10, 300),   # 10-19 → 5 min
        (5, 60),     # 5-9 → 1 min
    ]
    _CLEANUP_AFTER_S = 7200  # 2 horas

    def __init__(self) -> None:
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def check_allowed(self, ip: str) -> bool:
        """False si la IP está en cooldown."""
        return self._cooldown(ip) == 0.0

    def record_failure(self, ip: str) -> None:
        """Registra un intento fallido para la IP."""
        self._attempts[ip].append(time.time())

    def clear_success(self, ip: str) -> None:
        """Limpia los intentos fallidos de una IP tras login exitoso."""
        self._attempts.pop(ip, None)

    def _cooldown(self, ip: str) -> float:
        """0.0 si libre; segundos restantes de cooldown si bloqueado."""
        attempts = self._attempts.get(ip)
        if not attempts:
            return 0.0
        count = len(attempts)
        wait_s = 0
        for threshold, cooldown in self._THRESHOLDS:
            if count >= threshold:
                wait_s = cooldown
                break
        if wait_s == 0:
            return 0.0
        last = attempts[-1]
        elapsed = time.time() - last
        remaining = wait_s - elapsed
        return max(0.0, remaining)

    def cleanup(self) -> None:
        """Elimina entradas con último intento > 2 horas."""
        cutoff = time.time() - self._CLEANUP_AFTER_S
        stale = [ip for ip, ts_list in self._attempts.items()
                 if ts_list and ts_list[-1] < cutoff]
        for ip in stale:
            del self._attempts[ip]
