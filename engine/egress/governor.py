"""
Noise Governor — rate-limiting and jitter for outbound HTTP requests.

Port of ARTEX/egress/egress.go. Controls all requests the agent sends to
targets via a token-bucket per host, global concurrency cap, jitter, and
backoff on 429/503.

Profiles (ARES_NOISE_PROFILE env var):
  off        — strict passthrough, no pacing (default)
  quiet      — 2 rps/host, 1 in-flight/host, heavy jitter
  balanced   — 5 rps/host, 2 in-flight/host
  aggressive — 20 rps/host, 4 in-flight/host

Env vars:
  ARES_NOISE_PROFILE      off|quiet|balanced|aggressive
  ARES_TARGET_USER_AGENT  User-Agent injected on requests that have none
"""
from __future__ import annotations

import asyncio
import os
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse


MAX_JITTER = 0.25  # seconds


@dataclass
class Profile:
    name: str = "off"
    rps: float = 0.0          # token refill per host (req/s); 0 = off
    burst: int = 0            # bucket size per host
    max_per_host: int = 1     # max requests in-flight per host
    max_global: int = 1       # max requests in-flight globally
    jitter: float = 0.0       # uniform [0, min(jitter/rps, MAX_JITTER)]
    cache_ttl: float = 0.0    # GET cache TTL (seconds); 0 = no cache
    max_retries: int = 0      # retries after 429/503 (idempotent only)
    base_delay: float = 1.0   # backoff base (seconds)
    max_delay: float = 30.0   # backoff cap (seconds)
    user_agent: str = ""      # injected when request has none; "" = unchanged


PROFILES: dict[str, Profile] = {
    "quiet": Profile(
        name="quiet", rps=2, burst=4, max_per_host=1, max_global=8,
        jitter=0.5, cache_ttl=60, max_retries=3, base_delay=2.0, max_delay=60.0,
    ),
    "balanced": Profile(
        name="balanced", rps=5, burst=10, max_per_host=2, max_global=16,
        jitter=0.2, cache_ttl=30, max_retries=3, base_delay=1.0, max_delay=30.0,
    ),
    "aggressive": Profile(
        name="aggressive", rps=20, burst=40, max_per_host=4, max_global=32,
        jitter=0.1, cache_ttl=10, max_retries=2, base_delay=0.5, max_delay=10.0,
    ),
}


@dataclass
class HostState:
    tokens: float = 0.0
    last: float = field(default_factory=time.monotonic)
    not_before: float = 0.0   # monotonic time — end of backoff
    sent: int = 0
    dupes: int = 0
    inflight: int = 0
    peak_inflight: int = 0
    peak_rpm: int = 0


@dataclass
class HostNoise:
    host: str
    rpm: int
    peak_rpm: int
    peak_inflight: int
    inflight: int
    duplicates_avoided: int


def _host_key(url_str: str) -> str:
    p = urlparse(url_str)
    host = (p.hostname or "").lower()
    port = p.port
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        return f"{host}:{port}"
    return host


class Governor:
    def __init__(self, profile: Profile) -> None:
        self._p = profile
        self._lock = asyncio.Lock()
        self._host_states: dict[str, HostState] = {}
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._global_sem = asyncio.Semaphore(max(profile.max_global, 1))
        # cache_ttl: keyed by (method, url), value is (response, expires_monotonic)
        self._cache: dict[tuple[str, str], tuple[Any, float]] = {}
        self._cache_lock = asyncio.Lock()

    def off(self) -> bool:
        return self._p.rps <= 0

    @property
    def profile(self) -> Profile:
        return self._p

    def _get_host_state(self, host: str) -> HostState:
        if host not in self._host_states:
            self._host_states[host] = HostState(tokens=float(self._p.burst), last=time.monotonic())
        return self._host_states[host]

    def _get_host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(max(self._p.max_per_host, 1))
        return self._host_sems[host]

    def _reserve(self, state: HostState) -> float:
        """Consume one token; return seconds to wait (0 if bucket had tokens)."""
        now = time.monotonic()
        elapsed = now - state.last
        state.tokens = min(float(self._p.burst), state.tokens + elapsed * self._p.rps) - 1
        state.last = now
        wait_token = max(-state.tokens / self._p.rps, 0.0)
        wait_backoff = max(state.not_before - now, 0.0)
        return max(wait_token, wait_backoff)

    def _jitter(self) -> float:
        if self._p.rps <= 0:
            return 0.0
        bound = min(self._p.jitter / self._p.rps, MAX_JITTER)
        return random.uniform(0, bound)

    def backoff(self, headers: dict[str, str], attempt: int) -> tuple[float, bool]:
        """Return (delay_seconds, should_retry). False = Retry-After > max_delay."""
        ra = headers.get("Retry-After", "").strip()
        if ra:
            try:
                n = float(ra)
                if n >= 0:
                    return n, n <= self._p.max_delay
            except ValueError:
                pass
            try:
                dt = parsedate_to_datetime(ra)
                delay = max((dt.timestamp() - time.time()), 0.0)
                return delay, delay <= self._p.max_delay
            except Exception:
                pass
        # exponential
        delay = min(self._p.base_delay * (2 ** attempt), self._p.max_delay)
        return delay, True

    @asynccontextmanager
    async def acquire(self, url_str: str):
        """Async context manager that paces one outbound request."""
        host = _host_key(url_str)
        host_sem = self._get_host_sem(host)
        await host_sem.acquire()
        try:
            async with self._lock:
                state = self._get_host_state(host)
                wait = self._reserve(state) + self._jitter()
            if wait > 0:
                await asyncio.sleep(wait)
            await self._global_sem.acquire()
            try:
                async with self._lock:
                    state = self._get_host_state(host)
                    state.sent += 1
                    state.inflight += 1
                    state.peak_inflight = max(state.peak_inflight, state.inflight)
                yield
            finally:
                async with self._lock:
                    s = self._get_host_state(host)
                    s.inflight = max(s.inflight - 1, 0)
                self._global_sem.release()
        finally:
            host_sem.release()

    def mark_backoff(self, url_str: str, delay: float) -> None:
        """Mark a host in backoff after a 429/503."""
        host = _host_key(url_str)
        state = self._get_host_state(host)
        until = time.monotonic() + delay
        if until > state.not_before:
            state.not_before = until

    def snapshot(self) -> list[HostNoise]:
        return [
            HostNoise(
                host=k, rpm=s.sent, peak_rpm=max(s.peak_rpm, s.sent),
                peak_inflight=s.peak_inflight, inflight=s.inflight,
                duplicates_avoided=s.dupes,
            )
            for k, s in sorted(self._host_states.items())
            if s.sent or s.dupes or s.inflight or s.peak_rpm
        ]


# ── global singleton ─────────────────────────────────────────────────────────

_current_governor: Governor | None = None
_governor_lock = asyncio.Lock()


def profile_from_env() -> Profile:
    name = os.environ.get("ARES_NOISE_PROFILE", "off").strip().lower()
    if name == "off" or not name:
        p = Profile(name="off")
    else:
        p = PROFILES.get(name, Profile(name="off"))
    ua = os.environ.get("ARES_TARGET_USER_AGENT", "").strip()
    if ua and not any(c < " " for c in ua):
        p = Profile(**{**p.__dict__, "user_agent": ua})
    return p


def get_current() -> Governor:
    global _current_governor
    if _current_governor is None:
        _current_governor = Governor(profile_from_env())
    return _current_governor


def set_profile(name_or_profile: str | Profile) -> Governor:
    global _current_governor
    if isinstance(name_or_profile, str):
        p = PROFILES.get(name_or_profile.lower(), Profile(name="off"))
    else:
        p = name_or_profile
    _current_governor = Governor(p)
    return _current_governor


async def governed_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: bytes | None = None,
    session: Any = None,
) -> Any:
    """Make an HTTP request paced by the current governor.

    Uses httpx.AsyncClient if no session provided.
    Returns the httpx.Response.
    """
    import httpx

    gov = get_current()
    headers = headers or {}
    if gov.profile.user_agent and "user-agent" not in {k.lower() for k in headers}:
        headers = {**headers, "User-Agent": gov.profile.user_agent}

    async def _do() -> httpx.Response:
        if session is not None:
            return await session.request(method, url, headers=headers, content=body)
        async with httpx.AsyncClient(timeout=30) as c:
            return await c.request(method, url, headers=headers, content=body)

    if gov.off():
        return await _do()

    idempotent = method.upper() in ("GET", "HEAD", "OPTIONS") and not body

    # GET cache: check before acquiring the rate-limit slot
    cache_key = (method.upper(), url)
    if idempotent and gov.profile.cache_ttl > 0:
        async with gov._cache_lock:
            entry = gov._cache.get(cache_key)
            if entry is not None:
                cached_resp, expires = entry
                if time.monotonic() < expires:
                    return cached_resp
                del gov._cache[cache_key]

    async with gov.acquire(url):
        resp = await _do()

    # Store in cache on success
    if idempotent and gov.profile.cache_ttl > 0 and resp.status_code < 400:
        async with gov._cache_lock:
            gov._cache[cache_key] = (resp, time.monotonic() + gov.profile.cache_ttl)

    if resp.status_code not in (429, 503) or not idempotent:
        return resp

    for attempt in range(gov.profile.max_retries):
        delay, should_retry = gov.backoff(dict(resp.headers), attempt)
        if not should_retry:
            return resp
        gov.mark_backoff(url, delay)
        await asyncio.sleep(delay)
        async with gov.acquire(url):
            resp = await _do()
        if resp.status_code not in (429, 503):
            return resp

    return resp

# ARTEX-port: egress noise governor — token bucket + jitter + 429 backoff
