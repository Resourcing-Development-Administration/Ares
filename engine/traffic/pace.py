"""
Traffic request pacing — integrates with the egress governor noise profile.
Equivalent to ARTEX traffic/pace.go.
"""
from __future__ import annotations

import asyncio
from typing import Any

PACE_WAIT_MAX = 30.0  # seconds — never block a request indefinitely


async def pace_request(url: str, governor: Any = None) -> None:
    """
    Wait for the given URL under the current noise profile.
    governor is an optional egress.Governor instance; if None, pacing is a no-op.
    """
    if governor is None:
        return
    try:
        async with asyncio.timeout(PACE_WAIT_MAX):
            async with governor.acquire(url):
                pass
    except (asyncio.TimeoutError, AttributeError, Exception):
        return  # pacing must never block indefinitely


def is_pace_marker(proxy_auth: str) -> bool:
    """Check if a proxy auth header carries the pace marker."""
    return proxy_auth.startswith("Basic cGFjZTo=") or proxy_auth == "pace"
