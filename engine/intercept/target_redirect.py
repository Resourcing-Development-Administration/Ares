"""
Política de redirect HTTP con re-evaluación de scope en cada hop.
Puerto de ARTEX's intercept/target_redirect.go.
"""
from __future__ import annotations

import httpx

from engine.intercept.gate import InterceptGate


class RedirectDenied(Exception):
    pass


class TooManyRedirects(Exception):
    pass


class RedirectPolicy:
    """Policy para httpx que re-evalúa el scope en cada hop de redirect.

    Uso:
        client = httpx.AsyncClient(follow_redirects=False)
        policy = RedirectPolicy(gate)
        resp = await policy.get_with_redirect_check(client, url)
    """

    MAX_REDIRECTS = 10

    def __init__(self, gate: InterceptGate) -> None:
        self._gate = gate

    async def get_with_redirect_check(
        self,
        client: httpx.AsyncClient,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """GET con seguimiento manual de redirects, re-chequeando gate en cada hop.

        Lanza RedirectDenied si un hop sale del scope.
        Lanza TooManyRedirects si se superan MAX_REDIRECTS saltos.
        """
        for _ in range(self.MAX_REDIRECTS):
            resp = await client.get(url, follow_redirects=False, **kwargs)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp

            next_url = resp.headers.get("location", "")
            if not next_url:
                return resp

            # Re-check gate antes de seguir el hop
            decision = await self._gate.check_async(next_url, test_id="redirect", test_level=1)
            if decision.action == "deny":
                raise RedirectDenied(
                    f"Redirect a {next_url!r} denegado: {decision.reason}"
                )

            url = next_url

        raise TooManyRedirects(f"Más de {self.MAX_REDIRECTS} redirects")
