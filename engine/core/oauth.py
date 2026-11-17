"""
Flujo OAuth2 client-credentials: obtiene un access_token real contra el token endpoint del
proveedor, para usarlo como Bearer contra el target (MCP http/sse o API). Es el único grant que
tiene sentido para un scanner no interactivo: no hay humano en el loop para el consentimiento de
authorization_code, y el token se resuelve una sola vez al arrancar el scan (sin refresh
automático -- un scan es corto y no vive lo suficiente para necesitarlo).
"""
from __future__ import annotations
from typing import Optional, Union

import httpx


def fetch_client_credentials_token(token_url: str, client_id: str, client_secret: str,
                                    scope: Optional[str] = None, verify: Union[str, bool] = True,
                                    timeout: float = 15.0) -> str:
    """POST grant_type=client_credentials al token endpoint. Devuelve el access_token.

    Lanza RuntimeError con el detalle real (status + body) si el provider rechaza las
    credenciales o la respuesta no trae access_token -- fallar ruidoso acá es mejor que
    arrancar un scan sin credenciales válidas y que cada test reporte 401 como si fuera un
    hallazgo del target, en vez de un problema de config del operador.
    """
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    if scope:
        data["scope"] = scope
    try:
        r = httpx.post(token_url, data=data, timeout=timeout, verify=verify)
    except Exception as e:
        raise RuntimeError(f"no se pudo contactar el token endpoint OAuth2 ({token_url}): {e}") from e
    try:
        body = r.json()
    except Exception:
        body = {}
    token = body.get("access_token")
    if not token:
        raise RuntimeError(
            f"el token endpoint OAuth2 ({token_url}) no devolvió access_token "
            f"(status {r.status_code}): {str(body)[:300]}"
        )
    return token
