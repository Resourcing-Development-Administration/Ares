"""
Server MCP ACTIVAMENTE HOSTIL contra el propio Ares -- no contra un agente
que lo use, contra el escáner que lo audita. Es el fixture de regresión
formal de la ronda de hardening que confirmó (y corrigió) dos problemas
reales del motor:

  1. Una descripción de tool de ~10MB hacía que supplychain.secret_exposure
     (~200 regex) tardara ~57s contra ~0.2s de baseline -- fix:
     engine/core/limits.py (cap_text), aplicado en engine/core/client.py y
     en los blob-builders de recon/supplychain.
  2. Un tool que nunca responde (hang_forever) SÍ se cortaba por timeout
     (correcto, ya existía), pero el scan terminaba 100/A/ALLOW -- idéntico
     a un server limpio -- porque el timeout solo quedaba en report.errors
     (texto libre, invisible para score/policy). Fix: engine/orchestrator.py
     ahora emite un Finding real (orchestrator.test_unresponsive).

Correr esto contra Ares después de cualquier cambio al motor es la forma
más rápida de notar una regresión de resiliencia.
"""
import asyncio
import logging
logging.disable(logging.CRITICAL)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hostile-to-ares")

_FILLER = (
    "lorem ipsum sk- gh_ xox AKIA ghp_ api_key= password: token: secret: "
    "BEGIN RSA kind: secret data: " * 50
)
BIG_DESCRIPTION = _FILLER * 2000  # ~10MB -- sin el cap, esto solo rompía secret_exposure


@mcp.tool(description=BIG_DESCRIPTION)
def big_description_tool(x: str = "") -> str:
    return "ok"


@mcp.tool(description="Devuelve una respuesta de cientos de MB en un solo content block.")
def huge_response(size_mb: int = 300) -> str:
    return "A" * (size_mb * 1024 * 1024)


@mcp.tool(description="Nunca responde -- cuelga la llamada indefinidamente.")
async def hang_forever() -> str:
    await asyncio.sleep(999999)
    return "nunca llega acá"


if __name__ == "__main__":
    mcp.run(transport="stdio")
