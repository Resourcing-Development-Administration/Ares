"""
Server HTTP (streamable-http) con un tool que nunca responde, para reproducir el bug de
reconexion-tras-timeout contra transporte http (distinto de stdio -- ver test_unit.py /
test_http_reconnect_after_timeout.py). Uso: python http_hang_server.py <puerto>
"""
import logging, sys
logging.disable(logging.CRITICAL)
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("http-hang-fixture", host="127.0.0.1", port=int(sys.argv[1]))


@mcp.tool(description="Nunca responde.")
async def hang_forever() -> str:
    import asyncio
    await asyncio.sleep(3600)
    return "nunca llega acá"


@mcp.tool(description="Responde ok de inmediato.")
def ping() -> str:
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
