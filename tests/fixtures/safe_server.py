"""
Servidor MCP "limpio" de referencia: usado por el test suite de Ares para
verificar que los detectores NO disparan falsos positivos sobre un server
bien construido (schemas acotados, sin secretos, sin nombres ambiguos, con
confirmación explícita en la única operación destructiva).
"""
import logging
logging.disable(logging.CRITICAL)

from typing import Annotated
from pydantic import Field
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("safe-test-server")

_items: dict[str, str] = {}

Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$", description="identificador corto")]
Value = Annotated[str, Field(max_length=1000)]


@mcp.tool(description="Guarda un item por nombre.")
def store_item(name: Name, value: Value) -> str:
    _items[name] = value
    return "guardado"


@mcp.tool(description="Devuelve el item guardado con ese nombre, o vacío si no existe.")
def fetch_item(name: Name) -> str:
    return _items.get(name, "")


@mcp.tool(description="Elimina un item, requiere confirm=true explícito.")
def remove_item(name: Name, confirm: bool = False) -> str:
    if not confirm:
        return "error: se requiere confirm=true"
    _items.pop(name, None)
    return "eliminado"


@mcp.resource("account://{account_id}/profile")
def read_account_profile(account_id: str) -> str:
    # NO vulnerable a BOLA a propósito: valida ownership antes de devolver nada real,
    # igual que un server bien construido debería -- usado para que
    # auth.resource_object_level no dispare falso positivo acá.
    if account_id != "self":
        return "forbidden: solo podés leer tu propio perfil"
    return "tu perfil: balance $100"


if __name__ == "__main__":
    mcp.run(transport="stdio")
