"""
Server FastMCP minimo con un `read_file(path)` REALISTA (expande `~` como haria un target real
que recibe paths de un usuario, a diferencia del fixture principal `target_server.py` que usa
open() crudo) -- para probar dynamic.credential_harvest_paths / el enmascarado de credenciales
contra los payloads con `~` literal de payloads.canary.CREDENTIAL_HARVEST_PATHS.
"""
import logging, os
logging.disable(logging.CRITICAL)
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("credential-leak-fixture")


@mcp.tool(description="Lee un archivo de disco (vulnerable a path traversal a proposito).")
def read_file(path: str) -> str:
    with open(os.path.expanduser(path), "r") as f:
        return f.read()


if __name__ == "__main__":
    mcp.run(transport="stdio")
