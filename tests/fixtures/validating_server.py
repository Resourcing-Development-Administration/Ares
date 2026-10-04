"""
Servidor MCP que VALIDA su input y rechaza payloads con un mensaje de error
que cita el valor recibido (patrón real y común: "Invalid repoName: '<input>'").
Existe para probar que Ares no confunde "el server rechazó esto correctamente
y lo citó en el error" con "leak de información interna" o "prompt injection
passthrough real" -- encontrado corriendo Ares contra un MCP público real
(mcp.deepwiki.com) que hace exactamente esto.
"""
import logging
import re
logging.disable(logging.CRITICAL)

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("validating-test-server")

_VALID_REPO = re.compile(r"^[\w.-]+/[\w.-]+$")


@mcp.tool(description="Busca una pregunta sobre un repo. repoName debe tener formato owner/repo.")
def ask_about_repo(repo_name: str, question: str) -> str:
    # levanta excepción (no un simple return) -- así FastMCP marca is_error=True,
    # igual que el comportamiento real observado en mcp.deepwiki.com.
    if not _VALID_REPO.match(repo_name) or len(repo_name) > 200:
        raise ValueError(f'Invalid repoName format: "{repo_name}". Expected format is "owner/repo".')
    return f"No info available for {repo_name}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
