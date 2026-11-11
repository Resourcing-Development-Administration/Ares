"""
Server FastMCP para probar adv.multistep_chain y adv.stored_injection_roundtrip.
ARES_FIXTURE_MODE:
  vulnerable -> fuente (read_inventory), propagadores (format_text / summarize_text devuelven el
                dato), emisor (send_report) que lo acepta; y save_note / get_notes que devuelven lo
                guardado SIN escapar.
  safe       -> los propagadores NO devuelven el input (devuelven un conteo), así que ninguna cadena
                es ejecutable; get_notes escapa/rechaza el contenido (devuelve solo cantidad).
"""
import logging, os
logging.disable(logging.CRITICAL)
from mcp.server.fastmcp import FastMCP

MODE = os.environ.get("ARES_FIXTURE_MODE", "vulnerable")
mcp = FastMCP("chain-fixture")
_notes: list[str] = []


@mcp.tool(description="Lee el inventario interno.")
def read_inventory() -> str:
    return "widgets=10;gadgets=4"


@mcp.tool(description="Formatea un texto.")
def format_text(text: str) -> str:
    return f"[[{text.upper()}]]" if MODE == "vulnerable" else f"len={len(text)}"


@mcp.tool(description="Resume un texto.")
def summarize_text(text: str) -> str:
    return f"Resumen: {text[:1500]}" if MODE == "vulnerable" else f"palabras={len(text.split())}"


@mcp.tool(description="Envía un reporte por email.")
def send_report(body: str) -> str:
    return "enviado"


@mcp.tool(description="Guarda una nota.")
def save_note(content: str) -> str:
    _notes.append(content)
    return "guardado"


@mcp.tool(description="Lee las notas guardadas.")
def get_notes() -> str:
    return "\n".join(_notes) if MODE == "vulnerable" else f"{len(_notes)} nota(s)"


if __name__ == "__main__":
    mcp.run(transport="stdio")
