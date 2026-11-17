"""
Modelo de target para reconocimiento de red.
Separa la validación de scope del núcleo del scanner MCP,
porque un target de red es un dominio/IP/URL, no un MCPTarget.
"""
from __future__ import annotations
import re
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class NetworkTarget:
    """Describe un target de red para los tests del módulo netrecon."""

    # URL o dominio base del target (ej: "https://example.com" o "example.com")
    url: str

    # Dominios/CIDRs/IPs en scope; si está vacía no se verifica scope (modo libre)
    scope: list[str] = field(default_factory=list)

    # Hosts/IPs descubiertos durante el scan (poblado en tiempo de ejecución)
    discovered_hosts: list[str] = field(default_factory=list)
    discovered_subdomains: list[str] = field(default_factory=list)
    crawled_urls: list[str] = field(default_factory=list)

    @property
    def base_domain(self) -> str:
        """Extrae el hostname del campo url (sin esquema, sin path)."""
        parsed = urllib.parse.urlparse(self.url if "://" in self.url else f"https://{self.url}")
        return parsed.hostname or self.url

    @property
    def normalized_url(self) -> str:
        """URL con esquema HTTPS garantizado."""
        if "://" not in self.url:
            return f"https://{self.url}"
        return self.url

    def in_scope(self, host: str) -> bool:
        """Devuelve True si 'host' está dentro del scope declarado.
        Con scope vacío siempre devuelve True (sin restricciones)."""
        if not self.scope:
            return True
        host = host.lower().strip()
        for entry in self.scope:
            entry = entry.lower().strip()
            # coincidencia exacta o subdominio
            if host == entry or host.endswith(f".{entry}"):
                return True
            # comodín de tipo "*.example.com"
            if entry.startswith("*.") and host.endswith(entry[1:]):
                return True
        return False

    def __str__(self) -> str:
        return self.normalized_url
