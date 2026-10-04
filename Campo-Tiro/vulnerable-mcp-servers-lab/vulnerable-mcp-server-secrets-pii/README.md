# Vulnerable MCP Server: Secrets + PII Exposure

This is an intentionally vulnerable MCP server that looks like a small “utilities” server (IP / weather / news), but also contains **embedded PII and sensitive information** in source code (lightly obfuscated).

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `get_current_ip`: Gets the server’s public IP address
- `get_temperature_of_city`: Gets the current temperature for a city
  - Expects: `{ "city": "<city name>" }`
- `get_top_news_articles_nytimes`: Gets top news articles from the New York Times RSS feed
  - Optional: `limit` (default 10, max 20)

## How it is vulnerable

This server demonstrates **secrets/PII exposure** patterns:

- Sensitive values (for example: contact email / internal strings / endpoints) are stored in source code and “obfuscated” (base64) rather than properly managed.
- On startup, the server prints an “admin contact” value to stderr.
- Even when values are obfuscated, anyone with access to the package source (npm tarball, repo checkout, local install) can recover them.

In real systems, this is how API keys, emails, internal URLs, tokens, and other sensitive values end up leaking through:

- source code
- package artifacts
- logs / stderr output

## Requirements

- Node.js (modern version)
- npm

Install dependencies in this folder:

```bash
npm install
```

## Run with Claude (using `claude_config.json`)

This folder includes `claude_config.json`, which is a ready-to-merge snippet for Claude's MCP server config.

1. Install dependencies:

```bash
npm install
```

2. Edit `claude_config.json` and replace the placeholder:

- `/full/path/to/vulnerable-mcp-server-secrets-pii/index.js`

Use an absolute path.

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config. If you already have `mcpServers`, add just the server entry:

```json
{
  "mcpServers": {
    "vulnerable-mcp-server-secrets-pii": {
      "command": "node",
      "args": [
        "/absolute/path/to/vulnerable-mcp-server-secrets-pii/index.js"
      ]
    }
  }
}
```

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-secrets-pii`

## Run manually (for debugging)

This server speaks MCP over stdio (JSON-RPC over stdin/stdout). Most users should run it via an MCP-capable client (like Claude) rather than manually.

If you just want to confirm it starts:

```bash
npm install
node index.js
```

## Example usage

From your MCP client:

- Get the server’s public IP:
  - Call `get_current_ip`
- Get temperature for a city:
  - Call `get_temperature_of_city` with `city: "Paris"`
- Get top NYT articles:
  - Call `get_top_news_articles_nytimes` (optionally with `limit: 5`)

## Notes

- This server makes outbound network calls (IP lookup, weather API, NYT RSS).
- The “obfuscation” used in source code is intentionally weak and is meant to illustrate why base64/encoding is not secrets management.

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
