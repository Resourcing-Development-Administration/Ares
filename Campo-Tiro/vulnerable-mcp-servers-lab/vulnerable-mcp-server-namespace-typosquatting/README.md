# Vulnerable MCP Server: Namespace Typosquatting (`twittter-mcp`)

This is an intentionally malicious/vulnerable MCP server designed to demonstrate **namespace/package typosquatting** attacks.

It is deliberately named **`twittter-mcp`** (note the extra “t”) to resemble a hypothetical legitimate `twitter-mcp` server.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `get_account`: Accepts a `username` and returns a demo response
- `get_tweets`: Accepts a `username` and optional `limit` and returns a demo response

In this lab version, both tools return the same message:

- `This is not the real Twitter MCP server.`

## How it is vulnerable

This demo focuses on the **supply chain / trust** problem:

- A user intends to install/use a legitimate server (e.g. `twitter-mcp`), but mistakenly installs a lookalike name (`twittter-mcp`).
- Once installed/configured, the malicious server can expose tools that appear legitimate and can return misleading content or perform harmful actions.

In real-world attacks, the payload would not be a harmless message — it could exfiltrate data, alter tool results, or execute actions on the user’s machine.

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

- `/full/path/to/vulnerable-mcp-server-namespace-typosquatting/index.js`

Use an absolute path.

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config. If you already have `mcpServers`, add just the server entry:

```json
{
  "mcpServers": {
    "twittter-mcp": {
      "command": "node",
      "args": [
        "/absolute/path/to/vulnerable-mcp-server-namespace-typosquatting/index.js"
      ]
    }
  }
}
```

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `twittter-mcp`

## Run manually (for debugging)

This server speaks MCP over stdio (JSON-RPC over stdin/stdout). Most users should run it via an MCP-capable client (like Claude) rather than manually.

If you just want to confirm it starts:

```bash
npm install
node index.js
```

## Example usage (demo)

From your MCP client:

- Ask for a profile:
  - “Get the account for username `jack`”
- Ask for tweets:
  - “Get recent tweets for `jack`”

Both calls will return the demo message indicating this is not a real Twitter MCP server.

## Notes

- The point of this server is the **name collision / lookalike** risk, not the tool logic.
- Always verify package names, publisher/source, signatures, and repository URLs before installing MCP servers.

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
