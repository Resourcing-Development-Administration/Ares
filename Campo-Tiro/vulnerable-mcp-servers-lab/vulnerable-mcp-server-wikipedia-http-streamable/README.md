# Vulnerable MCP Server: Wikipedia (Streamable HTTP)

This is an intentionally vulnerable MCP server that provides Wikipedia search and retrieval tools over **Streamable HTTP**.

Because it fetches and returns content from an untrusted public source (Wikipedia) without any sanitization or instruction/data separation, it can be used to demonstrate **indirect prompt injection** and related risks when connecting to remote MCP servers.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `search_wikipedia`: Search Wikipedia for matching articles
  - Inputs: `query` (string), `limit` (number, default 5)
- `get_wikipedia_summary`: Get the summary/intro for an article
  - Inputs: `title` (string)
- `get_wikipedia_content`: Get the plaintext content for an article (optionally a section)
  - Inputs: `title` (string), `section` (string, optional)

## How it is vulnerable

This server demonstrates **untrusted content + remote transport** risk:

- Wikipedia pages can contain attacker-controlled text (including prompt-injection style content).
- The server returns that content directly to the client with no filtering or safety controls.
- The server is exposed over HTTP (intended to be reachable over a network), which mirrors real-world “remote MCP” deployments.

Additionally, the server sets `MCP_ALLOWED_HOSTS="*"`, disabling host allowlisting in the Python MCP SDK. While this server’s tools currently only call Wikipedia endpoints, this setting is unsafe in general and is included as part of the lab scenario.

## Requirements

- Python 3
- Python packages: `mcp` (Python SDK), `httpx`, `uvicorn`

Example install (adjust for your environment):

```bash
python3 -m pip install mcp httpx uvicorn
```

### Node/Claude compatibility note (common error)

Claude Desktop typically runs MCP servers over stdio. The included `claude_config.json` uses `mcp-remote` (invoked via `npx`) as a bridge to connect Claude to this remote HTTP server.

If Claude is using **Node.js 16**, you may see errors like:

- `npm WARN cli npm v10.x does not support Node.js v16.x`
- `ReferenceError: ReadableStream is not defined`

Workarounds (pick one):

- Ensure the `node` that Claude Desktop uses is **Node >= 18.17** (or **>= 20.5**).
- Launch Claude from an environment where a newer Node is on `PATH` (common when using `nvm`/`asdf`).
- Pin an older `mcp-remote` version if needed (as a stopgap).

## Run the server

This server starts an HTTP listener on port `8000`.

### Run locally

```bash
python3 wikipedia-mcp.py
```

The MCP endpoint is typically:

- `http://localhost:8000/mcp`

## Run with Claude (using `claude_config.json`)

1. Start the server:

```bash
python3 wikipedia-mcp.py
```

2. Edit `claude_config.json` and replace the URL argument if needed (for example, if running on a different host/port):

- `http://localhost:8000/mcp`

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config.

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-wikipedia-http-streamable`

## Run manually (for debugging)

If you want to validate the server is reachable before wiring it into Claude, confirm port 8000 is listening and that your environment can reach:

- `http://localhost:8000/mcp`

(Exact probing commands depend on your MCP client/tooling; most users will test via an MCP-capable client.)

## Example usage (benign + injection)

From your MCP client:

- Search Wikipedia:
  - “Search Wikipedia for `prompt injection` and show the top 5 results.”
- Fetch a summary:
  - “Get the Wikipedia summary for `Prompt injection`.”
- Fetch full content:
  - “Get the Wikipedia content for `Prompt injection`.”

If you treat retrieved content as instructions rather than untrusted data, a malicious page can try to influence tool use or responses.

## Notes

- This server makes outbound requests to Wikipedia and may be rate-limited/blocked depending on your environment.
- This is intentionally insecure and exists only for demonstration/training.

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
