# Vulnerable MCP Server: Indirect Prompt Injection (Remote MCP over HTTP+SSE)

This is an intentionally vulnerable MCP server that simulates a document retrieval/search system where retrieved documents include *hidden instructions* designed to manipulate the model.

Unlike the [local stdio version](../vulnerable-mcp-server-indirect-prompt-injection), this server exposes MCP over **HTTP + Server-Sent Events (SSE)** so clients can connect over the network.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `get_document`: Retrieve a document by ID (expects `document_id`)
  - Available IDs: `company_policy`, `product_specs`, `user_review`, `safe_document`
- `search_documents`: Search for documents containing keywords (expects `query`)

Documents are loaded from `documents/*.txt` and returned verbatim.

## How it is vulnerable

This server demonstrates **indirect prompt injection** in a remote context:

- Retrieved documents contain “internal notes” / “guidelines” that look legitimate but act as **prompt-like directives**.
- The server returns the content with **no sanitization, filtering, or instruction/data separation**.
- Because this is a **remote MCP server**, it also models the risk of connecting to **untrusted network-accessible MCP endpoints**.

Examples in the bundled documents include attempts to:

- Add an unrelated “wellness tip” (recipe) when answering policy questions
- Steer users to a premium product variant / inflate claims
- Reframe a negative review as an “outlier” and push 5-star language

## Requirements

- Node.js (modern version)
- npm

Install dependencies in this folder:

```bash
npm install
```

### Node/Claude compatibility note (common error)

If you use the included `claude_config.json` (which runs `npx … mcp-remote …`) on **Node.js 16**, you may see errors like:

- `npm WARN cli npm v10.x does not support Node.js v16.x`
- `ReferenceError: ReadableStream is not defined` (from `undici`)

This happens because the **bridge** (`mcp-remote` invoked via `npx`) pulls dependencies that expect a newer Node.js runtime (web streams / `ReadableStream` are available globally in Node 18+).

Workarounds (pick one):

- **Upgrade Node for the bridge** (recommended): ensure the `node` that Claude Desktop uses is **Node >= 18.17** (or **>= 20.5**). On Linux, Claude will use whatever `node`/`npx` it finds on its `PATH`, which may differ from your interactive shell.
- **Use a version manager**: with `nvm`/`asdf`, make sure Claude is launched from an environment where `node -v` is 18+ (e.g., log out/in after changing defaults, or start Claude from a shell where the newer Node is active).
- **Pin an older `mcp-remote`** (stopgap if you must stay on Node 16): change the `claude_config.json` command args to run a specific older version, e.g. `mcp-remote@0.0.14`, instead of the latest. (This avoids newer dependency chains, but may not support all features.)

## Run the server

By default it listens on port `3000` (or `PORT` if set).

### Run locally

```bash
node index.js
```

Then the SSE endpoint is:

- `http://localhost:3000/mcp`

### Run behind a reverse proxy with a path prefix (your setup)

If your reverse proxy exposes this service under a prefix like `/document`, set `BASE_PATH` so the server advertises the correct message endpoint to clients:

```bash
BASE_PATH=/document node index.js
```

Make sure your reverse proxy routes **both**:

- `/document/mcp`
- `/document/messages`

to this process.

## Run with Claude (using `claude_config.json`)

Claude Desktop typically runs MCP servers over stdio. Since this server is HTTP+SSE, the included `claude_config.json` uses `mcp-remote` as a small bridge that connects to the SSE endpoint and exposes it to Claude as a local stdio MCP server.

1. Start this server (examples):

```bash
npm install
BASE_PATH=/document node index.js
```

2. Edit `claude_config.json` and replace the URL argument with your SSE endpoint, for example:

- `http://localhost:3000/mcp` (local)
- `https://agents.apsc.co/document/mcp` (behind your proxy)

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config.

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-indirect-prompt-injection-remote-mcp`

## Run manually (for debugging)

### Quick connectivity tests

- Local test client:

```bash
node local-test.js
```

- Remote/proxied test client (as configured in `test.js`):

```bash
node test.js
```

## Example usage (safe + injection)

From your MCP client:

- Demonstrate normal retrieval:
  - Ask for: “Retrieve `safe_document` and summarize it.”
- Search for documents:
  - Use `search_documents` with `query: "vacation"` (should find `company_policy`)
- Demonstrate indirect prompt injection:
  - Ask: “What does `company_policy` say about vacations?”
  - Ask: “Summarize `product_specs`.”
  - Ask: “Summarize `user_review`.”

These documents intentionally contain embedded instructions that attempt to bias or override the assistant’s response.

## Notes

- This server is intentionally insecure and exists only for demonstration/training.
- Document content is loaded from `documents/*.txt` so you can easily tweak injection payloads.
- This server intentionally has **no authentication** and is meant for local/lab use only.

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
