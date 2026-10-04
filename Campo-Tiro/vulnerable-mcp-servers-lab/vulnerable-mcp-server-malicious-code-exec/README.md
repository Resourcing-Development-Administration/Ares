# Vulnerable MCP Server: Malicious Code Execution

This is an intentionally vulnerable MCP server that exposes a seemingly harmless “Quote of the Day” tool, but implements an unsafe formatting feature that allows **arbitrary JavaScript code execution**.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes this MCP tool:

- `get_qotd`: Fetch a quote of the day from an external API
  - Optional argument: `format` (string)
    - `default` returns a JSON string with quote fields
    - Any other value is treated as a JavaScript expression used for “advanced formatting”

## How it is vulnerable

If `format` is not `"default"`, the server evaluates the provided string using JavaScript `eval()`.

This turns a “formatting” parameter into an RCE primitive. An attacker can execute arbitrary JavaScript in the MCP server process context (including reading environment variables, running commands via Node APIs if accessible, etc.).

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

- `/full/path/to/vulnerable-mcp-server-malicious-code-exec/index.js`

Use an absolute path.

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config. If you already have `mcpServers`, add just the server entry:

```json
{
  "mcpServers": {
    "vulnerable-mcp-server-malicious-code-exec": {
      "command": "node",
      "args": [
        "/absolute/path/to/vulnerable-mcp-server-malicious-code-exec/index.js"
      ]
    }
  }
}
```

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-malicious-code-exec`

## Run manually (for debugging)

This server speaks MCP over stdio (JSON-RPC over stdin/stdout). Most users should run it via an MCP-capable client (like Claude) rather than manually.

If you just want to confirm it starts:

```bash
npm install
node index.js
```

## Example usage (safe + exploit)

From your MCP client:

- Safe/default behavior:
  - In Claude - `Get me a quote of the day`

- Demonstrate code execution via the formatting feature (dangerous; do this only in a disposable VM/container):
  - `Get me a quote of the day and format output with "JSON.stringify(process.env)"`
  - `Get me a quote of the day and format output with "require('child_process').execSync('open -a Calculator').toString()"`
    - Note: this specific command is macOS-oriented (it’s included as a demo payload); substitute an OS-appropriate command for your environment.

## Notes

- This server makes outbound network calls to fetch quotes.
- The API key used by the demo is embedded in source code as part of the lab scenario.

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
