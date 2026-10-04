# Vulnerable MCP Server: Filesystem Workspace Actions

This is an intentionally vulnerable MCP server that exposes file and code execution actions scoped to a "workspace" directory, but fails to properly prevent path traversal.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `read_file`: Read a file (expects a relative `path`)
- `write_file`: Write a file (expects a relative `path` and `content`)
- `list_directory`: List a directory (optional relative `path`, default `"."`)
- `execute_code`: Execute arbitrary Python code (requires `code`, optional `working_dir`, default `"."`)

## How it is vulnerable

All filesystem paths are joined naïvely with `os.path.join(workspace_dir, user_input)` and are not validated to stay inside the workspace directory. This allows inputs like `../../..` to escape the workspace.

`execute_code` also executes arbitrary Python with no sandboxing.

## Requirements

- Python 3
- An existing directory to act as the "workspace" (the server will refuse to start if it does not exist)

## Run with Claude (using `claude_config.json`)

This folder includes `claude_config.json`, which is a ready-to-merge snippet for Claude's MCP server config.

1. Pick/create a workspace directory (sandbox), for example:

   - `/tmp/mcp-sandbox`

2. Edit `claude_config.json` and replace both placeholders:

   - `/full/path/to/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py`
   - `/full/path/to/your-sandbox-workspace`

   Use absolute paths.

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config. If you already have `mcpServers`, add just the server entry:

```json
{
  "mcpServers": {
    "vulnerable-mcp-server-filesystem-workspace-actions": {
      "command": "python3",
      "args": [
        "/absolute/path/to/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py",
        "/absolute/path/to/your-sandbox-workspace"
      ]
    }
  }
}
```

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-filesystem-workspace-actions`

## Run manually (for debugging)

This server speaks MCP over stdio (JSON-RPC over stdin/stdout). Most users should run it via an MCP-capable client (like Claude) rather than manually.

If you just want to confirm it starts:

```bash
python3 vulnerable-mcp-server-filesystem-workspace-actions-mcp.py /absolute/path/to/sandbox
```

## Example usage (safe + traversal)

From your MCP client, call tools like these:

- List the workspace root:
  - `list_directory` with `path: "."`
- Read a file inside the workspace:
  - `read_file` with `path: "notes.txt"`
- Demonstrate traversal by listing a parent directory outside the workspace:
  - `list_directory` with `path: "../../"`
- Demonstrate traversal by reading a system file:
  - `read_file` with `path: "../../../../etc/passwd"`
- Demonstrate write traversal (dangerous; do this only in a disposable VM/container):
  - `write_file` with `path: "../../outside.txt"`
- Demonstrate arbitrary code execution:
  - `execute_code` with `code: "import os; print(os.getcwd())"`

## Notes

- `write_file` will create parent directories automatically.
- `read_file` opens files as text; reading binary files may error.

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
