# Vulnerable MCP Server: Outdated Packages (Supply Chain)

This is an intentionally vulnerable MCP server that provides basic, *read-only* filesystem/system inspection tools.

The primary purpose of this lab is to demonstrate **supply chain risk from outdated, deprecated, and vulnerable dependency versions**.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `get_folder_size`: Calculate the total size of a folder (bytes + MB)
  - Expects: `{ "path": "<absolute-folder-path>" }`
- `list_directory`: List files/directories in a path
  - Expects: `{ "path": "<absolute-directory-path>" }`
- `get_system_info`: Return OS/CPU/memory/hostname/home/tmp details
  - No arguments
- `check_path_exists`: Check whether a path exists
  - Expects: `{ "path": "<absolute-path>" }`
- `get_file_stats`: Return file/directory stats (size/timestamps/permissions)
  - Expects: `{ "path": "<absolute-path>" }`

## How it is vulnerable

This package intentionally pins **older, deprecated, and/or vulnerable dependency versions** in `package.json` so that:

- `npm audit` produces findings
- dependency scanners can demonstrate detection/reporting
- you can discuss how “works fine” != “safe to run”

Examples of intentionally-problematic dependencies include:

- `request` (deprecated/unmaintained)
- `lodash` pinned to an older version
- other old ecosystem packages that frequently appear in audits

This is a **supply chain** demonstration: in real systems, known-vulnerable packages can be exploited directly, or used as stepping stones (prototype pollution, SSRF, ReDoS, etc.), depending on where/how they are used.

## Requirements

- Node.js (the package declares `>=14`, but using a modern Node LTS is recommended)
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

- `/full/path/to/vulnerable-mcp-server-outdated-pacakges/index.js`

Use an absolute path.

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config. If you already have `mcpServers`, add just the server entry:

```json
{
  "mcpServers": {
    "vulnerable-mcp-server-outdated-pacakges": {
      "command": "node",
      "args": [
        "/absolute/path/to/vulnerable-mcp-server-outdated-pacakges/index.js"
      ]
    }
  }
}
```

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-outdated-pacakges`

## Run manually (for debugging)

This server speaks MCP over stdio (JSON-RPC over stdin/stdout). Most users should run it via an MCP-capable client (like Claude) rather than manually.

If you just want to confirm it starts:

```bash
npm install
node index.js
```

## Example usage (tools)

From your MCP client, call tools like these:

- Get OS/system info:
  - `get_system_info`
- List a directory:
  - `list_directory` with `path: "/tmp"`
- Check if a path exists:
  - `check_path_exists` with `path: "/etc/passwd"`
- Get file stats:
  - `get_file_stats` with `path: "/etc/hosts"`
- Calculate a folder size:
  - `get_folder_size` with `path: "/var/log"`

## Notes

- To surface the intentionally vulnerable dependency set:

```bash
npm audit
```

- You can also inspect the dependency tree:

```bash
npm ls
```

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
