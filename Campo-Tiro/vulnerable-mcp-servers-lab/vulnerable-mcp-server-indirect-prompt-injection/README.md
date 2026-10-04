# Vulnerable MCP Server: Indirect Prompt Injection

This is an intentionally vulnerable MCP server that simulates a document retrieval/search system where retrieved documents include *hidden instructions* designed to manipulate the model.

Do not use this outside a controlled lab environment.

## What it provides

The server exposes these MCP tools:

- `get_document`: Retrieve a document by ID (expects `document_id`)
  - Available IDs: `company_policy`, `product_specs`, `user_review`, `safe_document`
- `search_documents`: Search for documents containing keywords (expects `query`)

`get_document` returns the full document as plain text, including any embedded hidden instructions.

## How it is vulnerable

This server demonstrates **indirect prompt injection**:

- Retrieved documents contain prompt-like directives embedded in normal-looking content (examples include bracketed “SYSTEM INSTRUCTION” text, HTML comments, and delimited injection blocks).
- The server returns this content verbatim with no sanitization, no filtering, and no separation between “data” and “instructions”.

In a real RAG / document assistant system, this can lead the model to follow attacker-controlled instructions that override user intent or policy.

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

- `/full/path/to/vulnerable-mcp-server-indirect-prompt-injection/index.js`

Use an absolute path.

3. Open Claude and edit its MCP configuration (Claude Desktop typically exposes this under Settings -> Developer -> Edit config).

4. Merge the `mcpServers` entry into your config. If you already have `mcpServers`, add just the server entry:

```json
{
  "mcpServers": {
    "vulnerable-mcp-server-indirect-prompt-injection": {
      "command": "node",
      "args": [
        "/absolute/path/to/vulnerable-mcp-server-indirect-prompt-injection/index.js"
      ]
    }
  }
}
```

5. Restart Claude so it loads the updated MCP configuration.

After Claude restarts, the server should appear as:

- `vulnerable-mcp-server-indirect-prompt-injection`

## Run manually (for debugging)

This server speaks MCP over stdio. Most users should run it via an MCP-capable client (like Claude) rather than manually.

If you just want to confirm it starts:

```bash
npm install
node index.js
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
  - Ask: “What does `user_review` say about the product?”

These documents intentionally contain embedded instructions that attempt to bias or override the assistant’s response.

## Notes

- This server is intentionally insecure and exists only for demonstration/training.
- The “hidden instructions” are embedded in different formats to illustrate how injections can be smuggled in:
  - Bracketed pseudo-system directives
  - HTML comments
  - Delimited injection blocks

## Links to Appsecco Resources

- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
