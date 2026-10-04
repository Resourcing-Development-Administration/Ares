// test.js
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const transport = new SSEClientTransport(
  new URL("http://localhost:3000/mcp")  // Test locally first
);

const client = new Client({
  name: "test-client",
  version: "1.0.0",
}, {
  capabilities: {}
});

await client.connect(transport);
console.log("✅ Connected!");

const tools = await client.listTools();
console.log("📋 Available tools:", tools);

await client.close();
