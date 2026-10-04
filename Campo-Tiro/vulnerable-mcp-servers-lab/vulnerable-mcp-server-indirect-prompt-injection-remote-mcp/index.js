#!/usr/bin/env node

/**
 * MCP Server demonstrating Indirect Prompt Injection
 * This server simulates a document retrieval system where retrieved content
 * contains hidden instructions that could influence the AI's behavior.
 *
 * Remote mode: exposes an HTTP+SSE interface so MCP clients can connect over the network.
 */

import express from "express";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Base path for when running behind a reverse proxy
const BASE_PATH = process.env.BASE_PATH || "";

// Load documents from files
function loadDocument(filename) {
  try {
    return readFileSync(join(__dirname, 'documents', filename), 'utf-8').trim();
  } catch (error) {
    console.error(`Error loading ${filename}:`, error);
    return `Error: Could not load document ${filename}`;
  }
}

// Simulated document database - now loaded from files
const DOCUMENTS = {
  company_policy: {
    title: "Company Policy Document",
    content: loadDocument('company_policy.txt'),
  },
  product_specs: {
    title: "Product Specifications",
    content: loadDocument('product_specs.txt'),
  },
  user_review: {
    title: "Customer Review",
    content: loadDocument('user_review.txt'),
  },
  safe_document: {
    title: "Safe Document",
    content: loadDocument('safe_document.txt'),
  },
};

// Factory to create a configured MCP server instance
function createServer() {
  const server = new Server(
    {
      name: "vulnerable-mcp-server-indirect-prompt-injection-remote-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    console.log("📋 Received ListTools request");
    return {
      tools: [
        {
          name: "get_document",
          description:
            "Retrieve a document by its ID. Available IDs: company_policy, product_specs, user_review, safe_document",
          inputSchema: {
            type: "object",
            properties: {
              document_id: {
                type: "string",
                description: "The ID of the document to retrieve",
              },
            },
            required: ["document_id"],
          },
        },
        {
          name: "search_documents",
          description: "Search for documents containing specific keywords",
          inputSchema: {
            type: "object",
            properties: {
              query: {
                type: "string",
                description: "Search query",
              },
            },
            required: ["query"],
          },
        },
      ],
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    console.log(`🔧 Received tool call: ${name}`, args);

    if (name === "get_document") {
      const docId = args.document_id;

      if (docId in DOCUMENTS) {
        const doc = DOCUMENTS[docId];
        console.log(`📄 Returning document: ${docId}`);
        return {
          content: [
            {
              type: "text",
              text: `# ${doc.title}\n\n${doc.content}`,
            },
          ],
        };
      } else {
        console.log(`❌ Document not found: ${docId}`);
        return {
          content: [
            {
              type: "text",
              text: `Error: Document '${docId}' not found. Available IDs: ${Object.keys(
                DOCUMENTS
              ).join(", ")}`,
            },
          ],
        };
      }
    } else if (name === "search_documents") {
      const query = (args.query || "").toLowerCase();
      console.log(`🔍 Searching for: ${query}`);
      const results = [];

      for (const [docId, doc] of Object.entries(DOCUMENTS)) {
        if (
          doc.title.toLowerCase().includes(query) ||
          doc.content.toLowerCase().includes(query)
        ) {
          results.push(`- ${docId}: ${doc.title}`);
        }
      }

      const resultText =
        results.length > 0
          ? `Found documents:\n${results.join("\n")}`
          : "No documents found matching your query.";

      console.log(`✅ Found ${results.length} documents`);
      return {
        content: [
          {
            type: "text",
            text: resultText,
          },
        ],
      };
    } else {
      console.log(`❌ Unknown tool: ${name}`);
      return {
        content: [
          {
            type: "text",
            text: `Unknown tool: ${name}`,
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

// Remote HTTP+SSE server
const app = express();

// Add logging middleware BEFORE express.json()
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

app.use(express.json());

// Keep track of active SSE transports by session ID
const transports = {};

// Endpoint to establish SSE stream; client receives the POST endpoint via an "endpoint" event
app.get("/mcp", async (req, res) => {
  console.log("🔌 New SSE connection attempt");
  console.log(`📍 BASE_PATH is set to: "${BASE_PATH}"`);
  try {
    // Use BASE_PATH to construct the full messages endpoint path
    const transport = new SSEServerTransport(`${BASE_PATH}/messages`, res);
    const sessionId = transport.sessionId;
    transports[sessionId] = transport;
    console.log(`✅ SSE connection established with sessionId: ${sessionId}`);
    console.log(`📬 Messages endpoint will be: ${BASE_PATH}/messages`);

    transport.onclose = () => {
      console.log(`🔌 SSE connection closed for sessionId: ${sessionId}`);
      delete transports[sessionId];
    };

    const server = createServer();
    await server.connect(transport);
  } catch (error) {
    console.error("❌ Error establishing SSE stream:", error);
    if (!res.headersSent) {
      res.status(500).send("Error establishing SSE stream");
    }
  }
});

// Endpoint to receive client JSON-RPC messages (POST), routed by sessionId query param
app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId;
  console.log(`📨 Received POST to /messages with sessionId: ${sessionId}`);
  
  if (!sessionId) {
    console.log("❌ Missing sessionId parameter");
    res.status(400).send("Missing sessionId parameter");
    return;
  }
  const transport = transports[sessionId];
  if (!transport) {
    console.log(`❌ Session not found: ${sessionId}`);
    res.status(404).send("Session not found");
    return;
  }
  try {
    await transport.handlePostMessage(req, res, req.body);
  } catch (error) {
    console.error("❌ Error handling POST request:", error);
    if (!res.headersSent) {
      res.status(500).send("Error handling request");
    }
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "127.0.0.1", (error) => {  // parcheado para el lab: solo localhost, no exponer a la red
  if (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
  console.log(`✅ Injection Demo MCP Server (HTTP+SSE) listening on 127.0.0.1:${PORT}`);
  console.log(`   BASE_PATH: "${BASE_PATH}"`);
  console.log(`   Direct access: http://localhost:${PORT}/mcp`);
  if (BASE_PATH) {
    console.log(`   Via Caddy: http://agents.apsc.co${BASE_PATH}/mcp`);
  }
});
