#!/usr/bin/env node

// Test if we're being run directly
console.error("Starting Filesystem MCP Server...");

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { promises as fs } from "fs";
import path from "path";
import os from "os";

class FileSystemMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: "vulnerable-mcp-server-outdated-pacakges",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    this.server.onerror = (error) => console.error("[MCP Error]", error);
    process.on("SIGINT", async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "get_folder_size",
          description: "Calculate the total size of a folder and its contents in bytes",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "Absolute path to the folder",
              },
            },
            required: ["path"],
          },
        },
        {
          name: "list_directory",
          description: "List all files and directories in a given path",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "Absolute path to the directory",
              },
            },
            required: ["path"],
          },
        },
        {
          name: "get_system_info",
          description: "Get system information including OS, CPU, and memory details",
          inputSchema: {
            type: "object",
            properties: {},
          },
        },
        {
          name: "check_path_exists",
          description: "Check if a file or directory exists at the given path",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "Absolute path to check",
              },
            },
            required: ["path"],
          },
        },
        {
          name: "get_file_stats",
          description: "Get detailed statistics about a file or directory",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "Absolute path to the file or directory",
              },
            },
            required: ["path"],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      switch (request.params.name) {
        case "get_folder_size":
          return await this.getFolderSize(request.params.arguments);
        case "list_directory":
          return await this.listDirectory(request.params.arguments);
        case "get_system_info":
          return await this.getSystemInfo();
        case "check_path_exists":
          return await this.checkPathExists(request.params.arguments);
        case "get_file_stats":
          return await this.getFileStats(request.params.arguments);
        default:
          throw new Error(`Unknown tool: ${request.params.name}`);
      }
    });
  }

  async getFolderSize(args) {
    try {
      const folderPath = args.path;
      let totalSize = 0;

      async function calculateSize(currentPath) {
        const stats = await fs.stat(currentPath);
        
        if (stats.isFile()) {
          totalSize += stats.size;
        } else if (stats.isDirectory()) {
          const items = await fs.readdir(currentPath);
          for (const item of items) {
            await calculateSize(path.join(currentPath, item));
          }
        }
      }

      await calculateSize(folderPath);

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              path: folderPath,
              totalSize: totalSize,
              sizeInMB: (totalSize / (1024 * 1024)).toFixed(2),
            }, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  }

  async listDirectory(args) {
    try {
      const dirPath = args.path;
      const items = await fs.readdir(dirPath, { withFileTypes: true });

      const itemList = items.map(item => ({
        name: item.name,
        type: item.isDirectory() ? "directory" : "file",
        path: path.join(dirPath, item.name),
      }));

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ directory: dirPath, items: itemList }, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  }

  async getSystemInfo() {
    try {
      const info = {
        platform: os.platform(),
        architecture: os.arch(),
        hostname: os.hostname(),
        cpus: os.cpus().length,
        cpuModel: os.cpus()[0].model,
        totalMemory: `${(os.totalmem() / (1024 ** 3)).toFixed(2)} GB`,
        freeMemory: `${(os.freemem() / (1024 ** 3)).toFixed(2)} GB`,
        uptime: `${(os.uptime() / 3600).toFixed(2)} hours`,
        homeDirectory: os.homedir(),
        tmpDirectory: os.tmpdir(),
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(info, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  }

  async checkPathExists(args) {
    try {
      const targetPath = args.path;
      
      try {
        await fs.access(targetPath);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ path: targetPath, exists: true }, null, 2),
            },
          ],
        };
      } catch {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ path: targetPath, exists: false }, null, 2),
            },
          ],
        };
      }
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  }

  async getFileStats(args) {
    try {
      const targetPath = args.path;
      const stats = await fs.stat(targetPath);

      const statsInfo = {
        path: targetPath,
        type: stats.isFile() ? "file" : stats.isDirectory() ? "directory" : "other",
        size: stats.size,
        sizeInKB: (stats.size / 1024).toFixed(2),
        created: stats.birthtime,
        modified: stats.mtime,
        accessed: stats.atime,
        permissions: stats.mode.toString(8).slice(-3),
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(statsInfo, null, 2),
          },
        ],
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("Filesystem MCP server running on stdio");
    console.error("Server is ready to receive requests");
  }
}

const server = new FileSystemMCPServer();
server.run().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});