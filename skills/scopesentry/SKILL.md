---
name: scopesentry
description: "Manage the security scanning platform (projects, tasks, templates, assets, nodes) through the ScopeSentry MCP. Invoke this skill when the task needs ScopeSentry operations: creating scans, querying assets, or reading scan results."
---

# ScopeSentry MCP usage guide

For users with a **deployed ScopeSentry instance**. Connect to the platform through an MCP client; no local source code needed.

## 1. Preparation

### 1.1 Confirm the service is reachable

- Default web interface: `http://<host>`
- MCP endpoint: `http://<host>/mcp` (or `http://<host>:8082/mcp`)

### 1.2 Create an API Key

1. Log in to the ScopeSentry web interface
2. Go to the **API Key** management page to create a key
3. Save the returned `ssk_...` string (**shown only once**)

### 1.3 Configure the MCP

```json
{
  "mcpServers": {
    "scopesentry": {
      "url": "http://<your-host>:8082/mcp",
      "headers": { "X-API-Key": "ssk_your-key" }
    }
  }
}
```

## 2. Tool overview

| Tool | Purpose |
|---|---|
| `list_projects` | Project tree grouped by tag (with project IDs) |
| `list_projects_data` | Paginated project list, searchable by name |
| `get_project` | Project details |
| `create_project` | Create a project |
| `list_tasks` / `get_task` | Scan task list / details |
| `list_scan_templates` / `create_scan_template` | Templates |
| `create_scan_task` | Create a scan task |
| `list_assets` / `count_assets` | Query assets (paginated) |
| `get_asset_detail` | Asset or vulnerability details |
| `add_asset_tag` | Add a tag to an asset |
| `list_nodes` | Scan node list |
| `list_plugin_modules` / `list_plugins` | Pipeline modules and plugins |

## 3. Common workflows

### Query assets by project

1. `list_projects` or `list_projects_data` → get project **ObjectID**
2. Pass `filter.project` (must be ObjectID, not display name) to `list_assets`

```json
{"asset_type":"asset","pageIndex":1,"pageSize":20,"search":"domain=^example.com","filter":{"project":["<ObjectID>"]}}
```

### Create a scan task

1. `list_nodes` → get online node names
2. `list_scan_templates` → get template ObjectID
3. `create_scan_task`: `name` and `node` are required; `template` takes the template ID

**targetSource options:** `general` (direct targets), `project` (from project), `asset`/`subdomain`/`RootDomain`/`UrlScan` (from asset stores)

```json
{"name":"example-scan","node":["node-1"],"template":"<template-ObjectID>","targetSource":"general","target":"example.com","project":["<project-ObjectID>"]}
```

### Full recon for root domains (two stages)

1. Stage 1 — subdomain collection: `targetSource: general`, template with `SubdomainScan + SubdomainSecurity`
2. Stage 2 — follow-up modules: `targetSource: subdomain`, `search: "task==\"stage-1-task-name\""`, template with port/vuln/asset modules

## 4. Asset queries

**Asset types:** `asset`, `RootDomain`, `subdomain`, `app`, `mp`, `UrlScan`, `SensitiveResult`, `DirScanResult`, `crawler`, `vulnerability`, `PageMonitoring`, `IPAsset`, `SubdomainTakerResult`

**Search operators:** `==` (exact, uses index), `=` (fuzzy/regex, slow), `!=` (exclude), `^` (prefix, uses index), `&&` (AND), `||` (OR)

**Key tip**: use `==` or `^` prefix matching on indexed fields; avoid `=` fuzzy on large datasets.

**filter keys:** `project` (ObjectID), `port`, `service`, `app`, `statuscode`, `level`, `type`, `status`, `task`, `tags`

## 5. Scan template modules

`TargetHandler`, `SubdomainScan`, `SubdomainSecurity`, `PortScanPreparation`, `PortScan`, `PortFingerprint`, `AssetMapping`, `AssetHandle`, `URLScan`, `WebCrawler`, `URLSecurity`, `DirScan`, `VulnerabilityScan`, `PassiveScan`

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| No MCP tools | Check the URL, the API Key, and whether ScopeSentry is running |
| 401 / 403 | Recreate or replace the API Key |
| Assets not found | Confirm `filter.project` is an ObjectID; do not put project in search |
| Queries slow | Add `filter.project` when you have a project; use `==` or `^` in search |
