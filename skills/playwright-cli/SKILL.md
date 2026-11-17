---
name: playwright-cli
description: Automate browser interactions, test web pages and work with Playwright tests.
allowed-tools: Bash(playwright-cli:*) Bash(npx:*) Bash(npm:*)
---

# Browser Automation with playwright-cli

## Quick start

```bash
playwright-cli open
playwright-cli goto https://example.com
playwright-cli snapshot
playwright-cli click e15
playwright-cli type "search query"
playwright-cli press Enter
playwright-cli screenshot
playwright-cli close
```

## Core commands

```bash
playwright-cli open [url]
playwright-cli goto <url>
playwright-cli snapshot [--depth=N] [--filename=file.yml]
playwright-cli find "text" | --regex "pattern"
playwright-cli click <ref|selector>
playwright-cli fill <ref> "value" [--submit]
playwright-cli type "text"
playwright-cli press <Key>
playwright-cli select <ref> "value"
playwright-cli upload ./file.pdf
playwright-cli check / uncheck <ref>
playwright-cli hover <ref>
playwright-cli drag <ref1> <ref2>
playwright-cli screenshot [--filename=out.png] [--hires]
playwright-cli eval "expression" [ref]
playwright-cli close
```

## Sessions and tabs

```bash
playwright-cli -s=<name> open <url>  # named session
playwright-cli tab-new [url]
playwright-cli tab-list
playwright-cli tab-select <index>
playwright-cli tab-close [index]
playwright-cli list              # list all sessions
playwright-cli close-all
```

## Storage

```bash
playwright-cli state-save [auth.json]
playwright-cli state-load auth.json
playwright-cli cookie-list / cookie-get / cookie-set / cookie-clear
playwright-cli localstorage-list / localstorage-get / localstorage-set / localstorage-clear
```

## Network mocking

```bash
playwright-cli route "**/*.jpg" --status=404
playwright-cli route "https://api.example.com/**" --body='{"mock":true}'
playwright-cli route-list
playwright-cli unroute "pattern"
```

## DevTools

```bash
playwright-cli console [level]
playwright-cli requests
playwright-cli request <id>
playwright-cli tracing-start / tracing-stop
playwright-cli video-start video.webm / video-stop
playwright-cli show --annotate   # UI review: user draws/annotates, you receive snapshot + notes
```

## Open options

```bash
playwright-cli open --browser=chrome|firefox|webkit|msedge
playwright-cli open --mobile [--device="iPhone 15"]
playwright-cli open --persistent [--profile=/path]
playwright-cli attach --cdp=http://localhost:9222
playwright-cli attach --cdp=chrome  # attach to running Chrome
```

## Raw output

```bash
playwright-cli --raw snapshot > before.yml
playwright-cli --raw eval "JSON.stringify(performance.timing)" | jq '.loadEventEnd - .navigationStart'
```

## Installation (if global playwright-cli is unavailable)

```bash
npm install -g @playwright/cli@latest
# or use: npx playwright cli <command>
```
