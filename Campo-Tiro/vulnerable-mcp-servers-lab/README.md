Vulnerable MCP Servers Lab
==========================

This repository contains **intentionally vulnerable** implementations of Model Context Protocol (MCP) servers (both local and remote). Each server lives in its own folder and includes a dedicated `README.md` with full details on **what it does**, **how to run it**, and **how to demonstrate/attack the vulnerability**.

**Do not run any of this outside a controlled lab environment.**

> **Credits / Upstream:** this lab is based on the original project by **Appsecco**: [`appsecco/vulnerable-mcp-servers-lab`](https://github.com/appsecco/vulnerable-mcp-servers-lab) (MIT License). All credit for the original servers, write-ups and research goes to them; check the upstream repository for the original versions.

## What this repo is for

- **Security training / research** into common MCP server and tool-integration failure modes.
- **Hands-on demos** of how vulnerable MCP servers can lead to data exposure, instruction injection, supply-chain compromise, and code execution.

## Safety / lab guidance

- **Use a disposable VM/container** and avoid using real secrets or personal data.
- Prefer running on an **isolated network**; several servers make outbound network calls.
- Treat **all tool output and retrieved content as untrusted data**.
- If you expose any server over HTTP, assume it may be reachable/abused unless you add proper controls.

## Getting started

- **Pick a server** from the index below.
- Open its per-server README and follow the instructions there.
- Many servers include a `claude_config.json` snippet intended to be merged into Claude Desktop’s MCP configuration.

## MCP servers in this repo

- **Filesystem Workspace Actions (path traversal + code exec)**: Tools for reading/writing/listing a “workspace” plus Python execution; vulnerable to naive path joining and unsandboxed code execution.
  - README: [`vulnerable-mcp-server-filesystem-workspace-actions/README.md`](vulnerable-mcp-server-filesystem-workspace-actions/README.md)

- **Indirect Prompt Injection (local stdio)**: Document retrieval/search that returns documents verbatim, including embedded hidden instructions.
  - README: [`vulnerable-mcp-server-indirect-prompt-injection/README.md`](vulnerable-mcp-server-indirect-prompt-injection/README.md)

- **Indirect Prompt Injection (remote MCP over HTTP+SSE)**: Network-accessible MCP server (HTTP + SSE) returning untrusted documents verbatim; models risk of connecting to untrusted remote MCP endpoints.
  - README: [`vulnerable-mcp-server-indirect-prompt-injection-remote-mcp/README.md`](vulnerable-mcp-server-indirect-prompt-injection-remote-mcp/README.md)

- **Malicious Code Execution (eval-based RCE)**: “Quote of the day” tool with an unsafe formatting feature that `eval()`s attacker-controlled JavaScript.
  - README: [`vulnerable-mcp-server-malicious-code-exec/README.md`](vulnerable-mcp-server-malicious-code-exec/README.md)

- **Malicious Tools (instruction injection / fabricated tool output)**: Appears to return status data, but injects misleading instructions and can fabricate plausible-looking incidents.
  - README: [`vulnerable-mcp-server-malicious-tools/README.md`](vulnerable-mcp-server-malicious-tools/README.md)

- **Namespace Typosquatting (`twittter-mcp`)**: Demonstrates supply-chain/trust issues via a lookalike server name intended to be mistaken for a legitimate package.
  - README: [`vulnerable-mcp-server-namespace-typosquatting/README.md`](vulnerable-mcp-server-namespace-typosquatting/README.md)

- **Outdated Packages (supply chain risk)**: Read-only system/filesystem inspection tools whose primary purpose is to demonstrate risk from outdated/deprecated/vulnerable dependencies.
  - README: [`vulnerable-mcp-server-outdated-pacakges/README.md`](vulnerable-mcp-server-outdated-pacakges/README.md)

- **Secrets + PII Exposure**: “Utilities” tools (IP/weather/news) but with embedded sensitive values in source code and leakage via logs.
  - README: [`vulnerable-mcp-server-secrets-pii/README.md`](vulnerable-mcp-server-secrets-pii/README.md)

- **Wikipedia (remote, Streamable HTTP)**: Wikipedia search/retrieval over HTTP; returns untrusted public content without sanitization or instruction/data separation (remote-content prompt injection risk).
  - README: [`vulnerable-mcp-server-wikipedia-http-streamable/README.md`](vulnerable-mcp-server-wikipedia-http-streamable/README.md)

## About Appsecco

**Appsecco** is a cybersecurity company specializing in product security testing, penetration testing, and security assessments. We hack SaaS products, AI Agents, MCP Servers and cloud/K8s infrastructure like attackers do, focusing on pragmatic, high-signal outcomes for real-world systems.

This lab repository exists to support security research and hands-on training for pentesters, who are on their journey to becoming AI Red Teamers, around MCP server vulnerabilities and the risks of integrating untrusted tools and untrusted content into AI agent workflows.

### Contact

- **Website**: [`https://appsecco.com`](https://appsecco.com)
- **Email**: [`HackMyProduct@appsecco.com`](mailto:hackmyproduct@appsecco.com)
- **LinkedIn**: [`https://linkedin.com/company/appsecco`](https://linkedin.com/company/appsecco)

## License

See [`LICENSE`](LICENSE).

## Links to Appsecco Resources

- [Original repository (upstream)](https://github.com/appsecco/vulnerable-mcp-servers-lab)
- [Appsecco LinkedIn](https://www.linkedin.com/company/appsecco/)
- [Appsecco YouTube](https://www.youtube.com/@Appsecco)
- [Appsecco Website](https://appsecco.com)
