---
name: codeaudit
description: "Invoke this skill when the task is a white-box audit of source code the operator provided or fetched (a plugin, an application, a repository). Attacker-first forward analysis from every user-controllable input to dangerous sinks, adversarial verification, PoC with measured impact."
---

# Code Audit (white-box source review)

Under an **authorized** engagement, audit first-party production source code the way an attacker reads it: enumerate every user-controllable input, trace each one forward to dangerous sinks, keep only findings that pass the gates, and prove each one with a PoC and a measured impact.

## Scope rules (production code only)

Never report findings in, and never trace through: test code, build and packaging scripts, vendored or third-party code, generated code, documentation.

**Exception**: security-relevant infrastructure configuration (nginx directives, trust proxy settings, CORS policy) IS in scope when it affects the application's security assumptions.

## Phase 1: input inventory and partitioning

Enumerate **every** user-controllable input: HTTP routes/parameters, headers, cookies, request bodies, REST/RPC methods, queue/event consumers, CLI arguments, config/env values read at request time, file uploads, webhooks. For each entry point record the handler file:line.

Partition large codebases by module. Build the **shared defense catalog** first: middleware, auth wrappers, sanitizers, ORM base classes.

## Phase 2: forward hunt, per vulnerability class

For each input, trace **forward** (entry point to sink), one vuln class at a time (injection, XSS, authorization, file ops, deserialization, cryptography, SSRF). Rules:
- **Never stop at an abstraction boundary**: follow dispatchers, middleware chains, callbacks to their conclusion.
- **Exhaust all paths**: an input used in three places is three traces.
- **Follow through stores**: input written to DB/cache/queue continues wherever a reader consumes it.
- **Transitive caller search** on every candidate sink.

## Gates (a candidate must pass all three)

1. **Reachable** in production
2. **Attacker-controlled** data reaches the sink
3. **New capability** for the attacker

## Verification

- Search the **whole** codebase for shared defenses the partition hunt could not see.
- An elimination cites the file:line of the defense that kills it.

## PoC and measured impact

Prefer executing the PoC against a real instance. When execution is impossible, provide a static trace PoC with: concrete attacker input, file:line at every step, literal dangerous value at the sink, concrete impact. Label it `proof basis: static-analysis-unexecuted`.

## Completion self-check

- [ ] every candidate from Phase 2 appears as confirmed, eliminated, or downgraded
- [ ] every confirmed finding has a PoC and measured impact
- [ ] sweep and count cross-check completed
