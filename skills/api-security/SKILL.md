---
name: api-security
description: "Invoke this skill when the task is authorized offensive testing of a REST, GraphQL, WebSocket, or SOAP API beyond recon: authentication and authorization flaws (BOLA, IDOR, BFLA), JWT and OAuth weaknesses, GraphQL-specific abuse, input validation, business logic, rate-limit trust confusion, and excessive data exposure."
---

# API Security Testing (REST, GraphQL, WebSocket, SOAP)

This is the hunting counterpart of api-recon. api-recon maps the API surface and stops; this skill attacks the mapped surface under an authorized engagement. The standing finding quality gates and the adversarial gate apply throughout, and an access-control finding only exists once a second account or role has proven the boundary is real.

Attribution: adapted from the `api-security` playbook of [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) (MIT License).

## Boundaries

- Rate-limit and load tests only within the engagement's written impact budget. Most bounty programs forbid denial of service outright; volume that degrades the service for other users is out of bounds. Race-condition tests use a handful of concurrent requests, never load tools.
- Do not exfiltrate real user data to prove a BOLA. One record you are authorized to touch, or your own second account, is sufficient evidence.
- Destructive payloads (deletion, mass assignment on write endpoints) only against accounts and resources created for the test.
- Every confirmed finding needs a replayable artifact: the exact request, the exact response, and the authorization context that produced it.

## Phase checklists

### Phase 1: discovery (handoff from api-recon)

- Spec sources: `/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, JS bundles, robots.txt.
- Undocumented path brute force: ffuf or kiterunner with API wordlists.
- GraphQL introspection, three tiers: full introspection query; trimmed if full is blocked; minimal `__schema { types { name } }` as the last probe.

### Phase 2: authentication

JWT (jwt_tool or manual):
- [ ] `alg: none`: header rewritten, signature stripped.
- [ ] key confusion: RS256 public key accepted as an HS256 secret.
- [ ] weak HMAC secret: dictionary attack (`jwt_tool -C -d wordlist.txt`).
- [ ] expired or tampered claims: `exp`, `iat`, `sub`, `role`.
- [ ] `kid` injection: path traversal inside the key id.

OAuth 2.0:
- [ ] `redirect_uri` manipulation leading to authorization-code theft.
- [ ] missing `state` (CSRF on the authorization flow).
- [ ] token leakage via `Referer` or platform logs.
- [ ] missing PKCE on public clients.

### Phase 3: authorization (BOLA / IDOR / BFLA)

BOLA, object level:
- [ ] enumerate numeric ids: `/user/1` to `/user/2`.
- [ ] enumerate UUIDs harvested from other responses.
- [ ] two-session replay: user A's session requesting user B's objects.

BFLA, function level:
- [ ] standard user calling admin endpoints.
- [ ] HTTP method swap: GET to PUT, PATCH, DELETE.
- [ ] version downgrade: `/v2/admin` to `/v1/admin`.

### Phase 4: GraphQL-specific

- [ ] introspection exposing schema details it should hide.
- [ ] alias overload and batched queries as compute amplification, within impact budget.
- [ ] field-suggestion error messages leaking schema names.
- [ ] GraphiQL or playground exposed unauthenticated.

### Phase 5: REST input validation

- [ ] HTTP method swap on every endpoint.
- [ ] Content-Type tampering: JSON to XML to multipart (XXE where XML is accepted).
- [ ] NoSQL operator injection: `{"username": {"$gt": ""}}`.
- [ ] SSRF through URL-taking parameters (webhooks, avatar imports, fetchers).
- [ ] mass assignment: `is_admin: true` added to request bodies.

### Phase 6: business logic

- [ ] diff v1 against v2 of the same API.
- [ ] role matrix: admin, user, readonly through the same workflow.
- [ ] TOCTOU races with a few concurrent requests.

### Phase 7: WebSocket

- [ ] endpoint discovery (upgrade handshakes).
- [ ] message injection, prototype pollution through frames.
- [ ] cross-site WebSocket hijacking (CSWH).

### Phase 8: rate-limit trust confusion

- [ ] header spoofing: `X-Forwarded-For`, `X-Real-IP`.
- [ ] path variants: `/api/`, `/api`, `/Api/` bypassing a path-keyed limiter.

### Phase 9: data exposure

- [ ] response fields beyond what the UI renders.
- [ ] pagination enumeration: `?page=1&limit=10000`.
- [ ] error messages leaking stack traces, internal paths, or SQL.

## Completion self-check

- [ ] every executed phase produced artifacts (requests, responses, diffs) in the work dir.
- [ ] each access-control finding was confirmed with a second session or role.
- [ ] nothing in the report relies on a tool or output you did not actually run.
