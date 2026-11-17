---
name: api-recon
description: Invoke this skill when collecting a website's API endpoints.
---

# API Recon (frontend API reconnaissance)

Under an **authorized** engagement, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI feature trigger points** (tabs, modals, table actions, etc.).

---

## Boundaries and prohibitions (agents must read · violation means going out of bounds)

This skill **only performs API / parameter-surface reconnaissance**; it is not the vulnerability-hunting or exploitation phase.

### Task boundaries

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege-escalation/brute-force/fuzz vulnerabilities, modified-packet attacks, destructive operations |
| **Auth** | Hook + stub/mock to bypass the **client-side** login gate | Asking the user for or guessing credentials; attempting real login form submissions |
| **Runtime** | Hook endpoints without credentials and use mock responses to get the SPA into its post-login shell | Flows that require a real backend session to continue |

### Credential-free dynamic analysis (Phase 3 default)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** bootstrap endpoints such as login, permissions, and menus;
2. Return mock bodies for business query endpoints that are **structurally correct, carry a success business code, and may have empty data**;
3. Keep the frontend rendering post-login pages even without a backend or under 401s, thereby triggering more XHR/fetch/WebSocket traffic;
4. **Empty data, blank tables, and placeholder UI are all expected** — do not switch to real login or vulnerability testing over them.

**In one sentence**: use mocks to pry open frontend routes and component mounting and **record outbound requests only**; what the backend returns does not matter — what matters is **which other endpoints the frontend still calls**.

## Execution roadmap

```
Phase 0 classify + OUTDIR
  → Gate A → Phase 1 harvest
  → Phase 1b parameter reverse engineering
  → Phase 2 three auth gates → config.json
  → Gate B → Phase 3 runtime + parameter matrix
  → Phase 4 permission tree (if needed) → rerun Phase 3
  → Phase 5 merge report + insert_assets
```

## Phase 0 — Classification

Fetch the entry HTML and **create `OUTDIR`**:

- **SPA**: empty shell + `<div id=app>` + chunks → Phase 1–5
- **MPA**: SSR + `<form>`, no endpoint bundle → `python3 recon/spider_mpa.py <BASE_URL> <OUTDIR>`

## Phase 1 — Static

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

### Phase 1b — Parameter reverse engineering

Anchor on a known path and widen the window to find the payload-assembly object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

## Phase 2 — The three auth gates

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | How does the app decide the user is logged in? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers a redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

## Phase 3 — Runtime

Gate B must pass. Use `preload.js` + mock strategy. Enumerate tabs, modals, table actions in coverage mode.

## Phase 5 — Merge and report

```bash
# insert every discovered service and endpoint as an asset
```

Output: `api_merged.txt`, `params_merged.json`, `site_map.json`.
