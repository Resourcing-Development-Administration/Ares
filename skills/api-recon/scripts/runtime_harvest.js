/**
 * runtime_harvest.js — Runtime API endpoint harvester.
 * Executed in the browser context after page load to collect observed routes.
 *
 * Run via: CDP Runtime.evaluate or Playwright evaluate()
 * Returns a JSON string with all endpoints observed since preload.js injection.
 *
 * Usage (Playwright):
 *   const result = await page.evaluate(() => window.__ARES_HARVEST());
 */
(function () {
  "use strict";

  // Storage for intercepted calls, populated by preload.js hooks
  if (!window.__ARES_CALLS) window.__ARES_CALLS = [];

  /**
   * __ARES_HARVEST() — Collect and deduplicate all observed API calls.
   * Returns a JSON-serializable object with the endpoint map.
   */
  window.__ARES_HARVEST = function () {
    const calls = window.__ARES_CALLS || [];
    const seen = new Map();

    for (const call of calls) {
      const url = call.url || "";
      if (!url) continue;
      try {
        const parsed = new URL(url, window.location.origin);
        const path = parsed.pathname;
        // Normalize IDs
        const norm = path
          .replace(/\/\d{3,}/g, "/{id}")
          .replace(/\/[0-9a-f-]{36}/g, "/{id}")
          .replace(/\/[0-9a-f]{24}/g, "/{id}");
        const key = `${call.method || "GET"}:${norm}`;
        if (!seen.has(key)) {
          seen.set(key, {
            method: (call.method || "GET").toUpperCase(),
            path: norm,
            raw_path: path,
            host: parsed.host,
            status: call.status || null,
            source: call.source || "unknown",
            count: 1,
            first_seen: call.ts || Date.now(),
          });
        } else {
          seen.get(key).count++;
          if (call.status) seen.get(key).status = call.status;
        }
      } catch (_) {}
    }

    const endpoints = Array.from(seen.values()).sort((a, b) =>
      a.path.localeCompare(b.path)
    );

    return {
      origin: window.location.origin,
      total_calls: calls.length,
      unique_endpoints: endpoints.length,
      endpoints,
      harvested_at: new Date().toISOString(),
    };
  };

  /**
   * __ARES_ROUTES() — Extract SPA routes from popular routers.
   * Supports React Router (v5/v6), Vue Router, Angular Router.
   */
  window.__ARES_ROUTES = function () {
    const routes = [];

    // React Router v5: window.__reactRouterRoutes or history
    try {
      if (window.__reactRouterRoutes) {
        for (const r of window.__reactRouterRoutes) {
          routes.push({ path: r.path, component: r.component?.name || "", source: "react-router-v5" });
        }
      }
    } catch (_) {}

    // React Router v6: __reactRouterVersion and routes in fiber
    try {
      const root = document.getElementById("root") || document.getElementById("app");
      if (root && root._reactFiber) {
        const traverse = (fiber, depth = 0) => {
          if (depth > 50) return;
          if (fiber?.memoizedProps?.path) {
            routes.push({ path: fiber.memoizedProps.path, source: "react-router-fiber" });
          }
          if (fiber?.child) traverse(fiber.child, depth + 1);
          if (fiber?.sibling) traverse(fiber.sibling, depth + 1);
        };
        traverse(root._reactFiber);
      }
    } catch (_) {}

    // Vue Router
    try {
      const app = document.querySelector("#app")?.__vue_app__;
      const router = app?.config?.globalProperties?.$router;
      if (router?.getRoutes) {
        for (const r of router.getRoutes()) {
          routes.push({ path: r.path, name: r.name, source: "vue-router" });
        }
      }
    } catch (_) {}

    // Angular Router
    try {
      const ngZone = window.getAllAngularRootElements?.();
      if (ngZone && ngZone.length > 0) {
        const injector = ngZone[0].__ngContext__;
        if (injector) routes.push({ note: "Angular app detected", source: "angular" });
      }
    } catch (_) {}

    return { routes, extracted_at: new Date().toISOString() };
  };

  return "Ares runtime harvester loaded";
})();
