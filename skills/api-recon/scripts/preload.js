/**
 * preload.js — Injected into page context before navigation to hook XHR/fetch.
 * Intercepts all API calls made by the page and reports them to the collector.
 *
 * Injection method: CDP Runtime.addScriptToEvaluateOnNewDocument
 * or Playwright addInitScript.
 *
 * The collector endpoint is set via window.__ARES_COLLECTOR_URL before injection.
 */
(function () {
  "use strict";

  const COLLECTOR = window.__ARES_COLLECTOR_URL || "http://localhost:7443/api/harvest";
  const TOKEN = window.__ARES_TOKEN || "";
  const MAX_BODY = 65536;

  // ── Helpers ───────────────────────────────────────────────────────────────

  function truncate(s) {
    if (!s) return "";
    return s.length > MAX_BODY ? s.slice(0, MAX_BODY) + "[TRUNCATED]" : s;
  }

  function sendToCollector(entry) {
    try {
      const h = { "Content-Type": "application/json" };
      if (TOKEN) h["X-Ares-Token"] = TOKEN;
      navigator.sendBeacon
        ? navigator.sendBeacon(COLLECTOR, JSON.stringify(entry))
        : fetch(COLLECTOR, { method: "POST", headers: h, body: JSON.stringify(entry), keepalive: true });
    } catch (_) {}
  }

  // ── XHR hook ──────────────────────────────────────────────────────────────

  const OrigXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function () {
    const xhr = new OrigXHR(...arguments);
    const entry = { type: "xhr", method: "", url: "", reqBody: "", ts: 0 };

    const origOpen = xhr.open.bind(xhr);
    xhr.open = function (method, url, ...rest) {
      entry.method = method;
      entry.url = url;
      entry.ts = Date.now();
      return origOpen(method, url, ...rest);
    };

    const origSend = xhr.send.bind(xhr);
    xhr.send = function (body) {
      entry.reqBody = truncate(typeof body === "string" ? body : "");
      xhr.addEventListener("load", function () {
        sendToCollector({
          source: "xhr",
          method: (entry.method || "GET").toUpperCase(),
          url: entry.url,
          status: xhr.status,
          requestBody: entry.reqBody,
          responseBody: truncate(xhr.responseText),
          responseHeaders: parseHeaders(xhr.getAllResponseHeaders()),
          ts: entry.ts,
        });
      });
      return origSend(body);
    };
    return xhr;
  };
  window.XMLHttpRequest.prototype = OrigXHR.prototype;

  // ── fetch hook ────────────────────────────────────────────────────────────

  const origFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const ts = Date.now();
    const url = typeof input === "string" ? input : input instanceof Request ? input.url : String(input);
    const method = ((init && init.method) || (input instanceof Request && input.method) || "GET").toUpperCase();
    let reqBody = "";
    if (init && init.body && typeof init.body === "string") {
      reqBody = truncate(init.body);
    }

    let resp;
    try {
      resp = await origFetch(input, init);
    } catch (err) {
      sendToCollector({ source: "fetch", method, url, error: String(err), ts });
      throw err;
    }

    const clone = resp.clone();
    clone.text().then((text) => {
      const headers = {};
      clone.headers.forEach((v, k) => { headers[k] = v; });
      sendToCollector({
        source: "fetch",
        method,
        url,
        status: resp.status,
        requestBody: reqBody,
        responseBody: truncate(text),
        responseHeaders: headers,
        ts,
      });
    }).catch(() => {});

    return resp;
  };

  // ── Helper: parse XHR getAllResponseHeaders() ──────────────────────────────

  function parseHeaders(raw) {
    const out = {};
    if (!raw) return out;
    raw.trim().split(/[\r\n]+/).forEach((line) => {
      const idx = line.indexOf(": ");
      if (idx > 0) out[line.slice(0, idx).toLowerCase()] = line.slice(idx + 2);
    });
    return out;
  }

  // ── WebSocket hook ────────────────────────────────────────────────────────

  const OrigWS = window.WebSocket;
  window.WebSocket = function (url, protocols) {
    const ws = protocols ? new OrigWS(url, protocols) : new OrigWS(url);
    const ts = Date.now();
    sendToCollector({ source: "websocket_open", url, ts });

    ws.addEventListener("message", (evt) => {
      sendToCollector({
        source: "websocket_message",
        url,
        direction: "server",
        data: truncate(typeof evt.data === "string" ? evt.data : "[binary]"),
        ts: Date.now(),
      });
    });

    const origSend = ws.send.bind(ws);
    ws.send = function (data) {
      sendToCollector({
        source: "websocket_message",
        url,
        direction: "client",
        data: truncate(typeof data === "string" ? data : "[binary]"),
        ts: Date.now(),
      });
      return origSend(data);
    };
    return ws;
  };
  window.WebSocket.prototype = OrigWS.prototype;
  Object.defineProperty(window.WebSocket, "CONNECTING", { value: 0 });
  Object.defineProperty(window.WebSocket, "OPEN", { value: 1 });
  Object.defineProperty(window.WebSocket, "CLOSING", { value: 2 });
  Object.defineProperty(window.WebSocket, "CLOSED", { value: 3 });

})();
