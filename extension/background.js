// Ares Traffic Capture — MV3 service worker
// CDP upgrade: full request/response body capture via chrome.debugger
// Falls back to webRequest header-only capture on tabs without debugger attached.

const DEFAULT_ARES_URL = "http://localhost:7443";
const CDP_VERSION = "1.3";

let captureEnabled = false;
let aresUrl = DEFAULT_ARES_URL;
let scopePattern = "";
let aresToken = "";

// tabId → {attached: bool, pendingRequests: Map<requestId, partial>}
const debuggerTabs = new Map();

// ── Config ────────────────────────────────────────────────────────────────────

chrome.storage.local.get(["captureEnabled","aresUrl","scopePattern","aresToken"], (d) => {
  captureEnabled = !!d.captureEnabled;
  aresUrl  = d.aresUrl  || DEFAULT_ARES_URL;
  scopePattern = d.scopePattern || "";
  aresToken = d.aresToken || "";
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.captureEnabled) {
    captureEnabled = changes.captureEnabled.newValue;
    captureEnabled ? attachAllTabs() : detachAllTabs();
  }
  if (changes.aresUrl)      aresUrl = changes.aresUrl.newValue || DEFAULT_ARES_URL;
  if (changes.scopePattern) scopePattern = changes.scopePattern.newValue || "";
  if (changes.aresToken)    aresToken = changes.aresToken.newValue || "";
});

// ── Scope filter ──────────────────────────────────────────────────────────────

function matchesScope(url) {
  if (!scopePattern) return true;
  try { return new RegExp(scopePattern, "i").test(url); }
  catch { return url.includes(scopePattern); }
}

function isSelf(url) {
  return url.startsWith(aresUrl) || url.startsWith("chrome-extension://");
}

// ── CDP helpers ───────────────────────────────────────────────────────────────

function cdpTarget(tabId) {
  return { tabId };
}

async function cdpCmd(tabId, method, params) {
  return new Promise((resolve, reject) => {
    chrome.debugger.sendCommand(cdpTarget(tabId), method, params || {}, (res) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(res);
    });
  });
}

async function attachTab(tabId) {
  if (debuggerTabs.has(tabId)) return;
  try {
    await new Promise((res, rej) =>
      chrome.debugger.attach(cdpTarget(tabId), CDP_VERSION, () =>
        chrome.runtime.lastError ? rej(new Error(chrome.runtime.lastError.message)) : res()
      )
    );
    debuggerTabs.set(tabId, { attached: true, pending: new Map() });

    // Enable Network domain for response body access
    await cdpCmd(tabId, "Network.enable", {
      maxResourceBufferSize: 10 * 1024 * 1024,
      maxTotalBufferSize:    50 * 1024 * 1024,
    });

    // Enable Fetch domain: pauses each request so we can read POST body before continuing
    await cdpCmd(tabId, "Fetch.enable", {
      patterns: [{ urlPattern: "*" }],
      handleAuthRequests: false,
    });
  } catch (e) {
    debuggerTabs.delete(tabId);
  }
}

async function detachTab(tabId) {
  if (!debuggerTabs.has(tabId)) return;
  debuggerTabs.delete(tabId);
  await new Promise((res) =>
    chrome.debugger.detach(cdpTarget(tabId), () => { chrome.runtime.lastError; res(); })
  );
}

async function attachAllTabs() {
  const tabs = await chrome.tabs.query({ url: ["http://*/*","https://*/*"] });
  for (const t of tabs) {
    if (t.id && t.id > 0) await attachTab(t.id).catch(() => {});
  }
}

async function detachAllTabs() {
  for (const tabId of [...debuggerTabs.keys()]) {
    await detachTab(tabId).catch(() => {});
  }
}

// ── Tab lifecycle ─────────────────────────────────────────────────────────────

chrome.tabs.onCreated.addListener((tab) => {
  if (captureEnabled && tab.id > 0) attachTab(tab.id).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  debuggerTabs.delete(tabId);
});

chrome.debugger.onDetach.addListener((target) => {
  if (target.tabId) debuggerTabs.delete(target.tabId);
});

// ── CDP event dispatcher ──────────────────────────────────────────────────────

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  if (!captureEnabled) return;
  const tabId = source.tabId;
  const tabState = debuggerTabs.get(tabId);
  if (!tabState) return;

  // --- Fetch.requestPaused: intercept outgoing request to read body, then continue ---
  if (method === "Fetch.requestPaused") {
    const req = params.request;
    if (!isSelf(req.url) && matchesScope(req.url)) {
      const entry = {
        type:      "request",
        requestId: params.requestId,
        networkId: params.networkId,
        method:    req.method,
        url:       req.url,
        headers:   req.headers,
        timestamp: Date.now(),
        tabId,
      };

      // POST/PUT/PATCH: try to get body
      if (req.postData) {
        entry.body = req.postData.length > 65536
          ? req.postData.slice(0, 65536) + "[TRUNCATED]"
          : req.postData;
      }

      // Store partial for later response join
      tabState.pending.set(params.networkId || params.requestId, entry);
      sendToAres(entry);
    }

    // Always continue the paused request so the page isn't blocked
    cdpCmd(tabId, "Fetch.continueRequest", { requestId: params.requestId }).catch(() => {});
    return;
  }

  // --- Network.responseReceived: capture response metadata ---
  if (method === "Network.responseReceived") {
    const resp = params.response;
    if (isSelf(resp.url) || !matchesScope(resp.url)) return;

    const entry = {
      type:         "response",
      requestId:    params.requestId,
      url:          resp.url,
      statusCode:   resp.status,
      mimeType:     resp.mimeType,
      headers:      resp.headers,
      fromCache:    resp.fromDiskCache || resp.fromServiceWorker || false,
      timestamp:    Date.now(),
      tabId,
    };

    // Fetch body asynchronously (may fail if not buffered)
    try {
      const bodyResp = await cdpCmd(tabId, "Network.getResponseBody", {
        requestId: params.requestId,
      });
      if (bodyResp && bodyResp.body) {
        const raw = bodyResp.base64Encoded
          ? atob(bodyResp.body)
          : bodyResp.body;
        entry.body = raw.length > 65536 ? raw.slice(0, 65536) + "[TRUNCATED]" : raw;
        entry.bodyEncoding = bodyResp.base64Encoded ? "base64decoded" : "text";
      }
    } catch {
      // Not buffered or already evicted from buffer — skip body
    }

    tabState.pending.delete(params.requestId);
    sendToAres(entry);
    return;
  }

  // --- Network.loadingFailed: clean up pending ---
  if (method === "Network.loadingFailed") {
    tabState.pending.delete(params.requestId);
  }
});

// ── Send to Ares ──────────────────────────────────────────────────────────────

async function sendToAres(event) {
  const headers = { "Content-Type": "application/json" };
  if (aresToken) headers["X-Ares-Token"] = aresToken;
  try {
    await fetch(`${aresUrl}/api/capture`, {
      method:  "POST",
      headers,
      body:    JSON.stringify(event),
    });
  } catch {
    // Ares may not be running — silent failure
  }
}

// ── webRequest fallback: request metadata for tabs without debugger ───────────
// (used when CDP attach failed, e.g. chrome:// pages or cross-origin iframes)

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!captureEnabled) return;
    if (debuggerTabs.has(details.tabId)) return; // CDP path handles it
    if (!matchesScope(details.url) || isSelf(details.url)) return;

    const event = {
      type:      "request",
      requestId: details.requestId,
      method:    details.method,
      url:       details.url,
      timestamp: Date.now(),
      tabId:     details.tabId,
      source:    "webRequest",
    };
    if (details.requestBody) {
      if (details.requestBody.raw) {
        try {
          event.body = new TextDecoder().decode(
            details.requestBody.raw.map(c => c.bytes).reduce((a, b) => {
              const t = new Uint8Array(a.byteLength + b.byteLength);
              t.set(new Uint8Array(a), 0);
              t.set(new Uint8Array(b), a.byteLength);
              return t.buffer;
            })
          ).slice(0, 65536);
        } catch {}
      } else if (details.requestBody.formData) {
        event.formData = details.requestBody.formData;
      }
    }
    sendToAres(event);
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!captureEnabled) return;
    if (debuggerTabs.has(details.tabId)) return;
    if (!matchesScope(details.url) || isSelf(details.url)) return;

    sendToAres({
      type:            "response",
      requestId:       details.requestId,
      url:             details.url,
      statusCode:      details.statusCode,
      responseHeaders: sanitizeHeaders(details.responseHeaders),
      fromCache:       details.fromCache,
      timestamp:       Date.now(),
      tabId:           details.tabId,
      source:          "webRequest",
    });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

function sanitizeHeaders(headers) {
  if (!headers) return {};
  const redact = /authorization|cookie|set-cookie|x-api-key|x-auth-token/i;
  const out = {};
  for (const h of headers) {
    out[h.name] = redact.test(h.name) ? "[REDACTED]" : h.value;
  }
  return out;
}

// ── Popup messages ────────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "get_state") {
    sendResponse({
      captureEnabled,
      aresUrl,
      scopePattern,
      cdpTabs: debuggerTabs.size,
    });
  } else if (msg.type === "open_ares") {
    chrome.tabs.create({ url: aresUrl });
  } else if (msg.type === "reattach") {
    detachAllTabs().then(attachAllTabs);
  }
  return true;
});
