// Ares Capture — popup controller
"use strict";

const toggleEl    = document.getElementById("toggle-capture");
const statusEl    = document.getElementById("status");
const aresUrlEl   = document.getElementById("ares-url");
const scopeEl     = document.getElementById("scope-pattern");
const tokenEl     = document.getElementById("ares-token");
const cdpStatusEl = document.getElementById("cdp-status");
const openBtn     = document.getElementById("open-ares");
const reattachBtn = document.getElementById("reattach-btn");

function setStatus(state) {
  const on = state.captureEnabled;
  statusEl.textContent = on ? "Captura activa" : "Captura desactivada";
  statusEl.className = `status ${on ? "on" : "off"}`;
  if (cdpStatusEl) {
    const n = state.cdpTabs || 0;
    cdpStatusEl.textContent = n > 0
      ? `CDP activo: ${n} tab${n > 1 ? "s" : ""} (captura completa con body)`
      : "CDP: sin tabs adjuntadas aún";
    cdpStatusEl.style.color = n > 0 ? "#34d399" : "#64748b";
  }
}

// Load current state
chrome.runtime.sendMessage({ type: "get_state" }, (state) => {
  if (!state) return;
  toggleEl.checked  = state.captureEnabled;
  aresUrlEl.value   = state.aresUrl || "";
  scopeEl.value     = state.scopePattern || "";
  tokenEl.value     = state.aresToken || "";
  setStatus(state);
});

toggleEl.addEventListener("change", () => {
  chrome.storage.local.set({ captureEnabled: toggleEl.checked });
  setStatus({ captureEnabled: toggleEl.checked, cdpTabs: 0 });
});

aresUrlEl.addEventListener("change", () => {
  chrome.storage.local.set({ aresUrl: aresUrlEl.value.trim() });
});

scopeEl.addEventListener("change", () => {
  chrome.storage.local.set({ scopePattern: scopeEl.value.trim() });
});

tokenEl.addEventListener("change", () => {
  chrome.storage.local.set({ aresToken: tokenEl.value.trim() });
});

openBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "open_ares" });
});

reattachBtn.addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "reattach" });
  setTimeout(() => {
    chrome.runtime.sendMessage({ type: "get_state" }, (state) => {
      if (state) setStatus(state);
    });
  }, 1200);
});
