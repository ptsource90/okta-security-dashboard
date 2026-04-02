// ─── CONFIG ──────────────────────────────────────────────────────────────────
const CONFIG = {
  redirectUri: "http://localhost:8080",
  scopes: "offline_access okta.logs.read",
};

// ─── TOKEN STORE (in-memory) ──────────────────────────────────────────────────
let tokenStore = {
  accessToken: null,
  refreshToken: null,
  idToken: null,
  expiresAt: 0,
  oktaDomain: null,
  clientId: null,
};

function storeTokens(tokens, domain, clientId) {
  tokenStore.accessToken = tokens.access_token;
  tokenStore.refreshToken = tokens.refresh_token ?? tokenStore.refreshToken;
  tokenStore.idToken = tokens.id_token;
  tokenStore.expiresAt = Date.now() + (tokens.expires_in ?? 3600) * 1000;
  if (domain) tokenStore.oktaDomain = domain;
  if (clientId) tokenStore.clientId = clientId;
  // Persist refresh token + domain + clientId across page loads (not access token)
  sessionStorage.setItem("okta_refresh", tokenStore.refreshToken ?? "");
  sessionStorage.setItem("okta_domain", tokenStore.oktaDomain ?? "");
  sessionStorage.setItem("okta_client_id", tokenStore.clientId ?? "");
}

function loadPersistedSession() {
  tokenStore.refreshToken = sessionStorage.getItem("okta_refresh") || null;
  tokenStore.oktaDomain = sessionStorage.getItem("okta_domain") || null;
  tokenStore.clientId = sessionStorage.getItem("okta_client_id") || null;
}

function clearTokens() {
  tokenStore = {
    accessToken: null,
    refreshToken: null,
    idToken: null,
    expiresAt: 0,
    oktaDomain: null,
    clientId: null,
  };
  sessionStorage.removeItem("okta_refresh");
  sessionStorage.removeItem("okta_domain");
  sessionStorage.removeItem("okta_client_id");
  sessionStorage.removeItem("pkce_verifier");
  sessionStorage.removeItem("oauth_state");
  sessionStorage.removeItem("okta_domain_pending");
  sessionStorage.removeItem("okta_client_id_pending");
}

function isExpired() {
  return Date.now() >= tokenStore.expiresAt - 60_000; // 60 s buffer
}

function isAuthenticated() {
  return (
    !!(tokenStore.accessToken && !isExpired()) || !!tokenStore.refreshToken
  ); // can silently refresh
}

// ─── PKCE HELPERS ─────────────────────────────────────────────────────────────
function randomString(len) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const values = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(values, (v) => chars[v % chars.length]).join("");
}

async function generatePKCE() {
  const verifier = randomString(64);
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return { verifier, challenge };
}

// ─── AUTH FLOW ────────────────────────────────────────────────────────────────
window.startLogin = async function () {
  const domain = document
    .getElementById("okta-domain")
    .value.trim()
    .replace(/\/$/, "");
  const clientId = document.getElementById("okta-client-id").value.trim();
  if (!domain) {
    showError("Please enter your Okta domain first.");
    return;
  }
  if (!clientId) {
    showError("Please enter your Client ID first.");
    return;
  }

  const { verifier, challenge } = await generatePKCE();
  const state = randomString(32);

  sessionStorage.setItem("pkce_verifier", verifier);
  sessionStorage.setItem("oauth_state", state);
  sessionStorage.setItem("okta_domain_pending", domain);
  sessionStorage.setItem("okta_client_id_pending", clientId);

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    response_mode: "query",
    scope: CONFIG.scopes,
    redirect_uri: CONFIG.redirectUri,
    state,
    code_challenge_method: "S256",
    code_challenge: challenge,
  });

  const authUrl = `https://${domain}/oauth2/v1/authorize?${params}`;
  window.open(authUrl, "okta_auth", "width=520,height=660,left=200,top=100");
  setStatus("Waiting for authentication in popup…");
};

// Child window posts the full URL back, or we poll for sessionStorage key
window.addEventListener("message", async (event) => {
  if (event.data?.type === "okta_callback") {
    await handleCallback(event.data.url);
  }
});

async function handleCallback(callbackUrl) {
  const url = new URL(callbackUrl);
  const code = url.searchParams.get("code");
  const retState = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    showError(
      `Auth error: ${error} — ${url.searchParams.get("error_description") ?? ""}`,
    );
    return;
  }
  if (!code) {
    showError("No code received in callback.");
    return;
  }

  const savedState = sessionStorage.getItem("oauth_state");
  if (retState !== savedState) {
    showError("State mismatch — possible CSRF.");
    return;
  }

  const verifier = sessionStorage.getItem("pkce_verifier");
  const domain = sessionStorage.getItem("okta_domain_pending");
  const clientId = sessionStorage.getItem("okta_client_id_pending");
  sessionStorage.removeItem("pkce_verifier");
  sessionStorage.removeItem("oauth_state");
  sessionStorage.removeItem("okta_domain_pending");
  sessionStorage.removeItem("okta_client_id_pending");

  setStatus("Exchanging code for tokens…");

  try {
    const resp = await fetch(`https://${domain}/oauth2/v1/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        redirect_uri: CONFIG.redirectUri,
        code,
        code_verifier: verifier,
      }),
    });
    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      throw new Error(e.error_description ?? resp.statusText);
    }
    const tokens = await resp.json();
    storeTokens(tokens, domain, clientId);
    onAuthenticated();
  } catch (err) {
    showError(`Token exchange failed: ${err.message}`);
  }
}

async function refreshAccessToken() {
  const domain = tokenStore.oktaDomain;
  const clientId = tokenStore.clientId;
  if (!domain || !tokenStore.refreshToken) throw new Error("No refresh token");

  const resp = await fetch(`https://${domain}/oauth2/v1/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: clientId,
      scope: CONFIG.scopes,
      refresh_token: tokenStore.refreshToken,
    }),
  });

  if (!resp.ok) {
    clearTokens();
    showLoginScreen();
    throw new Error("Refresh token expired — please log in again.");
  }

  const tokens = await resp.json();
  storeTokens(tokens);
  updateTokenLifetimeBar();
}

async function getValidToken() {
  if (isExpired()) await refreshAccessToken();
  return tokenStore.accessToken;
}

// ─── OKTA LOGS API ────────────────────────────────────────────────────────────
async function fetchLogs(since) {
  const token = await getValidToken();
  const domain = tokenStore.oktaDomain;
  const params = new URLSearchParams({ limit: 100, since });
  const resp = await fetch(`https://${domain}/api/v1/logs?${params}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!resp.ok) throw new Error(`Logs API ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

// ─── DASHBOARD LOGIC ──────────────────────────────────────────────────────────
let refreshTimer = null;
const EVENTS_PAGE_SIZE = 10;
let eventTableState = {
  rows: [],
  page: 1,
  search: "",
  sort: "published_desc",
};

window.onEventsSearch = function (event) {
  eventTableState.search = event.target.value;
  eventTableState.page = 1;
  renderEventsPanel();
};

window.onEventsSortChange = function (event) {
  eventTableState.sort = event.target.value;
  eventTableState.page = 1;
  renderEventsPanel();
};

window.onEventsPage = function (step) {
  const rows = applyEventFilters();
  const totalPages = Math.max(1, Math.ceil(rows.length / EVENTS_PAGE_SIZE));
  eventTableState.page = Math.min(
    Math.max(1, eventTableState.page + step),
    totalPages,
  );
  renderEventsPanel();
};

function onAuthenticated() {
  document.getElementById("login-screen").style.display = "none";
  document.getElementById("dashboard").style.display = "block";
  updateTokenLifetimeBar();
  startTokenWatcher();
  loadDashboard();
  scheduleAutoRefresh();
}

function showLoginScreen() {
  document.getElementById("login-screen").style.display = "flex";
  document.getElementById("dashboard").style.display = "none";
  clearInterval(refreshTimer);
}

function scheduleAutoRefresh() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(loadDashboard, 5 * 60 * 1000); // every 5 min
  updateCountdown();
}

// Countdown timer display
let nextRefreshAt = 0;
function updateCountdown() {
  nextRefreshAt = Date.now() + 5 * 60 * 1000;
  const el = document.getElementById("next-refresh");
  const tick = setInterval(() => {
    const secs = Math.max(0, Math.round((nextRefreshAt - Date.now()) / 1000));
    if (el)
      el.textContent = `Next auto-refresh in ${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
    if (secs === 0) clearInterval(tick);
  }, 1000);
}

window.manualRefresh = function () {
  loadDashboard();
  scheduleAutoRefresh();
};

window.logout = function () {
  clearTokens();
  clearInterval(refreshTimer);
  showLoginScreen();
  document.getElementById("error-bar").style.display = "none";
};

async function loadDashboard() {
  setStatus("Fetching logs…");
  document.getElementById("refresh-btn").disabled = true;
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const logs = await fetchLogs(since);
    renderDashboard(logs);
    document.getElementById("last-updated").textContent =
      "Last updated: " + new Date().toLocaleTimeString();
    setStatus("");
  } catch (err) {
    showError(err.message);
  } finally {
    document.getElementById("refresh-btn").disabled = false;
  }
}

function renderDashboard(logs) {
  // ── Summary cards ──
  const failed = logs.filter((l) => l.outcome?.result === "FAILURE");
  const mfaEvents = logs.filter((l) => l.eventType?.startsWith("user.mfa"));
  const policyChg = logs.filter((l) =>
    l.eventType?.startsWith("policy.lifecycle"),
  );
  const suspicious = logs.filter(
    (l) =>
      l.outcome?.result === "FAILURE" && l.eventType === "user.session.start",
  );

  document.getElementById("stat-total").textContent = logs.length;
  document.getElementById("stat-failed").textContent = failed.length;
  document.getElementById("stat-mfa").textContent = mfaEvents.length;
  document.getElementById("stat-policy").textContent = policyChg.length;

  // ── Severity breakdown ──
  const sev = { DEBUG: 0, INFO: 0, WARN: 0, ERROR: 0 };
  logs.forEach((l) => {
    const s = l.severity?.toUpperCase();
    if (s in sev) sev[s]++;
  });
  document.getElementById("sev-debug").style.width = pct(
    sev.DEBUG,
    logs.length,
  );
  document.getElementById("sev-info").style.width = pct(sev.INFO, logs.length);
  document.getElementById("sev-warn").style.width = pct(sev.WARN, logs.length);
  document.getElementById("sev-error").style.width = pct(
    sev.ERROR,
    logs.length,
  );
  document.getElementById("sev-debug-lbl").textContent = `DEBUG ${sev.DEBUG}`;
  document.getElementById("sev-info-lbl").textContent = `INFO ${sev.INFO}`;
  document.getElementById("sev-warn-lbl").textContent = `WARN ${sev.WARN}`;
  document.getElementById("sev-error-lbl").textContent = `ERROR ${sev.ERROR}`;

  // ── Hourly chart ──
  renderHourlyChart(logs);

  // ── Suspicious logins ──
  renderTable(
    "suspicious-table",
    suspicious,
    ["Time", "User", "IP", "Result"],
    (l) => [
      fmtTime(l.published),
      l.actor?.alternateId ?? "—",
      l.securityContext?.ipAddress ?? "—",
      badge(l.outcome?.result),
    ],
  );

  // ── Recent events ──
  const NUM_RECENT = 100;
  eventTableState.rows = [...logs]
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, NUM_RECENT);
  eventTableState.page = 1;
  renderEventsPanel();

  // ── Top actors ──
  const actors = {};
  logs.forEach((l) => {
    const a = l.actor?.alternateId ?? "unknown";
    actors[a] = (actors[a] ?? 0) + 1;
  });
  const top = Object.entries(actors)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  const topEl = document.getElementById("top-actors");
  topEl.innerHTML = top
    .map(
      ([name, count]) =>
        `<div class="actor-row"><span class="actor-name">${esc(name)}</span>
     <span class="actor-bar-wrap"><span class="actor-bar" style="width:${pct(count, top[0][1])}"></span></span>
     <span class="actor-count">${count}</span></div>`,
    )
    .join("");
}

function renderHourlyChart(logs) {
  const hours = {};
  for (let i = 23; i >= 0; i--) {
    const h = new Date(Date.now() - i * 3600_000);
    hours[h.getHours()] = 0;
  }
  logs.forEach((l) => {
    const h = new Date(l.published).getHours();
    hours[h] = (hours[h] ?? 0) + 1;
  });

  const vals = Object.values(hours);
  const max = Math.max(...vals, 1);
  const keys = Object.keys(hours);
  const chart = document.getElementById("hourly-chart");
  chart.innerHTML = keys
    .map(
      (h, i) =>
        `<div class="bar-col">
       <div class="bar-fill" style="height:${Math.round((vals[i] / max) * 100)}%" title="${vals[i]} events"></div>
       <div class="bar-label">${String(h).padStart(2, "0")}</div>
     </div>`,
    )
    .join("");
}

function renderTable(id, rows, headers, mapper) {
  const el = document.getElementById(id);
  if (!rows.length) {
    el.innerHTML = '<p class="empty">No events found.</p>';
    return;
  }
  el.innerHTML = `<table><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
     <tbody>${rows
       .map(
         (r) =>
           `<tr>${mapper(r)
             .map((c) => `<td>${c}</td>`)
             .join("")}</tr>`,
       )
       .join("")}</tbody></table>`;
}

function applyEventFilters() {
  const query = eventTableState.search.trim().toLowerCase();
  return eventTableState.rows
    .filter((l) => {
      if (!query) return true;
      const values = [
        l.displayMessage,
        l.eventType,
        l.actor?.alternateId,
        l.outcome?.result,
        l.securityContext?.ipAddress,
      ];
      return values.some((v) =>
        String(v ?? "")
          .toLowerCase()
          .includes(query),
      );
    })
    .sort((a, b) => compareEventRows(a, b, eventTableState.sort));
}

function compareEventRows(a, b, sortKey) {
  const compare = (left, right) =>
    String(left ?? "").localeCompare(String(right ?? ""), undefined, {
      numeric: true,
      sensitivity: "base",
    });

  switch (sortKey) {
    case "published_asc":
      return new Date(a.published) - new Date(b.published);
    case "published_desc":
      return new Date(b.published) - new Date(a.published);
    case "event_asc":
      return compare(
        a.displayMessage ?? a.eventType,
        b.displayMessage ?? b.eventType,
      );
    case "event_desc":
      return compare(
        b.displayMessage ?? b.eventType,
        a.displayMessage ?? a.eventType,
      );
    case "actor_asc":
      return compare(a.actor?.alternateId, b.actor?.alternateId);
    case "actor_desc":
      return compare(b.actor?.alternateId, a.actor?.alternateId);
    case "outcome_asc":
      return compare(a.outcome?.result, b.outcome?.result);
    case "outcome_desc":
      return compare(b.outcome?.result, a.outcome?.result);
    default:
      return 0;
  }
}

function renderEventsPanel() {
  const rows = applyEventFilters();
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / EVENTS_PAGE_SIZE));
  eventTableState.page = Math.min(
    Math.max(1, eventTableState.page),
    totalPages,
  );

  const start = (eventTableState.page - 1) * EVENTS_PAGE_SIZE;
  const pageRows = rows.slice(start, start + EVENTS_PAGE_SIZE);
  renderTable(
    "events-table",
    pageRows,
    ["Time", "Event", "Actor", "Outcome"],
    (l) => [
      fmtTime(l.published),
      l.displayMessage ?? l.eventType,
      l.actor?.alternateId ?? "—",
      badge(l.outcome?.result),
    ],
  );

  const pagination = document.getElementById("events-pagination");
  if (pagination) {
    pagination.innerHTML = total
      ? `<div class="pager">
           <button class="btn btn-outline" onclick="onEventsPage(-1)" ${
             eventTableState.page === 1 ? "disabled" : ""
           }>Prev</button>
           <span>Page ${eventTableState.page} of ${totalPages}</span>
           <button class="btn btn-outline" onclick="onEventsPage(1)" ${
             eventTableState.page === totalPages ? "disabled" : ""
           }>Next</button>
         </div>
         <div class="pager"><span>${total} matching event${
           total === 1 ? "" : "s"
         }</span></div>`
      : `<div class="pager"><span>No matching events.</span></div>`;
  }
}

// ─── TOKEN LIFETIME BAR ───────────────────────────────────────────────────────
let tokenWatchInterval = null;

function startTokenWatcher() {
  clearInterval(tokenWatchInterval);
  tokenWatchInterval = setInterval(updateTokenLifetimeBar, 5000);
}

function updateTokenLifetimeBar() {
  const bar = document.getElementById("token-bar");
  const lbl = document.getElementById("token-lifetime-lbl");
  if (!bar || !tokenStore.expiresAt) return;

  const totalMs = 3600_000; // assume 1 h token lifetime
  const remaining = Math.max(0, tokenStore.expiresAt - Date.now());
  const pctLeft = Math.round((remaining / totalMs) * 100);
  bar.style.width = `${pctLeft}%`;
  bar.className =
    "token-bar-fill " +
    (pctLeft < 15 ? "danger" : pctLeft < 40 ? "warn" : "ok");
  const mins = Math.floor(remaining / 60_000);
  const secs = Math.floor((remaining % 60_000) / 1000);
  lbl.textContent =
    remaining > 0
      ? `Access token expires in ${mins}m ${secs}s`
      : "Access token expired — refreshing…";

  if (remaining <= 0 && tokenStore.refreshToken) {
    refreshAccessToken().catch((e) => showError(e.message));
  }
}

// ─── UI HELPERS ───────────────────────────────────────────────────────────────
function setStatus(msg) {
  const el = document.getElementById("status-msg");
  if (el) el.textContent = msg;
}

function showError(msg) {
  const bar = document.getElementById("error-bar");
  if (!bar) return;
  bar.textContent = "⚠ " + msg;
  bar.style.display = "block";
  console.error(msg);
  setTimeout(() => {
    bar.style.display = "none";
  }, 5000);
}

function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function pct(val, total) {
  return total ? `${Math.round((val / total) * 100)}%` : "0%";
}

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function badge(result) {
  if (!result) return '<span class="badge">—</span>';
  const cls =
    result === "SUCCESS"
      ? "success"
      : result === "FAILURE"
        ? "failure"
        : "neutral";
  return `<span class="badge ${cls}">${esc(result)}</span>`;
}

// ─── POPUP CALLBACK HANDLER ───────────────────────────────────────────────────
// If THIS page is loaded as the redirect target (popup), post message to opener
(function handlePopupReturn() {
  const url = window.location.href;
  const params = new URLSearchParams(window.location.search);
  if (params.has("code") || params.has("error")) {
    if (window.opener) {
      window.opener.postMessage({ type: "okta_callback", url }, "*");
      window.close();
    }
  }
})();

// ─── INIT ─────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadPersistedSession();

  // Restore domain + clientId inputs if available
  if (tokenStore.oktaDomain) {
    const inp = document.getElementById("okta-domain");
    if (inp) inp.value = tokenStore.oktaDomain;
  }
  if (tokenStore.clientId) {
    const inp = document.getElementById("okta-client-id");
    if (inp) inp.value = tokenStore.clientId;
  }

  // If we have a refresh token but no access token, try to silently refresh
  if (tokenStore.refreshToken && !tokenStore.accessToken) {
    setStatus("Restoring session…");
    refreshAccessToken()
      .then(onAuthenticated)
      .catch(() => showLoginScreen());
  } else if (tokenStore.accessToken && !isExpired()) {
    onAuthenticated();
  } else {
    showLoginScreen();
  }

  // Wire dismiss on error bar
  const errBar = document.getElementById("error-bar");
  if (errBar)
    errBar.addEventListener("click", () => {
      errBar.style.display = "none";
    });
});
