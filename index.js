// ─── CONFIG ──────────────────────────────────────────────────────────────────
const CONFIG = {
  scopes: "openid profile email offline_access okta.logs.read",
};

function getRedirectUri() {
  return `${window.location.origin}${window.location.pathname}`;
}

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
  [
    "okta_refresh",
    "okta_domain",
    "okta_client_id",
    "pkce_verifier",
    "oauth_state",
    "okta_domain_pending",
    "okta_client_id_pending",
  ].forEach((k) => sessionStorage.removeItem(k));
}

function isExpired() {
  return Date.now() >= tokenStore.expiresAt - 60_000;
}

// ─── PKCE HELPERS ─────────────────────────────────────────────────────────────
function randomString(len) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  return Array.from(
    crypto.getRandomValues(new Uint8Array(len)),
    (v) => chars[v % chars.length],
  ).join("");
}

async function generatePKCE() {
  const verifier = randomString(64);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
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
    redirect_uri: getRedirectUri(),
    state,
    code_challenge_method: "S256",
    code_challenge: challenge,
  });

  window.open(
    `https://${domain}/oauth2/v1/authorize?${params}`,
    "okta_auth",
    "width=520,height=660,left=200,top=100",
  );
  setStatus("Waiting for authentication in popup…");
};

window.addEventListener("message", async (event) => {
  if (event.data?.type === "okta_callback")
    await handleCallback(event.data.url);
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
  if (retState !== sessionStorage.getItem("oauth_state")) {
    showError("State mismatch — possible CSRF.");
    return;
  }

  const verifier = sessionStorage.getItem("pkce_verifier");
  const domain = sessionStorage.getItem("okta_domain_pending");
  const clientId = sessionStorage.getItem("okta_client_id_pending");
  [
    "pkce_verifier",
    "oauth_state",
    "okta_domain_pending",
    "okta_client_id_pending",
  ].forEach((k) => sessionStorage.removeItem(k));

  setStatus("Exchanging code for tokens…");
  try {
    const resp = await fetch(`https://${domain}/oauth2/v1/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        redirect_uri: getRedirectUri(),
        code,
        code_verifier: verifier,
      }),
    });
    if (!resp.ok) {
      const e = await resp.json().catch(() => ({}));
      throw new Error(e.error_description ?? resp.statusText);
    }
    storeTokens(await resp.json(), domain, clientId);
    onAuthenticated();
  } catch (err) {
    showError(`Token exchange failed: ${err.message}`);
  }
}

async function refreshAccessToken() {
  if (!tokenStore.oktaDomain || !tokenStore.refreshToken)
    throw new Error("No refresh token");
  const resp = await fetch(`https://${tokenStore.oktaDomain}/oauth2/v1/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: tokenStore.clientId,
      scope: CONFIG.scopes,
      refresh_token: tokenStore.refreshToken,
    }),
  });
  if (!resp.ok) {
    clearTokens();
    showLoginScreen();
    throw new Error("Refresh token expired — please log in again.");
  }
  storeTokens(await resp.json());
  updateTokenLifetimeBar();
}

async function getValidToken() {
  if (isExpired()) await refreshAccessToken();
  return tokenStore.accessToken;
}

// ─── OKTA LOGS API ────────────────────────────────────────────────────────────
async function fetchLogs(since) {
  const token = await getValidToken();
  const params = new URLSearchParams({ limit: 200, since });
  const resp = await fetch(
    `https://${tokenStore.oktaDomain}/api/v1/logs?${params}`,
    {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    },
  );
  if (!resp.ok) throw new Error(`Logs API ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

// ─── AI SECURITY ANALYST ─────────────────────────────────────────────────────
let currentLogs = [];
let aiChatHistory = [];

function getAiApiKey() {
  return sessionStorage.getItem("ai_api_key") || "";
}

window.saveAiApiKey = function () {
  const key = document.getElementById("ai-api-key-input").value.trim();
  if (!key.startsWith("sk-ant-")) {
    showError("Key should start with sk-ant-");
    return;
  }
  sessionStorage.setItem("ai_api_key", key);
  document.getElementById("ai-api-key-input").value = "•".repeat(20);
  const st = document.getElementById("ai-key-status");
  st.textContent = "✓ Saved";
  st.style.color = "var(--green)";
};

window.toggleAiPanel = function () {
  const panel = document.getElementById("ai-panel");
  const open = panel.classList.toggle("ai-panel-open");
  document.getElementById("ai-fab").textContent = open ? "✕" : "✦ Ask AI";
  if (open && aiChatHistory.length === 0) {
    appendAiMessage(
      "assistant",
      "👋 I'm your **AI Security Analyst**. I have full context of your current Okta logs. Try asking:\n\n- Are there any brute force patterns?\n- Which users look suspicious?\n- Summarize the security posture right now\n- Any anomalies I should investigate?",
    );
  }
};

window.sendAiMessage = async function () {
  const input = document.getElementById("ai-chat-input");
  const msg = input.value.trim();
  if (!msg) return;

  const apiKey = getAiApiKey();
  if (!apiKey) {
    showError("Enter your Claude API key in the AI panel first.");
    return;
  }
  if (!currentLogs.length) {
    showError("No log data loaded yet — refresh the dashboard first.");
    return;
  }

  input.value = "";
  input.disabled = true;
  document.getElementById("ai-send-btn").disabled = true;
  appendAiMessage("user", msg);
  aiChatHistory.push({ role: "user", content: msg });
  const thinking = appendAiThinking();

  try {
    const systemPrompt = buildSystemPrompt();
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true",
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 1024,
        system: systemPrompt,
        messages: aiChatHistory.slice(-12),
      }),
    });

    if (!response.ok) {
      const e = await response.json().catch(() => ({}));
      throw new Error(e.error?.message ?? `API error ${response.status}`);
    }

    const data = await response.json();
    const reply =
      data.content?.find((b) => b.type === "text")?.text ?? "No response.";
    thinking.remove();
    appendAiMessage("assistant", reply);
    aiChatHistory.push({ role: "assistant", content: reply });
  } catch (err) {
    thinking.remove();
    appendAiMessage("assistant", `⚠️ **Error:** ${err.message}`);
  } finally {
    input.disabled = false;
    document.getElementById("ai-send-btn").disabled = false;
    input.focus();
  }
};

window.clearAiChat = function () {
  aiChatHistory = [];
  document.getElementById("ai-messages").innerHTML = "";
  appendAiMessage(
    "assistant",
    "Chat cleared. Ask me anything about your Okta logs.",
  );
};

window.askQuick = function (prompt) {
  document.getElementById("ai-chat-input").value = prompt;
  sendAiMessage();
};

function buildSystemPrompt() {
  const logs = currentLogs;
  const failed = logs.filter((l) => l.outcome?.result === "FAILURE");
  const mfa = logs.filter((l) => l.eventType?.startsWith("user.mfa"));
  const policy = logs.filter((l) =>
    l.eventType?.startsWith("policy.lifecycle"),
  );

  const evtCounts = {};
  logs.forEach((l) => {
    evtCounts[l.eventType] = (evtCounts[l.eventType] ?? 0) + 1;
  });
  const topEvts = Object.entries(evtCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([t, c]) => `  ${t}: ${c}`)
    .join("\n");

  const failedByActor = {};
  failed.forEach((l) => {
    const a = l.actor?.alternateId ?? "?";
    failedByActor[a] = (failedByActor[a] ?? 0) + 1;
  });
  const topFailed = Object.entries(failedByActor)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([a, c]) => `  ${a}: ${c} failures`)
    .join("\n");

  const failedByIp = {};
  failed.forEach((l) => {
    const ip = l.securityContext?.ipAddress ?? "?";
    failedByIp[ip] = (failedByIp[ip] ?? 0) + 1;
  });
  const topIps = Object.entries(failedByIp)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, c]) => `  ${ip}: ${c} failures`)
    .join("\n");

  const notable = logs
    .filter(
      (l) =>
        l.outcome?.result === "FAILURE" ||
        l.severity === "WARN" ||
        l.severity === "ERROR",
    )
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, 40)
    .map(
      (l) =>
        `  [${l.published}] ${l.eventType} | actor:${l.actor?.alternateId ?? "?"} | result:${l.outcome?.result} | ip:${l.securityContext?.ipAddress ?? "?"} | msg:${l.outcome?.reason ?? ""}`,
    )
    .join("\n");

  const uniqueActors = [
    ...new Set(logs.map((l) => l.actor?.alternateId).filter(Boolean)),
  ];

  return `You are an expert cybersecurity analyst specializing in identity and access management (IAM) and Okta security.

You are analyzing LIVE Okta system logs from this organization. Respond as a security expert — be direct, specific, and actionable.

═══ LIVE LOG DATA — LAST 24 HOURS ═══
Total events: ${logs.length}
Failures: ${failed.length} | MFA events: ${mfa.length} | Policy changes: ${policy.length}
Unique actors: ${uniqueActors.length}
Time window: ${logs[logs.length - 1]?.published ?? "?"} → ${logs[0]?.published ?? "?"}

TOP EVENT TYPES:
${topEvts || "  (none)"}

TOP FAILING ACTORS (by failure count):
${topFailed || "  (none)"}

TOP FAILURE SOURCE IPs:
${topIps || "  (none)"}

RECENT FAILURES / WARNINGS (up to 40):
${notable || "  (none)"}
═══════════════════════════════════════

Instructions:
- Reference specific users, IPs, event types, and timestamps from the data
- Flag brute force, credential stuffing, privilege escalation, account takeover indicators
- Use **bold** for critical findings, bullet points for clarity
- Keep responses concise — lead with the most important finding
- Always end threat analysis with 1-2 concrete recommended actions`;
}

function appendAiMessage(role, text) {
  const container = document.getElementById("ai-messages");
  const div = document.createElement("div");
  div.className = `ai-msg ai-msg-${role}`;

  // Light markdown rendering
  const html = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/`(.*?)`/g, "<code>$1</code>")
    .replace(/^#{1,3} (.+)$/gm, "<strong>$1</strong>")
    .replace(/^- (.+)$/gm, "<li>$1</li>")
    .replace(/(<li>[\s\S]*?<\/li>)/g, "<ul>$1</ul>")
    .replace(/\n\n/g, "<br><br>")
    .replace(/\n/g, "<br>");

  div.innerHTML = html;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

function appendAiThinking() {
  const container = document.getElementById("ai-messages");
  const div = document.createElement("div");
  div.className = "ai-msg ai-msg-thinking";
  div.innerHTML = `<span class="ai-dot"></span><span class="ai-dot"></span><span class="ai-dot"></span>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

// ─── DASHBOARD LOGIC ──────────────────────────────────────────────────────────
let refreshTimer = null;
const EVENTS_PAGE_SIZE = 10;
let eventTableState = { rows: [], page: 1, search: "", sort: "published_desc" };

window.onEventsSearch = function (e) {
  eventTableState.search = e.target.value;
  eventTableState.page = 1;
  renderEventsPanel();
};
window.onEventsSortChange = function (e) {
  eventTableState.sort = e.target.value;
  eventTableState.page = 1;
  renderEventsPanel();
};
window.onEventsPage = function (step) {
  const totalPages = Math.max(
    1,
    Math.ceil(applyEventFilters().length / EVENTS_PAGE_SIZE),
  );
  eventTableState.page = Math.min(
    Math.max(1, eventTableState.page + step),
    totalPages,
  );
  renderEventsPanel();
};

function onAuthenticated() {
  document.getElementById("login-screen").style.display = "none";
  document.getElementById("dashboard").style.display = "block";
  const savedKey = getAiApiKey();
  if (savedKey) {
    document.getElementById("ai-api-key-input").value = "•".repeat(20);
    const st = document.getElementById("ai-key-status");
    st.textContent = "✓ Saved";
    st.style.color = "var(--green)";
  }
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
  refreshTimer = setInterval(loadDashboard, 5 * 60 * 1000);
  updateCountdown();
}

let nextRefreshAt = 0,
  countdownInterval = null;
function updateCountdown() {
  nextRefreshAt = Date.now() + 5 * 60 * 1000;
  clearInterval(countdownInterval);
  const el = document.getElementById("next-refresh");
  countdownInterval = setInterval(() => {
    const secs = Math.max(0, Math.round((nextRefreshAt - Date.now()) / 1000));
    if (el)
      el.textContent = `Auto-refresh ${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
  }, 1000);
}

window.manualRefresh = function () {
  loadDashboard();
  scheduleAutoRefresh();
};

window.logout = function () {
  clearTokens();
  clearInterval(refreshTimer);
  clearInterval(countdownInterval);
  showLoginScreen();
  document.getElementById("error-bar").style.display = "none";
};

async function loadDashboard() {
  setStatus("Fetching logs…");
  document.getElementById("refresh-btn").disabled = true;
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    currentLogs = await fetchLogs(since);
    renderDashboard(currentLogs);
    document.getElementById("last-updated").textContent =
      "Updated " + new Date().toLocaleTimeString();
    setStatus("");
  } catch (err) {
    showError(err.message);
    setStatus("");
  } finally {
    document.getElementById("refresh-btn").disabled = false;
  }
}

function renderDashboard(logs) {
  const failed = logs.filter((l) => l.outcome?.result === "FAILURE");
  const mfaEvents = logs.filter((l) => l.eventType?.startsWith("user.mfa"));
  const policyChg = logs.filter((l) =>
    l.eventType?.startsWith("policy.lifecycle"),
  );
  const suspicious = logs.filter(
    (l) =>
      l.outcome?.result === "FAILURE" && l.eventType === "user.session.start",
  );
  const uniqueIps = new Set(
    logs.map((l) => l.securityContext?.ipAddress).filter(Boolean),
  );

  document.getElementById("stat-total").textContent = logs.length;
  document.getElementById("stat-failed").textContent = failed.length;
  document.getElementById("stat-mfa").textContent = mfaEvents.length;
  document.getElementById("stat-policy").textContent = policyChg.length;
  document.getElementById("stat-ips").textContent = uniqueIps.size;

  // Risk score heuristic
  const riskScore = Math.min(
    100,
    Math.round(
      (failed.length / Math.max(logs.length, 1)) * 200 + suspicious.length * 4,
    ),
  );
  const riskEl = document.getElementById("stat-risk");
  riskEl.textContent = riskScore;
  riskEl.parentElement.className =
    "stat-card " +
    (riskScore > 60 ? "red" : riskScore > 25 ? "yellow" : "green");

  // Severity
  const sev = { DEBUG: 0, INFO: 0, WARN: 0, ERROR: 0 };
  logs.forEach((l) => {
    const s = l.severity?.toUpperCase();
    if (s in sev) sev[s]++;
  });
  ["DEBUG", "INFO", "WARN", "ERROR"].forEach((s) => {
    document.getElementById(`sev-${s.toLowerCase()}`).style.width = pct(
      sev[s],
      logs.length,
    );
    document.getElementById(`sev-${s.toLowerCase()}-lbl`).textContent =
      `${s} ${sev[s]}`;
  });

  renderHourlyChart(logs);

  // Suspicious logins
  renderTable(
    "suspicious-table",
    suspicious.slice(0, 25),
    ["Time", "User", "IP", "Country", "Reason"],
    (l) => [
      fmtTime(l.published),
      esc(l.actor?.alternateId ?? "—"),
      esc(l.securityContext?.ipAddress ?? "—"),
      esc(l.client?.geographicalContext?.country ?? "—"),
      esc(l.outcome?.reason ?? "—"),
    ],
  );

  // Top actors
  const actors = {};
  logs.forEach((l) => {
    const a = l.actor?.alternateId ?? "unknown";
    actors[a] = (actors[a] ?? 0) + 1;
  });
  const topActors = Object.entries(actors)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  document.getElementById("top-actors").innerHTML =
    topActors
      .map(
        ([name, count]) =>
          `<div class="actor-row">
      <span class="actor-name" title="${esc(name)}">${esc(name)}</span>
      <span class="actor-bar-wrap"><span class="actor-bar" style="width:${pct(count, topActors[0][1])}"></span></span>
      <span class="actor-count">${count}</span>
    </div>`,
      )
      .join("") || '<p class="empty">No actor data.</p>';

  // Top event types
  const evtCounts = {};
  logs.forEach((l) => {
    evtCounts[l.eventType] = (evtCounts[l.eventType] ?? 0) + 1;
  });
  const topEvts = Object.entries(evtCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  document.getElementById("event-types-list").innerHTML =
    topEvts
      .map(
        ([t, c]) =>
          `<div class="actor-row">
      <span class="actor-name" title="${esc(t)}">${esc(t)}</span>
      <span class="actor-bar-wrap"><span class="actor-bar" style="width:${pct(c, topEvts[0][1])};background:var(--accent2)"></span></span>
      <span class="actor-count">${c}</span>
    </div>`,
      )
      .join("") || '<p class="empty">No data.</p>';

  // Event log table
  eventTableState.rows = [...logs]
    .sort((a, b) => new Date(b.published) - new Date(a.published))
    .slice(0, 200);
  eventTableState.page = 1;
  renderEventsPanel();
}

function renderHourlyChart(logs) {
  const hours = {};
  for (let i = 23; i >= 0; i--)
    hours[new Date(Date.now() - i * 3600_000).getHours()] = 0;
  logs.forEach((l) => {
    const h = new Date(l.published).getHours();
    hours[h] = (hours[h] ?? 0) + 1;
  });
  const vals = Object.values(hours);
  const max = Math.max(...vals, 1);
  document.getElementById("hourly-chart").innerHTML = Object.keys(hours)
    .map(
      (h, i) =>
        `<div class="bar-col">
      <div class="bar-fill" style="height:${Math.round((vals[i] / max) * 100)}%" title="${vals[i]} events at ${h}:00"></div>
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
      return [
        l.displayMessage,
        l.eventType,
        l.actor?.alternateId,
        l.outcome?.result,
        l.securityContext?.ipAddress,
      ].some((v) =>
        String(v ?? "")
          .toLowerCase()
          .includes(query),
      );
    })
    .sort((a, b) => {
      const cmp = (x, y) =>
        String(x ?? "").localeCompare(String(y ?? ""), undefined, {
          numeric: true,
          sensitivity: "base",
        });
      switch (eventTableState.sort) {
        case "published_asc":
          return new Date(a.published) - new Date(b.published);
        case "published_desc":
          return new Date(b.published) - new Date(a.published);
        case "event_asc":
          return cmp(
            a.displayMessage ?? a.eventType,
            b.displayMessage ?? b.eventType,
          );
        case "event_desc":
          return cmp(
            b.displayMessage ?? b.eventType,
            a.displayMessage ?? a.eventType,
          );
        case "actor_asc":
          return cmp(a.actor?.alternateId, b.actor?.alternateId);
        case "actor_desc":
          return cmp(b.actor?.alternateId, a.actor?.alternateId);
        case "outcome_asc":
          return cmp(a.outcome?.result, b.outcome?.result);
        case "outcome_desc":
          return cmp(b.outcome?.result, a.outcome?.result);
        default:
          return 0;
      }
    });
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

  renderTable(
    "events-table",
    rows.slice(start, start + EVENTS_PAGE_SIZE),
    ["Time", "Event", "Actor", "IP", "Outcome"],
    (l) => [
      fmtTime(l.published),
      `<span title="${esc(l.eventType)}">${esc(l.displayMessage ?? l.eventType)}</span>`,
      esc(l.actor?.alternateId ?? "—"),
      esc(l.securityContext?.ipAddress ?? "—"),
      badge(l.outcome?.result),
    ],
  );

  const pg = document.getElementById("events-pagination");
  if (pg) {
    pg.innerHTML = total
      ? `<div class="pager">
           <button class="btn btn-outline" onclick="onEventsPage(-1)" ${eventTableState.page === 1 ? "disabled" : ""}>← Prev</button>
           <span>Page ${eventTableState.page} of ${totalPages}</span>
           <button class="btn btn-outline" onclick="onEventsPage(1)" ${eventTableState.page === totalPages ? "disabled" : ""}>Next →</button>
         </div>
         <div class="pager"><span>${total} matching event${total === 1 ? "" : "s"}</span></div>`
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
  const remaining = Math.max(0, tokenStore.expiresAt - Date.now());
  const pctLeft = Math.round((remaining / 3600_000) * 100);
  bar.style.width = `${pctLeft}%`;
  bar.className =
    "token-bar-fill " +
    (pctLeft < 15 ? "danger" : pctLeft < 40 ? "warn" : "ok");
  const mins = Math.floor(remaining / 60_000);
  const secs = Math.floor((remaining % 60_000) / 1000);
  lbl.textContent =
    remaining > 0 ? `Token: ${mins}m ${secs}s` : "Token expired — refreshing…";
  if (remaining <= 0 && tokenStore.refreshToken)
    refreshAccessToken().catch((e) => showError(e.message));
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
  }, 6000);
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
(function handlePopupReturn() {
  const params = new URLSearchParams(window.location.search);
  if ((params.has("code") || params.has("error")) && window.opener) {
    window.opener.postMessage(
      { type: "okta_callback", url: window.location.href },
      "*",
    );
    window.close();
  }
})();

// ─── INIT ─────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  loadPersistedSession();

  if (tokenStore.oktaDomain) {
    const inp = document.getElementById("okta-domain");
    if (inp) inp.value = tokenStore.oktaDomain;
  }
  if (tokenStore.clientId) {
    const inp = document.getElementById("okta-client-id");
    if (inp) inp.value = tokenStore.clientId;
  }

  // Enter to send AI message
  document.getElementById("ai-chat-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendAiMessage();
    }
  });

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

  document.getElementById("error-bar")?.addEventListener("click", () => {
    document.getElementById("error-bar").style.display = "none";
  });
});
