// HEAVEN — API client.
// Token kept in memory only; localStorage is exposed to any XSS so we don't.
// On 401 the SPA navigates to /login (handled by ProtectedRoute).

let authToken = null;
let currentUser = null;
const listeners = new Set();

const API_BASE = "/api";

export function getToken() {
  return authToken;
}

export function getUser() {
  return currentUser;
}

export function isAuthenticated() {
  return Boolean(authToken && currentUser);
}

export function onAuthChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify() {
  for (const l of listeners) {
    try { l({ token: authToken, user: currentUser }); } catch { /* swallow */ }
  }
}

export async function login(username, password) {
  const r = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (r.status === 429) {
    const err = new Error("Too many login attempts. Try again in a minute.");
    err.code = "rate_limited";
    throw err;
  }
  if (!r.ok) {
    const err = new Error("Invalid username or password");
    err.code = "auth_failed";
    throw err;
  }
  const data = await r.json();
  authToken = data.token;
  currentUser = data.user;
  notify();
  return data.user;
}

export async function logout() {
  if (authToken) {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${authToken}` },
      });
    } catch { /* network issues during logout are fine */ }
  }
  authToken = null;
  currentUser = null;
  notify();
}

async function api(path, opts = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
  const r = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  if (r.status === 401) {
    authToken = null;
    currentUser = null;
    notify();
    throw new Error("Authentication expired");
  }
  if (r.status === 429) {
    throw new Error("Rate limited — slow down");
  }
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch { detail = r.statusText; }
    throw new Error(`API ${path} failed: ${detail}`);
  }
  // No-content endpoints
  if (r.status === 204) return null;
  return r.json();
}

// ── Endpoint helpers ──

export const Engagement = {
  summary: () => api("/engagement"),
  findings: (filters = {}) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(filters)) {
      if (v !== undefined && v !== null && v !== "") q.append(k, v);
    }
    return api(`/engagement/findings?${q.toString()}`);
  },
  evidence: (id) => api(`/engagement/findings/${id}/evidence`),
  setStatus: (id, status, notes = "") =>
    api(`/engagement/findings/${id}/status`, {
      method: "PUT",
      body: JSON.stringify({ status, notes }),
    }),
};

export const Scans = {
  create: (req) =>
    api("/scans", { method: "POST", body: JSON.stringify(req) }),
  list: (limit = 20) => api(`/scans?limit=${limit}`),
  get: (id) => api(`/scans/${id}`),
  cancel: (id) => api(`/scans/${id}`, { method: "DELETE" }),
};

export const Vulns = {
  list: (filters = {}) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(filters)) {
      if (v !== undefined && v !== null && v !== "") q.append(k, v);
    }
    return api(`/vulnerabilities?${q.toString()}`);
  },
};

export const KillChain = {
  get: (scanId = "latest") => api(`/kill-chain/${scanId}`),
};

export const Dashboard = {
  get: () => api("/dashboard"),
};

// WebSocket helper — token via query string (browsers can't set headers on WS open)
export function openLogStream(onMessage) {
  if (!authToken) return null;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(
    `${proto}//${window.location.host}/api/ws/logs?token=${encodeURIComponent(authToken)}`
  );
  ws.onmessage = (ev) => onMessage(ev.data);
  return ws;
}
