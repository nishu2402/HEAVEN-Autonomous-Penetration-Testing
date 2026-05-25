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

// ── New API surface (publication-gap features) ──
// Mirrors the FastAPI endpoints added in heaven/api/server.py.
// Each helper degrades gracefully when the backend isn't running new code yet:
// callers should check for "skipped" / "available: false" in the response.

export const Replay = {
  // POST /api/scans/{scan_id}/replay
  scan: (scanId, body = {}) =>
    api(`/scans/${encodeURIComponent(scanId)}/replay`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
};

export const ExploitProof = {
  // POST /api/findings/{finding_id}/prove
  prove: (findingId, opts = {}) => {
    const q = new URLSearchParams();
    if (opts.engagement) q.append("engagement", opts.engagement);
    if (opts.external_callback_url)
      q.append("external_callback_url", opts.external_callback_url);
    const tail = q.toString() ? `?${q.toString()}` : "";
    return api(`/findings/${encodeURIComponent(findingId)}/prove${tail}`, {
      method: "POST",
    });
  },
};

export const AI = {
  // POST /api/ai/{kind}/run — kind ∈ {recon-parse, plan, fp-review}
  reconParse: (recon) =>
    api(`/ai/recon-parse/run`, { method: "POST", body: JSON.stringify({ recon }) }),
  plan: (findings, assets = [], objective_hint = "") =>
    api(`/ai/plan/run`, {
      method: "POST",
      body: JSON.stringify({ findings, assets, objective_hint }),
    }),
  fpReview: (finding) =>
    api(`/ai/fp-review/run`, { method: "POST", body: JSON.stringify({ finding }) }),
};

export const Postex = {
  linpeas: (body) =>
    api(`/postex/linpeas/run`, { method: "POST", body: JSON.stringify(body) }),
  bloodhound: (body) =>
    api(`/postex/bloodhound/run`, { method: "POST", body: JSON.stringify(body) }),
  credReuse: (body) =>
    api(`/postex/cred-reuse/run`, { method: "POST", body: JSON.stringify(body) }),
};

export const Priors = {
  train: () => api(`/priors/train`, { method: "POST" }),
};

export const SIEM = {
  status: () => api(`/siem/status`),
};

export const Methodology = {
  // Returns {"docs": [{"name": "owasp_testing_guide", "content": "..."}, ...]}
  list: () => api(`/methodology`),
};

export const Benchmark = {
  // Returns {"available": bool, "markdown": "..."} for the latest aggregated run
  latest: () => api(`/benchmark/results`),
};

// ── Sync round 2: autonomous loop, coverage, lateral, knowledge, ExploitDB ──

export const Autonomous = {
  // POST /api/autonomous/run
  run: (body) =>
    api(`/autonomous/run`, { method: "POST", body: JSON.stringify(body) }),
};

export const Coverage = {
  // GET /api/coverage?engagement=...&use_llm=true|false
  get: (opts = {}) => {
    const q = new URLSearchParams();
    if (opts.engagement) q.append("engagement", opts.engagement);
    if (opts.use_llm === false) q.append("use_llm", "false");
    const tail = q.toString() ? `?${q.toString()}` : "";
    return api(`/coverage${tail}`);
  },
};

export const Lateral = {
  // POST /api/lateral/run
  run: (body) =>
    api(`/lateral/run`, { method: "POST", body: JSON.stringify(body) }),
};

export const Knowledge = {
  // GET /api/knowledge/stats
  stats: () => api(`/knowledge/stats`),
  // GET /api/knowledge/rank?os=...&web_tech=...&ports=22,80
  rank: (profile = {}) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(profile)) {
      if (v !== undefined && v !== null && v !== "") q.append(k, v);
    }
    return api(`/knowledge/rank?${q.toString()}`);
  },
};

export const ExploitDB = {
  // GET /api/exploitdb/{cve}
  lookup: (cve) => api(`/exploitdb/${encodeURIComponent(cve)}`),
};

// ── Sync round 3: differential scanning + ticketing ──

export const Diff = {
  // GET /api/scans/{id}/diff?baseline=...&engagement=...
  compute: (currentScanId, baselineScanId, opts = {}) => {
    const q = new URLSearchParams();
    q.append("baseline", baselineScanId);
    if (opts.engagement) q.append("engagement", opts.engagement);
    if (opts.include_unchanged) q.append("include_unchanged", "true");
    return api(`/scans/${encodeURIComponent(currentScanId)}/diff?${q.toString()}`);
  },
};

export const Tickets = {
  // GET /api/tickets/status
  status: () => api(`/tickets/status`),
  // POST /api/tickets/push/{finding_id}?engagement=...
  push: (findingId, engagement) => {
    const q = engagement ? `?engagement=${encodeURIComponent(engagement)}` : "";
    return api(`/tickets/push/${encodeURIComponent(findingId)}${q}`,
               { method: "POST" });
  },
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
