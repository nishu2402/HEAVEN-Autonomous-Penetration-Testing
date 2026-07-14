// HEAVEN — API client.
//
// Auth token is persisted in sessionStorage so a page refresh keeps you signed
// in; it clears automatically when the browser tab closes. Tradeoff:
// sessionStorage is readable by any XSS while the tab is open — acceptable for
// an operator console that already sits behind login, and far better UX than
// logging out on every refresh. For maximum hardening, switch to an httpOnly
// refresh cookie (a server-side change).
// On 401 the token is cleared, a "session expired" event fires (toast), and
// ProtectedRoute redirects to /login.

const SS_KEY = "heaven.auth";

let authToken = null;
let currentUser = null;
let mustChangePassword = false;
const listeners = new Set();
const sessionExpiredListeners = new Set();

const API_BASE = "/api";

function persistAuth() {
  try {
    if (authToken && currentUser) {
      sessionStorage.setItem(
        SS_KEY,
        JSON.stringify({ token: authToken, user: currentUser, mustChangePassword }),
      );
    } else {
      sessionStorage.removeItem(SS_KEY);
    }
  } catch { /* sessionStorage unavailable (private mode / disabled) */ }
}

function hydrateAuth() {
  try {
    const raw = sessionStorage.getItem(SS_KEY);
    if (!raw) return;
    const d = JSON.parse(raw);
    authToken = d.token || null;
    currentUser = d.user || null;
    mustChangePassword = Boolean(d.mustChangePassword);
  } catch { /* corrupt/blocked storage — start logged out */ }
}

// Restore any existing session before the app first renders.
hydrateAuth();

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

// Fired when the server rejects our token (401). The app shows a toast; the
// redirect to /login is handled by ProtectedRoute reacting to onAuthChange.
export function onSessionExpired(fn) {
  sessionExpiredListeners.add(fn);
  return () => sessionExpiredListeners.delete(fn);
}

function emitSessionExpired(message) {
  for (const fn of sessionExpiredListeners) {
    try { fn(message); } catch { /* swallow */ }
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
  mustChangePassword = Boolean(data.must_change_password);
  persistAuth();
  notify();
  return data.user;
}

// True when the server flagged the account as still on the default password.
export function needsPasswordChange() {
  return mustChangePassword;
}

export async function changePassword(currentPassword, newPassword) {
  const r = await fetch(`${API_BASE}/auth/change-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch { detail = "Password change failed"; }
    throw new Error(detail);
  }
  mustChangePassword = false;
  persistAuth();
  notify();
  return true;
}

// Fetch a report as a blob and trigger a browser download. A plain <a download>
// can't be used because the export endpoint requires the bearer auth header.
export async function downloadReport(format, opts = {}) {
  const q = new URLSearchParams({ format });
  if (opts.engagement) q.append("engagement", opts.engagement);
  if (opts.framework) q.append("framework", opts.framework);
  const r = await fetch(`${API_BASE}/report/export?${q.toString()}`, {
    headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
  });
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch { detail = r.statusText; }
    throw new Error(detail || `Export failed (${r.status})`);
  }
  const blob = await r.blob();
  const cd = r.headers.get("content-disposition") || "";
  const m = /filename="?([^"]+)"?/.exec(cd);
  const filename = m ? m[1] : `heaven-report.${format}`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return filename;
}

// Open the professional HTML report in a new browser tab (respects auth by
// fetching with the bearer token, then opening a blob URL). The report has a
// built-in "Print / Save as PDF" button for a one-click PDF.
export async function previewReport(opts = {}) {
  const q = new URLSearchParams({ format: "html" });
  if (opts.engagement) q.append("engagement", opts.engagement);
  const r = await fetch(`${API_BASE}/report/export?${q.toString()}`, {
    headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
  });
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch { detail = r.statusText; }
    throw new Error(detail || `Preview failed (${r.status})`);
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const w = window.open(url, "_blank", "noopener");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  if (!w) throw new Error("Popup blocked — allow popups to preview the report");
  return true;
}

// Download the CycloneDX SBOM (discovered services + CVE findings) for the
// active engagement. Same auth-header constraint as report export, so it goes
// through fetch + blob rather than a bare <a download>.
export async function downloadSbom(opts = {}) {
  const q = new URLSearchParams({ download: "true" });
  if (opts.engagement) q.append("engagement", opts.engagement);
  const r = await fetch(`${API_BASE}/sbom?${q.toString()}`, {
    headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
  });
  if (!r.ok) {
    let detail;
    try { detail = (await r.json()).detail; } catch { detail = r.statusText; }
    throw new Error(detail || `SBOM export failed (${r.status})`);
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "heaven-sbom.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return "heaven-sbom.json";
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
  persistAuth();
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
    persistAuth();
    notify();
    emitSessionExpired("Your session expired — please sign in again.");
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
  // AI-assisted remediation for one finding. Falls back to the knowledge-base
  // remediation server-side when no LLM key is set (response.ai_generated says
  // which path produced the text).
  remediate: (id) =>
    api(`/findings/${encodeURIComponent(id)}/remediation`, { method: "POST" }),
  topFindings: (limit = 5) => api(`/engagement/top-findings?limit=${limit}`),
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
  get: (id, includeFindings = false) =>
    api(`/scans/${encodeURIComponent(id)}${includeFindings ? "?include_findings=true" : ""}`),
  // Findings produced by one scan (deduped rows from the engagement store).
  findings: (id) =>
    api(`/engagement/findings?scan_id=${encodeURIComponent(id)}&limit=1000`),
  // Cancel a running scan, or permanently remove a finished one.
  cancel: (id) => api(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
  remove: (id) => api(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

// Engagements — list all scanned engagements and switch which one the whole
// app (dashboard, findings, reports) is currently viewing.
export const Engagements = {
  list: () => api("/engagements"),
  setActive: (name) =>
    api("/engagements/active", { method: "POST", body: JSON.stringify({ name }) }),
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

// System health — GET /api/system/health mirrors `heaven doctor`. Shape:
// { version, python, tools:[{name,present,purpose,hint}], tools_missing,
//   install_command:"heaven install-tools", settings, modules, next_steps, … }.
// `install_command` powers the "install missing tools" CTA on the Health page.
export const System = {
  health: () => api("/system/health"),
};

// Demo / sample data — POST /api/demo/seed populates the active engagement with
// realistic example findings so a fresh install shows a full dashboard.
export const Demo = {
  seed: () => api("/demo/seed", { method: "POST" }),
  scan: () => api("/demo/scan", { method: "POST" }),
};

// Settings — API keys & integrations. Backed by GET/POST /api/settings, which
// persist to .env + the running process (shared with `heaven config` + the
// wizard). Secrets come back masked only; sending an empty value clears a key.
export const Settings = {
  get: () => api("/settings"),
  update: (settings) =>
    api("/settings", { method: "POST", body: JSON.stringify({ settings }) }),
  testLlm: () => api("/settings/test-llm", { method: "POST" }),
  testNvd: () => api("/settings/test-nvd", { method: "POST" }),
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
  // Advanced, self-contained post-exploitation (SSH-based, secrets redacted).
  enum: (body) =>
    api(`/postex/enum/run`, { method: "POST", body: JSON.stringify(body) }),
  winEnum: (body) =>
    api(`/postex/win-enum/run`, { method: "POST", body: JSON.stringify(body) }),
  loot: (body) =>
    api(`/postex/loot/run`, { method: "POST", body: JSON.stringify(body) }),
  full: (body) =>
    api(`/postex/full/run`, { method: "POST", body: JSON.stringify(body) }),
  linpeas: (body) =>
    api(`/postex/linpeas/run`, { method: "POST", body: JSON.stringify(body) }),
  bloodhound: (body) =>
    api(`/postex/bloodhound/run`, { method: "POST", body: JSON.stringify(body) }),
  credReuse: (body) =>
    api(`/postex/cred-reuse/run`, { method: "POST", body: JSON.stringify(body) }),
};

export const Cloud = {
  // Credential-free cloud misconfiguration checks.
  storage: (body) =>
    api(`/cloud/storage`, { method: "POST", body: JSON.stringify(body) }),
};

export const Cve = {
  // Dynamic live CVE lookup (NVD + CIRCL) for products not in the local DB.
  lookup: (body) =>
    api(`/cve/lookup`, { method: "POST", body: JSON.stringify(body) }),
};

export const Priors = {
  train: () => api(`/priors/train`, { method: "POST" }),
};

export const SIEM = {
  status: () => api(`/siem/status`),
};

export const Methodology = {
  // Returns { standards: [{name, meta_title, subtitle, summary, categories:[
  //   {code, title, rows:[{id, item, description, coverage, status, exercised,
  //   exercised_count}]}]}], engagement: {name, findings_total, vuln_types,
  //   owasp_categories, modules_active}, docs:[...] }.  The `standards` matrices
  //   are computed from the mapping docs; each row's `exercised` flag reflects
  //   whether the detector it names produced a finding in the active engagement.
  list: () => api(`/methodology`),
};

export const Benchmark = {
  // Latest scanner benchmark. Prefers a valid live-DVWA aggregate, else the
  // always-fresh native controlled run (`heaven benchmark`); washouts are skipped.
  // → { available, source: "native-controlled"|"live-dvwa", label, target,
  //     markdown, metrics: { precision, recall, f1 }, generated_at, size_bytes }
  // or { available: false, note } when nothing has been generated yet.
  latest: () => api(`/benchmark/results`),
};

// ── Sync round 2: autonomous loop, coverage, lateral, knowledge, ExploitDB ──

export const Autonomous = {
  // POST /api/autonomous/run → { job_id, status: "running" }
  // The run executes in the background on the server; poll job() for progress.
  run: (body) =>
    api(`/autonomous/run`, { method: "POST", body: JSON.stringify(body) }),
  // GET /api/autonomous/jobs/{id} → { status, result, error, ... }
  job: (jobId) => api(`/autonomous/jobs/${encodeURIComponent(jobId)}`),
  // GET /api/autonomous/jobs → { jobs: [...] }
  jobs: () => api(`/autonomous/jobs`),
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

// ── Sync round 4: SAST scanner ──

export const SAST = {
  // POST /api/sast/scan
  scan: (body) =>
    api(`/sast/scan`, { method: "POST", body: JSON.stringify(body) }),
  // GET /api/sast/rules
  rules: () => api(`/sast/rules`),
};

// ── Software Composition Analysis (OSV.dev) ──

export const SCA = {
  // POST /api/sca — audit dependency manifests against OSV.dev
  scan: (body) =>
    api(`/sca`, { method: "POST", body: JSON.stringify(body) }),
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

// Live progress for an autonomous job. `onMessage` receives parsed JSON
// ({type:"snapshot"|"iteration"|"done", ...}). Returns the WebSocket (or null
// if not authenticated) so the caller can close it. Polling remains a fallback.
export function openAutonomousStream(jobId, onMessage) {
  if (!authToken) return null;
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(
    `${proto}//${window.location.host}/api/autonomous/jobs/${encodeURIComponent(jobId)}` +
    `/stream?token=${encodeURIComponent(authToken)}`
  );
  ws.onmessage = (ev) => {
    try { onMessage(JSON.parse(ev.data)); } catch { /* ignore malformed frame */ }
  };
  return ws;
}
