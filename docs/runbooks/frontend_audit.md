# HEAVEN — Frontend Audit & Rebuild Runbook

The `heaven-ui/` directory contains a React + Vite frontend. The shipped `dist/` was built before the auth/RBAC API rewrite. This runbook gets the frontend talking to the new auth flow and runs a security audit.

---

## What's there

- `heaven-ui/src/` — React 18 source
- `heaven-ui/dist/` — pre-built static bundle (mounted at `/` by FastAPI)
- `heaven-ui/package.json` — dependency manifest
- `heaven-ui/vite.config.js` — build config

---

## Step 1 — Audit dependencies

```bash
cd heaven-ui
npm install
npm audit                       # surfaces CVEs in deps
npm audit --production          # CVEs in runtime deps only
npm outdated                    # what's behind on versions
```

Expected: a handful of medium severity issues from transitive deps. Anything `high` or `critical` should be fixed via `npm audit fix` or by upgrading the offending package.

For a deeper SCA audit, run:

```bash
npx better-npm-audit audit
# or
npx audit-ci --moderate
```

---

## Step 2 — Connect to the new auth API

The shipped frontend predates the new `/api/auth/login` endpoint. After this fix-pass it needs to:

1. POST to `/api/auth/login` with `{username, password}`.
2. Store the returned `token` (NOT in `localStorage` — use a memory store + httpOnly cookie set via the API response if you want persistence; localStorage is exposed to any XSS).
3. Send `Authorization: Bearer <token>` on every subsequent fetch.
4. Add a 401 interceptor that redirects to login on token expiry.
5. Handle 429 (rate-limited) gracefully on the login screen.

Sketch:

```javascript
// heaven-ui/src/api.js
const API_BASE = import.meta.env.VITE_API_BASE || "/api";

let authToken = null;

export async function login(username, password) {
  const r = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (r.status === 429) throw new Error("Too many login attempts. Try again in a minute.");
  if (!r.ok) throw new Error("Login failed");
  const data = await r.json();
  authToken = data.token;
  return data.user;
}

export async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
  const r = await fetch(`${API_BASE}${path}`, { ...opts, headers });
  if (r.status === 401) {
    authToken = null;
    window.location.href = "/login";
    return null;
  }
  if (!r.ok) throw new Error(`API ${path} failed: ${r.status}`);
  return r.json();
}

export async function logout() {
  await api("/auth/logout", { method: "POST" });
  authToken = null;
}
```

---

## Step 3 — WebSocket auth

The `/api/ws/scan/{id}` and `/api/ws/logs` endpoints now require a token via query string (browsers can't set headers on WebSocket open):

```javascript
const ws = new WebSocket(`ws://${location.host}/api/ws/scan/${scanId}?token=${authToken}`);
```

---

## Step 4 — Add CSP, X-Frame-Options, and friends

The FastAPI server doesn't currently set security headers on the static frontend. Add a middleware:

```python
# heaven/api/server.py — add this near the CORS middleware
@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith("/api/docs"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "  # Vite needs unsafe-inline for hydration
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none';"
        )
    return response
```

(I deliberately did NOT add this in the API rewrite because it interacts with how the React bundle is loaded — needs to be added once and tested against the actual UI.)

---

## Step 5 — Rebuild

```bash
cd heaven-ui
npm run build
```

Verify the new `dist/` is what FastAPI serves:

```bash
curl http://localhost:8443/ | grep -o '<title>[^<]*</title>'
# should print: <title>HEAVEN Command Centre</title>
```

---

## Step 6 — Subresource Integrity (optional but recommended)

If the frontend pulls any CDN script (Google Fonts, etc.), add SRI hashes:

```html
<link rel="stylesheet" href="https://fonts.googleapis.com/..." integrity="sha384-..." crossorigin="anonymous">
```

The Vite plugin `vite-plugin-sri` does this automatically:

```bash
npm install --save-dev vite-plugin-sri
```

```javascript
// vite.config.js
import sri from "vite-plugin-sri";
export default { plugins: [sri()] };
```

---

## Out-of-scope for this runbook

- Actual UI design / UX changes
- New pages / features
- Charts library swap (recharts → chart.js or vice versa)

Those are product decisions, not security/correctness fixes.
