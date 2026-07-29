# HEAVEN — Frontend Security Posture & Re-Audit Runbook

The `heaven-ui/` directory is a React 19 + Vite single-page app. The built
`dist/` is mounted at `/` by the FastAPI server and talks to the RBAC-protected
API. This runbook documents the security controls that already ship and gives a
checklist for re-auditing them (e.g. after a dependency bump or an API change).

---

## What's there

- `heaven-ui/src/` — React 19 source
- `heaven-ui/dist/` — pre-built static bundle (served at `/` by FastAPI)
- `heaven-ui/package.json` — dependency manifest
- `heaven-ui/vite.config.js` — build config

---

## Controls already implemented (verify, don't rebuild)

| Control | Where | Notes |
|---|---|---|
| **Token auth** | `heaven-ui/src/api.js` → `POST /api/auth/login` | Returns a JWT; sent as `Authorization: Bearer <token>` on every request. |
| **In-memory token store** | `heaven-ui/src/api.js` | Token is held in memory, **not** `localStorage` (which any XSS could read). |
| **401 interceptor** | `heaven-ui/src/api.js` | On a rejected token the client clears state, fires a "session expired" toast, and routes to login. |
| **Rate-limit handling** | `LoginPage.jsx` | `429` on the login screen is surfaced gracefully. |
| **WebSocket auth** | `?token=` query param | Browsers can't set headers on WS open, so `/api/ws/*` takes the token via query string. |
| **Security headers + CSP** | `heaven/api/server.py` (security-headers middleware) | Sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, and a `Content-Security-Policy` with `frame-ancestors 'none'`. |

Because these are wired, a re-audit is about **confirming they still hold**, not
adding them.

---

## Step 1 — Audit dependencies

```bash
cd heaven-ui
npm ci                          # reproducible install from the lockfile
npm audit                       # surfaces CVEs in deps
npm audit --production          # CVEs in runtime deps only
npm outdated                    # what's behind on versions
```

Anything `high` or `critical` should be fixed via `npm audit fix` or by upgrading
the offending package. HEAVEN's own dependency SCA (`heaven sca heaven-ui`)
scores the same tree against OSV.dev if you want a second source.

For a deeper third-party audit:

```bash
npx better-npm-audit audit
# or
npx audit-ci --moderate
```

---

## Step 2 — Confirm the security headers are served

```bash
curl -sI http://localhost:8443/ | grep -iE 'content-security-policy|x-frame-options|x-content-type-options|referrer-policy'
```

All four headers should be present. If you changed
`heaven/api/server.py`'s middleware, re-run this after a restart. The CSP
intentionally allows `'unsafe-inline'` for `script-src`/`style-src` because the
Vite bundle needs it for hydration — tightening that requires a nonce/hash build
step and must be tested against the live UI before shipping.

---

## Step 3 — Rebuild and verify what FastAPI serves

```bash
cd heaven-ui
npm run build
```

```bash
curl -s http://localhost:8443/ | grep -o '<title>[^<]*</title>'
# should print: <title>HEAVEN Command Centre</title>
```

If the title or a page 404s, the served `dist/` is stale — rebuild and confirm
the server is pointed at `heaven-ui/dist`.

---

## Step 4 — Subresource Integrity (optional)

The app's CSP `script-src` permits `cdn.jsdelivr.net`. If the build pulls any
script or style from that (or any) CDN, add SRI hashes so a compromised CDN
can't inject code:

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

- UI design / UX changes
- New pages / features
- Charts-library swaps

Those are product decisions, not security/correctness work.
