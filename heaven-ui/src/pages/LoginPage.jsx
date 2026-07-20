import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { login } from "../api";
import Logo from "../components/Logo.jsx";

const CAPS = [
  { icon: "🛰", title: "Autonomous recon", body: "LLM-driven attack-chain planning across scope" },
  { icon: "🧠", title: "ML risk triage", body: "13-feature CVSS model scores every finding" },
  { icon: "⛓", title: "Verified exploitation", body: "RCE canaries & SSRF callbacks — proven, not guessed" },
  { icon: "📡", title: "Continuous monitoring", body: "Scheduled re-scans with differential alerts" },
];

const ease = [0.22, 1, 0.36, 1];

export default function LoginPage() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const loc = useLocation();
  const dest = loc.state?.from?.pathname || "/";

  async function submit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await login(username, password);
      navigate(dest, { replace: true });
    } catch (err) {
      setError(err.message || "Authentication failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <div className="login-grid-fx" />

      {/* Left hero */}
      <motion.div
        className="login-hero"
        initial={{ opacity: 0, x: -24 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.6, ease }}
      >
        <div className="login-brand">
          <Logo size={56} className="brand-logo login-logo" />
          <div>
            <div className="login-wordmark gradient-text">HEAVEN</div>
            <div className="login-tagline">Autonomous Penetration Testing</div>
          </div>
        </div>

        <h1 className="login-headline">
          The offensive-security platform that{" "}
          <span className="gradient-text">thinks like an operator.</span>
        </h1>
        <p className="login-sub">
          Recon, exploitation, post-ex, lateral movement and reporting — orchestrated
          end-to-end, scored by ML, and verified with real proofs. One console for the
          whole engagement.
        </p>

        <div className="login-caps">
          {CAPS.map((c, i) => (
            <motion.div
              key={c.title}
              className="login-cap"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, ease, delay: 0.25 + i * 0.08 }}
            >
              <div className="login-cap-icon">{c.icon}</div>
              <div>
                <div className="login-cap-title">{c.title}</div>
                <div className="login-cap-body">{c.body}</div>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Right auth card */}
      <div className="login-panel">
        <motion.form
          onSubmit={submit}
          className="login-card card-glass"
          initial={{ opacity: 0, y: 24, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.55, ease, delay: 0.15 }}
        >
          <div className="login-card-title">Operator sign-in</div>
          <div className="login-card-sub">
            <span className="status-dot" />Encrypted session · HMAC-audited
          </div>

          <div className="login-field">
            <label htmlFor="login-user">Operator ID</label>
            <input
              id="login-user"
              className="form-input login-input"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
            />
          </div>

          <div className="login-field">
            <label htmlFor="login-pass">Access key</label>
            <input
              id="login-pass"
              className="form-input login-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          {error && (
            <div className="login-error">
              <span>✗</span>
              <span>{error}</span>
            </div>
          )}

          <button type="submit" className="btn btn-primary login-submit" disabled={busy}>
            {busy ? "Authenticating…" : "Sign in →"}
          </button>

          <div className="login-hint">
            Set <span className="mono">HEAVEN_ADMIN_PASSWORD</span> on the server to
            configure credentials.
          </div>
        </motion.form>
      </div>
    </div>
  );
}
