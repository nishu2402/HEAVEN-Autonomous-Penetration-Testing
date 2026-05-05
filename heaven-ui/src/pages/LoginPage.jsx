import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { login } from "../api";

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
      setError(err.message || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">⚡ HEAVEN</div>
        <div className="login-sub">Command Centre</div>
        <label>
          Username
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            autoComplete="username"
          />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <div className="login-error">{error}</div>}
        <button type="submit" disabled={busy}>
          {busy ? "Authenticating..." : "Sign in"}
        </button>
        <div className="login-hint">
          Set <code>HEAVEN_ADMIN_PASSWORD</code> environment variable on the server.
        </div>
      </form>
    </div>
  );
}
