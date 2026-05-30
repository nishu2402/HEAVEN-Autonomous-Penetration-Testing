import React, { useState } from "react";
import { changePassword } from "../api";

// Blocking overlay shown after login when the account is still on the default
// admin/admin credential. The user can't proceed until they set a strong one.
export default function ForcedPasswordChange({ onDone }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setErr("");
    if (next !== confirm) { setErr("New passwords don't match"); return; }
    if (next.length < 8) { setErr("Use at least 8 characters"); return; }
    setBusy(true);
    try {
      await changePassword(current, next);
      onDone?.();
    } catch (e2) {
      setErr(e2.message || "Could not change password");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 9000, display: "grid", placeItems: "center",
      background: "rgba(4,6,12,0.78)", backdropFilter: "blur(8px)", padding: 20,
    }}>
      <form onSubmit={submit} className="card-glass" style={{
        width: "100%", maxWidth: 440, padding: 32, borderRadius: "var(--radius-xl)",
        boxShadow: "var(--shadow-lg)",
      }}>
        <div style={{
          display: "inline-flex", alignItems: "center", gap: 8, padding: "5px 12px",
          borderRadius: 999, background: "rgba(255,77,106,0.12)",
          boxShadow: "inset 0 0 0 1px rgba(255,77,106,0.3)", color: "var(--crit)",
          fontSize: 11.5, fontWeight: 700, marginBottom: 16,
        }}>
          ● SECURITY · ACTION REQUIRED
        </div>
        <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>Set a new password</div>
        <div style={{ color: "var(--text-2)", fontSize: 13, marginBottom: 24, lineHeight: 1.6 }}>
          This account is using the default <span className="mono">admin/admin</span> credential.
          Choose a strong password to continue — HEAVEN won't let you in until you do.
        </div>

        <div className="login-field">
          <label>Current password</label>
          <input className="form-input" type="password" value={current}
                 onChange={(e) => setCurrent(e.target.value)} autoFocus
                 placeholder="admin (the default)" />
        </div>
        <div className="login-field">
          <label>New password</label>
          <input className="form-input" type="password" value={next}
                 onChange={(e) => setNext(e.target.value)} placeholder="At least 8 characters" />
        </div>
        <div className="login-field">
          <label>Confirm new password</label>
          <input className="form-input" type="password" value={confirm}
                 onChange={(e) => setConfirm(e.target.value)} />
        </div>

        {err && <div className="login-error"><span>✗</span><span>{err}</span></div>}

        <button type="submit" className="btn btn-primary" style={{ width: "100%", padding: 12, marginTop: 6 }}
                disabled={busy}>
          {busy ? "Updating…" : "Update password & continue →"}
        </button>
      </form>
    </div>
  );
}
