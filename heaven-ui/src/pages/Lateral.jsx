// HEAVEN — Lateral Movement launcher
// Wraps POST /api/lateral/run. Admin-only (config.modify permission).

import React, { useState } from "react";
import { Lateral, getUser } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";

export default function LateralPage() {
  const [sshKey, setSshKey] = useState("");
  const [sshUsers, setSshUsers] = useState("root\nubuntu\nec2-user");
  const [smbUser, setSmbUser] = useState("");
  const [smbDomain, setSmbDomain] = useState("");
  const [smbPass, setSmbPass] = useState("");
  const [smbNthash, setSmbNthash] = useState("");
  const [targetsText, setTargetsText] = useState("10.0.0.5:22\n10.0.0.5:445");
  const [authorized, setAuthorized] = useState(false);
  // Global job store: a credential spray keeps running (and keeps its result)
  // across page navigation. `formError` is local pre-flight validation only.
  const { loading, result, error, start } = useJob("lateral");
  const [formError, setFormError] = useState(null);
  const user = getUser();
  const isAdmin = (user?.role === "admin");

  function run() {
    setFormError(null);
    if (!authorized) { setFormError("Authorization checkbox is required."); return; }
    if (smbPass && smbNthash) { setFormError("smb-pass and smb-nthash are mutually exclusive"); return; }

    const targets = targetsText.split(/\n+/).map(t => t.trim()).filter(Boolean).map(t => {
      const [host, port] = t.split(":");
      return [host, parseInt(port, 10)];
    });

    const body = {
      ssh_key_path: sshKey || undefined,
      ssh_usernames: sshUsers.split(/\n+/).map(s => s.trim()).filter(Boolean),
      smb_username: smbUser || undefined,
      smb_password: smbPass || "",
      smb_nthash: smbNthash || "",
      smb_domain: smbDomain,
      targets,
    };
    start({ label: "Lateral movement", kind: "lateral", path: "/lateral" }, () => Lateral.run(body));
  }

  if (!isAdmin) {
    return (
      <div className="page">
        <div className="card error">
          Lateral movement is admin-only. You're signed in as
          {" "}<strong>{user?.username || "?"}</strong> ({user?.role || "no role"}).
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--accent-2)", marginTop: 0 }}>↔ Lateral Movement</h2>
        <p className="page-lead">
          SSH key reuse + SMB PsExec + pass-the-hash. Outputs a hop graph of
          which target accepted which credential. Mirrors{" "}
          <code>heaven lateral</code> from the CLI.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <fieldset className="form-fieldset">
            <legend>SSH key reuse</legend>
            <label className="form-label">Private key path (on this server)</label>
            <input className="form-input" type="text" value={sshKey}
                   onChange={(e) => setSshKey(e.target.value)}
                   placeholder="/path/to/id_rsa"
                   style={{ marginBottom: 10 }} />
            <label className="form-label">Usernames (one per line)</label>
            <textarea className="form-input mono-input" value={sshUsers} rows={3}
                      onChange={(e) => setSshUsers(e.target.value)} />
          </fieldset>

          <fieldset className="form-fieldset is-danger">
            <legend>SMB / pass-the-hash</legend>
            <label className="form-label">Username · Domain</label>
            <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
              <input className="form-input" type="text" value={smbUser}
                     onChange={(e) => setSmbUser(e.target.value)}
                     placeholder="Administrator" />
              <input className="form-input" type="text" value={smbDomain}
                     onChange={(e) => setSmbDomain(e.target.value)}
                     placeholder="CORP" />
            </div>
            <label className="form-label">Password (or NT hash for pass-the-hash)</label>
            <input className="form-input" type="password" value={smbPass}
                   onChange={(e) => setSmbPass(e.target.value)}
                   placeholder="password (leave blank for PtH)"
                   style={{ marginBottom: 8 }} />
            <input className="form-input mono-input" type="text" value={smbNthash}
                   onChange={(e) => setSmbNthash(e.target.value)}
                   placeholder="NT hash hex (32 chars)" />
          </fieldset>
        </div>

        <label className="form-label" style={{ marginTop: 14, display: "block", marginBottom: 6 }}>
          Targets (host:port, one per line)
        </label>
        <textarea className="form-input mono-input" value={targetsText} rows={4}
                  onChange={(e) => setTargetsText(e.target.value)} />

        <label className={"consent-row" + (authorized ? " is-ack" : "")}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I have <strong>written authorization</strong> to spray these credentials.</span>
        </label>

        <button className="btn btn-primary" disabled={loading || !authorized} onClick={run}>
          {loading ? "Spraying…" : "Run lateral movement"}
        </button>

        {(formError || error) && (
          <div className="error" style={{ marginTop: 12 }}>{formError || error}</div>
        )}
        {loading && (
          <div className="dim" style={{ marginTop: 10, fontSize: 12 }}>
            Running on the server — you can leave this page and come back; it won't stop.
          </div>
        )}
      </div>

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>
      )}

      {result && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">
            Summary — {result.successful} success(es) / {result.attempted} attempt(s)
          </div>
          {result.method_breakdown && Object.keys(result.method_breakdown).length > 0 && (
            <div className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
              By technique: {Object.entries(result.method_breakdown)
                .map(([k, v]) => `${k}=${v}`).join(", ")}
            </div>
          )}
          {(result.hops || []).length > 0 && (
            <>
              <div className="card-title" style={{ marginTop: 12 }}>Hop graph</div>
              {result.hops.map((h, i) => (
                <div key={i} style={{ fontFamily: "monospace", fontSize: 12, marginBottom: 4 }}>
                  <span className="dim">{h.from}</span> →{" "}
                  <span style={{ color: "var(--text-0)" }}>{h.to}</span>{" "}
                  <span className="dim">via</span> {h.technique}{" "}
                  <span className="dim">as</span> {h.credential_label}
                </div>
              ))}
            </>
          )}
          {(result.errors || []).length > 0 && (
            <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>
              {result.errors.length} error(s) suppressed
            </div>
          )}
        </div>
      )}
    </div>
  );
}
