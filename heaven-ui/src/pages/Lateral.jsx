// HEAVEN — Lateral Movement launcher
// Wraps POST /api/lateral/run. Admin-only (config.modify permission).

import React, { useState } from "react";
import { Lateral, getUser } from "../api";
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
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const user = getUser();
  const isAdmin = (user?.role === "admin");

  async function run() {
    setError(null);
    setResult(null);
    if (!authorized) { setError("Authorization checkbox is required."); return; }
    if (smbPass && smbNthash) { setError("smb-pass and smb-nthash are mutually exclusive"); return; }

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
    setLoading(true);
    try {
      const r = await Lateral.run(body);
      setResult(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
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
        <h2 style={{ color: "var(--crit)", marginTop: 0 }}>↔ Lateral Movement</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          SSH key reuse + SMB PsExec + pass-the-hash. Outputs a hop graph of
          which target accepted which credential. Mirrors{" "}
          <code>heaven lateral</code> from the CLI.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <fieldset style={{ border: "1px solid var(--border)", padding: 12 }}>
            <legend style={{ color: "var(--cyan)", fontSize: 11 }}>SSH key reuse</legend>
            <label className="form-label">Private key path (on this server)</label>
            <input type="text" value={sshKey}
                   onChange={(e) => setSshKey(e.target.value)}
                   placeholder="/path/to/id_rsa"
                   style={{ width: "100%", fontSize: 12, marginBottom: 8 }} />
            <label className="form-label">Usernames (one per line)</label>
            <textarea value={sshUsers} rows={3}
                      onChange={(e) => setSshUsers(e.target.value)}
                      style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }} />
          </fieldset>

          <fieldset style={{ border: "1px solid rgba(255,7,58,0.2)", padding: 12 }}>
            <legend style={{ color: "var(--crit)", fontSize: 11 }}>SMB / pass-the-hash</legend>
            <label className="form-label">Username · Domain</label>
            <div style={{ display: "flex", gap: 6, marginBottom: 8 }}>
              <input type="text" value={smbUser}
                     onChange={(e) => setSmbUser(e.target.value)}
                     placeholder="Administrator"
                     style={{ flex: 1, fontSize: 12 }} />
              <input type="text" value={smbDomain}
                     onChange={(e) => setSmbDomain(e.target.value)}
                     placeholder="CORP"
                     style={{ flex: 1, fontSize: 12 }} />
            </div>
            <label className="form-label">Password (or NT hash for pass-the-hash)</label>
            <input type="password" value={smbPass}
                   onChange={(e) => setSmbPass(e.target.value)}
                   placeholder="password (leave blank for PtH)"
                   style={{ width: "100%", fontSize: 12, marginBottom: 6 }} />
            <input type="text" value={smbNthash}
                   onChange={(e) => setSmbNthash(e.target.value)}
                   placeholder="NT hash hex (32 chars)"
                   style={{ width: "100%", fontSize: 12, fontFamily: "monospace" }} />
          </fieldset>
        </div>

        <label className="form-label" style={{ marginTop: 12 }}>Targets (host:port, one per line)</label>
        <textarea value={targetsText} rows={4}
                  onChange={(e) => setTargetsText(e.target.value)}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }} />

        <label style={{ display: "flex", alignItems: "flex-start", gap: 8,
                        color: authorized ? "var(--text-0)" : "var(--med)",
                        marginTop: 12, marginBottom: 12 }}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I have written authorization to spray these credentials.</span>
        </label>

        <button className="btn" disabled={loading || !authorized} onClick={run}>
          {loading ? "Spraying…" : "Run lateral movement"}
        </button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
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
