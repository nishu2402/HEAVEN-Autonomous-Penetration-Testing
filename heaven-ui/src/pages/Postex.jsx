// HEAVEN — Post-Exploitation triggers (linpeas / bloodhound / cred-reuse)
// Wraps POST /api/postex/{module}/run. Admin-only — refuses to run for non-admin.

import React, { useState } from "react";
import { Postex, getUser } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";

const MODULES = [
  { key: "linpeas", label: "Linpeas (SSH → privesc enum)" },
  { key: "bloodhound", label: "BloodHound (AD enumeration)" },
  { key: "cred-reuse", label: "Credential reuse spray" },
];

export default function PostexPage() {
  const [module, setModule] = useState("linpeas");
  const [bodyText, setBodyText] = useState(EXAMPLES.linpeas);
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const user = getUser();
  const isAdmin = (user?.role === "admin");

  function selectModule(m) {
    setModule(m);
    setBodyText(EXAMPLES[m]);
    setResult(null);
  }

  async function run() {
    setError(null);
    setResult(null);
    if (!authorized) {
      setError("Authorization checkbox is required.");
      return;
    }
    let body;
    try {
      body = JSON.parse(bodyText || "{}");
    } catch (e) {
      setError(`Body JSON is invalid: ${e.message}`);
      return;
    }
    setLoading(true);
    try {
      let r;
      if (module === "linpeas") r = await Postex.linpeas(body);
      else if (module === "bloodhound") r = await Postex.bloodhound(body);
      else r = await Postex.credReuse(body);
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
          Post-exploitation is admin-only. You're signed in as
          {" "}<strong>{user?.username || "?"}</strong> ({user?.role || "no role"}).
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--crit)", marginTop: 0 }}>⚡ Post-Exploitation</h2>
        <p className="page-lead">
          Destructive operations. Every module is admin-gated server-side and
          requires <code>authorized=True</code>; this UI checkbox is the
          operator's explicit ack.
        </p>

        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          {MODULES.map((m) => (
            <button key={m.key}
                    className={"btn-small" + (module === m.key ? " active" : "")}
                    onClick={() => selectModule(m.key)}>
              {m.label}
            </button>
          ))}
        </div>

        <label className="form-group">
          <span className="form-label">Body JSON</span>
          <textarea className="form-input mono-input" value={bodyText} rows={10}
                    spellCheck={false}
                    onChange={(e) => setBodyText(e.target.value)} />
        </label>

        <label className={"consent-row" + (authorized ? " is-ack" : "")}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I have <strong>written authorization</strong> for this destructive action.</span>
        </label>

        <button className="btn btn-danger" disabled={loading || !authorized} onClick={run}>
          {loading ? "Running…" : `Run ${module}`}
        </button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>
      )}

      {result && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">Result</div>
          <pre className="cli-block" style={{ wordBreak: "break-word", fontSize: 11 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

const EXAMPLES = {
  linpeas: JSON.stringify({
    host: "10.0.0.5",
    username: "root",
    password: "toor",
    port: 22,
  }, null, 2),
  bloodhound: JSON.stringify({
    domain: "CORP.LOCAL",
    dc_host: "10.0.0.10",
    username: "Administrator",
    password: "Password123!",
    use_ssl: false,
  }, null, 2),
  "cred-reuse": JSON.stringify({
    credentials: [["admin", "admin"], ["root", "toor"]],
    targets: [["10.0.0.5", 22, "ssh"], ["10.0.0.6", 445, "smb"]],
  }, null, 2),
};
