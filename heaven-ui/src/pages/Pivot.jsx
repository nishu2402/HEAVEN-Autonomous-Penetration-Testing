// HEAVEN — Network Pivoting (single / double pivot over authorized SSH jumps)
// Wraps POST /api/pivot/run. Admin-only + explicit written-authorization ack.

import React, { useState } from "react";
import { Pivot, getUser } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";

function emptyJump() {
  return { host: "", port: 22, username: "", password: "", key_path: "" };
}

export default function PivotPage() {
  const [jumps, setJumps] = useState([emptyJump()]);
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("21,22,23,25,80,139,445,3306,3389,8080");
  const [socks, setSocks] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const { loading, result, error, start, clear } = useJob("pivot");
  const [formError, setFormError] = useState(null);
  const user = getUser();
  const isAdmin = user?.role === "admin";

  function updateJump(i, field, value) {
    setJumps((prev) => prev.map((j, idx) => (idx === i ? { ...j, [field]: value } : j)));
  }
  function addJump() { setJumps((prev) => [...prev, emptyJump()]); }
  function removeJump(i) { setJumps((prev) => prev.filter((_, idx) => idx !== i)); }

  function run() {
    setFormError(null);
    const cleanJumps = jumps
      .filter((j) => j.host.trim() && j.username.trim())
      .map((j) => ({
        host: j.host.trim(), port: Number(j.port) || 22,
        username: j.username.trim(), password: j.password,
        key_path: j.key_path.trim(),
      }));
    if (cleanJumps.length === 0) {
      setFormError("At least one jump host (with host + username) is required.");
      return;
    }
    if (!authorized) {
      setFormError("Authorization checkbox is required.");
      return;
    }
    const body = {
      jumps: cleanJumps,
      targets: targets.split(",").map((t) => t.trim()).filter(Boolean),
      ports: ports.split(",").map((p) => Number(p.trim())).filter((n) => n > 0),
      socks,
      i_have_authorization: true,
    };
    start(
      { label: `Pivot · ${cleanJumps.length} hop(s)`, kind: "pivot", path: "/pivot" },
      () => Pivot.run(body),
    );
  }

  if (!isAdmin) {
    return (
      <div className="page">
        <div className="card error">
          Pivoting is admin-only. You're signed in as{" "}
          <strong>{user?.username || "?"}</strong> ({user?.role || "no role"}).
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--crit)", marginTop: 0 }}>↔ Network Pivoting</h2>
        <p className="page-lead">
          Tunnel through authorized SSH foothold host(s) to reach and connect-scan
          subnets your own machine cannot route to. Add a second jump for a double
          pivot (each tunnels through the previous). Read-only: it opens tunnels
          and connect-scans, nothing else.
        </p>

        {jumps.map((j, i) => (
          <div key={i} className="card" style={{ background: "var(--surface-1)", marginBottom: 10 }}>
            <div className="card-title" style={{ display: "flex", justifyContent: "space-between" }}>
              <span>Jump {i + 1}{i === 0 ? " (foothold)" : ""}</span>
              {jumps.length > 1 && (
                <button className="btn-small" onClick={() => removeJump(i)}>Remove</button>
              )}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10 }}>
              <label className="form-group">
                <span className="form-label">Host</span>
                <input className="form-input" value={j.host} placeholder="10.0.0.5"
                       onChange={(e) => updateJump(i, "host", e.target.value)} />
              </label>
              <label className="form-group">
                <span className="form-label">Port</span>
                <input className="form-input" type="number" value={j.port}
                       onChange={(e) => updateJump(i, "port", e.target.value)} />
              </label>
              <label className="form-group">
                <span className="form-label">Username</span>
                <input className="form-input" value={j.username} placeholder="msfadmin"
                       onChange={(e) => updateJump(i, "username", e.target.value)} />
              </label>
              <label className="form-group">
                <span className="form-label">Password</span>
                <input className="form-input" type="password" value={j.password}
                       autoComplete="new-password"
                       onChange={(e) => updateJump(i, "password", e.target.value)} />
              </label>
              <label className="form-group">
                <span className="form-label">Key path (optional)</span>
                <input className="form-input" value={j.key_path} placeholder="/path/to/id_rsa"
                       onChange={(e) => updateJump(i, "key_path", e.target.value)} />
              </label>
            </div>
          </div>
        ))}
        <button className="btn-small" onClick={addJump} style={{ marginBottom: 14 }}>
          + Add jump (double pivot)
        </button>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14 }}>
          <label className="form-group">
            <span className="form-label">Targets behind the pivot (comma-separated)</span>
            <input className="form-input" value={targets} placeholder="10.1.1.20, 10.1.1.21"
                   onChange={(e) => setTargets(e.target.value)} />
          </label>
          <label className="form-group">
            <span className="form-label">Ports to connect-scan</span>
            <input className="form-input" value={ports}
                   onChange={(e) => setPorts(e.target.value)} />
          </label>
        </div>

        <label className="consent-row" style={{ marginTop: 4 }}>
          <input type="checkbox" checked={socks} onChange={(e) => setSocks(e.target.checked)} />
          <span>Also start a local SOCKS proxy over the tunnel and keep it open.</span>
        </label>

        <label className={"consent-row" + (authorized ? " is-ack" : "")}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I have <strong>written authorization</strong> to pivot into these networks.</span>
        </label>

        <button className="btn btn-danger" disabled={loading || !authorized} onClick={run}>
          {loading ? "Pivoting…" : "Establish pivot"}
        </button>
        {result && (
          <button className="btn-small" style={{ marginLeft: 8 }} onClick={clear}>Clear</button>
        )}

        {(formError || error) && (
          <div className="error" style={{ marginTop: 12 }}>{formError || error}</div>
        )}
      </div>

      {loading && <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>}
      {result && <PivotResult result={result} />}
    </div>
  );
}

function PivotResult({ result }) {
  const reachable = (result.reachable || []).filter((r) => r.open);
  return (
    <>
      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">
          {result.established ? (
            <span style={{ color: "var(--ok)" }}>
              Pivot established: {(result.chain || []).join(" → ")}
            </span>
          ) : (
            <span style={{ color: "var(--crit)" }}>Pivot failed</span>
          )}
        </div>
        {result.socks_port && (
          <div style={{ fontSize: 13 }}>
            SOCKS proxy: <code>socks5://127.0.0.1:{result.socks_port}</code>
          </div>
        )}
        {(result.errors || []).length > 0 && (
          <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>
            {result.errors.join("; ")}
          </div>
        )}
      </div>

      {reachable.length > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">
            {reachable.length} open port(s) reached through the pivot
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="data-table" style={{ fontSize: 12 }}>
              <thead><tr><th>Host</th><th>Port</th><th>Banner</th></tr></thead>
              <tbody>
                {reachable.map((r, i) => (
                  <tr key={i}>
                    <td className="mono">{r.host}</td>
                    <td>{r.port}</td>
                    <td className="dim">{r.banner}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card" style={{ marginTop: 12 }}>
        <details>
          <summary className="card-title" style={{ cursor: "pointer" }}>Raw JSON</summary>
          <pre className="cli-block" style={{ wordBreak: "break-word", fontSize: 11 }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </details>
      </div>
    </>
  );
}
