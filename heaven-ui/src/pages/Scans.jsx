import React, { useEffect, useState } from "react";
import { Scans as ScansApi } from "../api";

export default function Scans() {
  const [scans, setScans]   = useState(null);
  const [error, setError]   = useState(null);
  const [selected, setSelected] = useState(null);

  function load() {
    ScansApi.list(50)
      .then((d) => { setScans(d.scans || []); setError(null); })
      .catch((e) => setError(e.message));
  }

  useEffect(() => {
    load();
    const i = setInterval(load, 8000);
    return () => clearInterval(i);
  }, []);

  function statusClass(s) {
    if (s === "running")   return "running";
    if (s === "completed") return "completed";
    if (s === "failed")    return "failed";
    if (s === "paused")    return "paused";
    return "";
  }

  return (
    <div className="page">
      <div className="card">
        <div className="card-title">Active &amp; Recent Scans</div>
        <p className="dim" style={{ fontSize: 12, lineHeight: 1.7, marginBottom: 12 }}>
          Scans launch from the CLI — the authorization gate is enforced there.
          The UI shows status and feeds findings into the engagement DB in real time.
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <pre className="code" style={{ flex: 1, fontSize: 11 }}>{`# Web scan
heaven scan -u https://app.example.com -m web \\
    --engagement my-eng --i-have-authorization

# Network scan
heaven scan -t 10.0.0.0/24 -m network \\
    --engagement my-eng --i-have-authorization

# Resume interrupted scan
heaven resume --engagement my-eng --i-have-authorization`}</pre>
        </div>
      </div>

      {error && <div className="card error">{error}</div>}

      {scans !== null && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div className="card-title" style={{ marginBottom: 0 }}>
              {scans.length === 0 ? "No scans yet" : `${scans.length} scan${scans.length !== 1 ? "s" : ""}`}
            </div>
            <button className="btn-small" onClick={load}>↻ Refresh</button>
          </div>

          {scans.length === 0 ? (
            <div className="info-state">
              <h3>No scans recorded</h3>
              <div className="dim">Run a scan from the CLI to see it here</div>
            </div>
          ) : (
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Mode</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Started</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s, i) => {
                  const id = s.scan_id || s.id || `scan-${i}`;
                  const progress = s.progress_pct ?? null;
                  const isActive = selected === id;
                  return (
                    <tr key={id} onClick={() => setSelected(isActive ? null : id)}
                        style={{ cursor: "pointer", background: isActive ? "rgba(0,255,65,0.04)" : "" }}>
                      <td>
                        <code style={{ fontSize: 11 }}>{id.slice(0, 8)}</code>
                      </td>
                      <td>{s.mode || s.config?.scan_type || "full"}</td>
                      <td>
                        <span className={`scan-status ${statusClass(s.status)}`}>
                          {s.status || "unknown"}
                        </span>
                      </td>
                      <td style={{ width: 100 }}>
                        {progress !== null ? (
                          <div className={`progress-bar ${s.status === "running" ? "progress-indeterminate" : ""}`}>
                            <div className="progress-fill" style={{ width: `${progress}%` }} />
                          </div>
                        ) : (
                          s.status === "running" ? (
                            <div className="progress-bar progress-indeterminate">
                              <div className="progress-fill" style={{ width: "40%" }} />
                            </div>
                          ) : "—"
                        )}
                      </td>
                      <td className="dim" style={{ fontSize: 11 }}>
                        {(s.created || s.started_at || "").slice(0, 16).replace("T", " ")}
                      </td>
                      <td>
                        {s.findings_count != null
                          ? <span style={{ color: s.findings_count > 0 ? "#FFB800" : "rgba(0,255,65,0.35)" }}>
                              {s.findings_count}
                            </span>
                          : "—"
                        }
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
