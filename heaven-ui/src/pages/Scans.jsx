import React, { useEffect, useState } from "react";
import { Scans as ScansApi } from "../api";

const MODES = ["web", "network", "full", "ad", "cloud"];
const STEALTH = [
  { value: "1", label: "1 — Paranoid (very slow, evasive)" },
  { value: "2", label: "2 — Stealth (slow, low noise)" },
  { value: "3", label: "3 — Normal (balanced)" },
  { value: "4", label: "4 — Aggressive (fast, loud)" },
];

export default function Scans() {
  const [scans, setScans]   = useState(null);
  const [error, setError]   = useState(null);
  const [selected, setSelected] = useState(null);

  // Launcher form
  const [targets, setTargets]   = useState("");
  const [mode, setMode]         = useState("web");
  const [stealth, setStealth]   = useState("3");
  const [engagement, setEngagement] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [launching, setLaunching]   = useState(false);
  const [launchError, setLaunchError] = useState(null);
  const [launchSuccess, setLaunchSuccess] = useState(null);

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

  async function launchScan(e) {
    e.preventDefault();
    if (!authorized) { setLaunchError("You must confirm written authorization before scanning."); return; }
    const rawTargets = targets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (rawTargets.length === 0) { setLaunchError("Enter at least one target URL or IP."); return; }

    setLaunching(true);
    setLaunchError(null);
    setLaunchSuccess(null);
    try {
      const payload = {
        targets: rawTargets,
        mode,
        stealth_level: parseInt(stealth, 10),
        engagement: engagement.trim() || undefined,
        i_have_authorization: true,
      };
      const result = await ScansApi.create(payload);
      setLaunchSuccess(`Scan launched · ID: ${result.scan_id || result.id || "—"}`);
      setTargets("");
      setAuthorized(false);
      setTimeout(load, 1500);
    } catch (err) {
      setLaunchError(err.message || "Launch failed");
    } finally {
      setLaunching(false);
    }
  }

  function statusClass(s) {
    if (s === "running")   return "running";
    if (s === "completed") return "completed";
    if (s === "failed")    return "failed";
    if (s === "paused")    return "paused";
    return "";
  }

  return (
    <div className="page">
      {/* Scan launcher */}
      <div className="card">
        <div className="card-title">Launch Scan</div>
        <form onSubmit={launchScan}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 14 }}>
            <div style={{ gridColumn: "1 / -1" }}>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
                Targets <span className="dim">(URLs or IPs, one per line or comma-separated)</span>
              </label>
              <textarea
                value={targets}
                onChange={e => setTargets(e.target.value)}
                placeholder={"https://app.example.com\n10.0.0.1\n192.168.1.0/24"}
                rows={4}
                style={{
                  width: "100%", background: "rgba(0,255,65,0.04)",
                  border: "1px solid rgba(0,255,65,0.2)", color: "#00FF41",
                  fontFamily: "monospace", fontSize: 12, padding: "8px 10px",
                  outline: "none", resize: "vertical", boxSizing: "border-box",
                }}
              />
            </div>

            <div>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>Scan Mode</label>
              <select
                value={mode}
                onChange={e => setMode(e.target.value)}
                style={{
                  width: "100%", background: "#0a0a0a", color: "#00FF41",
                  border: "1px solid rgba(0,255,65,0.25)", padding: "8px 10px",
                  fontFamily: "monospace", fontSize: 12, outline: "none",
                }}
              >
                {MODES.map(m => <option key={m} value={m}>{m.toUpperCase()}</option>)}
              </select>
            </div>

            <div>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>Stealth Level</label>
              <select
                value={stealth}
                onChange={e => setStealth(e.target.value)}
                style={{
                  width: "100%", background: "#0a0a0a", color: "#00FF41",
                  border: "1px solid rgba(0,255,65,0.25)", padding: "8px 10px",
                  fontFamily: "monospace", fontSize: 12, outline: "none",
                }}
              >
                {STEALTH.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
            </div>

            <div style={{ gridColumn: "1 / -1" }}>
              <label className="form-label" style={{ marginBottom: 4, display: "block" }}>
                Engagement name <span className="dim">(optional)</span>
              </label>
              <input
                type="text"
                value={engagement}
                onChange={e => setEngagement(e.target.value)}
                placeholder="e.g. acme-webapp-pentest"
                style={{
                  width: "100%", background: "rgba(0,255,65,0.04)",
                  border: "1px solid rgba(0,255,65,0.2)", color: "#00FF41",
                  fontFamily: "monospace", fontSize: 12, padding: "8px 10px",
                  outline: "none", boxSizing: "border-box",
                }}
              />
            </div>
          </div>

          <label style={{
            display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer",
            marginBottom: 16, fontSize: 12, color: authorized ? "#00FF41" : "#FFB800",
          }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={e => setAuthorized(e.target.checked)}
              style={{ marginTop: 2, accentColor: "#00FF41" }}
            />
            <span>
              I confirm I have <strong>written authorization</strong> from the target system owner.
              Unauthorized scanning is illegal. HEAVEN logs all scan activity.
            </span>
          </label>

          {launchError && (
            <div style={{
              marginBottom: 12, padding: "8px 12px",
              background: "rgba(255,0,60,0.07)", border: "1px solid rgba(255,0,60,0.3)",
              color: "#FF003C", fontSize: 11, fontFamily: "monospace",
            }}>✗ {launchError}</div>
          )}
          {launchSuccess && (
            <div style={{
              marginBottom: 12, padding: "8px 12px",
              background: "rgba(0,255,65,0.07)", border: "1px solid rgba(0,255,65,0.3)",
              color: "#00FF41", fontSize: 11, fontFamily: "monospace",
            }}>✓ {launchSuccess}</div>
          )}

          <button
            type="submit"
            disabled={launching || !authorized}
            className="btn"
            style={{
              opacity: (!authorized || launching) ? 0.5 : 1,
              borderColor: "#00FF41", color: "#00FF41",
            }}
          >
            {launching ? "⏳ Launching..." : "⚡ Launch Scan"}
          </button>
        </form>
      </div>

      {/* CLI reference */}
      <div className="card">
        <div className="card-title">CLI Reference</div>
        <p className="dim" style={{ fontSize: 11, lineHeight: 1.7, marginBottom: 10 }}>
          Scans can also be launched from the terminal (authorization gate is enforced in both places).
        </p>
        <pre className="code" style={{ fontSize: 11 }}>{`# Web scan
heaven scan -u https://app.example.com -m web \\
    --engagement my-eng --i-have-authorization

# Network scan
heaven scan -t 10.0.0.0/24 -m network \\
    --engagement my-eng --i-have-authorization

# Resume interrupted scan
heaven resume --engagement my-eng --i-have-authorization`}</pre>
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
              <div className="dim">Launch a scan above or run one from the CLI</div>
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
                          ? <span style={{ color: s.findings_count > 0 ? "#FFB800" : "rgba(0,255,65,0.62)" }}>
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
