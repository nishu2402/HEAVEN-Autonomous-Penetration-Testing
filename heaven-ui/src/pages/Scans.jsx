import React, { useEffect, useState } from "react";
import { Scans as ScansApi, Replay } from "../api";
import { useToast } from "../components/Toast.jsx";

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
  const [refreshing, setRefreshing] = useState(false);

  // Launcher form
  const [targets, setTargets]   = useState("");
  const [mode, setMode]         = useState("web");
  const [stealth, setStealth]   = useState("3");
  const [engagement, setEngagement] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [launching, setLaunching]   = useState(false);
  const [launchError, setLaunchError] = useState(null);
  const [launchSuccess, setLaunchSuccess] = useState(null);
  const toast = useToast();

  async function load() {
    setRefreshing(true);
    try {
      const d = await ScansApi.list(50);
      setScans(d.scans || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load();
    const i = setInterval(load, 8000);
    return () => clearInterval(i);
  }, []);

  // 1-second tick so a running scan's elapsed time updates live.
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
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
                  width: "100%", background: "var(--border)",
                  border: "1px solid var(--border)", color: "var(--text-0)",
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
                  width: "100%", background: "var(--bg-1)", color: "var(--text-0)",
                  border: "1px solid var(--border)", padding: "8px 10px",
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
                  width: "100%", background: "var(--bg-1)", color: "var(--text-0)",
                  border: "1px solid var(--border)", padding: "8px 10px",
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
                  width: "100%", background: "var(--border)",
                  border: "1px solid var(--border)", color: "var(--text-0)",
                  fontFamily: "monospace", fontSize: 12, padding: "8px 10px",
                  outline: "none", boxSizing: "border-box",
                }}
              />
            </div>
          </div>

          <label style={{
            display: "flex", alignItems: "flex-start", gap: 10, cursor: "pointer",
            marginBottom: 16, fontSize: 12, color: authorized ? "var(--text-0)" : "var(--med)",
          }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={e => setAuthorized(e.target.checked)}
              style={{ marginTop: 2, accentColor: "var(--text-0)" }}
            />
            <span>
              I confirm I have <strong>written authorization</strong> from the target system owner.
              Unauthorized scanning is illegal. HEAVEN logs all scan activity.
            </span>
          </label>

          {launchError && (
            <div style={{
              marginBottom: 12, padding: "8px 12px",
              background: "var(--border)", border: "1px solid var(--crit)",
              color: "var(--crit)", fontSize: 11, fontFamily: "monospace",
            }}>✗ {launchError}</div>
          )}
          {launchSuccess && (
            <div style={{
              marginBottom: 12, padding: "8px 12px",
              background: "var(--border)", border: "1px solid var(--text-2)",
              color: "var(--text-0)", fontSize: 11, fontFamily: "monospace",
            }}>✓ {launchSuccess}</div>
          )}

          <button
            type="submit"
            disabled={launching || !authorized}
            className="btn"
            style={{
              opacity: (!authorized || launching) ? 0.5 : 1,
              borderColor: "var(--text-0)", color: "var(--text-0)",
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
            <button className="btn-small" onClick={load} disabled={refreshing}>
              {refreshing ? "⏳ Refreshing…" : "↻ Refresh"}
            </button>
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
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s, i) => {
                  const id = s.scan_id || s.id || `scan-${i}`;
                  const progress = s.progress_pct ?? null;
                  const isActive = selected === id;
                  return (
                    <tr key={id} onClick={() => setSelected(isActive ? null : id)}
                        style={{ cursor: "pointer", background: isActive ? "var(--border)" : "" }}>
                      <td>
                        <code style={{ fontSize: 11 }}>{id.slice(0, 8)}</code>
                      </td>
                      <td>{s.mode || s.config?.scan_type || "full"}</td>
                      <td>
                        <span className={`scan-status ${statusClass(s.status)}`}>
                          {s.status || "unknown"}
                        </span>
                        {s.status === "running" && (() => {
                          const start = Date.parse(s.created || s.started_at || "");
                          if (!start) return null;
                          const sec = Math.max(0, Math.floor((now - start) / 1000));
                          const mm = Math.floor(sec / 60);
                          return (
                            <div className="dim" style={{ fontSize: 10, marginTop: 2 }}>
                              ⏱ {mm}m {sec % 60}s
                            </div>
                          );
                        })()}
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
                          ? <span style={{ color: s.findings_count > 0 ? "var(--med)" : "var(--text-1)" }}>
                              {s.findings_count}
                            </span>
                          : "—"
                        }
                      </td>
                      <td>
                        {(s.status === "completed" || s.status === "failed") && (
                          <button
                            className="btn-small"
                            title="Re-execute this scan with the stored seed (Gap 8: reproducibility)"
                            onClick={async (e) => {
                              e.stopPropagation();
                              try {
                                const r = await Replay.scan(id, {});
                                toast.success(
                                  "Replay started",
                                  `New scan ${String(r.new_scan_id || "").slice(0, 8)}` +
                                  (r.seed != null
                                    ? ` · seed ${r.seed} (deterministic)`
                                    : " · no seed stored (non-deterministic)")
                                );
                                load();
                              } catch (err) {
                                toast.error("Replay failed", err.message);
                              }
                            }}
                          >
                            ↻ Replay
                          </button>
                        )}
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
